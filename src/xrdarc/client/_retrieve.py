"""Getting results: ``retrieve`` one job's session directory, ``get`` many, ``cat`` one file.

Everything a CE names here is hostile until checked: the job name used as a
directory, every entry of the session listing and the job's log directory
must be one safe path component (:func:`~xrdarc.rest.is_safe_name`), and
every local path is checked to resolve inside the target before anything is
created (:func:`_inside`). ``get`` downloads on a small pool
(:func:`xrdcore.fanout.run_all`, the fan-out every client on the stack
shares), so Ctrl-C stops it at once: :attr:`_FetchPlan.stop` is set, no
queued download starts, and running ones stop mid-file (the transport's
cancel hook) before the interrupt propagates.
"""

from __future__ import annotations

import errno
import functools
import os
import threading
from collections.abc import Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

from xrdcore import fanout

from ..errors import ARCError, HTTPError
from ..joblist import Job
from ..rest import DIAGNOSE_ITEMS, RESTClient, is_safe_name
from ..states import JobState
from ._model import Outcome, Progress, _FetchPlan
from ._monitor import _Monitoring


class _Retrieving(_Monitoring):
    """Session directories, outputs and diagnose files."""

    # -- output -------------------------------------------------------------------

    def files(self, job: Job, path: str = "") -> Iterator[tuple[str, int | None]]:
        """Every file in the job's session directory (below ``path``), with sizes."""
        return self.rest(job.ce).walk(job.id, path)

    def retrieve(
        self,
        job: Job,
        directory: str | os.PathLike[str],
        *,
        name: str | None = None,
        force: bool = False,
        diagnose: bool = False,
        progress: Progress | None = None,
    ) -> Path:
        """Download a job's session directory into ``directory/<name or id>``.

        ``name`` (or the job id) must be a single file name - a job name
        comes from the CE, which must not be able to point the download at
        ``..`` or an absolute path - else ``ARCError`` (EINVAL). An existing
        target is refused (EEXIST) unless ``force``, which, as ``arcget -f``
        does, downloads into it and overwrites the files the job has while
        leaving any others alone. The whole listing is fetched and every
        local path checked to resolve inside the target (no ``..``, no
        symlink out) before anything is created.

        A-REX keeps a job's ``gmlog`` out of the session directory and
        serves the same files as ``diagnose`` items, so for a job with a log
        directory they are saved into ``<target>/<gmlog>`` as ``arcget``
        does; ``diagnose`` saves them for any job, into
        ``<target>/diagnose`` when it has no log directory. The job is not
        cleaned; ``get`` does both.
        """
        plan = _FetchPlan(Path(directory), force=force, diagnose=diagnose, progress=progress)
        return self._retrieve(job, name or job.id, plan)

    def _retrieve(self, job: Job, leaf: str, plan: _FetchPlan) -> Path:
        """``retrieve`` into ``plan.directory / leaf``, honouring ``plan.stop``."""
        target = _target(plan, leaf)
        client = self.rest(job.ce)
        # Resolved before it exists (``strict=False``), so the containment
        # checks compare against the real location even when ``directory``
        # itself is reached through a symlink the user chose.
        root = target.resolve()
        # Listing first: a hostile entry anywhere fails the job before any file is written.
        files = [(path, _inside(root, path)) for path, _size in client.walk(job.id)]
        diagnostics = _diagnostics_dir(root, job, plan)
        target.mkdir(parents=True, exist_ok=True)
        for path, local in files:
            # Between files as well as inside each download: a run of tiny
            # files would otherwise finish every one before noticing Ctrl-C.
            _check_stop(plan.stop)
            local.parent.mkdir(parents=True, exist_ok=True)
            written = client.get_file(job.id, path, local, cancel=plan.stop)
            if plan.progress is not None:
                plan.progress(path, written)
        if diagnostics is not None:
            self._save_diagnostics(client, job, diagnostics)
        return target

    def _save_diagnostics(self, client: RESTClient, job: Job, where: Path) -> None:
        """Save every diagnose item the job has into ``where`` (a missing one is skipped)."""
        where.mkdir(parents=True, exist_ok=True)
        for item in DIAGNOSE_ITEMS:
            try:
                (where / item).write_bytes(client.diagnose(job.id, item))
            except HTTPError as exc:
                # A-REX answers 404 for an item the job never produced (no
                # ``failed`` for a job that succeeded); any other error is real.
                if exc.status != 404:
                    raise

    def get(
        self,
        jobs: Sequence[Job],
        directory: str | os.PathLike[str],
        *,
        keep: bool = False,
        use_names: bool = False,
        force: bool = False,
        diagnose: bool = False,
        workers: int = 4,
        progress: Progress | None = None,
    ) -> list[Outcome]:
        """``arcget``: download finished jobs, then clean them unless ``keep``.

        Jobs are refreshed first; ones that are not finished are skipped
        with a reason. Downloads run ``workers`` jobs at a time. An
        interrupt (Ctrl-C) stops at once: nothing more is started, the
        downloads in progress stop before their next file, nothing is
        cleaned, and the ``KeyboardInterrupt`` propagates.
        """
        # Refreshed, not taken from the job list: a stored "Finished" may be
        # stale (the CE wiped the job since), and a 404 there is then reported
        # per job rather than as a failed download.
        fresh = self.status(jobs)
        ready = [o.job for o in fresh if o.ok and o.job.state.retrievable]
        plan = _FetchPlan(Path(directory), use_names, force, diagnose, progress)
        fetched = self._fetch_all(ready, plan, max(1, workers))
        # Cleaning only after every download has finished, and only the jobs
        # that downloaded completely: a clean cannot be undone, and a job
        # whose results did not all arrive must stay retrievable.
        if not keep:
            self._clean_fetched(fetched)
        # In the order the caller gave the jobs, whatever order they finished in.
        return [fetched.get(o.job.url) or _unready(o) for o in fresh]

    def _fetch_all(
        self, ready: Sequence[Job], plan: _FetchPlan, workers: int
    ) -> dict[str, Outcome]:
        """Download ``ready`` with ``workers`` threads; their outcomes by job URL.

        ``_fetch`` turns a job's own failure into an :class:`Outcome`, so the
        only exceptions :func:`xrdcore.fanout.run_all` sees are a bug or an
        interrupt, and either rightly ends the whole ``get``: ``plan.stop``
        is its stop flag, so the queued jobs never start and the running ones
        give up before their next file (or mid-file, through the transport's
        cancel hook). An interrupt of the calling thread does the same.
        """
        calls = [functools.partial(self._fetch, job, plan) for job in ready]
        outcomes = fanout.run_all(calls, workers=workers, name="xrdarc-get", stop=plan.stop)
        return {outcome.job.url: outcome for outcome in outcomes}

    def _fetch(self, job: Job, plan: _FetchPlan) -> Outcome:
        """``retrieve`` as an ``Outcome``: a failure is the job's, not the whole ``get``'s."""
        # Two jobs with the same name collide under ``-J``; the second then
        # meets EEXIST in ``_target`` (unless ``force``) rather than merging.
        name = job.name if plan.use_names and job.name else job.id
        try:
            _check_stop(plan.stop)
            path = self._retrieve(job, name, plan)
        except (ARCError, OSError) as exc:
            return Outcome(job, False, getattr(exc, "user_message", None) or str(exc))
        return Outcome(job, True, path=path)

    def _clean_fetched(self, fetched: dict[str, Outcome]) -> None:
        """Clean the downloaded jobs; one that could not be cleaned says so in its reason."""
        # One bulk clean for the lot, rather than one per job as each finishes:
        # the downloads are what take time, and a bulk request is one round trip.
        for outcome in self.clean([o.job for o in fetched.values() if o.ok]):
            if not outcome.ok:
                url = outcome.job.url
                fetched[url] = replace(fetched[url], reason=f"not cleaned: {outcome.reason}")

    def cat(self, job: Job, out: BinaryIO, what: str = "stdout") -> int:
        """Copy one of the job's outputs to ``out``: ``stdout``, ``stderr``, ``joblog``,
        or any path in the session directory. Returns the bytes written."""
        client = self.rest(job.ce)
        if what == "joblog":
            # A-REX's log of the job is the ``errors`` diagnose file, not a session file.
            data = client.diagnose(job.id, "errors")
            out.write(data)
            return len(data)
        path = self._stream_path(job, what) if what in ("stdout", "stderr") else what
        return client.stream_file(job.id, path, out)

    def _stream_path(self, job: Job, which: str) -> str:
        """Where the job's ``stdout``/``stderr`` is: as recorded, else as its CE says now."""
        path = getattr(job, which) or getattr(self.status([job])[0].job, which)
        if not path:
            raise ARCError(f"The job does not name a {which} file", errno.ENOENT)
        return str(path)

    def diagnose(self, job: Job, item: str) -> bytes:
        """One of A-REX's per-job control files: see ``rest.DIAGNOSE_ITEMS``."""
        return self.rest(job.ce).diagnose(job.id, item)


def _check_stop(stop: threading.Event) -> None:
    """Give up a download that ``get`` has been told to stop."""
    if stop.is_set():
        raise ARCError("The download was interrupted", errno.EINTR)


def _inside(root: Path, relative: str) -> Path:
    """``root/relative``, which must resolve inside ``root`` (already resolved).

    Every component of ``relative`` is a safe name by now (the listing and
    ``_log_dir`` check them), so what this catches is a symlink already in
    the target - possible with ``force`` - that would lead the write out.
    """
    # ``joinpath`` of the parts rather than of the string, so a ``/`` can never
    # be read as an absolute path on the way in.
    local = root.joinpath(*relative.split("/"))
    if not local.resolve().is_relative_to(root):
        raise ARCError(f"Refusing to write {relative!r} outside {root}", errno.EINVAL)
    return local


def _log_dir(name: str | None) -> str | None:
    """A job's log directory as a safe relative path; ARC's own ``/diagnose`` means none.

    The name comes from the description or the CE; ``..``, a backslash or a
    drive letter in any component means it is not used at all.
    """
    parts = [p for p in (name or "").split("/") if p not in ("", ".")]
    if not parts or not all(is_safe_name(p) for p in parts):
        return None
    # ARC writes ``/diagnose`` for "no log directory of the user's": the CE
    # path of the diagnose items, not something to create in the results.
    if parts == ["diagnose"] and (name or "").startswith("/"):
        return None
    return "/".join(parts)


def _unready(outcome: Outcome) -> Outcome:
    """``get``'s outcome for a job it did not download: why (already failed, deleted, not done)."""
    # A job whose status could not be read keeps that reason: it is more
    # useful than "not finished", which would be a guess.
    if not outcome.ok:
        return outcome
    state = outcome.job.state
    if state is JobState.DELETED:
        return Outcome(outcome.job, False, "The job's files have been deleted on the CE")
    return Outcome(outcome.job, False, f"The job is not finished ({state.value})")


def _target(plan: _FetchPlan, leaf: str) -> Path:
    """The result directory ``plan.directory / leaf``, once it is known to be one safe name.

    An existing one is refused unless ``force``, as ``arcget`` refuses it.
    """
    if not is_safe_name(leaf):
        raise ARCError(
            f"Refusing {leaf!r} as a result directory: it must be a single file name",
            errno.EINVAL,
        )
    target = plan.directory / leaf
    # ``exists`` follows symlinks: a dangling link at the target counts as
    # free, and the later mkdir then fails with an error naming it.
    if target.exists() and not plan.force:
        raise ARCError(f"{target} already exists (use force to overwrite its files)", errno.EEXIST)
    return target


def _diagnostics_dir(root: Path, job: Job, plan: _FetchPlan) -> Path | None:
    """Where the diagnose files go: the job's log directory, else ``diagnose`` if asked for."""
    log_dir = _log_dir(job.log_dir)
    if not (plan.diagnose or log_dir):
        return None
    return _inside(root, log_dir or "diagnose")
