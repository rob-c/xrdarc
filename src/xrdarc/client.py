"""The ARC client: submit, monitor, retrieve and manage jobs across CEs.

``ARCClient`` is what the command-line tools are built on and what a script
should use. It owns one HTTPS session (and so one credential), the job list,
and a ``RESTClient`` per CE, and turns each user-level operation into the
right sequence of REST calls:

* **submit**: delegate a proxy to the CE, POST the descriptions in one
  request, upload each job's local inputs into its session directory, and
  record the jobs; a job whose uploads fail is killed and cleaned rather than
  left waiting ten minutes for files that will never arrive;
* **status**: one ``action=info`` per CE for any number of jobs;
* **retrieve**: walk the session directory, download it, then clean;
* **kill / clean / resume / renew**: the bulk actions, per CE.

Operations on many jobs never stop at the first failure: they return one
``Outcome`` per job, so a report can say which ones failed and why.
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO

from . import joblist as _joblist
from .adl import is_adl, prepare_adl
from .config import UserConfig, load_config
from .creds import Credentials, discover
from .errors import ARCError, CredentialError, DescriptionError, HTTPError, JobNotFoundError
from .info import CEInfo, parse_activity, parse_ce_info
from .joblist import Job, JobList
from .proxy import Signer, sign_request
from .rest import DIAGNOSE_ITEMS, BulkResult, RESTClient, SubmitResult
from .states import JobState
from .transport import Session
from .urls import ce_url
from .xrsl import PreparedJob, prepare

__all__ = ["ARCClient", "Outcome", "Submission"]

_log = logging.getLogger("xrdarc")

Progress = Callable[[str, int], None]


@dataclass(frozen=True, slots=True)
class Submission:
    """One description's fate: ``job`` is set when the CE accepted it and its inputs went up."""

    prepared: PreparedJob
    job: Job | None
    status: int
    reason: str

    @property
    def ok(self) -> bool:
        return self.job is not None


@dataclass(frozen=True, slots=True)
class Outcome:
    """What one bulk operation did to one job."""

    job: Job
    ok: bool
    reason: str = ""
    path: Path | None = None
    status: int = 0


def _group(jobs: Iterable[Job]) -> dict[str, list[Job]]:
    grouped: dict[str, list[Job]] = defaultdict(list)
    for job in jobs:
        grouped[job.ce].append(job)
    return grouped


class ARCClient:
    """Jobs on ARC CEs, through the REST interface.

    Everything is optional: ``config`` defaults to ``client.conf``,
    ``credentials`` to ARC's discovery, the job list to ``config.joblist``
    (``joblist=None`` keeps no list at all). ``password`` is called if a
    user key must be decrypted to sign a delegation. Close it, or use
    ``with``, to release connections.
    """

    def __init__(
        self,
        *,
        config: UserConfig | None = None,
        credentials: Credentials | None = None,
        joblist: str | os.PathLike[str] | JobList | bool | None = True,
        timeout: float | None = None,
        version: str | None = None,
        session: Session | None = None,
        password: Callable[[], bytes] | None = None,
        delegation_lifetime: float | None = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.credentials = credentials if credentials is not None else discover(self.config)
        self.session = session or Session(
            self.credentials, timeout=timeout if timeout is not None else self.config.timeout
        )
        if joblist is True:
            self.joblist: JobList | None = JobList(self.config.joblist)
        elif isinstance(joblist, JobList) or joblist is None:
            self.joblist = joblist
        elif joblist is False:
            self.joblist = None
        else:
            self.joblist = JobList(joblist)
        self.version = version
        self.password = password
        self.delegation_lifetime = delegation_lifetime
        self._clients: dict[str, RESTClient] = {}
        self._signer: Signer | None = None

    def __enter__(self) -> ARCClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    # -- plumbing --------------------------------------------------------------

    def rest(self, ce: str) -> RESTClient:
        """The REST client for ``ce`` (an alias from ``client.conf`` or a URL)."""
        url = ce_url(self.config.resolve(ce)[0])
        if url not in self._clients:
            self._clients[url] = RESTClient(url, self.session, version=self.version)
        return self._clients[url]

    def signer(self) -> Signer:
        """The X.509 credential that signs delegations; ``CredentialError`` without one."""
        if self._signer is None:
            cert, key = self.credentials.cert, self.credentials.key
            if not cert or not key:
                raise CredentialError(
                    "Delegation needs an X.509 proxy or certificate, and none was found"
                )
            self._signer = Signer.load(cert, None if key == cert else key, password=self.password)
        return self._signer

    def delegate(self, ce: str) -> str:
        """Create a delegation on ``ce`` and fill it; returns its id.

        X.509 when there is a certificate to sign with, otherwise the bearer
        token (REST 1.1). A slot whose signing or upload fails is deleted.
        """
        client = self.rest(ce)
        if self.credentials.cert is None and self.credentials.token:
            return client.new_token_delegation(self.credentials.token)
        signer = self.signer()
        delegation_id, request = client.new_delegation()
        try:
            pem = sign_request(request, signer, lifetime=self.delegation_lifetime)
            client.put_delegation(delegation_id, pem)
        except BaseException:
            try:
                client.delete_delegation(delegation_id)
            except ARCError as exc:
                _log.debug("could not delete delegation %s: %s", delegation_id, exc)
            raise
        return delegation_id

    def _record(self, jobs: Sequence[Job]) -> None:
        if self.joblist is not None and jobs:
            self.joblist.write(jobs)

    def _forget(self, jobs: Sequence[Job]) -> None:
        if self.joblist is not None and jobs:
            self.joblist.remove(job.url for job in jobs)

    # -- information -----------------------------------------------------------

    def info(self, ce: str) -> CEInfo:
        """The CE's description: endpoints, queues, runtime environments."""
        return parse_ce_info(self.rest(ce).info())

    # -- submission ------------------------------------------------------------

    def prepare(
        self,
        text: str,
        *,
        base: Path,
        delegation_id: str | None = None,
        queue: str | None = None,
        version: str = "1.1",
    ) -> list[PreparedJob]:
        """Turn a description (xRSL or ADL) into what is POSTed, and the uploads it needs."""
        if is_adl(text):
            return [
                prepare_adl(
                    text,
                    base=base,
                    delegation_id=delegation_id,
                    embed_delegation=version == "1.0",
                )
            ]
        return prepare(text, base=base, delegation_id=delegation_id, queue=queue)

    def submit(
        self,
        ce: str,
        description: str,
        *,
        base: str | os.PathLike[str] | None = None,
        queue: str | None = None,
        delegate: bool = True,
        progress: Progress | None = None,
    ) -> list[Submission]:
        """Submit a description (several jobs, for ``+`` xRSL) to ``ce``.

        ``base`` is where relative input files are read from (default: the
        current directory). Raises for what stops every job - an unreadable
        description, no credential, a CE that cannot be reached; per-job
        refusals come back as unsuccessful ``Submission``s.
        """
        client = self.rest(ce)
        where = Path(base) if base is not None else Path.cwd()
        # A description that cannot be prepared must fail before the CE is touched,
        # not after a delegation was made for it.
        self.prepare(description, base=where, queue=queue)
        version = client.version
        delegation_id = self.delegate(ce) if delegate else None
        prepared = self.prepare(
            description, base=where, delegation_id=delegation_id, queue=queue, version=version
        )
        results = client.submit(_bundle(prepared), queue=queue, delegation_id=delegation_id)
        submissions = [
            self._finish(client, job, result, delegation_id, progress)
            for job, result in _paired(prepared, results)
        ]
        self._record([s.job for s in submissions if s.job is not None])
        return submissions

    def _finish(
        self,
        client: RESTClient,
        prepared: PreparedJob,
        result: SubmitResult,
        delegation_id: str | None,
        progress: Progress | None,
    ) -> Submission:
        if not result.ok or result.id is None:
            return Submission(prepared, None, result.status, result.reason or "Not submitted")
        job = Job(
            ce=client.ce,
            id=result.id,
            name=prepared.name,
            description=prepared.description,
            submitted=_joblist.now(),
            delegations=(delegation_id,) if delegation_id else (),
            state=JobState.ACCEPTED,
            rest_state=result.state,
            queue=prepared.queue,
            stdout=prepared.stdout,
            stderr=prepared.stderr,
            log_dir=prepared.gmlog,
        )
        try:
            for upload in prepared.uploads:
                sent = client.put_file(result.id, upload.name, upload.source)
                if progress is not None:
                    progress(upload.name, sent)
        except (ARCError, OSError) as exc:
            reason = getattr(exc, "user_message", None) or str(exc)
            self._abandon(client, result.id)
            return Submission(prepared, None, 0, f"Uploading input files failed: {reason}")
        return Submission(prepared, job, result.status, result.reason)

    def _abandon(self, client: RESTClient, job_id: str) -> None:
        """Kill and clean a job whose inputs could not be uploaded (best effort)."""
        for action in (client.kill, client.clean):
            try:
                action([job_id])
            except ARCError as exc:
                _log.warning("could not %s job %s: %s", action.__name__, job_id, exc)

    # -- selecting and refreshing jobs --------------------------------------------

    def known(self) -> list[Job]:
        """Every job in the job list."""
        return [] if self.joblist is None else self.joblist.jobs()

    def select(
        self,
        names: Sequence[str] = (),
        *,
        everything: bool = False,
        ces: Sequence[str] = (),
        states: Sequence[str] = (),
    ) -> list[Job]:
        """The jobs ``arcstat`` and friends would act on.

        ``names`` are job URLs or job names; a URL not in the job list is
        still accepted. ``ces`` keeps only jobs on those CEs; ``states`` is
        applied by the caller once fresh states are known (``filter_states``).
        A name that matches nothing raises ``JobNotFoundError``.
        """
        known = self.known()
        whole = everything or (not names and bool(ces or states))
        chosen: list[Job] = list(known) if whole else []
        for name in names:
            chosen.extend(m for m in _matching(known, name) if m not in chosen)
        if ces:
            wanted = {ce_url(url) for ce in ces for url in self.config.resolve(ce)}
            chosen = [job for job in chosen if job.ce in wanted]
        return chosen

    def status(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Ask each CE about its jobs (``action=info``); ``Outcome.job`` holds the news.

        A job the CE no longer knows comes back with ``ok=False`` and the
        CE's reason; transport failures for one CE do not affect the others.
        """
        outcomes: dict[str, Outcome] = {}
        for ce, group in _group(jobs).items():
            outcomes.update(self._per_ce(ce, "info", group, _refreshed))
        return [outcomes[job.url] for job in jobs]

    def _per_ce(
        self,
        ce: str,
        action: str,
        group: Sequence[Job],
        outcome: Callable[[Job, BulkResult], Outcome],
    ) -> dict[str, Outcome]:
        """One bulk ``action`` on one CE; a CE that fails the request fails every job."""
        try:
            results = self.rest(ce).bulk(action, [j.id for j in group])
        except ARCError as exc:
            return {job.url: Outcome(job, False, exc.user_message) for job in group}
        return {job.url: outcome(job, r) for job, r in zip(group, results, strict=True)}

    def wait(
        self,
        jobs: Sequence[Job],
        *,
        interval: float = 60.0,
        timeout: float | None = None,
        callback: Callable[[Sequence[Outcome]], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> list[Outcome]:
        """Poll until every job is in a terminal state (or unknown to its CE).

        ``callback`` sees each round's outcomes. ``timeout`` raises
        ``ARCError`` (ETIMEDOUT) with jobs still running.
        """
        deadline = None if timeout is None else clock() + timeout
        pending = list(jobs)
        done: dict[str, Outcome] = {}
        while True:
            outcomes = self.status(pending)
            if callback is not None:
                callback(outcomes)
            pending = _settle(outcomes, done)
            if not pending:
                return [done[job.url] for job in jobs]
            if deadline is not None and clock() + interval > deadline:
                raise ARCError(f"{len(pending)} jobs still not finished", errno.ETIMEDOUT)
            sleep(interval)

    # -- bulk management --------------------------------------------------------

    def _bulk(
        self, action: str, jobs: Sequence[Job], accept: Callable[[Job], str | None] | None = None
    ) -> list[Outcome]:
        outcomes: dict[str, Outcome] = {}
        eligible = []
        for job in jobs:
            refusal = accept(job) if accept else None
            if refusal:
                outcomes[job.url] = Outcome(job, False, refusal)
            else:
                eligible.append(job)
        for ce, group in _group(eligible).items():
            outcomes.update(self._per_ce(ce, action, group, _acted))
        return [outcomes[job.url] for job in jobs]

    def kill(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Ask the CEs to cancel the jobs; asynchronous, like A-REX itself."""
        return self._bulk("kill", jobs, _refuse_finished)

    def clean(self, jobs: Sequence[Job], *, forget: bool = True) -> list[Outcome]:
        """Remove finished jobs from their CEs and (``forget``) from the job list.

        A job its CE no longer knows (404) is forgotten too, as ``arcclean -f`` does.
        """
        outcomes = self._bulk("clean", jobs)
        if forget:
            self._forget([o.job for o in outcomes if o.ok or o.status == 404])
        return outcomes

    def resume(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Restart failed jobs from where they failed (needs ``rerun`` in the description)."""
        return self._bulk("restart", jobs)

    def renew(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Refresh the delegated proxies of running jobs with the current credential."""
        signer = self.signer()
        renewed: dict[tuple[str, str], str | None] = {}
        outcomes = []
        for job in jobs:
            ids, failure = (job.delegations, None) if job.delegations else self._delegations_of(job)
            for delegation_id in ids:
                key = (job.ce, delegation_id)
                if key not in renewed:
                    renewed[key] = self._renew_one(job.ce, delegation_id, signer)
                failure = failure or renewed[key]
            if not ids and failure is None:
                failure = "The CE knows of no delegation for this job"
            outcomes.append(Outcome(job, failure is None, failure or ""))
        return outcomes

    def _delegations_of(self, job: Job) -> tuple[tuple[str, ...], str | None]:
        """The job's delegation ids as its CE lists them, or why the CE could not say."""
        try:
            result = self.rest(job.ce).job_delegations([job.id])[0]
        except ARCError as exc:
            return (), exc.user_message
        if not result.ok:
            return (), result.reason or f"HTTP {result.status}"
        return result.delegations, None

    def _renew_one(self, ce: str, delegation_id: str, signer: Signer) -> str | None:
        client = self.rest(ce)
        try:
            request = client.renew_delegation(delegation_id)
            client.put_delegation(
                delegation_id, sign_request(request, signer, lifetime=self.delegation_lifetime)
            )
        except HTTPError as exc:
            return exc.reason or exc.user_message
        except ARCError as exc:
            return exc.user_message
        return None

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

        An existing target is refused (EEXIST) unless ``force``. A-REX keeps
        a job's ``gmlog`` out of the session directory and serves the same
        files as ``diagnose`` items, so for a job with a log directory they
        are saved into ``<target>/<gmlog>`` as ``arcget`` does; ``diagnose``
        saves them for any job, into ``<target>/diagnose`` when it has no
        log directory. The job is not cleaned; ``get`` does both.
        """
        target = Path(directory) / (name or job.id)
        if target.exists():
            if not force:
                raise ARCError(f"{target} already exists (use force to replace it)", errno.EEXIST)
            shutil.rmtree(target)
        client = self.rest(job.ce)
        target.mkdir(parents=True)
        for path, _size in client.walk(job.id):
            local = target.joinpath(*path.split("/"))
            local.parent.mkdir(parents=True, exist_ok=True)
            written = client.get_file(job.id, path, local)
            if progress is not None:
                progress(path, written)
        log_dir = _log_dir(job.log_dir)
        if diagnose or log_dir:
            self._save_diagnostics(
                client, job, target.joinpath(*(log_dir or "diagnose").split("/"))
            )
        return target

    def _save_diagnostics(self, client: RESTClient, job: Job, where: Path) -> None:
        where.mkdir(parents=True, exist_ok=True)
        for item in DIAGNOSE_ITEMS:
            try:
                (where / item).write_bytes(client.diagnose(job.id, item))
            except HTTPError as exc:
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
        with a reason. Downloads run ``workers`` jobs at a time.
        """
        fresh = self.status(jobs)
        ready = [o.job for o in fresh if o.ok and o.job.state.retrievable]

        def fetch(job: Job) -> Outcome:
            name = job.name if use_names else None
            return self._fetch(job, directory, name, force, diagnose, progress)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            fetched = {o.job.url: o for o in pool.map(fetch, ready)}
        if not keep:
            self._clean_fetched(fetched)
        return [fetched.get(o.job.url) or _unready(o) for o in fresh]

    def _fetch(
        self,
        job: Job,
        directory: str | os.PathLike[str],
        name: str | None,
        force: bool,
        diagnose: bool,
        progress: Progress | None,
    ) -> Outcome:
        """``retrieve`` as an ``Outcome``: a failure is the job's, not the whole ``get``'s."""
        try:
            path = self.retrieve(
                job, directory, name=name, force=force, diagnose=diagnose, progress=progress
            )
        except (ARCError, OSError) as exc:
            return Outcome(job, False, getattr(exc, "user_message", None) or str(exc))
        return Outcome(job, True, path=path)

    def _clean_fetched(self, fetched: dict[str, Outcome]) -> None:
        """Clean the downloaded jobs; one that could not be cleaned says so in its reason."""
        for outcome in self.clean([o.job for o in fetched.values() if o.ok]):
            if not outcome.ok:
                url = outcome.job.url
                fetched[url] = replace(fetched[url], reason=f"not cleaned: {outcome.reason}")

    def cat(self, job: Job, out: BinaryIO, what: str = "stdout") -> int:
        """Copy one of the job's outputs to ``out``: ``stdout``, ``stderr``, ``joblog``,
        or any path in the session directory. Returns the bytes written."""
        client = self.rest(job.ce)
        if what == "joblog":
            data = client.diagnose(job.id, "errors")
            out.write(data)
            return len(data)
        path = what
        if what in ("stdout", "stderr"):
            path = getattr(job, what) or getattr(self.status([job])[0].job, what) or ""
            if not path:
                raise ARCError(f"The job does not name a {what} file", errno.ENOENT)
        return client.stream_file(job.id, path, out)

    def diagnose(self, job: Job, item: str) -> bytes:
        """One of A-REX's per-job control files: see ``rest.DIAGNOSE_ITEMS``."""
        return self.rest(job.ce).diagnose(job.id, item)

    def sync(self, ce: str, *, replace_all: bool = False) -> list[Job]:
        """``arcsync``: add the CE's jobs for this user to the job list; returns the new ones."""
        client = self.rest(ce)
        ids = [job_id for job_id, _ in client.jobs()]
        delegations = {r.id: r.delegations for r in client.job_delegations(ids)} if ids else {}
        if self.joblist is not None and replace_all:
            self.joblist.clear()
        known = {job.url for job in self.known()}
        found = [
            Job(ce=client.ce, id=job_id, delegations=delegations.get(job_id, ())) for job_id in ids
        ]
        new = [job for job in found if job.url not in known]
        self._record(new)
        return new


def _bundle(prepared: Sequence[PreparedJob]) -> str:
    """One request body for several descriptions: ``+`` xRSL or ``ActivityDescriptions``."""
    if len(prepared) == 1:
        return prepared[0].description
    texts = [p.description for p in prepared]
    if all(t.lstrip().startswith("&") for t in texts):
        return "+" + "".join(f"({t})" for t in texts)
    raise DescriptionError("Several descriptions can only be submitted together as xRSL")


def _paired(
    prepared: Sequence[PreparedJob], results: Sequence[SubmitResult]
) -> Iterator[tuple[PreparedJob, SubmitResult]]:
    for index, job in enumerate(prepared):
        if index < len(results):
            yield job, results[index]
        else:
            yield job, SubmitResult(0, "The CE did not answer for this description", None, None)


def _matching(known: Sequence[Job], name: str) -> list[Job]:
    """The listed jobs ``name`` means (URL, id or job name); a job URL stands for itself."""
    matches = [j for j in known if name in (j.url, j.id, j.name)]
    if matches:
        return matches
    if "://" in name:
        return [Job.from_url(name)]
    raise JobNotFoundError(f"Job {name!r} is not in the job list")


def _settle(outcomes: Sequence[Outcome], done: dict[str, Outcome]) -> list[Job]:
    """File the outcomes that are final under ``done``; the jobs still to wait for."""
    pending = []
    for outcome in outcomes:
        if outcome.ok and not outcome.job.state.terminal:
            pending.append(outcome.job)
        else:
            done[outcome.job.url] = outcome
    return pending


def _acted(job: Job, result: BulkResult) -> Outcome:
    return Outcome(job, result.ok, result.reason, status=result.status)


def _refreshed(job: Job, result: BulkResult) -> Outcome:
    if not result.ok:
        return Outcome(job, False, result.reason or f"HTTP {result.status}", status=result.status)
    return Outcome(job.update(parse_activity(result.info, result.state)), True)


def _log_dir(name: str | None) -> str | None:
    """A job's log directory as a safe relative path; ARC's own ``/diagnose`` means none."""
    parts = [p for p in (name or "").split("/") if p not in ("", ".")]
    if not parts or ".." in parts or (parts == ["diagnose"] and (name or "").startswith("/")):
        return None
    return "/".join(parts)


def _refuse_finished(job: Job) -> str | None:
    if job.state.terminal:
        return f"The job is already {job.state.value.lower()}"
    return None


def _unready(outcome: Outcome) -> Outcome:
    if not outcome.ok:
        return outcome
    state = outcome.job.state
    if state is JobState.DELETED:
        return Outcome(outcome.job, False, "The job's files have been deleted on the CE")
    return Outcome(outcome.job, False, f"The job is not finished ({state.value})")
