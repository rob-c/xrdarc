"""``jobs/<id>/session/...`` and ``jobs/<id>/diagnose/...``: a job's files, as A-REX serves them.

The session directory is a real directory under the fake's ``root``
(``root/session/<job id>``), so a test can put files there or read what a
client uploaded. Each method is a port of the matching handler in
rest.cpp: ``GET`` of a directory lists it (``file`` with ``size``,
``dir``), of a file serves it with A-REX's loose ``Range`` reading; ``PUT``
writes at the ``Content-Range`` offset and tracks completion per file;
``DELETE`` removes; ``PROPFIND`` answers WebDAV. Each is gated by its own
operation class (``DataInfo``, ``DataRead``, ``DataWrite``) so a test can
deny one.

The diagnose files are computed from the job's state - ``status``,
``errors``, ``local``, ``failed``, ``diag``, ``input_status``, ``xml`` -
with :attr:`FakeJob.diagnose` on top for anything a test wants verbatim.

Path safety is the part not to weaken: every session path goes through
``_canonical`` (A-REX's ``CanonicalDir``) before it touches the disk, so a
``..`` that climbs out of the session directory is a 404, and listings use
``lstat`` so a symbolic link a job left behind is neither listed nor
followed. The fake runs on a developer's machine; a client bug must not be
able to make it read or delete files outside its ``root``.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import stat
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from xrdhttp.testing import dav_entries, propfind_reply
from xrdsec.testing.https import Response

from ._base import _ARexBase
from ._model import DIAGNOSE_ITEMS, FakeJob, _unique
from ._render import _Node, _render_xml
from ._wire import _canonical, _content_range, _Ctx, _fault, _merge, _ranged


class _SessionEndpoints(_ARexBase):
    """A job's sub-resources: the session directory and the diagnose files."""

    def _job(self, ctx: _Ctx, job_id: str) -> Response:
        """``jobs/<id>/<sub-resource>``: the session directory or a diagnose file."""
        sub = ctx.token()
        if not sub:
            return _fault(404, "Missing job sub-resource")
        if sub == "session":
            job = self._lookup(job_id, ctx.identity)
            # A-REX has no failure text for a job it cannot find: the reason is "OK".
            return self._session(ctx, job) if job is not None else _fault(404, "OK")
        # The job is looked up inside ``_diagnose``, after the item name and
        # method are checked: a bad item is 404 whether or not the job exists.
        if sub == "diagnose":
            return self._diagnose(ctx, job_id)
        return _fault(404, "Wrong job sub-resource requested")

    def _session(self, ctx: _Ctx, job: FakeJob) -> Response:
        """``jobs/<id>/session/<path>``, by method; a path that climbs out is refused.

        ``relative`` is "" for the session directory itself, which every
        method accepts: ``GET`` lists it, ``PROPFIND`` describes it, and
        ``DELETE`` removes the whole session directory.
        """
        relative = _canonical(ctx.rest)
        if relative is None:
            return _fault(404, "Wrong path")
        handler = self._SESSION.get(ctx.method)
        if handler is None:
            return _fault(501, "Not Implemented")
        return handler(self, ctx, job, relative)

    def _session_get(self, ctx: _Ctx, job: FakeJob, relative: str) -> Response:
        """A directory's listing (files with sizes, then directories) or a file, ranged.

        Symbolic links and other special files are left out of a listing, as
        A-REX leaves them out; ``HEAD`` ignores ``Range``.
        """
        target = job.session / relative
        if target.is_dir():
            return self._denied("DataInfo") or self._render(ctx, _listing(target), ("file", "dir"))
        # Checked after the directory case: listing and reading are separate
        # rights on A-REX (``DataInfo`` and ``DataRead``).
        denied = self._denied("DataRead")
        if denied is not None:
            return denied
        if target.is_file():
            ranges = ctx.header("Range") if ctx.method == "GET" else None
            return _ranged(target.read_bytes(), ranges, "application/octet-stream")
        return _fault(404, "Not found")

    def _session_put(self, ctx: _Ctx, job: FakeJob, relative: str) -> Response:
        """Write a chunk at its ``Content-Range`` offset; a file is an upload once complete.

        The file is opened without truncation, as A-REX opens it, so chunks
        may arrive in any order; ``diagnose/input_status`` lists it when the
        chunks cover it.
        """
        denied = self._denied("DataWrite")
        if denied is not None:
            return denied
        target = job.session / relative
        # Without ``Content-Range`` the body is the whole file from offset 0;
        # with ``bytes a-b/*`` the size is what this chunk reaches, so far.
        offset, total = _content_range(ctx.header("Content-Range"), len(ctx.body))
        try:
            # Owner-only, like a CE's session directories: an upload may be a
            # user's input data, and the fake's root is on a shared machine.
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            handle = os.open(target, os.O_WRONLY | os.O_CREAT, 0o600)  # no O_TRUNC, as A-REX
        except OSError:
            return _fault(500, "Error creating file")
        with os.fdopen(handle, "wb") as stream:
            stream.seek(offset)
            stream.write(ctx.body)
        if self._chunk(job, relative, offset, len(ctx.body), total):
            job.uploads = _unique([*job.uploads, "/" + relative])
        return Response(200, reason="OK")

    @staticmethod
    def _chunk(job: FakeJob, relative: str, offset: int, length: int, total: int) -> bool:
        """``FileChunks``: is the file complete after writing ``length`` at ``offset``?"""
        # The size is learnt from the first chunk's Content-Range total; a
        # later chunk can only grow it (a client that did not know it).
        size, ranges = job._chunks.get(relative, (0, []))
        size = size or total
        # An empty body completes only an empty file (``total == 0``); for any
        # other file it adds nothing, and nothing is recorded for it.
        if length == 0:
            return total == 0
        # Overlapping and adjacent chunks merge, so a retried chunk counts once
        # and completion is "one range covering 0..size", however it arrived.
        ranges = _merge([*ranges, (offset, offset + length)])
        size = max(size, offset + length)
        job._chunks[relative] = (size, ranges)
        return ranges == [(0, size)]

    def _session_delete(self, ctx: _Ctx, job: FakeJob, relative: str) -> Response:
        """Remove a file, or a directory with everything in it."""
        denied = self._denied("DataWrite")
        if denied is not None:
            return denied
        target = job.session / relative
        # A file, else a whole directory: A-REX deletes either with one DELETE.
        # ``unlink`` is tried first because it refuses a directory, and a path
        # that is neither fails both: a 500, as A-REX gives for a missing one.
        try:
            target.unlink()
        except OSError:
            try:
                shutil.rmtree(target)
            except OSError:
                return _fault(500, "Failed to delete")
        return Response(202, reason="Accepted")

    def _session_propfind(self, ctx: _Ctx, job: FakeJob, relative: str) -> Response:
        """``PROPFIND``: a WebDAV multistatus of the path, ``Depth`` 0, 1 or (anything else) all.

        A-REX answers ``200`` rather than ``207``, with absolute ``href``\\ s;
        the document is :func:`xrdhttp.testing.propfind_reply`'s.
        """
        denied = self._denied("DataInfo")
        if denied is not None:
            return denied
        # ``infinity`` (or anything else) is ten levels: deeper than any test
        # tree, yet bounded, so a pathological directory cannot make one
        # request walk forever.
        depth = {"0": 0, "1": 1}.get(ctx.header("Depth", "") or "", 10)
        # ``ctx.path`` already starts with the base path, so the href is built
        # from scheme, host and port rather than from :attr:`url`, which has it.
        scheme, _, _ = self.url.partition("://")
        href = f"{scheme}://{self.host}:{self.port}{urllib.parse.quote(ctx.path)}"
        entries = dav_entries(job.session / relative, href, depth)
        reply = propfind_reply(entries, status=200, content_type="application/xml")
        return dataclasses.replace(reply, reason="OK")

    #: The session directory's methods.
    _SESSION: ClassVar[dict[str, Callable[[_SessionEndpoints, _Ctx, FakeJob, str], Response]]] = {
        "GET": _session_get,
        "HEAD": _session_get,
        "PUT": _session_put,
        "DELETE": _session_delete,
        "PROPFIND": _session_propfind,
    }

    def _diagnose(self, ctx: _Ctx, job_id: str) -> Response:
        """``jobs/<id>/diagnose/<item>``: one of :data:`DIAGNOSE_ITEMS`, if the job has it."""
        name = ctx.rest
        refused = _diagnose_refusal(ctx, name) or self._denied("JobInfo")
        if refused is not None:
            return refused
        job = self._lookup(job_id, ctx.identity)
        if job is None:
            return _fault(404, "OK")
        text = self._diagnose_files(job).get(name)
        if text is None:
            return _fault(404, "Not found")
        mime = "application/xml" if name == "xml" else "text/plain"
        # Ranged like a session file, so a client can fetch only what was appended.
        return _ranged(text.encode(), ctx.header("Range"), mime)

    def _diagnose_files(self, job: FakeJob) -> dict[str, str]:
        """The control files A-REX would keep for ``job``, :attr:`FakeJob.diagnose` on top.

        Computed per request from the job's current fields, so a state a
        test sets is in ``status`` and ``errors`` at once; anything in
        :attr:`FakeJob.diagnose` replaces the computed file of that name.
        """
        local = {
            "globalid": f"{self.url}/rest/1.0/jobs/{job.id}",
            "headnode": self.url,
            "interface": "org.nordugrid.arcrest",
            "queue": job.queue,
            "subject": job.owner,
            "jobname": job.name,
            "rerun": str(job.rerun),
            "delegationid": " ".join(job.delegations),
            "sessiondir": str(job.session),
        }
        files = {
            "description": job.description,
            "status": job.gm_state,
            "errors": "".join(line + "\n" for line in job.log),
            "local": "".join(f"{key}={value}\n" for key, value in local.items()),
            "xml": _render_xml(self._activity(job)),
            **_optional_files(job),
        }
        files.update(job.diagnose)
        return files


def _listing(directory: Path) -> _Node:
    """One session directory level as A-REX lists it: files with sizes, directories, by name."""
    root = _Node("list")
    for entry in sorted(directory.iterdir()):
        info = entry.lstat()
        if stat.S_ISREG(info.st_mode):
            root.add("file", entry.name, {"size": str(info.st_size)})
        elif stat.S_ISDIR(info.st_mode):
            root.add("dir", entry.name)
    return root


def _diagnose_refusal(ctx: _Ctx, name: str) -> Response | None:
    """404 for an item A-REX does not serve, 501 for anything but reading one."""
    if name not in DIAGNOSE_ITEMS:
        return _fault(404, "Diagnostic item not found")
    if ctx.method not in ("GET", "HEAD"):
        return _fault(501, "Not Implemented")
    return None


def _optional_files(job: FakeJob) -> dict[str, str]:
    """The control files a job has only sometimes: ``failed``, ``diag``, ``input_status``.

    A file the job does not have is a 404, not an empty body: that is how a
    client tells "no failure recorded" from "an empty failure", and the
    command line skips the 404 for a job that did not fail.
    """
    files = {}
    if job.failure:
        files["failed"] = job.failure
    if job.exit_code is not None:
        files["diag"] = f"exitcode={job.exit_code}\n"
    if job.uploads:
        files["input_status"] = "".join(name + "\n" for name in job.uploads)
    return files
