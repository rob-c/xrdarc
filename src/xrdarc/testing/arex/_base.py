"""The fake A-REX's state, and what every endpoint shares: lookup, state changes, rendering.

:class:`_ARexBase` is the bottom of :class:`~xrdarc.testing.arex.FakeARex`'s
class stack. It declares every attribute the endpoint classes read
(``_info``, ``_session``, ``_jobs``, ``_delegations`` modules, one class
each) and holds the operations more than one of them needs: the job state
machine (:meth:`_transition`, :meth:`_observe`), ownership-checked lookup,
the per-operation denial a test can switch on, the negotiated rendering and
a job's GLUE2 ``ComputingActivity`` (the ``info`` action and
``diagnose/xml`` both serve it).

Locking: every request runs under :attr:`_lock` (taken in
``FakeARex._respond``), and so does every test control, so nothing here
locks again.
"""

from __future__ import annotations

import shutil
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric import rsa
from xrdsec.testing.https import FakeHTTPSServer, Response

from ._model import (
    _STARTED_STATES,
    _STATES,
    CANCEL_CAUSE,
    GLUE2_NS,
    TERMINAL_STATES,
    CEInfo,
    FakeDelegation,
    FakeJob,
    _iso,
)
from ._render import _negotiate, _Node, _render_html, _render_json, _render_xml
from ._wire import _Ctx, _fault


class _ARexBase:
    """What every endpoint class of the fake reads; see the module docstring.

    The attributes are assigned in ``FakeARex.__init__``, which documents
    them; they are declared here so that each endpoint module type-checks
    on its own. The endpoint classes are mixins rather than collaborators
    because they share one store and one lock, and every handler needs
    both: passing a state object around would add a parameter to each of
    them and buy nothing.
    """

    base_path: ClassVar[str] = "/arex"

    root: Path
    tls: ssl.SSLContext | None
    host: str
    versions: tuple[str, ...]
    legacy_json: bool
    tokens: dict[str, str]
    progression: tuple[str, ...] | None
    maxjobs: int | None
    info: CEInfo | str
    anonymous: str | None
    denied: set[str]
    policy: Callable[[str], str | None] | None
    erase_after: float
    delegation_key: rsa.RSAPrivateKey
    jobs: dict[str, FakeJob]
    delegations: dict[str, FakeDelegation]
    _rejections: list[str]
    _lock: threading.RLock
    _https: FakeHTTPSServer

    @property
    def port(self) -> int:
        """The port the fake listens on (bound when it was made)."""
        return self._https.port

    @property
    def url(self) -> str:
        """The CE URL: ``https://<host>:<port>/arex`` (``http://`` without TLS)."""
        scheme = "https" if self.tls is not None else "http"
        return f"{scheme}://{self.host}:{self.port}{self.base_path}"

    def session_dir(self, job_id: str) -> Path:
        """Where job ``job_id``'s session directory is (or will be) on disk."""
        return self.root / "session" / job_id

    # -- state machine ----------------------------------------------------------------

    def _transition(
        self,
        job: FakeJob,
        state: str,
        *,
        exit_code: int | None = None,
        failure: str | None = None,
        reason: str = "",
    ) -> None:
        """Move ``job`` to REST ``state``, keeping the records A-REX keeps in step with it.

        The restart state (where a failed job failed), the start and end
        times, the exit code (``0`` for a job that finished without one), and
        a line in ``diagnose/errors`` naming the grid-manager state change.
        """
        # The old GM state is read before anything changes: it is the left-hand
        # side of the ``errors`` line written at the end.
        before, now = job.gm_state, time.time()
        # A-REX tells KILLED from FAILED by the failure text (``fast_state``),
        # so a kill must leave the cancel cause behind or it would read FAILED.
        if state == "KILLED" and failure is None:
            failure = job.failure or CANCEL_CAUSE
        # Only on the way into a failure: failing an already-failed job again
        # must not overwrite where it originally failed with ``FAILED``.
        if state in ("FAILED", "KILLED") and not job.terminal:
            job.failed_state = job.state
        job.state = state
        _stamp(job, now)
        if failure is not None:
            job.failure = failure
        _exit_code(job, exit_code)
        change = f"Job state change {before} -> {job.gm_state}"
        job.log.append(f"{_iso(now)} {change}   Reason: {reason}")

    def _observe(self, job: FakeJob) -> None:
        """A status or info poll: apply a pending kill, else make one step of progress.

        Exactly one step per poll, never by wall-clock time, so a test drives
        a client's polling loop deterministically: N polls move a job N
        states along :attr:`progression`. A kill wins over progress, which
        is what makes "kill, then poll until KILLED" end in one poll.
        """
        if job.kill_requested:
            job.kill_requested = False
            self._transition(job, "KILLED", failure=CANCEL_CAUSE, reason="Cancelled by user")
        elif self.progression and job.state in self.progression[:-1]:
            step = self.progression[self.progression.index(job.state) + 1]
            self._transition(job, step, reason="Progress")

    def _purge(self) -> None:
        """A-REX honours a clean mark once the job has finished.

        Run at the start of every request (``FakeARex._process``), so a
        clean asked for while the job was running takes effect on whichever
        request follows its end - the job vanishes without a second clean.
        """
        # A copy of the matching jobs: entries are deleted while iterating.
        for job in [job for job in self.jobs.values() if job.clean_requested and job.terminal]:
            del self.jobs[job.id]
            shutil.rmtree(job.session, ignore_errors=True)

    def _lookup(self, job_id: str, identity: str) -> FakeJob | None:
        """``job_id`` if ``identity`` owns it: nobody sees anybody else's jobs, as on A-REX."""
        job = self.jobs.get(job_id)
        return job if job is not None and job.owner == identity else None

    # -- answering ------------------------------------------------------------------------

    def _denied(self, operation: str) -> Response | None:
        """A-REX's 403 if the test put ``operation`` (see :data:`OPERATIONS`) in :attr:`denied`."""
        if operation in self.denied:
            detail = f"{operation} operation is not allowed for this user"
            return _fault(403, "Operation is not allowed", detail)
        return None

    def _render(
        self,
        ctx: _Ctx,
        root: _Node,
        arrays: tuple[str, ...],
        *,
        status: int = 200,
        show_empty: bool = True,
    ) -> Response:
        """``root`` in the format ``Accept`` asks for; ``arrays`` are this endpoint's forced arrays.

        ``show_empty`` writes a forced array that has no members as ``[]``
        (most endpoints) rather than leaving it out (``/info``). A 201 says
        "Created", anything else "OK", as A-REX's renderer does.
        """
        kind, mime = _negotiate(ctx.header("Accept"))
        if kind == "json":
            # ARC 6 forced no arrays: a one-member list came back as an object,
            # which is the shape a client's "object or list" reading must survive.
            paths = () if self.legacy_json else arrays
            text = _render_json(root, paths, show_empty)
        elif kind == "xml":
            text = _render_xml(root)
        else:
            text = _render_html(root)
        headers = {"Content-Type": mime} if mime else {}
        reason = "Created" if status == 201 else "OK"
        return Response(status, text.encode(), headers, reason)

    def _activity(self, job: FakeJob) -> _Node:
        """The job's GLUE2 ComputingActivity, as the infoprovider writes it.

        Built afresh each time from the job's fields, so ``action=info``,
        ``diagnose/xml`` and the job's state can never disagree.
        """
        node = _Node(
            "ComputingActivity",
            attrs={"BaseType": "Activity", "CreationTime": _iso(time.time()), "Validity": "10800"},
            xmlns=GLUE2_NS,
        )
        node.add("ID", f"urn:caid:{self.host}:org.nordugrid.arcrest:{job.id}")
        if job.name:
            node.add("Name", job.name)
        node.add("OtherInfo", "SubmittedVia=org.nordugrid.arcrest")
        node.add("Type", "single")
        node.add("IDFromEndpoint", f"urn:idfe:{job.id}")
        node.add("JobDescription", job.language)
        # Both vocabularies, nordugrid's first, as the infoprovider lists them;
        # a client must pick the ``arcrest:`` one.
        node.add("State", f"nordugrid:{_STATES[job.state][2]}")
        node.add("State", f"arcrest:{job.state}")
        if job.failed_state and job.state in ("FAILED", "KILLED"):
            node.add("RestartState", f"arcrest:{job.failed_state}")
        for name, value in self._activity_fields(job):
            if value:
                node.add(name, value)
        node.add("Associations").add(
            "ComputingShareID", f"urn:ogf:ComputingShare:{self.host}:{job.queue}"
        )
        return node

    def _activity_fields(self, job: FakeJob) -> list[tuple[str, str]]:
        """The activity's plain fields, in the infoprovider's order; empty ones are left out.

        A failure text of several lines becomes one ``Error`` per line, as
        A-REX splits the ``failed`` file.
        """
        return [
            ("ExitCode", "" if job.exit_code is None else str(job.exit_code)),
            *(("Error", line) for line in job.failure.splitlines()),
            ("Owner", job.owner),
            ("LocalOwner", "arcuser"),
            ("StdOut", job.stdout),
            ("StdErr", job.stderr),
            ("LogDir", job.logdir),
            ("Queue", job.queue),
            ("SubmissionTime", _iso(job.submitted)),
            *self._times(job),
        ]

    def _times(self, job: FakeJob) -> list[tuple[str, str]]:
        """Start, end and erase times; each empty until the job has got there."""
        ended = job.ended
        return [
            ("StartTime", _iso(job.started) if job.started else ""),
            ("EndTime", _iso(ended) if ended else ""),
            ("WorkingAreaEraseTime", _iso(ended + self.erase_after) if ended else ""),
        ]


def _stamp(job: FakeJob, now: float) -> None:
    """Record when the job started running (once) and when it ended (cleared if it restarts).

    The start is kept across a restart - it is when the job first reached
    the batch system - while the end is cleared, because a restarted job is
    running again and must publish no ``EndTime`` or erase time.
    """
    if job.state in _STARTED_STATES and job.started is None:
        job.started = now
    job.ended = now if job.state in TERMINAL_STATES else None


def _exit_code(job: FakeJob, exit_code: int | None) -> None:
    """Set the exit code if one is given; a job that finishes without one exited 0.

    A FINISHED job always has an exit code on A-REX (``diag``), so a test
    that only says "finished" still gets the ``diag`` file and ``ExitCode``
    a client reports; FAILED and KILLED jobs keep ``None`` unless given one.
    """
    if exit_code is not None:
        job.exit_code = exit_code
    elif job.state == "FINISHED" and job.exit_code is None:
        job.exit_code = 0
