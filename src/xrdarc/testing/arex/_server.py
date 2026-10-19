"""The fake CE: :class:`FakeARex`, its test controls, and how a request reaches A-REX's router.

:class:`FakeARex` is the class stack of the endpoint modules
(:mod:`._jobs` - which builds on :mod:`._session` - :mod:`._info` and
:mod:`._delegations`, all on :mod:`._base`) with the lifecycle, the test
controls and the router on top. The HTTP(S) serving is
:class:`xrdsec.testing.https.FakeHTTPSServer`, owned as :attr:`_https`: it
does TLS per connection, keep-alive, the request log and the faults, and
hands every request that is not faulted to :meth:`FakeARex._respond`, which
works out who is asking (certificate or token) and runs A-REX's router
under the fake's lock.

The request log is the server's; :attr:`FakeARex.requests` presents each
entry as A-REX would have read it (its ``;`` query rule, the identity it
would have assigned), so faulted requests are in it too.
"""

from __future__ import annotations

import os
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from xrdsec.testing import https

from ._delegations import _DelegationEndpoints
from ._descriptions import _Description
from ._info import _InfoEndpoints
from ._jobs import _JobEndpoints
from ._model import (
    _ERASE_AFTER,
    _STATES,
    CEInfo,
    FakeDelegation,
    FakeJob,
    Request,
    _delegation_key,
)
from ._wire import _Ctx, _fault, _split_target, _Submit

#: An endpoint: what ``<base>/rest/<version>/<functionality>`` dispatches to.
_Functionality = Callable[["FakeARex", _Ctx], https.Response]


class _Server(https.FakeHTTPSServer):
    """The HTTP(S) side of one :class:`FakeARex`: every unfaulted request goes to its router.

    :meth:`respond` is overridden rather than routes registered because
    A-REX's router is a walk down the path with checks in a fixed order
    (404 outside the service before 403 for no credential before 404 for an
    unknown version); a table of independent regular expressions cannot say
    which refusal comes first. Faults, the log and the wire stay xrdsec's.
    """

    def __init__(self, arex: FakeARex, *, tls: ssl.SSLContext | None, host: str, port: int) -> None:
        """Bind the port; the fake starts serving with :meth:`FakeARex.start`."""
        super().__init__(tls=tls, host=host, port=port, name="xrdarc-fake-arex")
        self.arex = arex

    def respond(self, request: https.Request) -> https.Response | None:
        """A-REX's answer to ``request`` (faults have been applied already)."""
        return self.arex._respond(request)


class FakeARex(_JobEndpoints, _InfoEndpoints, _DelegationEndpoints):
    """A threaded fake ARC CE answering the A-REX REST interface under ``/arex``.

    ``root`` holds the session directories (``root/session/<job id>``).
    ``tls`` is a server context (``pki.server_context()``); ``None`` serves
    plain HTTP. Clients authenticate with a client certificate (identity =
    the end-entity subject, ``/DC=org/.../CN=Test User``) or with
    ``Authorization: Bearer <token>`` for a token in ``tokens`` (token ->
    identity); ``anonymous`` is the identity of a request with neither (by
    default such a request is refused with 403, as A-REX refuses it).

    The constructor's keywords are the CE's configuration, which is why
    there are so many: ``versions`` served, ``legacy_json`` (render JSON as
    an ARC 6 server did), ``progression`` (states each poll moves a job
    along), ``maxjobs``, ``info`` (what ``/info`` publishes) and the
    ``delegation_key_slot`` of the frozen test key behind every CSR.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        versions: tuple[str, ...] = ("1.0", "1.1"),
        legacy_json: bool = False,
        tokens: dict[str, str] | None = None,
        progression: tuple[str, ...] | None = None,
        maxjobs: int | None = None,
        info: CEInfo | str | None = None,
        anonymous: str | None = None,
        delegation_key_slot: int = 6,
    ) -> None:
        """Create the session root and bind the port; nothing is served until :meth:`start`."""
        self.root = Path(root)
        (self.root / "session").mkdir(parents=True, exist_ok=True)
        self.tls = tls
        self.host = host
        #: REST versions served (``GET /rest`` lists them; others answer 404).
        self.versions = versions
        #: Render JSON as an ARC 6 server did: no forced arrays, an empty list as no body.
        self.legacy_json = legacy_json
        self.tokens: dict[str, str] = dict(tokens or {})
        #: States each status/info poll moves a job along (``None``: jobs stay put).
        self.progression = progression
        #: A-REX's ``maxjobs``: how many jobs (of all users) may exist.
        self.maxjobs = maxjobs
        #: What ``GET /info`` publishes: a :class:`CEInfo`, or a GLUE2 XML document.
        self.info: CEInfo | str = info if info is not None else CEInfo()
        self.anonymous = anonymous
        #: Operation classes (see :data:`OPERATIONS`) answered 403 "Operation is not allowed".
        self.denied: set[str] = set()
        #: Called with each submitted description; a returned text fails that job with it.
        self.policy: Callable[[str], str | None] | None = None
        #: Seconds from a job's end to its ``WorkingAreaEraseTime``.
        self.erase_after = _ERASE_AFTER
        #: The key behind every delegation CSR.
        self.delegation_key = _delegation_key(delegation_key_slot)
        self.jobs: dict[str, FakeJob] = {}
        self.delegations: dict[str, FakeDelegation] = {}
        self._rejections: list[str] = []
        # Re-entrant: a test control may call another under the lock
        # (``add_job`` calls ``set_state``), and handlers call helpers that a
        # test may also call directly.
        self._lock = threading.RLock()
        self._https = _Server(self, tls=tls, host=host, port=port)

    # -- lifecycle ----------------------------------------------------------------------

    def start(self) -> FakeARex:
        """Serve in a background thread."""
        self._https.start()
        return self

    def stop(self) -> None:
        """Stop listening and hang up on every open connection, as a dead CE would."""
        self._https.stop()

    def __enter__(self) -> FakeARex:
        """Start serving; the ``with`` block is the CE's lifetime."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """Stop, whether or not the block raised."""
        self.stop()

    @property
    def connections(self) -> int:
        """Connections accepted so far (after the TLS handshake)."""
        return self._https.connections

    @property
    def faults(self) -> list[https.Fault]:
        """Faults not yet used up (see :meth:`fault`); the list is live."""
        return self._https.faults

    @property
    def requests(self) -> list[Request]:
        """Every request so far, as A-REX read it (faulted ones included), oldest first."""
        # Copied under the lock, converted outside it: reading a certificate
        # identity per entry is slow and must not hold up a request in flight.
        with self._lock:
            logged = list(self._https.requests)
        return [self._as_read(request) for request in logged]

    # -- test controls ----------------------------------------------------------------

    def fault(
        self,
        method: str | None = None,
        path_pattern: str | None = None,
        *,
        status: int | None = 500,
        reason: str = "",
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        times: int = 1,
        drop: bool = False,
        delay: float = 0.0,
    ) -> https.Fault:
        """Answer the next ``times`` matching requests with this instead (see :class:`Fault`).

        ``path_pattern`` is searched for in the decoded request target. Public
        API with one keyword per :class:`~xrdsec.testing.https.Fault` field,
        so a test reads like the answer it fakes.
        """
        return self._https.add_fault(
            https.Fault(
                method=method,
                pattern=path_pattern,
                status=status,
                reason=reason,
                body=body,
                headers=dict(headers or {}),
                times=times,
                drop=drop,
                delay=delay,
            )
        )

    def reject_next(self, reason: str, times: int = 1) -> None:
        """Fail the next ``times`` submitted jobs with per-job 500 ``reason`` (and no id)."""
        with self._lock:
            self._rejections.extend([reason] * times)

    def add_job(
        self,
        owner: str,
        description: str = '&(executable="/bin/true")',
        *,
        state: str = "ACCEPTING",
        files: dict[str, bytes] | None = None,
        exit_code: int | None = None,
        failure: str | None = None,
    ) -> FakeJob:
        """Put a job straight into the store (no request), with session ``files``.

        The job goes through the same :meth:`_build` a submission does, so
        it has a real session directory and A-REX's id format; ``state``,
        ``exit_code`` and ``failure`` then move it as :meth:`set_state` would.
        Raises ``ValueError`` for a description the fake cannot read.
        """
        language = "emies:adl" if description.lstrip().startswith("<") else "nordugrid:xrsl"
        with self._lock:
            # Straight to ``_build``: no ``maxjobs``, no queued rejection and no
            # policy, so a test's setup is never refused by the test's own rules.
            job = self._build(owner, _Description(description, language), _Submit("", "", 1, 1))
            if isinstance(job, str):
                raise ValueError(job)
            _write_files(job, files or {})
            if state != job.state or exit_code is not None or failure is not None:
                self.set_state(job.id, state, exit_code=exit_code, failure=failure)
            return job

    def set_state(
        self,
        job_id: str,
        state: str,
        *,
        exit_code: int | None = None,
        failure: str | None = None,
    ) -> FakeJob:
        """Move a job to REST ``state`` (``KeyError`` for no such job, ``ValueError`` state)."""
        if state not in _STATES:
            raise ValueError(f"not a REST state: {state!r}")
        with self._lock:
            job = self.jobs[job_id]
            self._transition(job, state, exit_code=exit_code, failure=failure)
            return job

    def fail_job(
        self, job_id: str, failure: str = "Job failed", *, exit_code: int | None = 1
    ) -> FakeJob:
        """Make a job FAILED in its current state (its ``RestartState``)."""
        return self.set_state(job_id, "FAILED", exit_code=exit_code, failure=failure)

    def clear(self) -> None:
        """Forget the recorded requests."""
        with self._lock:
            self._https.requests.clear()

    # -- request entry --------------------------------------------------------------------

    def _identify(self, request: https.Request) -> str | None:
        """The identity; ``""`` with no credential; ``None`` for a bearer token not known.

        A token wins over a certificate, as on A-REX: a client that sends
        both is authorised as the token's subject. The certificate identity
        is the end-entity subject of the chain (proxy CNs removed).
        """
        auth = request.header("Authorization") or ""
        # An unknown token is refused even when a valid certificate came with
        # it: the client chose to be the token's subject, and A-REX does not
        # fall back to a different identity than the one presented.
        if auth.startswith("Bearer "):
            return self.tokens.get(auth[7:].strip())
        if request.peer is not None:
            return request.peer.identity
        return self.anonymous or ""

    def _as_read(self, request: https.Request) -> Request:
        """``request`` as A-REX read it: its own query rule, its identity."""
        path, query = _split_target(request.target)
        identity = self._identify(request) or ""
        return Request(
            request.method, path, query, request.headers, request.body, identity, request.target
        )

    def _respond(self, request: https.Request) -> https.Response:
        """Route ``request`` through A-REX's router, holding the fake's lock throughout."""
        # Parsed and identified before the lock is taken: neither reads shared
        # state, and a slow certificate parse should not serialise requests.
        path, query = _split_target(request.target)
        identity = self._identify(request)
        ctx = _Ctx(request.method, path, "", query, request.headers, request.body, identity or "")
        with self._lock:
            return self._process(ctx, identity)

    def _process(self, ctx: _Ctx, identity: str | None) -> https.Response:
        """A-REX's router: ``<base>/rest[/<version>[/<functionality>/...]]``, checks in its order.

        The order is A-REX's and visible to clients: a path outside the
        service is 404 before authentication is looked at, an unknown token
        is 403 before an unknown version is 404.
        """
        refused = self._outside(ctx) or _unauthorised(identity)
        if refused is not None:
            return refused
        # Purged for every authorised request, whatever it asks: a cleaned job
        # must already be gone when the client next lists or polls anything.
        self._purge()
        version = ctx.token()
        if not version:
            return self._versions(ctx)
        if version not in self.versions:
            return _fault(404, "Version Not Supported")
        ctx.version = version
        return self._functionality(ctx)

    def _outside(self, ctx: _Ctx) -> https.Response | None:
        """404 for a path that is not ``<base>/rest...``; otherwise consume that much of it."""
        base = self.base_path
        # ``/arexfoo`` is outside the service: the base must end at a segment.
        if ctx.path != base and not ctx.path.startswith(base + "/"):
            return _fault(404, "Not Found")
        ctx.rest = ctx.path[len(base) :]
        return None if ctx.token() == "rest" else _fault(404, "Not Found")

    def _functionality(self, ctx: _Ctx) -> https.Response:
        """``info``, ``jobs`` or ``delegations``: the third path segment picks the endpoint."""
        functionality = ctx.token()
        if not functionality:
            return _fault(404, "Not Found")
        handler = self._FUNCTIONALITIES.get(functionality)
        if handler is None:
            return _fault(404, "Functionality Not Supported")
        return handler(self, ctx)

    _FUNCTIONALITIES: ClassVar[dict[str, _Functionality]] = {
        "info": _InfoEndpoints._info,
        "jobs": _JobEndpoints._jobs,
        "delegations": _DelegationEndpoints._delegations_endpoint,
    }


def _unauthorised(identity: str | None) -> https.Response | None:
    """A-REX's two 403s: a bearer token it does not know, and no credential at all.

    The texts are A-REX's, carried in the reason phrase; xrdarc shows them
    to the user, so they are kept word for word.
    """
    if identity is None:
        return _fault(403, "Not authorized: token is not valid")
    if not identity:
        return _fault(403, "User can't be assigned configuration")
    return None


def _write_files(job: FakeJob, files: dict[str, bytes]) -> None:
    """Put ``files`` (relative name -> contents) into the job's session directory."""
    for name, data in files.items():
        target = job.session / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
