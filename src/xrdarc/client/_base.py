"""The client's plumbing: configuration, credentials, the session, the job list, delegation.

:class:`_ClientBase` is the bottom of :class:`~xrdarc.client.ARCClient`'s
stack (the operations are :mod:`._submit`, :mod:`._monitor` and
:mod:`._retrieve`). It owns the one HTTPS session, a cached
:class:`~xrdarc.rest.RESTClient` per CE, the signer delegations are made
with, and the two ways of touching the job list: plainly (an error is the
caller's) and *safely* for jobs that already exist on a CE, where an error
must never lose them, so it is a warning naming the jobs and ``xrdarc sync``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import Self

from xrdsec.lifetime import Lifetime, assess

from ..config import UserConfig, load_config
from ..creds import Credentials, discover
from ..errors import ARCError, CredentialError
from ..info import CEInfo, parse_ce_info
from ..joblist import Job, JobList
from ..proxy import Signer, load_signer, sign_request
from ..rest import RESTClient
from ..transport import Session
from ..urls import ce_url
from ._model import LOW_LIFETIME, _log


class _ClientBase:
    """Configuration, credentials, session and job list; see the module docstring."""

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
        """Resolve everything not given (see :class:`~xrdarc.client.ARCClient`); nothing is sent.

        Public API, hence the keywords: each one is a thing a script may
        want to supply itself (a shared session, a job list of its own).
        """
        # Order matters: the credentials are discovered with the configuration
        # (``proxypath``, ``cacertificatesdirectory``), the session is built on
        # the credentials, and the job list path comes from the configuration.
        self.config = config if config is not None else load_config()
        self.credentials = credentials if credentials is not None else discover(self.config)
        self.session = session or Session(
            self.credentials, timeout=timeout if timeout is not None else self.config.timeout
        )
        self.joblist = _joblist_for(joblist, self.config)
        self.version = version
        self.password = password
        self.delegation_lifetime = delegation_lifetime
        #: The least credential lifetime :meth:`check_lifetime` accepts; the
        #: command line raises it from ``--min-lifetime``, a script may too.
        self.min_lifetime = 0.0
        #: One REST client per canonical CE URL (see :meth:`rest`).
        self._clients: dict[str, RESTClient] = {}
        #: The loaded signer, kept so an encrypted key is unlocked once.
        self._signer: Signer | None = None

    def __enter__(self) -> Self:
        """The client itself; leaving the block closes it."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close, whether or not the block raised."""
        self.close()

    def close(self) -> None:
        """Release the session's pooled connections; the client cannot be used afterwards.

        A session passed in by the caller is closed too: the client was given
        it to use, and a script sharing one between clients closes the last.
        """
        self.session.close()

    # -- plumbing --------------------------------------------------------------

    def rest(self, ce: str) -> RESTClient:
        """The REST client for ``ce`` (an alias from ``client.conf`` or a URL)."""
        # Cached per canonical URL, so an alias and its URL share one client
        # (and one negotiated REST version).
        # A group resolves to several CEs; this method addresses one, the
        # first, and callers that fan out over a group resolve it themselves.
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
            # Loaded once: an encrypted key's pass phrase is asked for once per client.
            self._signer = load_signer(cert, None if key == cert else key, password=self.password)
        return self._signer

    def check_lifetime(self, minimum: float | None = None) -> float | None:
        """Seconds left on the X.509 credential delegations are signed with.

        ``None`` when there is no X.509 credential (token delegation needs
        none). Raises ``CredentialError`` when it has expired - ``arcsub``'s
        "Proxy expired. Job submission aborted." - or has less than
        ``minimum`` (default ``min_lifetime``) seconds left, and logs a
        warning below ``LOW_LIFETIME``: the delegated proxy can never outlive
        it, so a longer job would fail at stage-out. The classification is
        :func:`xrdsec.lifetime.assess`'s, the one every tool on the stack
        shares; the wording and the error class are xrdarc's.
        """
        if self.credentials.cert is None:
            return None
        left = self.signer().remaining()
        floor = self.min_lifetime if minimum is None else minimum
        lifetime = assess(left, minimum=floor, warn_below=LOW_LIFETIME)
        _refuse_short_lived(lifetime, left, floor)
        if lifetime is Lifetime.LOW:
            _log.warning(
                "The proxy has only %d minutes left: jobs that run longer will fail. "
                "Make a new one with 'xrdarc proxy' (and 'xrdarc renew' running jobs)",
                left // 60,
            )
        return left

    def delegate(self, ce: str) -> str:
        """Create a delegation on ``ce`` and fill it; returns its id.

        X.509 when there is a certificate to sign with, otherwise the bearer
        token (REST 1.1). A slot whose signing or upload fails is deleted.
        """
        client = self.rest(ce)
        # A token-only user delegates the token itself (REST 1.1's ``jwt``).
        if self.credentials.cert is None and self.credentials.token:
            return client.new_token_delegation(self.credentials.token)
        signer = self.signer()
        delegation_id, request = client.new_delegation()
        try:
            pem = sign_request(request, signer, lifetime=self.delegation_lifetime)
            client.put_delegation(delegation_id, pem)
        except BaseException:
            # BaseException so a Ctrl-C between the two requests cleans up too.
            # An empty slot is useless: nothing will ever fill it.
            _drop_delegation(client, delegation_id)
            raise
        return delegation_id

    def _record(self, jobs: Sequence[Job]) -> None:
        """Add or update ``jobs`` in the job list (if there is one); errors propagate."""
        if self.joblist is not None and jobs:
            self.joblist.write(jobs)

    def _forget(self, jobs: Sequence[Job]) -> None:
        """Remove ``jobs`` from the job list (if there is one); errors propagate."""
        if self.joblist is not None and jobs:
            self.joblist.remove(job.url for job in jobs)

    def _record_safely(self, jobs: Sequence[Job]) -> None:
        """``_record`` for jobs that exist on a CE: a failure is warned about, never raised.

        Raising here would lose the very jobs being recorded (the caller has
        no other copy), so the warning names them and the way to get them
        back, as ``arcsub`` does when it cannot write ``jobs.dat``.
        """
        try:
            self._record(jobs)
        except ARCError as exc:
            _log.warning(
                "Could not record %s in the job list: %s. To recover them, run 'xrdarc sync'",
                ", ".join(job.url for job in jobs),
                exc,
            )

    def _forget_safely(self, jobs: Sequence[Job]) -> None:
        """``_forget`` for jobs already gone from their CE: a stale entry is only warned about."""
        # Never raised: the jobs are already gone from the CE, so the worst a
        # stale entry does is show up in the next ``stat`` as not found.
        try:
            self._forget(jobs)
        except ARCError as exc:
            _log.warning("Could not remove %s from the job list: %s", jobs[0].url, exc)

    # -- information -----------------------------------------------------------

    def info(self, ce: str) -> CEInfo:
        """The CE's description: endpoints, queues, runtime environments."""
        return parse_ce_info(self.rest(ce).info())


def _drop_delegation(client: RESTClient, delegation_id: str) -> None:
    """Delete a delegation nothing will use (best effort: a failure is only logged)."""
    # Debug, not warning: the caller is already raising the error that
    # matters, and a second message about the clean-up would bury it.
    try:
        client.delete_delegation(delegation_id)
    except ARCError as exc:
        _log.debug("could not delete delegation %s: %s", delegation_id, exc)


def _joblist_for(
    joblist: str | os.PathLike[str] | JobList | bool | None, config: UserConfig
) -> JobList | None:
    """The job list ``joblist`` asks for: the configured one (``True``), none, or the one named."""
    # ``is True``/``is False`` rather than truthiness: a path is truthy too,
    # and must be taken as a path, not as "the configured one".
    if joblist is True:
        return JobList(config.joblist)
    if joblist is None or joblist is False:
        return None
    return joblist if isinstance(joblist, JobList) else JobList(joblist)


def _refuse_short_lived(lifetime: Lifetime, left: float, floor: float) -> None:
    """Refuse a delegating credential that has expired, or has less than ``floor`` seconds left."""
    if lifetime is Lifetime.EXPIRED:
        raise CredentialError(
            "The proxy has expired, so jobs cannot be submitted; make a new one with 'xrdarc proxy'"
        )
    if lifetime is Lifetime.SHORT:
        raise CredentialError(
            f"The proxy has {int(left)} s left, less than the {floor:g} s required; "
            "make a new one with 'xrdarc proxy'"
        )
