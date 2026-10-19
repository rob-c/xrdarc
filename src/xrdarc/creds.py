"""Finding the credential to present to a CE, in ARC's search order.

The searches themselves are xrdsec's, shared with every other grid client
on the stack; this module feeds them ARC's settings and turns their answers
into one :class:`Credentials` value per session:

* **X.509** is :data:`xrdsec.discovery.ARC` - ARC's own
  ``UserConfig::InitializeCredentials``: a proxy someone named
  (``$X509_USER_PROXY``, else ``proxypath`` from ``client.conf``), the
  default proxy ``/tmp/x509up_u<uid>``, the same name under ``$TMPDIR``,
  then a certificate and key (``$X509_USER_CERT``/``$X509_USER_KEY``, else
  ``certificatepath``/``keypath``), then ``~/.arc`` and ``~/.globus``. A
  named proxy that is missing is an error rather than a reason to present
  some other identity. The environment outranks ``client.conf``, as in
  ARC, which is why the settings are merged here before the search runs.
* **Tokens** are WLCG Bearer Token Discovery
  (:func:`xrdsec.credentials.find_bearer_token`): ``$BEARER_TOKEN``,
  ``$BEARER_TOKEN_FILE``, ``$XDG_RUNTIME_DIR/bt_u<uid>``, ``/tmp/bt_u<uid>``.
  A token file someone else could read is refused, never used.
* **Trust anchors** are :func:`xrdsec.discovery.discover_ca_dir`:
  ``$X509_CERT_DIR``, ``cacertificatesdirectory``, ``~/.arc/certificates``,
  ``~/.globus/certificates``, then ``grid-security/certificates``; with none,
  the system store, which is right for a CE with a public certificate.
  ARC's ``$X509_CERT_POLICY`` decides whether the system store is trusted as
  well (``any``) or instead (``system``).

TLS contexts come from :func:`xrdsec.tls.client_context` - one cache for the
process, rebuilt when a proxy is renewed or the CA directory changes, with
Python 3.13's RFC 5280 strict mode relaxed as ARC (OpenSSL with its
defaults) never applies it.

What a maintainer must keep: every failure leaves this module as an xrdarc
:class:`~xrdarc.errors.CredentialError` (see
:func:`~xrdarc.errors.credential_error`), never as a library exception, so
the command line's exit code and the report's ``code`` stay right.
"""

from __future__ import annotations

import enum
import errno
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from xrdcore.errors import CredentialError as _LibraryCredentialError
from xrdsec import credentials as _credentials
from xrdsec import discovery as _discovery

from .config import UserConfig
from .errors import CredentialError, credential_error

__all__ = [
    "Auth",
    "Credentials",
    "default_proxy_path",
    "discover",
    "proxy_candidates",
]

#: ``$X509_CERT_POLICY`` values (ARC's) that add the system store to the grid's.
_SYSTEM_TOO = frozenset({"any", "any.nofile", "any.onlyfile"})
#: ``$X509_CERT_POLICY`` values that trust the system store instead of the grid's.
_SYSTEM_ONLY = frozenset({"system", "system.nofile", "system.onlyfile"})


class Auth(enum.Enum):
    """Which credential to present: ARC's ``--x509-authentication`` family."""

    AUTO = "auto"
    X509 = "x509"
    TOKEN = "token"
    NONE = "none"


def default_proxy_path(environ: Mapping[str, str] | None = None, uid: int | None = None) -> Path:
    """Where a new proxy goes: ``$X509_USER_PROXY``, else ``/tmp/x509up_u<uid>``.

    ``/tmp`` rather than ``$TMPDIR``, because that is where
    ``voms-proxy-init``, gfal2 and XRootD look; ARC's own tools also check
    ``$TMPDIR``, and so does :func:`proxy_candidates`. The answer is
    :func:`xrdsec.credentials.default_proxy_path`'s, so ``xrdarc proxy`` and
    every other client agree on it.
    """
    return Path(_credentials.default_proxy_path(environ, uid))


def proxy_candidates(environ: Mapping[str, str] | None = None) -> list[Path]:
    """The default proxy locations ARC looks in, most preferred first.

    ``/tmp/x509up_u<uid>``, then the same name under ``$TMPDIR`` when that
    is set and different. ``$X509_USER_PROXY`` is not a candidate: a proxy
    someone named is the answer, not one guess among several.
    """
    env = os.environ if environ is None else environ
    first = default_proxy_path({})
    found = [first]
    tmpdir = env.get("TMPDIR", "").strip()
    if tmpdir and Path(tmpdir) / first.name != first:
        found.append(Path(tmpdir) / first.name)
    return found


@dataclass(frozen=True, slots=True)
class Credentials:
    """What to present to a CE and what to trust, resolved once per session.

    ``cert``/``key`` are the X.509 client credential (the same file for a
    proxy); ``token`` a bearer token; ``ca_dir``/``ca_file`` the trust
    anchors (both ``None`` means the system store); ``system_ca`` trusts the
    system store alongside them (``X509_CERT_POLICY=any``); ``verify=False``
    turns server verification off, for test CEs only. Delegation signs with
    the X.509 credential whenever there is one, even when authentication
    uses the token.
    """

    cert: str | None = None
    key: str | None = None
    # A bearer token is a password: it must never reach a log line or a traceback
    # through ``repr`` (a ``Credentials`` shows up in both when a request fails).
    token: str | None = field(default=None, repr=False)
    ca_dir: str | None = None
    ca_file: str | None = None
    verify: bool = True
    auth: Auth = Auth.AUTO
    system_ca: bool = False

    @property
    def is_proxy(self) -> bool:
        """The X.509 credential is a single file holding chain and key."""
        return self.cert is not None and self.cert == self.key

    @property
    def uses_token(self) -> bool:
        """Requests carry ``Authorization: Bearer``."""
        return self.token is not None and self.auth in (Auth.AUTO, Auth.TOKEN)

    @property
    def uses_x509(self) -> bool:
        """The TLS handshake presents the X.509 credential."""
        return self.cert is not None and self.auth in (Auth.AUTO, Auth.X509)

    def headers(self) -> dict[str, str]:
        """Per-request authentication headers."""
        return {"Authorization": f"Bearer {self.token}"} if self.uses_token else {}

    def ssl_context(self) -> ssl.SSLContext:
        """A client TLS context presenting the X.509 credential: :func:`xrdsec.tls.client_context`.

        A proxy is passed as its own key, so it is read through xrdsec's
        private-file checks (ours, mode ``0600``) and piped to OpenSSL, as a
        separate user key always is. The context is shared and must not be
        modified. Raises :class:`~xrdarc.errors.CredentialError` if the chain
        or key cannot be loaded or is not private.
        """
        from xrdsec import tls  # imports ssl; only once a connection is about to be made

        cert, key = self._presented()
        try:
            return tls.client_context(
                cert=cert,
                key=key,
                ca_path=self.ca_dir,
                ca_file=self.ca_file,
                verify=self.verify,
                system_ca=self.system_ca,
                x509_strict=False,
            )
        except (_LibraryCredentialError, OSError, ValueError) as exc:
            raise credential_error(exc, f"Cannot use the X.509 credential {self.cert}") from exc

    def _presented(self) -> tuple[str | None, str | None]:
        """The certificate and key the handshake presents: none in token or anonymous mode."""
        if self.uses_x509 and self.key is not None:
            return self.cert, self.key
        return None, None

    def with_token(self, token: str | None) -> Credentials:
        """A copy using ``token`` instead of the discovered one."""
        return replace(self, token=token)


def _setting(env: Mapping[str, str], name: str, configured: str | None) -> str | None:
    """``$name`` when set (and not blank), else the ``client.conf`` value: ARC's precedence."""
    return env.get(name, "").strip() or configured or None


def _configured(config: UserConfig | None, name: str) -> str | None:
    """A path setting from ``client.conf``, or ``None`` with no configuration."""
    return None if config is None else getattr(config, name)


def _x509(env: Mapping[str, str], config: UserConfig | None) -> tuple[str, str] | None:
    """The certificate and key ARC would present, by :data:`xrdsec.discovery.ARC`.

    The configuration's values are passed as the tool's own settings, after
    the environment has had its say (``$X509_USER_PROXY`` beats
    ``proxypath``). A named proxy that is missing raises ``ENOENT``.
    """
    try:
        found = _discovery.discover_x509(
            _discovery.ARC,
            proxy=_setting(env, "X509_USER_PROXY", _configured(config, "proxy_path")),
            cert=_setting(env, "X509_USER_CERT", _configured(config, "cert_path")),
            key=_setting(env, "X509_USER_KEY", _configured(config, "key_path")),
            environ=env,
        )
    except _LibraryCredentialError as exc:
        # xrdsec's sentence already says how to make one; the errno is the file's.
        raise CredentialError(str(exc), errno.ENOENT) from exc
    return None if found is None else (found.cert, found.key)


def _trust(env: Mapping[str, str], config: UserConfig | None) -> tuple[str | None, bool]:
    """The CA directory and whether the system store is trusted too, by ``$X509_CERT_POLICY``.

    ARC's policy names: ``grid`` (the default) uses the grid directory
    alone; ``any`` adds the system store; ``system`` uses the system store
    alone; ``none`` is not honoured - a client that trusts nothing cannot
    talk to a CE.
    """
    policy = env.get("X509_CERT_POLICY", "").strip()
    if policy in _SYSTEM_ONLY:
        return None, False
    configured = _setting(env, "X509_CERT_DIR", _configured(config, "ca_dir"))
    found = _discovery.discover_ca_dir(_discovery.ARC, configured=configured, environ=env)
    return found, policy in _SYSTEM_TOO


def _token(env: Mapping[str, str], auth: Auth) -> str | None:
    """The WLCG-discovered bearer token, or ``None``.

    With ``auth=AUTO`` a token is optional, so a file that cannot be read
    for an ordinary reason (a directory, permission denied) is passed over
    as gfal2 does; with ``TOKEN`` it is reported. A token file someone else
    could read is refused either way.
    """
    try:
        return _credentials.find_bearer_token(env, skip_unreadable=auth is Auth.AUTO)
    except (_LibraryCredentialError, OSError) as exc:
        raise credential_error(exc, "Cannot use the bearer token") from exc


def discover(
    config: UserConfig | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    auth: Auth = Auth.AUTO,
    cert: str | None = None,
    key: str | None = None,
    token: str | None = None,
    ca_dir: str | None = None,
    verify: bool = True,
) -> Credentials:
    """The credentials ARC would use, with explicit arguments taking precedence.

    ``auth`` restricts what is looked for: ``X509`` ignores tokens, ``TOKEN``
    requires one (X.509 is still found, for delegation), ``NONE`` presents
    nothing. ``environ`` replaces the process environment. Raises
    :class:`~xrdarc.errors.CredentialError` when a named proxy is missing or
    the requested kind of credential cannot be found.
    """
    env = os.environ if environ is None else environ
    trusted, system_ca = _trust(env, config)
    # What to trust is the same whatever is presented.
    base = Credentials(ca_dir=ca_dir or trusted, verify=verify, auth=auth, system_ca=system_ca)
    if auth is Auth.NONE:
        return base
    pair = (cert, key or cert) if cert else _x509(env, config)
    bearer = None if auth is Auth.X509 else _token(env, auth) if token is None else token
    _require(auth, pair, bearer)
    cert, key = pair or (None, None)
    return replace(base, cert=cert, key=key, token=bearer)


def _require(auth: Auth, pair: tuple[str, str] | None, token: str | None) -> None:
    """Refuse a search that found nothing of the kind ``auth`` insists on.

    ``AUTO`` insists on nothing: a CE that wants a credential says so itself,
    with a 401/403 the user can act on. The messages say how to get one.
    """
    if auth is Auth.X509 and pair is None:
        raise CredentialError(
            "No X.509 proxy or certificate found. Create a proxy (xrdarc proxy, arcproxy or "
            "voms-proxy-init) or set X509_USER_PROXY."
        )
    if auth is Auth.TOKEN and not token:
        raise CredentialError(
            "No bearer token found. Set BEARER_TOKEN or BEARER_TOKEN_FILE, or store one in "
            "$XDG_RUNTIME_DIR/bt_u<uid>."
        )
