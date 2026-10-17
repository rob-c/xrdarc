"""Finding the credential to present to a CE, in ARC's search order.

X.509 first looks for a proxy - ``$X509_USER_PROXY``, then ``proxypath`` from
``client.conf``, then the default proxy file - and only without one falls back to the user
certificate and key. That is ARC's order (``UserConfig::InitializeCredentials``),
and a proxy named by ``X509_USER_PROXY`` that is missing is an error rather
than a reason to present some other identity.

Tokens follow the WLCG bearer token discovery rules, shared with xgfalclient:
``$BEARER_TOKEN``, ``$BEARER_TOKEN_FILE``, ``$XDG_RUNTIME_DIR/bt_u<uid>``,
``/tmp/bt_u<uid>``.

Trust anchors come from ``$X509_CERT_DIR``, ``cacertificatesdirectory``, or
the first of ARC's default directories that exists; with none, the system
store is used, which is right for a CE with a public (non-IGTF) certificate.
"""

from __future__ import annotations

import enum
import errno
import getpass
import logging
import os
import ssl
import stat
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from xgfalclient import creds as _gfal
from xgfalclient.errors import GError
from xgfalclient.options import Options

from .config import UserConfig, arc_dir
from .errors import CredentialError

__all__ = [
    "Auth",
    "Credentials",
    "default_proxy_path",
    "discover",
    "proxy_candidates",
]

_log = logging.getLogger("xrdarc")
_CONTEXTS = _gfal.TLSContexts()


class Auth(enum.Enum):
    """Which credential to present: ARC's ``--x509-authentication`` family."""

    AUTO = "auto"
    X509 = "x509"
    TOKEN = "token"
    NONE = "none"


def _uid() -> str:
    """The suffix of default credential file names: the uid, or the login on Windows."""
    if hasattr(os, "geteuid"):
        return str(os.geteuid())
    return getpass.getuser()


def default_proxy_path(environ: Mapping[str, str] | None = None) -> Path:
    """Where a new proxy goes: ``/tmp/x509up_u<uid>``, or the temp directory on Windows.

    ``/tmp`` rather than ``$TMPDIR`` on POSIX, because that is where
    ``voms-proxy-init``, gfal2 and XRootD look; ARC's own tools also check
    ``$TMPDIR``, and so does ``proxy_candidates``.
    """
    env = os.environ if environ is None else environ
    if env.get("X509_USER_PROXY", "").strip():
        return Path(env["X509_USER_PROXY"].strip())
    if sys.platform == "win32":
        return Path(tempfile.gettempdir()) / f"x509up_u{_uid()}"
    return Path("/tmp") / f"x509up_u{_uid()}"


def proxy_candidates(environ: Mapping[str, str] | None = None) -> list[Path]:
    """The default proxy locations, most preferred first."""
    env = os.environ if environ is None else environ
    name = f"x509up_u{_uid()}"
    found = [default_proxy_path({})]
    tmpdir = env.get("TMPDIR", "").strip()
    if tmpdir and Path(tmpdir) / name not in found:
        found.append(Path(tmpdir) / name)
    return found


def _check_private(path: str) -> None:
    """Warn about a key file others can read (POSIX only; Windows has ACLs)."""
    if sys.platform == "win32":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        _log.warning("%s is readable by other users; it should be mode 0600", path)


def _first_file(*paths: str | Path | None) -> str | None:
    return next((str(p) for p in paths if p and os.path.isfile(p)), None)


@dataclass(frozen=True, slots=True)
class Credentials:
    """What to present to a CE and what to trust, resolved once per session.

    ``cert``/``key`` are the X.509 client credential (the same file for a
    proxy); ``token`` a bearer token; ``ca_dir``/``ca_file`` the trust
    anchors (both ``None`` means the system store); ``verify=False`` turns
    server verification off, for test CEs only. ``signer`` is what delegation
    signs with: always the X.509 credential when there is one, even when
    authentication uses the token.
    """

    cert: str | None = None
    key: str | None = None
    token: str | None = None
    ca_dir: str | None = None
    ca_file: str | None = None
    verify: bool = True
    auth: Auth = Auth.AUTO

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
        """A client TLS context presenting the X.509 credential, cached per credential set.

        Raises ``CredentialError`` if the chain or key cannot be loaded.
        """
        cred = None
        if self.uses_x509 and self.cert and self.key:
            cred = _gfal.X509Credential(self.cert, self.key)
        try:
            return _CONTEXTS.get(
                cred, verify=self.verify, ca_path=self.ca_dir, ca_file=self.ca_file
            )
        except GError as exc:
            raise CredentialError(str(exc), exc.code) from exc

    def with_token(self, token: str | None) -> Credentials:
        """A copy using ``token`` instead of the discovered one."""
        return replace(self, token=token)


def _named_proxy(env: Mapping[str, str], config: UserConfig | None) -> str | None:
    named = env.get("X509_USER_PROXY", "").strip() or (config.proxy_path if config else None)
    if named and not os.path.isfile(named):
        raise CredentialError(
            f"The proxy {named} does not exist. Create one (xrdarc proxy, arcproxy or "
            "voms-proxy-init) or unset X509_USER_PROXY.",
            errno.ENOENT,
        )
    return named or None


def _x509(env: Mapping[str, str], config: UserConfig | None) -> tuple[str, str] | None:
    proxy = _named_proxy(env, config) or _first_file(*proxy_candidates(env))
    if proxy:
        return proxy, proxy
    cert = env.get("X509_USER_CERT", "").strip() or (config.cert_path if config else None)
    key = env.get("X509_USER_KEY", "").strip() or (config.key_path if config else None)
    if cert and key:
        return cert, key
    home = arc_dir(env).parent
    for directory in (home / ".arc", home / ".globus"):
        pair = _first_file(directory / "usercert.pem"), _first_file(directory / "userkey.pem")
        if pair[0] and pair[1]:
            return pair[0], pair[1]
    return None


def _ca_dir(env: Mapping[str, str], config: UserConfig | None) -> str | None:
    configured = env.get("X509_CERT_DIR", "").strip() or (config.ca_dir if config else None)
    if configured:
        return configured
    home = arc_dir(env).parent
    for candidate in (home / ".arc" / "certificates", home / ".globus" / "certificates"):
        if candidate.is_dir():
            return str(candidate)
    return _gfal.find_ca_path(env)


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
    nothing. Raises ``CredentialError`` when a named proxy is missing or the
    requested kind of credential cannot be found.
    """
    env = os.environ if environ is None else environ
    if auth is Auth.NONE:
        return Credentials(ca_dir=ca_dir or _ca_dir(env, config), verify=verify, auth=auth)
    pair = (cert, key or cert) if cert else _x509(env, config)
    if pair is not None:
        _check_private(pair[1])
    if token is None and auth is not Auth.X509:
        token = _gfal.find_bearer_token(Options(), environ=env)
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
    return Credentials(
        cert=pair[0] if pair else None,
        key=pair[1] if pair else None,
        token=token if auth is not Auth.X509 else None,
        ca_dir=ca_dir or _ca_dir(env, config),
        verify=verify,
        auth=auth,
    )
