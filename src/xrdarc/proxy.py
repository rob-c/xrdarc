"""X.509 proxies for ARC: signing a CE's delegation request, making and describing proxies.

The cryptography is :mod:`xrdsec.proxies`, the one proxy issuer every client
on the stack uses; this module is what is ARC-specific about using it, and
the translation of its errors into xrdarc's.

Delegation is where an ARC client does real cryptography. The CE generates a
key pair, sends a certificate request with an empty subject, and expects back
an RFC 3820 proxy certificate for that key, issued by the user's own proxy,
followed by the chain that proves it. The certificate is xrdsec's ``"arc"``
profile, the one ARC's ``DelegationProvider`` issues:

* subject = issuer subject + ``CN=<serial>``, a random 63-bit serial (ARC's
  C++ reuses the issuer's serial, which RFC 3820 section 3.3 forbids);
* critical ``keyUsage`` digitalSignature + keyEncipherment;
* critical ``proxyCertInfo`` with the inheritAll policy, or the limited one
  when the issuer is itself limited;
* valid from five minutes ago (never before the issuer) until the earliest
  expiry in the chain, or sooner when a lifetime is asked for.

The VOMS attribute certificates are carried into the new certificate as
well, as ``voms-proxy-init`` places them: the CE hands the delegated proxy
to storage elements during data staging, and some of them read VOMS
attributes only from the end-entity side of the chain.

A *signer* is an :class:`xrdsec.x509.ProxyCredential` - chain and key in
memory - loaded once per client by :func:`load_signer`.

Making a proxy file the way ``arcproxy`` does - VOMS ACs first, then the
proxy, then the file - is :mod:`xrdsec.proxytool`'s workflow, shared with
xrdclient's ``xrd-proxy``; :func:`make_proxy`, :func:`write_proxy` and
:func:`proxy_info` are it with xrdarc's errors.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable, Sequence
from pathlib import Path

from xrdcore.errors import CredentialError as _LibraryCredentialError
from xrdsec import proxies as _proxies
from xrdsec import proxytool
from xrdsec.delegation import load_proxy_request
from xrdsec.proxies import ProxyInfo
from xrdsec.voms_client import VOMSConfigError
from xrdsec.x509 import ProxyCredential

from .errors import ARCError, CredentialError, credential_error

__all__ = [
    "DEFAULT_LIFETIME",
    "ProxyInfo",
    "Signer",
    "create_proxy",
    "load_signer",
    "make_proxy",
    "proxy_info",
    "sign_request",
    "write_proxy",
]

#: What signs delegations and new proxies: a certificate chain and its key, in memory.
Signer = ProxyCredential

#: ``arcproxy``'s default proxy lifetime, in seconds: twelve hours.
DEFAULT_LIFETIME = 12 * 3600.0
#: The proxy profile every certificate here is issued under (see the module docstring).
PROFILE: _proxies.ProfileName = "arc"
#: ``errno`` for an expired signer, where the platform has one.
_EXPIRED = getattr(errno, "EKEYEXPIRED", errno.EACCES)


def load_signer(
    cert: str | os.PathLike[str],
    key: str | os.PathLike[str] | None = None,
    *,
    password: Callable[[], bytes] | None = None,
) -> Signer:
    """Read a proxy file, or a certificate and its (possibly encrypted) key.

    :func:`xrdsec.proxies.load_credential`: a key (or a proxy, which holds
    one) must be a private regular file of this user's. ``password`` is
    called only if the key turns out to be encrypted. Raises
    :class:`~xrdarc.errors.CredentialError` - ``ENOENT`` for a missing file,
    ``EACCES`` for anything else: a key others can read, no or the wrong
    pass phrase, files that hold no certificate or a key that does not
    belong to it.
    """
    try:
        return _proxies.load_credential(cert, key, password=password)
    except (_LibraryCredentialError, OSError, ValueError) as exc:
        raise credential_error(exc) from exc


def sign_request(
    request_pem: str | bytes,
    signer: Signer,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    now: float | None = None,
) -> str:
    """Answer a delegation request: the new proxy, then ``signer``'s chain, as PEM.

    The request's own subject is ignored (ARC sends an empty one); only its
    key is certified, after checking the request is signed by that key.
    ``limited`` defaults to the signer's own limitation and cannot lift it.
    The VOMS attribute certificates of the chain are always carried into
    the new proxy (see the module docstring).
    The chain that follows leaves out a self-signed CA, which a verifier
    never takes from the wire. Raises :class:`~xrdarc.errors.CredentialError`:
    ``EKEYEXPIRED`` for an expired signer, ``EINVAL`` for an unreadable or
    unsigned request.
    """
    _check_alive(signer, now)
    try:
        request = load_proxy_request(request_pem)
        certificate = _proxies.issue_proxy(
            signer,
            request,
            profile=PROFILE,
            lifetime=lifetime,
            limited=limited,
            now=now,
        )
    except ValueError as exc:  # DelegationError / ProxyError
        raise CredentialError(
            f"The CE's delegation request cannot be signed: {exc}", errno.EINVAL
        ) from exc
    return (certificate.pem() + signer.pem()).decode("ascii")


def create_proxy(
    signer: Signer,
    *,
    lifetime: float = DEFAULT_LIFETIME,
    bits: int = 2048,
    limited: bool = False,
    voms_acs: Sequence[bytes] = (),
) -> ProxyCredential:
    """A new RFC 3820 proxy - fresh RSA key, its certificate, ``signer``'s chain - in memory.

    :func:`xrdsec.proxies.create_proxy` under the ARC profile. ``voms_acs``
    are DER attribute certificates (from
    :func:`xrdsec.voms_client.fetch_ac`) for the new proxy's VOMS extension;
    without them, ACs already in ``signer``'s chain are carried forward.
    Nothing is written: :func:`write_proxy` does that. (A test that needs
    a proxy from another moment calls :func:`xrdsec.proxies.create_proxy`
    with ``now=`` and ``profile="arc"`` directly.)
    """
    _check_alive(signer, None)
    try:
        return _proxies.create_proxy(
            signer,
            lifetime=lifetime,
            bits=bits,
            limited=limited,
            voms_acs=voms_acs,
            profile=PROFILE,
        )
    except ValueError as exc:
        raise CredentialError(f"Cannot make the proxy: {exc}", errno.EINVAL) from exc


def make_proxy(
    signer: Signer, request: proxytool.ProxyRequest, progress: proxytool.Progress | None = None
) -> ProxyCredential:
    """``arcproxy``'s proxy, VOMS ACs included: :func:`xrdsec.proxytool.make_proxy`.

    ``request.profile`` is the caller's (``xrdarc proxy`` asks for
    :data:`PROFILE`). Errors become xrdarc's: an expired signer
    ``EKEYEXPIRED``, a ``vomses`` configuration that is missing or names no
    server for the VO an :class:`~xrdarc.errors.ARCError` (``ENOENT``, a
    local problem), a VOMS refusal or no server answering a
    :class:`~xrdarc.errors.CredentialError`, a proxy that cannot be issued
    ``EINVAL``. A malformed FQAN stays a :class:`ValueError`: the user typed
    it, and the command line reports it as a usage error.
    """
    _check_alive(signer, None)
    try:
        return proxytool.make_proxy(signer, request, progress)
    except VOMSConfigError as exc:
        raise ARCError(str(exc), errno.ENOENT) from exc
    except _LibraryCredentialError as exc:
        raise credential_error(exc) from exc
    except _proxies.ProxyError as exc:
        raise CredentialError(f"Cannot make the proxy: {exc}", errno.EINVAL) from exc


def write_proxy(
    path: str | os.PathLike[str], credential: ProxyCredential, *, follow_symlinks: bool = True
) -> Path:
    """Write ``credential`` as a proxy file: atomically, readable by its owner only.

    :func:`xrdsec.proxies.write_proxy`. A symbolic link at ``path`` is
    followed for a path the user chose (``--proxy``, ``$X509_USER_PROXY``)
    and refused at the predictable default: ``follow_symlinks`` is
    :func:`xrdsec.proxytool.proxy_target`'s answer.
    """
    try:
        return Path(_proxies.write_proxy(path, credential, follow_symlinks=follow_symlinks))
    except (_LibraryCredentialError, OSError) as exc:
        raise credential_error(exc, f"Cannot write the proxy {path}") from exc


def proxy_info(
    path: str | os.PathLike[str], *, follow_symlinks: bool = True, now: float | None = None
) -> ProxyInfo:
    """Describe the proxy file at ``path`` (no pass phrase needed): ``arcproxy -I``.

    :func:`xrdsec.proxytool.read_proxy_info` - read under the private-file
    rules, then identity, lifetime counted from ``now``, kind in
    ``voms-proxy-info``'s words, the VOMS ACs decoded but not validated.
    Raises :class:`~xrdarc.errors.CredentialError`: ``ENOENT`` when there
    is no file, ``EACCES`` for one others can read or that holds no
    certificate.
    """
    try:
        return proxytool.read_proxy_info(path, follow_symlinks=follow_symlinks, now=now)
    except (_LibraryCredentialError, OSError) as exc:
        raise credential_error(exc) from exc


def _check_alive(signer: Signer, now: float | None) -> None:
    """Refuse an expired signer up front, with the errno ``arcproxy`` users know.

    :func:`xrdsec.proxytool.require_alive`, whose
    :class:`~xrdsec.proxytool.ExpiredCredentialError` becomes
    ``EKEYEXPIRED``: an expired proxy is the one failure a user fixes by
    running ``xrdarc proxy``.
    """
    try:
        proxytool.require_alive(signer, now=now)
    except proxytool.ExpiredCredentialError as exc:
        raise CredentialError(
            "The credential has expired; it cannot issue a proxy", _EXPIRED
        ) from exc
