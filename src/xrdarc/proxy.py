"""X.509 proxies: signing the CE's delegation requests, making and inspecting proxies.

Delegation is where an ARC client does real cryptography. The CE generates a
key pair, sends a certificate request with an empty subject, and expects back
an RFC 3820 proxy certificate for that key, issued by the user's own proxy,
followed by the chain that proves it. The profile here is the one ARC's
``DelegationProvider`` issues:

* subject = issuer subject + ``CN=<serial>``, a random 63-bit serial;
* critical ``keyUsage`` digitalSignature + keyEncipherment;
* critical ``proxyCertInfo`` with the inheritAll policy, or the limited one
  when the issuer is itself limited;
* valid from five minutes ago (never before the issuer) until the earliest
  expiry in the chain, or sooner when a lifetime is asked for; SHA-256.

The VOMS attribute certificate is copied into the new certificate as well,
as ``voms-proxy-init`` places it and as XRootD's delegation does: the CE
hands the delegated proxy to storage elements during data staging, and some
of them read VOMS attributes only from the end-entity side of the chain.
"""

from __future__ import annotations

import datetime as _dt
import errno
import os
import re
import secrets
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import NameOID
from xrdclient.crypto import inspect_voms
from xrdclient.crypto.x509 import parse_certificate

from .errors import CredentialError

__all__ = [
    "ProxyInfo",
    "Signer",
    "VOMSAttributes",
    "create_proxy",
    "openssl_name",
    "proxy_info",
    "sign_request",
    "write_proxy",
]

PROXY_CERT_INFO = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14")
VOMS_AC = x509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")

#: ``ProxyCertInfo`` DER for RFC 3820 inheritAll and Globus' limited policy.
_INHERIT_ALL = bytes.fromhex("300c300a06082b06010505071501")
_LIMITED = bytes.fromhex("300f300d060b2b060104019b5001010109")
_LIMITED_OID = bytes.fromhex("060b2b060104019b5001010109")
_INDEPENDENT_OID = bytes.fromhex("06082b06010505071502")

BACKDATE = _dt.timedelta(minutes=5)
_EXPIRED = getattr(errno, "EKEYEXPIRED", errno.EACCES)
DEFAULT_LIFETIME = 12 * 3600.0

_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----\r?\n?", re.DOTALL)
_SHORT_NAMES = {NameOID.EMAIL_ADDRESS: "emailAddress", NameOID.USER_ID: "UID"}


def openssl_name(name: x509.Name) -> str:
    """A name in OpenSSL's one-line form, ``/DC=org/DC=example/CN=Alice``: grid DNs."""
    parts = []
    for rdn in name.rdns:
        for attribute in rdn:
            label = _SHORT_NAMES.get(attribute.oid) or attribute.rfc4514_attribute_name
            parts.append(f"{label}={attribute.value!s}")
    return "/" + "/".join(parts)


def _utc(when: float | None) -> _dt.datetime:
    if when is None:
        return _dt.datetime.now(_dt.UTC)
    return _dt.datetime.fromtimestamp(when, _dt.UTC)


def _last_cn(cert: x509.Certificate) -> str | None:
    """The subject's last common name: ``proxy`` or ``limited proxy`` on a legacy proxy."""
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cns[-1].value) if cns else None


def _is_proxy(cert: x509.Certificate) -> bool:
    try:
        cert.extensions.get_extension_for_oid(PROXY_CERT_INFO)
        return True
    except x509.ExtensionNotFound:
        return _last_cn(cert) in ("proxy", "limited proxy")


def _policy(cert: x509.Certificate) -> bytes:
    try:
        ext = cert.extensions.get_extension_for_oid(PROXY_CERT_INFO).value
    except x509.ExtensionNotFound:
        return b""
    return ext.value if isinstance(ext, x509.UnrecognizedExtension) else b""


def _identity(chain: Sequence[x509.Certificate]) -> str:
    for cert in chain:
        if not _is_proxy(cert):
            return openssl_name(cert.subject)
    return openssl_name(chain[-1].subject)


def _not_after(chain: Sequence[x509.Certificate]) -> _dt.datetime:
    return min(cert.not_valid_after_utc for cert in chain)


@dataclass(frozen=True, slots=True)
class Signer:
    """A credential that can issue proxies: its certificate chain and private key.

    ``chain[0]`` is the certificate that signs (a proxy, or the user
    certificate itself); the rest prove it, leaf to root.
    """

    chain: tuple[x509.Certificate, ...]
    key: CertificateIssuerPrivateKeyTypes

    @classmethod
    def load(
        cls,
        cert_path: str | os.PathLike[str],
        key_path: str | os.PathLike[str] | None = None,
        *,
        password: Callable[[], bytes] | None = None,
    ) -> Signer:
        """Read a proxy file, or a certificate and its (possibly encrypted) key.

        ``password`` is called only if the key turns out to be encrypted.
        Raises ``CredentialError``: ENOENT for a missing file, EACCES for a
        key that is encrypted with no or the wrong passphrase, EINVAL for
        files that hold no certificate, no key, or a key that does not
        belong to the certificate.
        """
        cert_data = _read(cert_path)
        key_data = cert_data if key_path is None else _read(key_path)
        chain = _certificates(cert_data, cert_path)
        key = _private_key(key_data, key_path or cert_path, password)
        if _spki(key.public_key()) != _spki(chain[0].public_key()):
            raise CredentialError(
                f"The private key in {key_path or cert_path} does not belong to the "
                f"certificate in {cert_path}",
                errno.EINVAL,
            )
        return cls(chain, key)

    @property
    def certificate(self) -> x509.Certificate:
        return self.chain[0]

    @property
    def identity(self) -> str:
        """The end-entity subject: the user, whatever the proxy depth."""
        return _identity(self.chain)

    @property
    def not_after(self) -> _dt.datetime:
        """When the first certificate in the chain expires."""
        return _not_after(self.chain)

    @property
    def limited(self) -> bool:
        """Issued from a limited proxy: what it signs must be limited too."""
        cert = self.certificate
        return _last_cn(cert) == "limited proxy" or _LIMITED_OID in _policy(cert)

    def voms_extension(self) -> x509.Extension[x509.ExtensionType] | None:
        """The VOMS AC extension nearest the leaf, if any certificate carries one."""
        for cert in self.chain:
            try:
                return cert.extensions.get_extension_for_oid(VOMS_AC)
            except x509.ExtensionNotFound:
                continue
        return None

    def chain_pem(self) -> str:
        """The chain without the key, leaf first: what follows a delegated certificate."""
        return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in self.chain)


def _spki(public_key: object) -> bytes:
    """A public key's DER SubjectPublicKeyInfo, for comparing keys of any kind."""
    return public_key.public_bytes(  # type: ignore[attr-defined, no-any-return]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _read(path: str | os.PathLike[str]) -> bytes:
    try:
        return Path(path).read_bytes()
    except FileNotFoundError as exc:
        raise CredentialError(f"{path} does not exist", errno.ENOENT) from exc
    except OSError as exc:
        raise CredentialError(f"Cannot read {path}: {exc.strerror}", errno.EACCES) from exc


def _blocks(data: bytes, *kinds: str) -> list[bytes]:
    return [m.group(0) for m in _PEM.finditer(data) if m.group(1).decode() in kinds]


def _certificates(data: bytes, path: str | os.PathLike[str]) -> tuple[x509.Certificate, ...]:
    blocks = _blocks(data, "CERTIFICATE")
    if not blocks:
        raise CredentialError(f"{path} holds no certificate", errno.EINVAL)
    try:
        return tuple(x509.load_pem_x509_certificate(block) for block in blocks)
    except ValueError as exc:
        raise CredentialError(f"{path} holds a malformed certificate: {exc}", errno.EINVAL) from exc


def _private_key(
    data: bytes, path: str | os.PathLike[str], password: Callable[[], bytes] | None
) -> CertificateIssuerPrivateKeyTypes:
    blocks = _blocks(
        data, "RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY"
    )
    if not blocks:
        raise CredentialError(f"{path} holds no private key", errno.EINVAL)
    try:
        key = serialization.load_pem_private_key(blocks[0], None)
    except TypeError:
        if password is None:
            raise CredentialError(f"The private key in {path} is encrypted", errno.EACCES) from None
        try:
            key = serialization.load_pem_private_key(blocks[0], password())
        except ValueError as exc:
            raise CredentialError(f"Wrong passphrase for {path}", errno.EACCES) from exc
    except ValueError as exc:
        raise CredentialError(f"{path} holds a malformed private key: {exc}", errno.EINVAL) from exc
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CredentialError(f"{path} holds an unsupported kind of key", errno.EINVAL)
    return key


def _build(
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    signer: Signer,
    *,
    lifetime: float | None,
    limited: bool,
    voms: x509.Extension[x509.ExtensionType] | None,
    now: float | None,
) -> x509.Certificate:
    """The proxy certificate for ``public_key``, issued by ``signer``."""
    issued = _utc(now)
    serial = secrets.randbits(63) | 1
    issuer = signer.certificate
    not_before = max(issued - BACKDATE, issuer.not_valid_before_utc)
    not_after = signer.not_after
    if lifetime is not None:
        not_after = min(not_after, issued + _dt.timedelta(seconds=lifetime))
    if not_after <= issued:
        raise CredentialError("The credential has expired; it cannot issue a proxy", _EXPIRED)
    subject = x509.Name(
        [
            *issuer.subject.rdns,
            x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, str(serial))]),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(PROXY_CERT_INFO, _LIMITED if limited else _INHERIT_ALL),
            critical=True,
        )
    )
    if voms is not None:
        builder = builder.add_extension(voms.value, critical=voms.critical)
    return builder.sign(signer.key, hashes.SHA256())


def sign_request(
    request_pem: str | bytes,
    signer: Signer,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    copy_voms: bool = True,
    now: float | None = None,
) -> str:
    """Answer a delegation request: the new proxy, then ``signer``'s chain, as PEM.

    The request's own subject is ignored (ARC sends an empty one); only its
    key is certified, after checking the request is signed by that key.
    ``limited`` defaults to the signer's own limitation and cannot be
    lifted. Raises ``CredentialError`` (EINVAL) for an unreadable or
    unsigned request, EKEYEXPIRED for an expired signer.
    """
    data = request_pem.encode() if isinstance(request_pem, str) else request_pem
    try:
        request = x509.load_pem_x509_csr(data)
        valid = request.is_signature_valid
        public_key = request.public_key()
    except ValueError as exc:
        raise CredentialError(
            f"The CE sent an unreadable delegation request: {exc}", errno.EINVAL
        ) from exc
    if not valid:
        raise CredentialError("The CE's delegation request is not signed by its key", errno.EINVAL)
    if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise CredentialError(
            "The CE asked to delegate to an unsupported kind of key", errno.EINVAL
        )
    restrict = signer.limited or bool(limited)
    voms = signer.voms_extension() if copy_voms else None
    cert = _build(public_key, signer, lifetime=lifetime, limited=restrict, voms=voms, now=now)
    return cert.public_bytes(serialization.Encoding.PEM).decode() + signer.chain_pem()


def create_proxy(
    signer: Signer,
    *,
    lifetime: float = DEFAULT_LIFETIME,
    bits: int = 2048,
    limited: bool = False,
    voms_extension: bytes | None = None,
    now: float | None = None,
) -> bytes:
    """A new RFC 3820 proxy file's contents: certificate, key, then ``signer``'s chain.

    ``voms_extension`` is the DER value of a VOMS AC extension (a sequence of
    attribute certificates, as ``xrdarc.voms`` fetches); without one, a VOMS
    extension already in ``signer``'s chain is carried over.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    voms = signer.voms_extension()
    if voms_extension is not None:
        voms = x509.Extension(VOMS_AC, False, x509.UnrecognizedExtension(VOMS_AC, voms_extension))
    restrict = signer.limited or limited
    cert = _build(key.public_key(), signer, lifetime=lifetime, limited=restrict, voms=voms, now=now)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM) + key_pem + signer.chain_pem().encode()


def write_proxy(path: str | os.PathLike[str], contents: bytes) -> Path:
    """Write a proxy file atomically, readable by its owner only."""
    target = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".x509up.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(contents)
        os.replace(temporary, target)
    except BaseException:
        os.unlink(temporary)
        raise
    return target


@dataclass(frozen=True, slots=True)
class VOMSAttributes:
    """One VOMS attribute certificate found in a proxy (not verified)."""

    vo: str
    fqans: tuple[str, ...]
    not_after: _dt.datetime | None
    uri: str

    def remaining(self, now: float | None = None) -> float:
        if self.not_after is None:
            return 0.0
        return max(0.0, (self.not_after - _utc(now)).total_seconds())


@dataclass(frozen=True, slots=True)
class ProxyInfo:
    """What ``arcproxy -I`` reports about a credential."""

    path: str
    subject: str
    issuer: str
    identity: str
    kind: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    key_bits: int
    voms: tuple[VOMSAttributes, ...]

    def remaining(self, now: float | None = None) -> float:
        return max(0.0, (self.not_after - _utc(now)).total_seconds())


def _kind(cert: x509.Certificate) -> str:
    policy = _policy(cert)
    if not _is_proxy(cert):
        return "end-entity certificate"
    if not policy:
        limited = "limited " if _last_cn(cert) == "limited proxy" else ""
        return f"legacy Globus {limited}proxy"
    if _LIMITED_OID in policy:
        return "RFC 3820 compliant limited proxy"
    if _INDEPENDENT_OID in policy:
        return "RFC 3820 compliant independent proxy"
    return "RFC 3820 compliant impersonation proxy"


def _voms(chain: Sequence[x509.Certificate]) -> tuple[VOMSAttributes, ...]:
    parsed = [parse_certificate(c.public_bytes(serialization.Encoding.DER)) for c in chain]
    found = []
    for entry in inspect_voms(parsed).entries:
        expires = None if entry.not_after is None else _utc(entry.not_after)
        found.append(VOMSAttributes(entry.vo or "", tuple(entry.fqans), expires, entry.uri or ""))
    return tuple(found)


def proxy_info(path: str | os.PathLike[str]) -> ProxyInfo:
    """Describe the credential at ``path``: identity, lifetime, kind, VOMS attributes."""
    data = _read(path)
    chain = _certificates(data, path)
    leaf = chain[0]
    public = leaf.public_key()
    bits = (
        public.key_size if isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) else 0
    )
    return ProxyInfo(
        path=str(path),
        subject=openssl_name(leaf.subject),
        issuer=openssl_name(leaf.issuer),
        identity=_identity(chain),
        kind=_kind(leaf),
        not_before=leaf.not_valid_before_utc,
        not_after=_not_after(chain),
        key_bits=bits,
        voms=_voms(chain),
    )


def verify_chain_link(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """``child`` was signed by ``parent``'s key (no trust decision)."""
    try:
        child.verify_directly_issued_by(parent)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True
