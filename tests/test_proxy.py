"""xrdarc's proxy adapter: the ARC profile, the errors, and proxies a real TLS stack accepts.

The issuer itself is :mod:`xrdsec.proxies`, whose suite covers every profile
rule (path lengths, limited signers, forbidden extensions, VOMS carrying).
What is pinned here is what xrdarc promises on top: the certificate a CE
gets back has ARC's shape, every failure is an xrdarc ``CredentialError``
with the errno a user can act on, and what comes out works in a handshake.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from xrdcore.fanout import run_all
from xrdsec import proxies as _proxies
from xrdsec.proxytool import ProxyRequest, VOMSRequest
from xrdsec.testing.pki import PKI, test_key
from xrdsec.testing.voms import make_ac, vomses_line

from xrdarc import proxy
from xrdarc.errors import ARCError, CredentialError
from xrdarc.proxy import Signer

PROXY_CERT_INFO = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14")
VOMS_AC = x509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")
INHERIT_ALL = bytes.fromhex("300c300a06082b06010505071501")
LIMITED = bytes.fromhex("300f300d060b2b060104019b5001010109")
EXPIRED = getattr(errno, "EKEYEXPIRED", errno.EACCES)

posix_only = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="POSIX modes, as a non-root user"
)


# -- helpers -------------------------------------------------------------------------------


def _csr(key: rsa.RSAPrivateKey, subject: x509.Name | None = None) -> bytes:
    """A PKCS#10 request for ``key``, empty subject by default (as A-REX sends it)."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject or x509.Name([]))
    request = builder.sign(key, hashes.SHA256())
    return request.public_bytes(serialization.Encoding.PEM)


def _split(pem: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(pem.encode())


def _policy(cert: x509.Certificate) -> bytes:
    value = cert.extensions.get_extension_for_oid(PROXY_CERT_INFO).value
    assert isinstance(value, x509.UnrecognizedExtension)
    return value.value


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _user(pki: PKI) -> Signer:
    return proxy.load_signer(pki.user_cert_path, pki.user_key_path)


@pytest.fixture
def signer(pki: PKI) -> Signer:
    return proxy.load_signer(pki.proxy_path)


@pytest.fixture
def voms_proxy(pki: PKI, tmp_path: Path) -> Path:
    """A proxy file carrying a VOMS AC, made by ``create_proxy``."""
    user = _user(pki)
    ac = make_ac(pki.user, pki.host, pki.host_key)
    made = proxy.create_proxy(user, bits=1024, voms_acs=[ac])
    return proxy.write_proxy(tmp_path / "voms-proxy", made)


# -- load_signer ---------------------------------------------------------------------------


def test_load_proxy_file_and_pair(pki: PKI, signer: Signer) -> None:
    assert signer.identity == _user(pki).identity
    assert len(signer.chain) == 2
    assert _user(pki).chain[0].subject == signer.chain[1].subject


def _encrypted_key(pki: PKI, tmp_path: Path) -> Path:
    path = tmp_path / "encrypted.pem"
    key = serialization.load_pem_private_key(pki.user_key_path.read_bytes(), None)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret"),
        )
    )
    path.chmod(0o600)
    return path


def test_encrypted_key_asks_for_the_pass_phrase_once(pki: PKI, tmp_path: Path) -> None:
    asked: list[int] = []

    def password() -> bytes:
        asked.append(1)
        return b"secret"

    key = _encrypted_key(pki, tmp_path)
    loaded = proxy.load_signer(pki.user_cert_path, key, password=password)
    assert asked == [1]
    assert loaded.identity == _user(pki).identity


@pytest.mark.parametrize("password", [None, lambda: b"wrong"])
def test_encrypted_key_without_the_right_pass_phrase(
    pki: PKI, tmp_path: Path, password: Callable[[], bytes] | None
) -> None:
    key = _encrypted_key(pki, tmp_path)
    with pytest.raises(CredentialError) as caught:
        proxy.load_signer(pki.user_cert_path, key, password=password)
    assert caught.value.code == errno.EACCES


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CredentialError) as caught:
        proxy.load_signer(tmp_path / "missing")
    assert caught.value.code == errno.ENOENT


def test_load_key_that_is_not_the_certificates(pki: PKI) -> None:
    with pytest.raises(CredentialError, match="does not belong") as caught:
        proxy.load_signer(pki.user_cert_path, pki.host_key_path)
    assert caught.value.code == errno.EACCES


@posix_only
def test_load_key_others_can_read(pki: PKI, tmp_path: Path) -> None:
    shared = tmp_path / "userkey.pem"
    shared.write_bytes(pki.user_key_path.read_bytes())
    shared.chmod(0o644)
    with pytest.raises(CredentialError) as caught:
        proxy.load_signer(pki.user_cert_path, shared)
    assert caught.value.code == errno.EACCES


# -- sign_request: what a CE gets back -----------------------------------------------------


def test_sign_request_is_the_arc_profile(signer: Signer) -> None:
    """Subject = issuer + CN=<63-bit serial>, critical keyUsage and inheritAll, SHA-256."""
    now = time.time()
    chain = _split(proxy.sign_request(_csr(test_key(5)), signer, now=now))
    new, issuer = chain[0], chain[1]
    assert [link.subject for link in chain[1:]] == [
        x509.load_der_x509_certificate(link.der).subject for link in signer.chain
    ]
    assert new.subject == x509.Name(
        [
            *issuer.subject.rdns,
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COMMON_NAME, str(new.serial_number))]
            ),
        ]
    )
    assert new.serial_number < 1 << 63
    key = new.public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    assert key.public_numbers() == test_key(5).public_key().public_numbers()
    new.verify_directly_issued_by(issuer)
    assert isinstance(new.signature_hash_algorithm, hashes.SHA256)
    usage = new.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.digital_signature and usage.value.key_encipherment
    assert new.extensions.get_extension_for_oid(PROXY_CERT_INFO).critical
    assert _policy(new) == INHERIT_ALL
    assert abs(new.not_valid_before_utc.timestamp() - (now - 300)) <= 1


def test_sign_request_ignores_the_request_subject(signer: Signer) -> None:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chosen by the CE")])
    new = _split(proxy.sign_request(_csr(test_key(5), subject).decode(), signer))[0]
    assert "chosen by the CE" not in new.subject.rfc4514_string()


def test_sign_request_lifetime_and_limits(pki: PKI, signer: Signer, tmp_path: Path) -> None:
    now = time.time()
    short = _split(proxy.sign_request(_csr(test_key(5)), signer, lifetime=600, now=now))[0]
    assert abs(short.not_valid_after_utc.timestamp() - (now + 600)) <= 1
    limited = _split(proxy.sign_request(_csr(test_key(5)), signer, limited=True))[0]
    assert _policy(limited) == LIMITED
    from_limited = proxy.load_signer(pki.proxy("limited", path=tmp_path / "limited"))
    lifted = _split(proxy.sign_request(_csr(test_key(5)), from_limited, limited=False))[0]
    assert _policy(lifted) == LIMITED


def test_sign_request_carries_voms(voms_proxy: Path) -> None:
    parent = proxy.load_signer(voms_proxy)
    copied = _split(proxy.sign_request(_csr(test_key(5)), parent))[0]
    assert copied.extensions.get_extension_for_oid(VOMS_AC)


@pytest.mark.parametrize("request_pem", [b"not a request", "garbage"])
def test_sign_request_unreadable(signer: Signer, request_pem: bytes | str) -> None:
    with pytest.raises(CredentialError, match="cannot be signed") as caught:
        proxy.sign_request(request_pem, signer)
    assert caught.value.code == errno.EINVAL


def test_sign_request_bad_signature(signer: Signer) -> None:
    """A request whose signature does not verify: no proof the CE holds the key."""
    der = bytearray(
        x509.load_pem_x509_csr(_csr(test_key(5))).public_bytes(serialization.Encoding.DER)
    )
    der[-1] ^= 0x01  # the last byte of the signature
    pem = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(CredentialError, match="cannot be signed") as caught:
        proxy.sign_request(pem, signer)
    assert caught.value.code == errno.EINVAL


def test_sign_request_expired_signer(signer: Signer) -> None:
    with pytest.raises(CredentialError, match="expired") as caught:
        proxy.sign_request(_csr(test_key(5)), signer, now=time.time() + 400 * 86400)
    assert caught.value.code == EXPIRED


# -- a TLS stack accepts what comes out ----------------------------------------------------


def _handshake(pki: PKI, credential: Path) -> str:
    """Present ``credential`` to a server that verifies proxies; returns the peer's subject."""
    server_side, client_side = socket.socketpair()
    server = pki.server_context(require_client=True).wrap_socket(
        server_side, server_side=True, do_handshake_on_connect=False
    )
    context = pki.client_context(proxy=credential, check_hostname=False)

    def handshake_as_client() -> None:
        with context.wrap_socket(client_side) as client:
            client.do_handshake()

    # Both ends at once, each waiting on the other; ``run_all`` re-raises a failure here.
    with server:
        run_all([server.do_handshake, handshake_as_client])
        peer = server.getpeercert()
    assert peer is not None
    return str(peer["subject"])


def test_delegated_proxy_is_accepted_by_openssl(pki: PKI, signer: Signer, tmp_path: Path) -> None:
    chain = _split(proxy.sign_request(_csr(test_key(5)), signer))
    delegated = tmp_path / "delegated"
    pem = b"".join(link.public_bytes(serialization.Encoding.PEM) for link in chain)
    first, _, rest = pem.partition(b"-----END CERTIFICATE-----\n")
    delegated.write_bytes(first + b"-----END CERTIFICATE-----\n" + _key_pem(test_key(5)) + rest)
    assert "Test User" in _handshake(pki, delegated)


def test_created_proxy_is_accepted_by_openssl(pki: PKI, tmp_path: Path) -> None:
    made = proxy.write_proxy(tmp_path / "made", proxy.create_proxy(_user(pki)))
    assert "Test User" in _handshake(pki, made)


# -- create_proxy, write_proxy, proxy_info -------------------------------------------------


def test_create_proxy(pki: PKI, tmp_path: Path) -> None:
    now = time.time()
    made = proxy.create_proxy(_user(pki), lifetime=3600, bits=1024)
    assert made.identity == _user(pki).identity
    assert abs(made.chain[0].not_after - (now + 3600)) <= 5
    path = proxy.write_proxy(tmp_path / "made", made)
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
    info = proxy.proxy_info(path)
    assert info.kind == "RFC3820 compliant impersonation proxy"
    assert info.strength == 1024 and info.path == str(path)
    assert info.voms == ()


def test_create_limited_proxy(pki: PKI, tmp_path: Path) -> None:
    made = proxy.create_proxy(_user(pki), bits=1024, limited=True)
    info = proxy.proxy_info(proxy.write_proxy(tmp_path / "limited", made))
    assert info.limited and info.kind == "RFC3820 compliant limited proxy"


def test_create_proxy_embeds_and_carries_voms(pki: PKI, voms_proxy: Path) -> None:
    (entry,) = proxy.proxy_info(voms_proxy).voms
    assert entry.vo == "atlas"
    child = proxy.create_proxy(proxy.load_signer(voms_proxy), bits=1024)
    assert len(_proxies.describe_proxy(child).voms) >= 1


def test_create_proxy_refusals(pki: PKI) -> None:
    old = _proxies.create_proxy(_user(pki), lifetime=60, now=time.time() - 3600, profile="arc")
    with pytest.raises(CredentialError, match="expired") as caught:
        proxy.create_proxy(old)
    assert caught.value.code == EXPIRED
    with pytest.raises(CredentialError, match="Cannot make the proxy") as refused:
        proxy.create_proxy(_user(pki), bits=512)
    assert refused.value.code == errno.EINVAL


def test_write_proxy_into_a_missing_directory(pki: PKI, tmp_path: Path) -> None:
    made = proxy.create_proxy(_user(pki), bits=1024)
    with pytest.raises(CredentialError, match="Cannot write the proxy") as caught:
        proxy.write_proxy(tmp_path / "no" / "such" / "dir" / "x509up", made)
    assert caught.value.code == errno.ENOENT


def test_proxy_info_of_files_that_are_not_proxies(pki: PKI, tmp_path: Path) -> None:
    """Read as a proxy is - privately - so a certificate others can read is refused."""
    with pytest.raises(CredentialError, match="chmod 600") as public:
        proxy.proxy_info(pki.user_cert_path)
    assert public.value.code == errno.EACCES
    private = tmp_path / "usercert.pem"
    private.write_bytes(pki.user_cert_path.read_bytes())
    private.chmod(0o600)
    assert proxy.proxy_info(private).kind == "end entity credential"
    with pytest.raises(CredentialError, match="there is no proxy at") as missing:
        proxy.proxy_info(tmp_path / "missing")
    assert missing.value.code == errno.ENOENT
    junk = tmp_path / "junk"
    junk.write_text("not a certificate")
    junk.chmod(0o600)
    with pytest.raises(CredentialError, match="there is no certificate in") as caught:
        proxy.proxy_info(junk)
    assert caught.value.code == errno.EACCES


# -- make_proxy ----------------------------------------------------------------------------


def test_make_proxy_is_the_arc_profile_with_xrdarcs_errors(pki: PKI, tmp_path: Path) -> None:
    request = ProxyRequest(lifetime=3600, bits=1024, profile=proxy.PROFILE)
    made = proxy.make_proxy(_user(pki), request)
    assert made.chain[1] == _user(pki).chain[0]
    assert _proxies.describe_proxy(made).kind == "RFC3820 compliant impersonation proxy"
    old = _proxies.create_proxy(_user(pki), lifetime=60, now=time.time() - 3600, profile="arc")
    with pytest.raises(CredentialError, match="expired") as expired:
        proxy.make_proxy(old, request)
    assert expired.value.code == EXPIRED
    last = _proxies.create_proxy(_user(pki), bits=1024, path_length=0)
    with pytest.raises(CredentialError, match="Cannot make the proxy") as refused:
        proxy.make_proxy(last, request)
    assert refused.value.code == errno.EINVAL


def test_make_proxy_maps_voms_failures(pki: PKI, tmp_path: Path) -> None:
    vomses = tmp_path / "vomses"
    vomses.write_text(vomses_line("atlas", "127.0.0.1", 1, "/CN=voms"))
    asked = ProxyRequest(bits=1024, voms=(VOMSRequest("cms"),), vomses=(str(vomses),))
    with pytest.raises(ARCError, match="no VOMS server is configured") as unknown:
        proxy.make_proxy(_user(pki), asked)
    assert unknown.value.code == errno.ENOENT and not isinstance(unknown.value, CredentialError)
    down = dataclasses.replace(asked, voms=(VOMSRequest("atlas"),), timeout=2)
    with pytest.raises(CredentialError, match=r"127\.0\.0\.1:1"):
        proxy.make_proxy(_user(pki), down, _Quiet())


class _Quiet:
    """A :class:`xrdsec.proxytool.Progress` that drops everything."""

    def contacting(self, request: VOMSRequest, servers: object) -> None:
        """Nothing."""

    def contacted(self, request: VOMSRequest) -> None:
        """Nothing."""

    def warned(self, message: str) -> None:
        """Nothing."""
