"""X.509 proxies: loading signers, answering delegation requests, making and describing proxies."""

from __future__ import annotations

import datetime as dt
import errno
import functools
import os
import socket
import ssl
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from xgfalclient.crypto.rsa import private_key_pem
from xgfalclient.testing.pki import PKI, test_key

from _voms_fixtures import make_ac
from xrdarc import proxy, voms
from xrdarc.errors import CredentialError
from xrdarc.proxy import Signer

INHERIT_ALL = bytes.fromhex("300c300a06082b06010505071501")
LIMITED = bytes.fromhex("300f300d060b2b060104019b5001010109")
INDEPENDENT = bytes.fromhex("300c300a06082b06010505071502")
USER_DN = "/DC=org/DC=xgfal/OU=People/CN=Test User"
EXPIRED = getattr(errno, "EKEYEXPIRED", errno.EACCES)


# -- helpers -------------------------------------------------------------------------------


@functools.cache
def _key(slot: int) -> rsa.RSAPrivateKey:
    """One of the PKI's frozen RSA keys, as a ``cryptography`` key."""
    key = serialization.load_pem_private_key(private_key_pem(test_key(slot)), None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def _pem(*items: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in items)


AnyKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


def _key_pem(key: AnyKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _user(pki: PKI) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = serialization.load_pem_private_key(pki.user_key_path.read_bytes(), None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return _cert(pki.user_cert_path), key


def _craft(
    issuer: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    *,
    cn: str = "1234",
    policy: bytes | None = INHERIT_ALL,
    slot: int = 4,
    not_before: dt.datetime | None = None,
    extensions: Sequence[x509.Extension[x509.ExtensionType]] = (),
) -> x509.Certificate:
    """A proxy of ``issuer``: ``policy`` its proxyCertInfo, ``None`` for a legacy one."""
    now = dt.datetime.now(dt.UTC)
    name = x509.Name([*issuer.subject.rdns, x509.RelativeDistinguishedName(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )])  # fmt: skip
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject)
        .public_key(_key(slot).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=6))
    )
    if policy is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(proxy.PROXY_CERT_INFO, policy), critical=True
        )
    for extension in extensions:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder.sign(issuer_key, hashes.SHA256())


def _write(path: Path, leaf: x509.Certificate, slot: int, *chain: x509.Certificate) -> Path:
    path.write_bytes(_pem(leaf) + _key_pem(_key(slot)) + _pem(*chain))
    path.chmod(0o600)
    return path


def _csr(key: object, subject: x509.Name | None = None) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject or x509.Name([]))
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    request = builder.sign(key, algorithm)  # type: ignore[arg-type]
    return request.public_bytes(serialization.Encoding.PEM)


def _split(pem: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(pem.encode())


def _ext(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> x509.Extension[x509.ExtensionType]:
    return cert.extensions.get_extension_for_oid(oid)


def _voms_der(pki: PKI, holder: x509.Certificate) -> bytes:
    host_key = serialization.load_pem_private_key(pki.host_key_path.read_bytes(), None)
    assert isinstance(host_key, rsa.RSAPrivateKey)
    return voms.ac_sequence([make_ac(holder, _cert(pki.host_cert_path), host_key)])


@pytest.fixture
def signer(pki: PKI) -> Signer:
    return Signer.load(pki.proxy_path)


@pytest.fixture
def voms_proxy(pki: PKI, tmp_path: Path) -> Path:
    """A proxy file carrying a VOMS AC, made by ``create_proxy``."""
    user = Signer.load(pki.user_cert_path, pki.user_key_path)
    data = proxy.create_proxy(user, bits=1024, voms_extension=_voms_der(pki, user.certificate))
    return proxy.write_proxy(tmp_path / "voms-proxy", data)


# -- Signer.load ---------------------------------------------------------------------------


def test_load_proxy_file(pki: PKI, signer: Signer) -> None:
    assert len(signer.chain) == 2
    assert signer.chain[1] == _cert(pki.user_cert_path)
    assert signer.identity == USER_DN
    assert not signer.limited
    assert signer.voms_extension() is None


def test_load_certificate_and_key(pki: PKI) -> None:
    loaded = Signer.load(pki.user_cert_path, pki.user_key_path)
    assert loaded.certificate == _cert(pki.user_cert_path)
    assert loaded.identity == USER_DN
    assert loaded.not_after == loaded.certificate.not_valid_after_utc


def _encrypted(pki: PKI, tmp_path: Path, form: serialization.PrivateFormat) -> Path:
    _, key = _user(pki)
    data = key.private_bytes(
        serialization.Encoding.PEM, form, serialization.BestAvailableEncryption(b"secret")
    )
    target = tmp_path / "userkey.pem"
    target.write_bytes(data)
    return target


@pytest.mark.parametrize(
    "form", [serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL]
)
def test_load_encrypted_key_with_password(
    pki: PKI, tmp_path: Path, form: serialization.PrivateFormat
) -> None:
    calls: list[int] = []

    def password() -> bytes:
        calls.append(1)
        return b"secret"

    loaded = Signer.load(pki.user_cert_path, _encrypted(pki, tmp_path, form), password=password)
    assert loaded.identity == USER_DN
    assert calls == [1]


def test_password_not_asked_for_plain_key(pki: PKI) -> None:
    def password() -> bytes:
        raise AssertionError("not encrypted")

    Signer.load(pki.user_cert_path, pki.user_key_path, password=password)


def test_load_encrypted_key_without_password(pki: PKI, tmp_path: Path) -> None:
    key = _encrypted(pki, tmp_path, serialization.PrivateFormat.PKCS8)
    with pytest.raises(CredentialError, match="encrypted") as caught:
        Signer.load(pki.user_cert_path, key)
    assert caught.value.code == errno.EACCES


def test_load_encrypted_key_wrong_password(pki: PKI, tmp_path: Path) -> None:
    key = _encrypted(pki, tmp_path, serialization.PrivateFormat.PKCS8)
    with pytest.raises(CredentialError, match="Wrong passphrase") as caught:
        Signer.load(pki.user_cert_path, key, password=lambda: b"wrong")
    assert caught.value.code == errno.EACCES


def _assert_einval(match: str, *args: Path) -> None:
    with pytest.raises(CredentialError, match=match) as caught:
        Signer.load(*args)
    assert caught.value.code == errno.EINVAL


def test_load_key_mismatch(pki: PKI) -> None:
    _assert_einval("does not belong", pki.user_cert_path, pki.host_key_path)


def test_load_no_certificate(pki: PKI) -> None:
    _assert_einval("holds no certificate", pki.user_key_path)


def test_load_no_key(pki: PKI) -> None:
    _assert_einval("holds no private key", pki.user_cert_path)


def test_load_malformed_certificate(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    _assert_einval("malformed certificate", bad)


def test_load_malformed_key(pki: PKI, tmp_path: Path) -> None:
    bad = tmp_path / "key.pem"
    bad.write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    _assert_einval("malformed private key", pki.user_cert_path, bad)


def test_load_unsupported_key(pki: PKI, tmp_path: Path) -> None:
    other = tmp_path / "ed25519.pem"
    other.write_bytes(_key_pem(ed25519.Ed25519PrivateKey.generate()))
    _assert_einval("unsupported kind of key", pki.user_cert_path, other)


def test_load_ec_key(pki: PKI, tmp_path: Path) -> None:
    ca_key = _key(0)
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC User")]))
        .issuer_name(_cert(pki.ca_file).subject)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .sign(ca_key, hashes.SHA256())
    )
    path = tmp_path / "ec.pem"
    path.write_bytes(_pem(cert) + _key_pem(key))
    assert Signer.load(path).identity == "/CN=EC User"


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CredentialError, match="does not exist") as caught:
        Signer.load(tmp_path / "absent")
    assert caught.value.code == errno.ENOENT


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_load_unreadable_file(pki: PKI, tmp_path: Path) -> None:
    locked = tmp_path / "locked.pem"
    locked.write_bytes(pki.proxy_path.read_bytes())
    locked.chmod(0)
    try:
        with pytest.raises(CredentialError, match="Cannot read") as caught:
            Signer.load(locked)
    finally:
        locked.chmod(0o600)
    assert caught.value.code == errno.EACCES


# -- identity and limitation ---------------------------------------------------------------


def test_identity_through_proxy_of_proxy(pki: PKI, tmp_path: Path) -> None:
    first = pki.credential(pki.proxy_path)
    second = pki.proxy(path=tmp_path / "second", issuer=first, key_slot=5)
    loaded = Signer.load(second)
    assert len(loaded.chain) == 3
    assert loaded.identity == USER_DN


def test_identity_of_legacy_proxy(pki: PKI, tmp_path: Path) -> None:
    loaded = Signer.load(pki.proxy("legacy", path=tmp_path / "legacy"))
    assert loaded.certificate.subject.rfc4514_string().startswith("CN=proxy,")
    assert loaded.identity == USER_DN
    assert not loaded.limited


def test_identity_without_end_entity(pki: PKI, tmp_path: Path) -> None:
    """A file holding only proxies names the last one: the closest thing to a user."""
    user, user_key = _user(pki)
    leaf = _craft(user, user_key)
    loaded = Signer.load(_write(tmp_path / "lonely", leaf, 4))
    assert loaded.identity == USER_DN + "/CN=1234"


def test_limited_rfc_proxy(pki: PKI, tmp_path: Path) -> None:
    assert Signer.load(pki.proxy("limited", path=tmp_path / "limited")).limited


def test_limited_legacy_proxy(pki: PKI, tmp_path: Path) -> None:
    user, user_key = _user(pki)
    leaf = _craft(user, user_key, cn="limited proxy", policy=None)
    loaded = Signer.load(_write(tmp_path / "legacy-limited", leaf, 4, user))
    assert loaded.limited
    assert loaded.identity == USER_DN


def test_not_limited_without_common_name(pki: PKI, tmp_path: Path) -> None:
    key = _key(6)
    now = dt.datetime.now(dt.UTC)
    nameless = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Anon")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(nameless)
        .issuer_name(nameless)
        .public_key(key.public_key())
        .serial_number(9)
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    loaded = Signer.load(_write(tmp_path / "anon", cert, 6))
    assert not loaded.limited
    assert loaded.identity == "/O=Anon"


def test_voms_extension_found_on_parent(pki: PKI, voms_proxy: Path, tmp_path: Path) -> None:
    parent = Signer.load(voms_proxy)
    request = _csr(_key(5))
    delegated = _split(proxy.sign_request(request, parent, copy_voms=False))
    child = Signer(tuple(delegated), _key(5))
    assert child.voms_extension() == parent.voms_extension()
    assert child.voms_extension() is not None


def test_chain_pem(signer: Signer) -> None:
    assert _split(signer.chain_pem()) == list(signer.chain)
    assert "PRIVATE KEY" not in signer.chain_pem()


# -- sign_request --------------------------------------------------------------------------


def test_sign_request_profile(signer: Signer) -> None:
    now = time.time()
    chain = _split(proxy.sign_request(_csr(_key(5)), signer, now=now))
    new = chain[0]
    assert chain[1:] == list(signer.chain)
    serial = new.serial_number
    assert serial % 2 == 1
    assert new.subject == x509.Name(
        [*signer.certificate.subject.rdns, x509.RelativeDistinguishedName(
            [x509.NameAttribute(NameOID.COMMON_NAME, str(serial))]
        )]
    )  # fmt: skip
    assert new.issuer == signer.certificate.subject
    assert new.public_key().public_numbers() == _key(5).public_key().public_numbers()
    new.verify_directly_issued_by(signer.certificate)
    assert proxy.verify_chain_link(new, signer.certificate)
    assert isinstance(new.signature_hash_algorithm, hashes.SHA256)


def test_sign_request_extensions(signer: Signer) -> None:
    new = _split(proxy.sign_request(_csr(_key(5)), signer))[0]
    usage = _ext(new, x509.oid.ExtensionOID.KEY_USAGE)
    assert usage.critical
    assert isinstance(usage.value, x509.KeyUsage)
    assert usage.value.digital_signature and usage.value.key_encipherment
    assert not (usage.value.key_cert_sign or usage.value.content_commitment)
    info = _ext(new, proxy.PROXY_CERT_INFO)
    assert info.critical
    assert isinstance(info.value, x509.UnrecognizedExtension)
    assert info.value.value == INHERIT_ALL
    assert len(new.extensions) == 2


def test_sign_request_ignores_request_subject(signer: Signer) -> None:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mallory")])
    new = _split(proxy.sign_request(_csr(_key(5), subject).decode(), signer))[0]
    assert "Mallory" not in new.subject.rfc4514_string()


def test_sign_request_validity_defaults(signer: Signer) -> None:
    now = time.time()
    new = _split(proxy.sign_request(_csr(_key(5)), signer, now=now))[0]
    assert abs(new.not_valid_before_utc.timestamp() - (now - 300)) <= 1
    assert new.not_valid_after_utc == signer.not_after


def test_sign_request_lifetime(signer: Signer) -> None:
    now = time.time()
    new = _split(proxy.sign_request(_csr(_key(5)), signer, lifetime=600, now=now))[0]
    assert abs(new.not_valid_after_utc.timestamp() - (now + 600)) <= 1


def test_sign_request_lifetime_clamped_to_signer(signer: Signer) -> None:
    new = _split(proxy.sign_request(_csr(_key(5)), signer, lifetime=30 * 86400))[0]
    assert new.not_valid_after_utc == signer.not_after


def test_sign_request_backdate_clamped_to_issuer(signer: Signer) -> None:
    start = signer.certificate.not_valid_before_utc
    now = start.timestamp() + 60
    new = _split(proxy.sign_request(_csr(_key(5)), signer, now=now))[0]
    assert new.not_valid_before_utc == start


def _policy_of(pem: str) -> bytes:
    value = _ext(_split(pem)[0], proxy.PROXY_CERT_INFO).value
    assert isinstance(value, x509.UnrecognizedExtension)
    return value.value


def test_sign_request_limited_on_request(signer: Signer) -> None:
    assert _policy_of(proxy.sign_request(_csr(_key(5)), signer, limited=True)) == LIMITED


def test_sign_request_limited_signer_cannot_be_lifted(pki: PKI, tmp_path: Path) -> None:
    limited = Signer.load(pki.proxy("limited", path=tmp_path / "limited"))
    assert _policy_of(proxy.sign_request(_csr(_key(5)), limited, limited=False)) == LIMITED


def test_sign_request_ec_key(signer: Signer) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    new = _split(proxy.sign_request(_csr(key), signer))[0]
    assert isinstance(new.public_key(), ec.EllipticCurvePublicKey)
    new.verify_directly_issued_by(signer.certificate)


def test_sign_request_copies_voms(voms_proxy: Path) -> None:
    parent = Signer.load(voms_proxy)
    original = parent.voms_extension()
    assert original is not None
    copied = _ext(_split(proxy.sign_request(_csr(_key(5)), parent))[0], proxy.VOMS_AC)
    assert copied.critical == original.critical
    assert isinstance(copied.value, x509.UnrecognizedExtension)
    assert isinstance(original.value, x509.UnrecognizedExtension)
    assert copied.value.value == original.value.value


def test_sign_request_without_voms_copy(voms_proxy: Path) -> None:
    new = _split(proxy.sign_request(_csr(_key(5)), Signer.load(voms_proxy), copy_voms=False))[0]
    with pytest.raises(x509.ExtensionNotFound):
        _ext(new, proxy.VOMS_AC)


def _assert_rejected(request: bytes, signer: Signer, match: str, code: int = errno.EINVAL) -> None:
    with pytest.raises(CredentialError, match=match) as caught:
        proxy.sign_request(request, signer)
    assert caught.value.code == code


def test_sign_request_unreadable(signer: Signer) -> None:
    _assert_rejected(b"not a request", signer, "unreadable delegation request")


def test_sign_request_bad_signature(signer: Signer) -> None:
    request = x509.load_pem_x509_csr(_csr(_key(5)))
    der = bytearray(request.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF
    tampered = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    _assert_rejected(tampered, signer, "not signed by its key")


def test_sign_request_unsupported_key(signer: Signer) -> None:
    _assert_rejected(_csr(ed25519.Ed25519PrivateKey.generate()), signer, "unsupported kind")


def test_sign_request_expired_signer(signer: Signer) -> None:
    with pytest.raises(CredentialError, match="expired") as caught:
        proxy.sign_request(_csr(_key(5)), signer, now=time.time() + 400 * 86400)
    assert caught.value.code == EXPIRED
    assert caught.value.code in (getattr(errno, "EKEYEXPIRED", errno.EACCES), errno.EACCES)


def _handshake(pki: PKI, credential: Path) -> str:
    """Present ``credential`` to a server that verifies proxies; returns the peer's subject."""
    server_side, client_side = socket.socketpair()
    server = pki.server_context(require_client=True).wrap_socket(
        server_side, server_side=True, do_handshake_on_connect=False
    )
    seen: list[object] = []

    def serve() -> None:
        try:
            server.do_handshake()
            seen.append(server.getpeercert())
        except ssl.SSLError as exc:
            seen.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    context = pki.client_context(proxy=credential)
    context.check_hostname = False
    with context.wrap_socket(client_side) as client:
        client.do_handshake()
    thread.join(10)
    server.close()
    assert isinstance(seen[0], dict), seen
    return str(seen[0]["subject"])


def test_delegated_proxy_is_accepted_by_openssl(pki: PKI, signer: Signer, tmp_path: Path) -> None:
    pem = proxy.sign_request(_csr(_key(5)), signer)
    chain = _split(pem)
    delegated = tmp_path / "delegated"
    delegated.write_bytes(_pem(chain[0]) + _key_pem(_key(5)) + _pem(*chain[1:]))
    assert "Test User" in _handshake(pki, delegated)


# -- create_proxy and write_proxy ----------------------------------------------------------


def test_create_proxy(pki: PKI, tmp_path: Path) -> None:
    user = Signer.load(pki.user_cert_path, pki.user_key_path)
    now = time.time()
    data = proxy.create_proxy(user, lifetime=3600, bits=1024, now=now)
    made = Signer.load(proxy.write_proxy(tmp_path / "made", data))
    assert made.chain[1:] == user.chain
    assert made.identity == USER_DN
    assert isinstance(made.key, rsa.RSAPrivateKey)
    assert made.key.key_size == 1024
    assert abs(made.certificate.not_valid_after_utc.timestamp() - (now + 3600)) <= 1
    assert b"BEGIN RSA PRIVATE KEY" in data
    assert not made.limited
    assert made.voms_extension() is None


def test_create_proxy_is_accepted_by_openssl(pki: PKI, tmp_path: Path) -> None:
    user = Signer.load(pki.user_cert_path, pki.user_key_path)
    made = proxy.write_proxy(tmp_path / "made", proxy.create_proxy(user))
    assert "Test User" in _handshake(pki, made)


def test_create_limited_proxy(pki: PKI, tmp_path: Path) -> None:
    user = Signer.load(pki.user_cert_path, pki.user_key_path)
    made = proxy.write_proxy(tmp_path / "lim", proxy.create_proxy(user, bits=1024, limited=True))
    assert Signer.load(made).limited
    assert proxy.proxy_info(made).kind == "RFC 3820 compliant limited proxy"


def test_create_proxy_embeds_voms(pki: PKI) -> None:
    user = Signer.load(pki.user_cert_path, pki.user_key_path)
    der = _voms_der(pki, user.certificate)
    data = proxy.create_proxy(user, bits=1024, voms_extension=der)
    leaf = x509.load_pem_x509_certificates(data)[0]
    extension = _ext(leaf, proxy.VOMS_AC)
    assert not extension.critical
    assert isinstance(extension.value, x509.UnrecognizedExtension)
    assert extension.value.value == der


def test_create_proxy_carries_signer_voms(voms_proxy: Path, tmp_path: Path) -> None:
    parent = Signer.load(voms_proxy)
    child = Signer.load(
        proxy.write_proxy(tmp_path / "child", proxy.create_proxy(parent, bits=1024))
    )
    assert _ext(child.certificate, proxy.VOMS_AC) == parent.voms_extension()


def test_create_proxy_explicit_voms_replaces_signer_voms(voms_proxy: Path) -> None:
    parent = Signer.load(voms_proxy)
    replacement = voms.ac_sequence([b"\x30\x00"])
    data = proxy.create_proxy(parent, bits=1024, voms_extension=replacement)
    leaf = x509.load_pem_x509_certificates(data)[0]
    value = _ext(leaf, proxy.VOMS_AC).value
    assert isinstance(value, x509.UnrecognizedExtension)
    assert value.value == replacement


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_write_proxy_mode_and_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "x509up"
    target.write_bytes(b"old")
    target.chmod(0o644)
    assert proxy.write_proxy(str(target), b"new") == target
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x509up"]


def test_write_proxy_cleans_up_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(source: object, target: object) -> None:
        raise OSError(errno.EXDEV, "no")

    monkeypatch.setattr(proxy.os, "replace", refuse)
    with pytest.raises(OSError, match="no"):
        proxy.write_proxy(tmp_path / "x509up", b"data")
    assert list(tmp_path.iterdir()) == []


def test_write_proxy_closes_file_when_chmod_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: object, mode: int) -> None:
        raise PermissionError(errno.EPERM, "chmod refused")

    monkeypatch.setattr(proxy.os, "chmod", refuse)
    with pytest.raises(PermissionError):
        proxy.write_proxy(tmp_path / "x509up", b"data")
    assert list(tmp_path.iterdir()) == []


# -- proxy_info ----------------------------------------------------------------------------


def test_info_end_entity(pki: PKI) -> None:
    info = proxy.proxy_info(pki.user_cert_path)
    assert info.kind == "end-entity certificate"
    assert info.subject == info.identity == USER_DN
    assert info.issuer == "/DC=org/DC=xgfal/CN=xgfal Test CA"
    assert info.key_bits == 2048
    assert info.voms == ()
    assert info.path == str(pki.user_cert_path)


def test_info_rfc_proxy(pki: PKI) -> None:
    info = proxy.proxy_info(pki.proxy_path)
    assert info.kind == "RFC 3820 compliant impersonation proxy"
    assert info.identity == USER_DN
    assert info.issuer == USER_DN
    assert info.subject.startswith(USER_DN + "/CN=")
    chain = x509.load_pem_x509_certificates(pki.proxy_path.read_bytes())
    assert info.not_after == min(c.not_valid_after_utc for c in chain)
    assert info.not_before == chain[0].not_valid_before_utc


def test_info_limited_proxy(pki: PKI, tmp_path: Path) -> None:
    kind = proxy.proxy_info(pki.proxy("limited", path=tmp_path / "limited")).kind
    assert kind == "RFC 3820 compliant limited proxy"


def test_info_independent_proxy(pki: PKI, tmp_path: Path) -> None:
    user, user_key = _user(pki)
    leaf = _craft(user, user_key, policy=INDEPENDENT)
    info = proxy.proxy_info(_write(tmp_path / "independent", leaf, 4, user))
    assert info.kind == "RFC 3820 compliant independent proxy"


def test_info_legacy_proxy(pki: PKI, tmp_path: Path) -> None:
    info = proxy.proxy_info(pki.proxy("legacy", path=tmp_path / "legacy"))
    assert info.kind == "legacy Globus proxy"
    assert info.identity == USER_DN


def test_info_legacy_limited_proxy(pki: PKI, tmp_path: Path) -> None:
    user, user_key = _user(pki)
    leaf = _craft(user, user_key, cn="limited proxy", policy=None)
    info = proxy.proxy_info(_write(tmp_path / "legacy-limited", leaf, 4, user))
    assert info.kind == "legacy Globus limited proxy"
    assert info.subject == USER_DN + "/CN=limited proxy"


def test_info_proxy_with_odd_policy_extension(pki: PKI, tmp_path: Path) -> None:
    """A proxyCertInfo whose policy is neither limited nor independent is impersonation."""
    user, user_key = _user(pki)
    leaf = _craft(user, user_key, policy=bytes.fromhex("30053003060100"))
    info = proxy.proxy_info(_write(tmp_path / "odd", leaf, 4, user))
    assert info.kind == "RFC 3820 compliant impersonation proxy"


def test_info_voms(voms_proxy: Path) -> None:
    info = proxy.proxy_info(voms_proxy)
    assert info.key_bits == 1024
    (entry,) = info.voms
    assert entry.vo == "atlas"
    assert entry.fqans == ("/atlas/Role=production/Capability=NULL",)
    assert entry.uri == "voms.example:15000"
    assert entry.not_after is not None
    assert 3000 < entry.remaining() <= 3600


def test_info_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CredentialError) as caught:
        proxy.proxy_info(tmp_path / "absent")
    assert caught.value.code == errno.ENOENT


def test_voms_attributes_remaining() -> None:
    end = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    attributes = proxy.VOMSAttributes("vo", (), end, "host:1")
    assert attributes.remaining(end.timestamp() - 90) == 90
    assert attributes.remaining(end.timestamp() + 90) == 0
    assert proxy.VOMSAttributes("vo", (), None, "").remaining() == 0


def test_proxy_info_remaining(pki: PKI) -> None:
    info = proxy.proxy_info(pki.proxy_path)
    assert info.remaining(info.not_after.timestamp() - 10) == 10
    assert info.remaining(info.not_after.timestamp() + 10) == 0
    assert 0 < info.remaining() <= 12 * 3600


def test_openssl_name() -> None:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "org"),
            x509.NameAttribute(NameOID.USER_ID, "alice"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "alice@example.org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
        ]
    )
    assert proxy.openssl_name(name) == "/DC=org/UID=alice/emailAddress=alice@example.org/CN=Alice"


def test_openssl_name_multivalued_rdn() -> None:
    rdn = x509.RelativeDistinguishedName(
        [x509.NameAttribute(NameOID.COMMON_NAME, "A"), x509.NameAttribute(NameOID.SURNAME, "B")]
    )
    assert sorted(proxy.openssl_name(x509.Name([rdn]))[1:].split("/")) == ["2.5.4.4=B", "CN=A"]


def test_verify_chain_link(pki: PKI) -> None:
    chain = x509.load_pem_x509_certificates(pki.proxy_path.read_bytes())
    assert proxy.verify_chain_link(chain[0], chain[1])
    assert not proxy.verify_chain_link(chain[1], chain[0])
    assert not proxy.verify_chain_link(chain[0], _cert(pki.host_cert_path))
