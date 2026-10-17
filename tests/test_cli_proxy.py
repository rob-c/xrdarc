"""``xrdarc proxy`` (arcproxy): making, inspecting and removing proxies."""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from xgfalclient.testing.pki import PKI

from _client_helpers import results, run, run_json
from _voms_fixtures import make_ac
from xrdarc import voms
from xrdarc.cli import _common
from xrdarc.proxy import Signer, create_proxy, proxy_info, write_proxy
from xrdarc.transport import Session

pytest_plugins = ["_cli_fixtures"]
pytestmark = pytest.mark.usefixtures("restore_logging")

Proxy = Callable[..., tuple[int, str, str]]


@pytest.fixture
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where proxies go by default in these tests (never the session PKI's own proxy)."""
    path = tmp_path / "x509up"
    monkeypatch.setenv("X509_USER_PROXY", str(path))
    return path


@pytest.fixture
def proxy(capsys: pytest.CaptureFixture[str], target: Path) -> Proxy:
    def call(*argv: str) -> tuple[int, str, str]:
        return run(capsys, "proxy", *argv)

    return call


def _user(pki: PKI) -> list[str]:
    return ["--cert", str(pki.user_cert_path), "--key", str(pki.user_key_path)]


def test_create_from_cert_and_key(proxy: Proxy, pki: PKI, target: Path) -> None:
    code, out, err = proxy(*_user(pki), "--bits", "1024")
    assert (code, err) == (0, "")
    assert out.startswith("Proxy generation succeeded\nYour proxy is valid until: ")
    assert "Proxy type: RFC 3820 compliant impersonation proxy\n" in out
    assert "Proxy key length: 1024\n" in out
    assert "Time left for proxy: 11 hours 59 minutes" in out
    info = proxy_info(target)
    assert info.identity == "/DC=org/DC=xgfal/OU=People/CN=Test User"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_create_limited_for_days(
    capsys: pytest.CaptureFixture[str], pki: PKI, tmp_path: Path, restore_logging: None
) -> None:
    out_path = tmp_path / "limited"
    argv = ["proxy", "--proxy", str(out_path), *_user(pki), "--limited", "--lifetime", "2d"]
    code, doc = run_json(capsys, *argv)
    assert code == 0
    [record] = results(doc)
    assert record["proxy_type"] == "RFC 3820 compliant limited proxy"
    assert record["path"] == str(out_path)
    assert 2 * 86400 - 60 < record["time_left"] <= 2 * 86400
    assert record["voms"] == []


def _install(pki: PKI, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "usercert.pem", directory / "userkey.pem"
    shutil.copy(pki.user_cert_path, cert)
    shutil.copy(pki.user_key_path, key)
    key.chmod(0o600)
    return cert, key


def test_user_credential_from_the_environment(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, key = _install(pki, tmp_path / "elsewhere")
    monkeypatch.setenv("X509_USER_CERT", str(cert))
    monkeypatch.setenv("X509_USER_KEY", str(key))
    code, _, _ = proxy("--lifetime", "90m")
    assert code == 0


def test_user_credential_from_globus_directory(
    proxy: Proxy, pki: PKI, home: Path, target: Path
) -> None:
    _install(pki, home / ".globus")
    code, out, _ = proxy()
    assert code == 0
    assert f"Proxy path: {target}\n" in out


def test_no_user_credential(proxy: Proxy, home: Path) -> None:
    (home / ".arc").mkdir()
    (home / ".arc" / "usercert.pem").write_text("only a certificate")
    code, out, err = proxy()
    assert (code, out) == (errno.ENOENT, "")
    assert "No user certificate found" in err


@pytest.mark.parametrize("lifetime", ["0", "bogus"])
def test_bad_lifetime(proxy: Proxy, pki: PKI, lifetime: str) -> None:
    code, _, err = proxy(*_user(pki), "--lifetime", lifetime)
    assert code == errno.EINVAL
    assert err.startswith("xrdarc proxy: ")


def test_info(proxy: Proxy, pki: PKI, target: Path) -> None:
    shutil.copy(pki.proxy_path, target)
    code, out, _ = proxy("-I")
    assert code == 0
    assert out.startswith(f"Subject: {proxy_info(target).subject}\n")
    assert f"Proxy path: {target}" in out


def test_info_of_an_expired_proxy(
    capsys: pytest.CaptureFixture[str], pki: PKI, tmp_path: Path, restore_logging: None
) -> None:
    old = tmp_path / "old"
    signer = Signer.load(pki.user_cert_path, pki.user_key_path)
    write_proxy(old, create_proxy(signer, lifetime=60, now=time.time() - 120))
    code, doc = run_json(capsys, "proxy", "-I", "--proxy", str(old))
    assert code == 0
    assert results(doc)[0]["time_left"] == 0
    assert "Time left for proxy: expired" in "".join(
        r["text"] for r in doc["records"] if r["kind"] == "message"
    )


def test_info_without_a_proxy(proxy: Proxy) -> None:
    code, _, err = proxy("-I")
    assert code == errno.ENOENT
    assert "There is no proxy at" in err


def test_remove(proxy: Proxy, target: Path) -> None:
    target.write_text("x")
    assert proxy("-r") == (0, f"Removed {target}\n", "")
    assert not target.exists()
    assert proxy("-r") == (0, f"Removed {target}\n", "")


def test_default_target_without_x509_user_proxy(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, restore_logging: None
) -> None:
    monkeypatch.delenv("X509_USER_PROXY", raising=False)
    code, _, err = run(capsys, "proxy", "-I")
    assert code == errno.ENOENT
    assert "There is no proxy at /tmp/x509up_u7654321" in err


# ---------------------------------------------------------------------------
# Encrypted keys
# ---------------------------------------------------------------------------


def _encrypted_key(pki: PKI, tmp_path: Path) -> Path:
    key = serialization.load_pem_private_key(pki.user_key_path.read_bytes(), None)
    path = tmp_path / "userkey-enc.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret"),
        )
    )
    path.chmod(0o600)
    return path


def test_encrypted_key_asks_for_the_pass_phrase(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(_common.getpass, "getpass", lambda p: prompts.append(p) or "secret")
    key = _encrypted_key(pki, tmp_path)
    code, _, err = proxy("--cert", str(pki.user_cert_path), "--key", str(key))
    assert (code, err) == (0, "")
    assert prompts == ["Enter PEM pass phrase: "]


def test_encrypted_key_without_a_terminal(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    key = _encrypted_key(pki, tmp_path)
    code, _, err = proxy("--cert", str(pki.user_cert_path), "--key", str(key))
    assert code == errno.EACCES
    assert "no terminal to ask for its pass phrase" in err


# ---------------------------------------------------------------------------
# VOMS
# ---------------------------------------------------------------------------


def _fake_fetch(pki: PKI, calls: list[dict[str, Any]]) -> Callable[..., bytes]:
    holder = x509.load_pem_x509_certificate(pki.user_cert_path.read_bytes())
    voms_cert = x509.load_pem_x509_certificate(pki.host_cert_path.read_bytes())
    voms_key = serialization.load_pem_private_key(pki.host_key_path.read_bytes(), None)

    def fetch(
        session: Session,
        servers: Sequence[voms.VOMSServer],
        *,
        fqans: Sequence[str] = (),
        lifetime: int | None = None,
    ) -> bytes:
        calls.append({"servers": [s.alias for s in servers], "fqans": fqans, "lifetime": lifetime})
        assert session.credentials.is_proxy
        assert os.path.isfile(str(session.credentials.cert))
        return make_ac(holder, voms_cert, voms_key, fqans=tuple(fqans) or ("/atlas",))

    return fetch


def _vomses(tmp_path: Path) -> Path:
    path = tmp_path / "vomses"
    path.write_text('"atlas" "voms.example" "15000" "/CN=voms.example" "atlas"\n')
    return path


def test_voms_attributes(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(voms, "fetch_ac", _fake_fetch(pki, calls))
    argv = ["-S", "atlas:/atlas/Role=pilot", "-S", "atlas", "--voms-lifetime", "1h"]
    code, out, err = proxy(*_user(pki), *argv, "--vomses", str(_vomses(tmp_path)))
    assert (code, err) == (0, "")
    assert out.startswith("Contacting VOMS server for atlas\nContacting VOMS server for atlas\n")
    assert calls == [
        {"servers": ["atlas"], "fqans": ["/atlas/Role=pilot"], "lifetime": 3600},
        {"servers": ["atlas"], "fqans": [], "lifetime": 3600},
    ]
    assert "====== AC extension information for VO atlas ======" in out
    assert "attribute : /atlas/Role=pilot\n" in out
    assert "uri       : voms.example:15000" in out
    assert not list(Path(tempfile.gettempdir()).glob("xrdarc-proxy-*"))


def test_voms_lifetime_defaults_to_the_proxy_lifetime(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(voms, "fetch_ac", _fake_fetch(pki, calls))
    monkeypatch.setenv("X509_VOMSES", str(_vomses(tmp_path)))
    code, _, _ = proxy(*_user(pki), "-S", "atlas", "--lifetime", "2h", "--insecure", "-t", "5")
    assert code == 0
    assert calls[0]["lifetime"] == 7200


def test_voms_server_unknown(
    proxy: Proxy, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(voms, "fetch_ac", pytest.fail)
    code, _, err = proxy(*_user(pki), "-S", "cms", "--vomses", str(_vomses(tmp_path)))
    assert code == errno.ENOENT
    assert "No VOMS server for 'cms'" in err
