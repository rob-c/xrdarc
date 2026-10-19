"""``xrdarc proxy`` (arcproxy): making, inspecting and removing proxies."""

from __future__ import annotations

import getpass
import shutil
import ssl
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from xrdsec import proxies
from xrdsec.testing.pki import PKI
from xrdsec.testing.voms import FakeVOMSServer, vomses_line, write_lsc

from _client_helpers import results, run, run_json
from conftest import PROXY_NAME
from xrdarc.proxy import load_signer, proxy_info, write_proxy

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
    assert "Proxy type: RFC3820 compliant impersonation proxy\n" in out
    assert "Proxy key length: 1024\n" in out
    assert "Time left for proxy: 11 hours 59 minutes" in out
    info = proxy_info(target)
    assert info.identity == load_signer(pki.user_cert_path, pki.user_key_path).identity
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_create_limited_for_days(
    capsys: pytest.CaptureFixture[str], pki: PKI, tmp_path: Path, restore_logging: None
) -> None:
    out_path = tmp_path / "limited"
    argv = ["proxy", "--proxy", str(out_path), *_user(pki), "--limited", "--lifetime", "2d"]
    code, doc = run_json(capsys, *argv)
    assert code == 0
    [record] = results(doc)
    assert record["proxy_type"] == "RFC3820 compliant limited proxy"
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
    assert (code, out) == (3, "")
    assert "no user certificate found" in err


@pytest.mark.parametrize("lifetime", ["0", "bogus"])
def test_bad_lifetime(proxy: Proxy, pki: PKI, lifetime: str) -> None:
    code, _, err = proxy(*_user(pki), "--lifetime", lifetime)
    assert code == 2
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
    signer = load_signer(pki.user_cert_path, pki.user_key_path)
    write_proxy(
        old, proxies.create_proxy(signer, lifetime=60, now=time.time() - 120, profile="arc")
    )
    code, doc = run_json(capsys, "proxy", "-I", "--proxy", str(old))
    assert code == 0
    assert results(doc)[0]["time_left"] == 0
    assert "Time left for proxy: expired" in "".join(
        r["text"] for r in doc["records"] if r["kind"] == "message"
    )


def test_info_without_a_proxy(proxy: Proxy) -> None:
    code, _, err = proxy("-I")
    assert code == 3
    assert "there is no proxy at" in err


def test_remove(proxy: Proxy, target: Path) -> None:
    target.write_text("x")
    assert proxy("-r") == (0, f"Removed {target}\n", "")
    assert not target.exists()
    assert proxy("-r") == (0, f"Removed {target}\n", "")


def test_default_target_without_x509_user_proxy(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    restore_logging: None,
    tmp_dir: Path,
) -> None:
    monkeypatch.delenv("X509_USER_PROXY", raising=False)
    code, _, err = run(capsys, "proxy", "-I")
    assert code == 3
    assert f"there is no proxy at {tmp_dir / PROXY_NAME}" in err


def test_default_target_is_written_without_following_a_link(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    pki: PKI,
    restore_logging: None,
    tmp_dir: Path,
    tmp_path: Path,
) -> None:
    """A link at the predictable ``/tmp/x509up_u<uid>`` is a trap; at a named path it is not."""
    monkeypatch.delenv("X509_USER_PROXY", raising=False)
    default = tmp_dir / PROXY_NAME
    elsewhere = tmp_path / "elsewhere"
    default.symlink_to(elsewhere)
    code, _, err = run(capsys, "proxy", *_user(pki), "--bits", "1024")
    assert code == 3 and "symbolic link" in err and not elsewhere.exists()
    monkeypatch.setenv("X509_USER_PROXY", str(default))
    code, _, _ = run(capsys, "proxy", *_user(pki), "--bits", "1024")
    assert code == 0 and elsewhere.is_file()


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

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return "secret"

    monkeypatch.setattr(getpass, "getpass", ask)
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
    assert code == 3
    assert "no terminal to ask for its pass phrase" in err


# ---------------------------------------------------------------------------
# VOMS
# ---------------------------------------------------------------------------


@dataclass
class VOMS:
    """A running fake VOMS server and the ``vomses`` file that names it."""

    server: FakeVOMSServer
    vomses: Path


@pytest.fixture
def voms(pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[VOMS]:
    """A VOMS server for ``atlas`` on loopback, trusted as a real one would be.

    The server's host certificate is the PKI's, so ``X509_CERT_DIR`` trusts
    it, and an LSC file in ``X509_VOMS_DIR`` lets the AC it mints verify.
    """
    server = FakeVOMSServer(pki.host_signer, pki.server_context(require_client=True))
    server.holder = pki.user  # the user certificate, whatever the peer chain shows
    vomsdir = tmp_path / "vomsdir"
    write_lsc(vomsdir, "atlas", "localhost", pki.host_signer.chain)
    monkeypatch.setenv("X509_CERT_DIR", str(pki.ca_dir))
    monkeypatch.setenv("X509_VOMS_DIR", str(vomsdir))
    vomses = tmp_path / "vomses"
    with server:
        vomses.write_text(vomses_line("atlas", "127.0.0.1", server.port, "/CN=voms"))
        yield VOMS(server, vomses)


def test_voms_attributes(proxy: Proxy, pki: PKI, voms: VOMS) -> None:
    argv = ["-S", "atlas:/atlas/Role=pilot", "-S", "atlas", "--voms-lifetime", "1h"]
    code, out, err = proxy(*_user(pki), *argv, "--vomses", str(voms.vomses))
    assert (code, err) == (0, "")
    assert out.startswith("Contacting VOMS server for atlas\nContacting VOMS server for atlas\n")
    assert "====== AC extension information for VO atlas ======" in out
    assert "attribute : /atlas/Role=pilot\n" in out
    assert "uri       : 127.0.0.1:" in out
    assert "Time left for AC: 0 hours 59 minutes" in out
    asked = [r.target for r in voms.server.requests]
    assert asked[0].startswith("/generate-ac?fqans=%2Fatlas%2FRole%3Dpilot&lifetime=3600")
    assert asked[1] == "/generate-ac?lifetime=3600"


def test_voms_servers_are_reached_without_rfc5280_strict_mode(
    proxy: Proxy, pki: PKI, voms: VOMS, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As a CE is: ``arcproxy`` (OpenSSL's defaults) never applies Python 3.13's strict checks."""
    from xrdsec import tls

    strict: list[bool] = []
    real = tls.client_context

    def spy(**kwargs: Any) -> ssl.SSLContext:
        strict.append(kwargs["x509_strict"])
        return real(**kwargs)

    monkeypatch.setattr(tls, "client_context", spy)
    code, _, _ = proxy(*_user(pki), "-S", "atlas", "--vomses", str(voms.vomses))
    assert code == 0 and strict == [False]


def test_voms_lifetime_defaults_to_the_proxy_lifetime(
    proxy: Proxy, pki: PKI, voms: VOMS, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("X509_VOMSES", str(voms.vomses))
    code, _, _ = proxy(*_user(pki), "-S", "atlas", "--lifetime", "2h", "-t", "5")
    assert code == 0
    assert voms.server.requests[0].param("lifetime") == "7200"


def test_voms_warning_is_logged(
    proxy: Proxy, pki: PKI, voms: VOMS, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An AC this machine cannot verify is still used, with a warning in the log, not a trace."""
    monkeypatch.setenv("X509_VOMS_DIR", str(tmp_path / "empty-vomsdir"))
    code, out, err = proxy(*_user(pki), "-S", "atlas", "--vomses", str(voms.vomses))
    assert code == 0
    assert err.startswith("WARNING: the attribute certificate from 127.0.0.1:")
    assert "VOMSWarning" not in err
    assert "AC extension information for VO atlas" in out


def test_voms_refusal_is_a_credential_error(proxy: Proxy, pki: PKI, voms: VOMS) -> None:
    voms.server.refuse("NoSuchUser", "not a member")
    code, _, err = proxy(*_user(pki), "-S", "atlas", "--vomses", str(voms.vomses))
    assert code == 3
    assert "not a member" in err or "does not know your certificate" in err


def test_vomses_missing_is_a_local_error(proxy: Proxy, pki: PKI) -> None:
    code, _, err = proxy(*_user(pki), "-S", "atlas", "--vomses", "/nowhere")
    assert code == 6
    assert "/nowhere does not exist" in err


def test_voms_server_unknown(proxy: Proxy, pki: PKI, voms: VOMS) -> None:
    code, _, err = proxy(*_user(pki), "-S", "cms", "--vomses", str(voms.vomses))
    assert code == 6
    assert "no VOMS server is configured for 'cms'" in err


def test_voms_bad_fqan_is_a_usage_error(proxy: Proxy, pki: PKI, voms: VOMS) -> None:
    code, _, err = proxy(*_user(pki), "-S", "atlas:no-slash", "--vomses", str(voms.vomses))
    assert code == 2
    assert "not a VOMS FQAN" in err


def test_voms_request_without_a_vo_is_a_usage_error(proxy: Proxy, pki: PKI) -> None:
    code, _, err = proxy(*_user(pki), "-S", ":/atlas")
    assert code == 2
    assert "-S: a VOMS request needs a VO name" in err


def test_voms_unreachable(proxy: Proxy, pki: PKI, tmp_path: Path) -> None:
    vomses = tmp_path / "vomses"
    vomses.write_text(vomses_line("atlas", "127.0.0.1", 1, "/CN=voms"))
    code, _, err = proxy(*_user(pki), "-S", "atlas", "--vomses", str(vomses), "-t", "2")
    assert code == 3
    assert "127.0.0.1:1" in err
