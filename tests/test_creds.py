"""Credential discovery in ARC's order, token discovery, trust anchors, TLS contexts."""

from __future__ import annotations

import errno
import logging
import os
import shutil
import ssl
import sys
import tempfile
from pathlib import Path

import pytest
from xgfalclient.testing.pki import PKI

from conftest import UNUSED_UID
from xrdarc import creds
from xrdarc.config import UserConfig
from xrdarc.creds import Auth, Credentials, discover
from xrdarc.errors import CredentialError

#: The module's own ``_uid``, captured at import, before the hermetic fixture patches it.
_REAL_UID = creds._uid
PROXY_NAME = f"x509up_u{UNUSED_UID}"


def _config(home: Path, **paths: str) -> UserConfig:
    return UserConfig(joblist=home / ".arc" / "jobs.dat", **paths)  # type: ignore[arg-type]


def _pair(directory: Path, pki: PKI, *, key: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(pki.user_cert_path, directory / "usercert.pem")
    if key:
        shutil.copy(pki.user_key_path, directory / "userkey.pem")
        (directory / "userkey.pem").chmod(0o600)
    return directory


def _proxy_copy(pki: PKI, target: Path) -> Path:
    shutil.copy(pki.proxy_path, target)
    target.chmod(0o600)
    return target


# -- X.509 search order --------------------------------------------------------------------


def test_env_proxy_first(pki: PKI, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X509_USER_PROXY", f" {pki.proxy_path} ")
    monkeypatch.setenv("X509_USER_CERT", str(pki.user_cert_path))
    monkeypatch.setenv("X509_USER_KEY", str(pki.user_key_path))
    other = _proxy_copy(pki, home / "other-proxy")
    found = discover(_config(home, proxy_path=str(other)))
    assert (found.cert, found.key) == (str(pki.proxy_path), str(pki.proxy_path))
    assert found.is_proxy


def test_config_proxy_before_cert(pki: PKI, home: Path) -> None:
    configured = _proxy_copy(pki, home / "configured-proxy")
    cfg = _config(
        home,
        proxy_path=str(configured),
        cert_path=str(pki.user_cert_path),
        key_path=str(pki.user_key_path),
    )
    found = discover(cfg, environ={"HOME": str(home)})
    assert found.cert == found.key == str(configured)


@pytest.mark.parametrize("where", ["env", "config"])
def test_named_proxy_missing(home: Path, where: str) -> None:
    missing = str(home / "no-such-proxy")
    env = {"HOME": str(home), "X509_USER_PROXY": missing} if where == "env" else {}
    cfg = _config(home, proxy_path=missing) if where == "config" else None
    with pytest.raises(CredentialError, match="does not exist") as caught:
        discover(cfg, environ=env)
    assert caught.value.code == errno.ENOENT


def test_blank_proxy_variable_is_unset(pki: PKI, home: Path) -> None:
    _pair(home / ".arc", pki)
    found = discover(environ={"HOME": str(home), "X509_USER_PROXY": "  "})
    assert found.cert == str(home / ".arc" / "usercert.pem")


def test_default_proxy_before_tmpdir(
    pki: PKI, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = _proxy_copy(pki, home / PROXY_NAME)
    tmpdir = tmp_path / "tmpdir"
    tmpdir.mkdir()
    _proxy_copy(pki, tmpdir / PROXY_NAME)
    monkeypatch.setattr(creds, "default_proxy_path", lambda environ=None: default)
    found = discover(environ={"HOME": str(home), "TMPDIR": str(tmpdir)})
    assert found.cert == str(default)


def test_tmpdir_proxy_before_certificate(pki: PKI, home: Path, tmp_path: Path) -> None:
    proxy = _proxy_copy(pki, tmp_path / PROXY_NAME)
    _pair(home / ".arc", pki)
    env = {
        "HOME": str(home),
        "TMPDIR": str(tmp_path),
        "X509_USER_CERT": str(pki.user_cert_path),
        "X509_USER_KEY": str(pki.user_key_path),
    }
    found = discover(environ=env)
    assert found.cert == found.key == str(proxy)


def test_env_certificate_before_config(pki: PKI, home: Path) -> None:
    arc = _pair(home / ".arc", pki)
    env = {
        "HOME": str(home),
        "X509_USER_CERT": str(pki.user_cert_path),
        "X509_USER_KEY": str(pki.user_key_path),
    }
    cfg = _config(home, cert_path=str(arc / "usercert.pem"), key_path=str(arc / "userkey.pem"))
    found = discover(cfg, environ=env)
    assert (found.cert, found.key) == (str(pki.user_cert_path), str(pki.user_key_path))
    assert not found.is_proxy


def test_config_certificate(pki: PKI, home: Path) -> None:
    cfg = _config(home, cert_path=str(pki.user_cert_path), key_path=str(pki.user_key_path))
    found = discover(cfg, environ={"HOME": str(home)})
    assert (found.cert, found.key) == (str(pki.user_cert_path), str(pki.user_key_path))


def test_cert_without_key_falls_through(pki: PKI, home: Path) -> None:
    arc = _pair(home / ".arc", pki)
    found = discover(environ={"HOME": str(home), "X509_USER_CERT": str(pki.user_cert_path)})
    assert found.cert == str(arc / "usercert.pem")


def test_arc_directory_before_globus(pki: PKI, home: Path) -> None:
    arc = _pair(home / ".arc", pki)
    _pair(home / ".globus", pki)
    found = discover(environ={"HOME": str(home)})
    assert (found.cert, found.key) == (str(arc / "usercert.pem"), str(arc / "userkey.pem"))


def test_globus_when_arc_incomplete(pki: PKI, home: Path) -> None:
    _pair(home / ".arc", pki, key=False)
    globus = _pair(home / ".globus", pki)
    found = discover(environ={"HOME": str(home)})
    assert (found.cert, found.key) == (str(globus / "usercert.pem"), str(globus / "userkey.pem"))


def test_nothing_found(home: Path) -> None:
    found = discover(environ={"HOME": str(home)})
    assert found.cert is found.key is found.token is None
    assert not found.uses_x509 and not found.uses_token
    assert found.headers() == {}


def test_explicit_cert_and_key(pki: PKI, home: Path) -> None:
    env = {"HOME": str(home), "X509_USER_PROXY": str(home / "missing")}
    found = discover(environ=env, cert=str(pki.user_cert_path), key=str(pki.user_key_path))
    assert (found.cert, found.key) == (str(pki.user_cert_path), str(pki.user_key_path))
    alone = discover(environ=env, cert=str(pki.proxy_path))
    assert alone.cert == alone.key == str(pki.proxy_path)


def test_reads_process_environment(grid_env: PKI) -> None:
    found = discover()
    assert found.cert == str(grid_env.proxy_path)
    assert found.ca_dir == str(grid_env.ca_dir)


# -- authentication modes and tokens -------------------------------------------------------


def test_auto_uses_both(grid_env: PKI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEARER_TOKEN", " tok ")
    found = discover()
    assert found.token == "tok"
    assert found.uses_token and found.uses_x509
    assert found.headers() == {"Authorization": "Bearer tok"}
    assert found.auth is Auth.AUTO


def test_x509_ignores_token(grid_env: PKI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEARER_TOKEN", "tok")
    found = discover(auth=Auth.X509, token="explicit")
    assert found.token is None
    assert found.uses_x509 and not found.uses_token
    assert found.headers() == {}


def test_x509_requires_certificate(home: Path) -> None:
    with pytest.raises(CredentialError, match=r"No X\.509 proxy") as caught:
        discover(environ={"HOME": str(home), "BEARER_TOKEN": "tok"}, auth=Auth.X509)
    assert caught.value.code == errno.EACCES


def test_token_requires_token(grid_env: PKI) -> None:
    with pytest.raises(CredentialError, match="No bearer token"):
        discover(auth=Auth.TOKEN)


def test_token_mode_keeps_x509_for_delegation(grid_env: PKI) -> None:
    found = discover(auth=Auth.TOKEN, token="explicit")
    assert found.cert == str(grid_env.proxy_path)
    assert found.uses_token and not found.uses_x509
    assert found.headers() == {"Authorization": "Bearer explicit"}


def test_token_mode_without_x509(home: Path) -> None:
    found = discover(environ={"HOME": str(home), "BEARER_TOKEN": "tok"}, auth=Auth.TOKEN)
    assert found.cert is None and found.token == "tok"


def test_none_presents_nothing(grid_env: PKI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEARER_TOKEN", "tok")
    monkeypatch.setenv("X509_USER_PROXY", "/no/such/proxy")
    found = discover(auth=Auth.NONE, verify=False)
    assert found.cert is found.key is found.token is None
    assert found.ca_dir == str(grid_env.ca_dir)
    assert not found.verify and found.auth is Auth.NONE
    assert discover(auth=Auth.NONE, ca_dir="/explicit").ca_dir == "/explicit"


def test_token_file(home: Path, tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("from-file\n")
    found = discover(environ={"HOME": str(home), "BEARER_TOKEN_FILE": str(token)})
    assert found.token == "from-file"


def test_token_in_runtime_dir(home: Path, tmp_path: Path) -> None:
    (tmp_path / f"bt_u{UNUSED_UID}").write_text("runtime\n")
    found = discover(environ={"HOME": str(home), "XDG_RUNTIME_DIR": str(tmp_path)})
    assert found.token == "runtime"


def test_token_variable_before_file(home: Path, tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("from-file")
    env = {"HOME": str(home), "BEARER_TOKEN": "inline", "BEARER_TOKEN_FILE": str(token)}
    assert discover(environ=env).token == "inline"


# -- trust anchors -------------------------------------------------------------------------


def test_ca_dir_env_first(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (home / ".arc" / "certificates").mkdir(parents=True)
    env = {"HOME": str(home), "X509_CERT_DIR": "/from/env"}
    assert discover(_config(home, ca_dir="/from/config"), environ=env).ca_dir == "/from/env"


def test_ca_dir_config(home: Path) -> None:
    (home / ".arc" / "certificates").mkdir(parents=True)
    cfg = _config(home, ca_dir="/from/config")
    assert discover(cfg, environ={"HOME": str(home)}).ca_dir == "/from/config"


def test_ca_dir_arc_then_globus(home: Path) -> None:
    globus = home / ".globus" / "certificates"
    globus.mkdir(parents=True)
    assert discover(environ={"HOME": str(home)}).ca_dir == str(globus)
    arc = home / ".arc" / "certificates"
    arc.mkdir(parents=True)
    assert discover(environ={"HOME": str(home)}).ca_dir == str(arc)


def test_ca_dir_fallback(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert discover(environ={"HOME": str(home)}).ca_dir is None
    monkeypatch.setattr(creds._gfal, "find_ca_path", lambda environ=None: "/etc/grid-security")
    assert discover(environ={"HOME": str(home)}).ca_dir == "/etc/grid-security"


def test_explicit_ca_dir_wins(grid_env: PKI) -> None:
    assert discover(ca_dir="/explicit").ca_dir == "/explicit"


# -- key permissions -----------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_group_readable_key_warns(pki: PKI, home: Path, caplog: pytest.LogCaptureFixture) -> None:
    arc = _pair(home / ".arc", pki)
    (arc / "userkey.pem").chmod(0o640)
    with caplog.at_level(logging.WARNING, logger="xrdarc"):
        discover(environ={"HOME": str(home)})
    assert "readable by other users" in caplog.text
    assert str(arc / "userkey.pem") in caplog.text


def test_private_key_does_not_warn(pki: PKI, home: Path, caplog: pytest.LogCaptureFixture) -> None:
    _pair(home / ".arc", pki)
    with caplog.at_level(logging.WARNING, logger="xrdarc"):
        discover(environ={"HOME": str(home)})
    assert caplog.text == ""


def test_permission_check_skipped_on_windows(
    pki: PKI, home: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    arc = _pair(home / ".arc", pki)
    (arc / "userkey.pem").chmod(0o644)
    monkeypatch.setattr(sys, "platform", "win32")
    with caplog.at_level(logging.WARNING, logger="xrdarc"):
        found = discover(environ={"HOME": str(home)})
    assert caplog.text == ""
    assert found.key == str(arc / "userkey.pem")


def test_missing_explicit_key_does_not_crash(home: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="xrdarc"):
        found = discover(environ={"HOME": str(home)}, cert="/no/cert", key="/no/key")
    assert found.key == "/no/key"
    assert caplog.text == ""


# -- default proxy locations ---------------------------------------------------------------


def test_default_proxy_path_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert creds.default_proxy_path({}) == Path("/tmp") / PROXY_NAME
    assert creds.default_proxy_path() == Path("/tmp") / PROXY_NAME
    named = {"X509_USER_PROXY": " /some/proxy "}
    assert creds.default_proxy_path(named) == Path("/some/proxy")


def test_default_proxy_path_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert creds.default_proxy_path({}) == Path(tempfile.gettempdir()) / PROXY_NAME


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX uid")
def test_uid_is_effective_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(creds, "_uid", _REAL_UID)
    assert creds._uid() == str(os.geteuid())


def test_uid_is_login_without_geteuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(creds, "_uid", _REAL_UID)
    monkeypatch.delattr(os, "geteuid", raising=False)
    monkeypatch.setattr(creds.getpass, "getuser", lambda: "alice")
    monkeypatch.setattr(sys, "platform", "win32")
    assert creds.default_proxy_path({}) == Path(tempfile.gettempdir()) / "x509up_ualice"
    assert creds.proxy_candidates({}) == [Path(tempfile.gettempdir()) / "x509up_ualice"]


def test_proxy_candidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    default = Path("/tmp") / PROXY_NAME
    assert creds.proxy_candidates({}) == [default]
    assert creds.proxy_candidates({"TMPDIR": "  "}) == [default]
    assert creds.proxy_candidates({"TMPDIR": "/tmp"}) == [default]
    assert creds.proxy_candidates({"TMPDIR": str(tmp_path)}) == [default, tmp_path / PROXY_NAME]
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert creds.proxy_candidates() == [default, tmp_path / PROXY_NAME]


def test_candidates_ignore_named_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert creds.proxy_candidates({"X509_USER_PROXY": "/named"}) == [Path("/tmp") / PROXY_NAME]


# -- Credentials ---------------------------------------------------------------------------


def test_credentials_properties() -> None:
    proxy = Credentials(cert="/p", key="/p", token="t")
    assert proxy.is_proxy and proxy.uses_x509 and proxy.uses_token
    pair = Credentials(cert="/c", key="/k", auth=Auth.X509, token="t")
    assert not pair.is_proxy and pair.uses_x509 and not pair.uses_token
    token_only = Credentials(cert="/c", key="/c", token="t", auth=Auth.TOKEN)
    assert not token_only.uses_x509 and token_only.uses_token
    nothing = Credentials(cert="/c", key="/c", token="t", auth=Auth.NONE)
    assert not nothing.uses_x509 and not nothing.uses_token
    assert not Credentials().is_proxy


def test_with_token() -> None:
    original = Credentials(cert="/p", key="/p", token="old", ca_dir="/ca")
    changed = original.with_token("new")
    assert changed.token == "new" and original.token == "old"
    assert changed.cert == "/p" and changed.ca_dir == "/ca"
    assert original.with_token(None).headers() == {}


def test_ssl_context_loads_proxy(pki: PKI) -> None:
    found = Credentials(cert=str(pki.proxy_path), key=str(pki.proxy_path), ca_dir=str(pki.ca_dir))
    context = found.ssl_context()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert found.ssl_context() is context


def test_ssl_context_without_certificate(pki: PKI) -> None:
    context = Credentials(ca_file=str(pki.ca_file), verify=False).ssl_context()
    assert context.verify_mode == ssl.CERT_NONE


def test_ssl_context_token_mode_skips_certificate(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    found = Credentials(cert=str(bad), key=str(bad), token="t", auth=Auth.TOKEN)
    assert isinstance(found.ssl_context(), ssl.SSLContext)


def test_ssl_context_bad_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    with pytest.raises(CredentialError, match="Could not load") as caught:
        Credentials(cert=str(bad), key=str(bad)).ssl_context()
    assert caught.value.code == errno.EACCES


def test_ssl_context_missing_file(tmp_path: Path) -> None:
    missing = str(tmp_path / "missing.pem")
    with pytest.raises(CredentialError) as caught:
        Credentials(cert=missing, key=missing).ssl_context()
    assert caught.value.code == errno.ENOENT
