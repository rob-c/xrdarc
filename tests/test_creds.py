"""Credential discovery in ARC's order, token discovery, trust anchors, TLS contexts.

The searches are xrdsec's (its suite covers each step); these tests pin what
xrdarc adds: ``client.conf`` values fed in after the environment, ARC's
``$X509_CERT_POLICY``, the auth modes, and every failure arriving as an
xrdarc ``CredentialError`` with an errno.
"""

from __future__ import annotations

import errno
import os
import shutil
import ssl
import sys
from pathlib import Path
from typing import Any

import pytest
import xrdcore.errors
from xrdsec.testing.pki import PKI

from conftest import PROXY_NAME, TOKEN_NAME
from xrdarc import creds
from xrdarc.config import UserConfig
from xrdarc.creds import Auth, Credentials, discover
from xrdarc.errors import CredentialError

posix_only = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="POSIX modes, as a non-root user"
)


def _config(home: Path, **paths: Any) -> UserConfig:
    return UserConfig(joblist=home / ".arc" / "jobs.dat", **paths)


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


def test_default_proxy_before_tmpdir(pki: PKI, home: Path, tmp_path: Path, tmp_dir: Path) -> None:
    default = _proxy_copy(pki, tmp_dir / PROXY_NAME)
    tmpdir = tmp_path / "tmpdir"
    tmpdir.mkdir()
    _proxy_copy(pki, tmpdir / PROXY_NAME)
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
    token.chmod(0o600)
    found = discover(environ={"HOME": str(home), "BEARER_TOKEN_FILE": str(token)})
    assert found.token == "from-file"


def test_token_in_runtime_dir(home: Path, tmp_path: Path) -> None:
    token = tmp_path / TOKEN_NAME
    token.write_text("runtime\n")
    token.chmod(0o600)
    found = discover(environ={"HOME": str(home), "XDG_RUNTIME_DIR": str(tmp_path)})
    assert found.token == "runtime"


def test_token_variable_before_file(home: Path, tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("from-file")
    env = {"HOME": str(home), "BEARER_TOKEN": "inline", "BEARER_TOKEN_FILE": str(token)}
    assert discover(environ=env).token == "inline"


@posix_only
def test_token_file_others_can_read_is_a_credential_error(home: Path, tmp_path: Path) -> None:
    """A token file somebody else could read is refused - as xrdarc's error, not the library's."""
    token = tmp_path / "token"
    token.write_text("shared")
    token.chmod(0o644)
    with pytest.raises(CredentialError, match="Cannot use the bearer token") as caught:
        discover(environ={"HOME": str(home), "BEARER_TOKEN_FILE": str(token)})
    assert isinstance(caught.value, xrdcore.errors.CredentialError)
    assert caught.value.code == errno.EACCES


@posix_only
def test_unreadable_token_file_is_skipped_unless_a_token_is_required(
    home: Path, tmp_path: Path
) -> None:
    """A token file we may not read is "no token" in AUTO mode, an error in TOKEN mode."""
    token = tmp_path / "token"
    token.write_text("secret")
    token.chmod(0o000)
    env = {"HOME": str(home), "BEARER_TOKEN_FILE": str(token)}
    assert discover(environ=env).token is None
    with pytest.raises(CredentialError, match="Cannot use the bearer token"):
        discover(environ=env, auth=Auth.TOKEN)


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


def test_ca_dir_fallback_is_the_system_store(home: Path) -> None:
    assert discover(environ={"HOME": str(home)}).ca_dir is None


def test_ca_dir_grid_wide_comes_after_the_per_user_ones(home: Path, grid_security: Path) -> None:
    """``grid-security/certificates`` is the last place ARC looks before the system store."""
    grid = grid_security / "certificates"
    grid.mkdir(parents=True)
    assert discover(environ={"HOME": str(home)}).ca_dir == str(grid)
    (home / ".globus" / "certificates").mkdir(parents=True)
    assert discover(environ={"HOME": str(home)}).ca_dir == str(home / ".globus" / "certificates")


def test_blank_ca_dir_variable_is_unset(home: Path) -> None:
    """``X509_CERT_DIR=`` is "not configured", never a CA path of ``""`` that trusts nothing."""
    cfg = _config(home, ca_dir="/from/config")
    assert discover(cfg, environ={"HOME": str(home), "X509_CERT_DIR": "  "}).ca_dir == (
        "/from/config"
    )


@pytest.mark.parametrize(
    ("policy", "ca_dir", "system_ca"),
    [
        ("", "/grid", False),
        ("grid", "/grid", False),
        ("any", "/grid", True),
        ("any.nofile", "/grid", True),
        ("system", None, False),
        ("system.onlyfile", None, False),
    ],
)
def test_cert_policy(home: Path, policy: str, ca_dir: str | None, system_ca: bool) -> None:
    """ARC's ``X509_CERT_POLICY``: the grid directory alone, with the system store, or neither."""
    env = {"HOME": str(home), "X509_CERT_DIR": "/grid", "X509_CERT_POLICY": policy}
    found = discover(environ=env)
    assert (found.ca_dir, found.system_ca) == (ca_dir, system_ca)
    assert discover(environ=env, auth=Auth.NONE).system_ca is system_ca


def test_explicit_ca_dir_wins(grid_env: PKI) -> None:
    assert discover(ca_dir="/explicit").ca_dir == "/explicit"


# -- default proxy locations ---------------------------------------------------------------


def test_default_proxy_path(tmp_dir: Path) -> None:
    assert creds.default_proxy_path({}) == tmp_dir / PROXY_NAME
    assert creds.default_proxy_path() == tmp_dir / PROXY_NAME
    assert creds.default_proxy_path({}, uid=42) == tmp_dir / "x509up_u42"
    named = {"X509_USER_PROXY": " /some/proxy "}
    assert creds.default_proxy_path(named) == Path("/some/proxy")


def test_proxy_candidates(tmp_path: Path, tmp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    default = tmp_dir / PROXY_NAME
    assert creds.proxy_candidates({}) == [default]
    assert creds.proxy_candidates({"TMPDIR": "  "}) == [default]
    assert creds.proxy_candidates({"TMPDIR": str(tmp_dir)}) == [default]
    assert creds.proxy_candidates({"TMPDIR": str(tmp_path)}) == [default, tmp_path / PROXY_NAME]
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert creds.proxy_candidates() == [default, tmp_path / PROXY_NAME]


def test_candidates_ignore_named_proxy(tmp_dir: Path) -> None:
    assert creds.proxy_candidates({"X509_USER_PROXY": "/named"}) == [tmp_dir / PROXY_NAME]


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
    bad.chmod(0o600)
    with pytest.raises(CredentialError, match=r"Cannot use the X\.509 credential") as caught:
        Credentials(cert=str(bad), key=str(bad)).ssl_context()
    assert caught.value.code == errno.EACCES


def test_ssl_context_missing_file(tmp_path: Path) -> None:
    missing = str(tmp_path / "missing.pem")
    with pytest.raises(CredentialError) as caught:
        Credentials(cert=missing, key=missing).ssl_context()
    assert caught.value.code == errno.ENOENT


@posix_only
def test_ssl_context_refuses_a_key_others_can_read(pki: PKI, tmp_path: Path) -> None:
    """A proxy or key readable by others is not presented (ARC refuses it as well)."""
    shared = _proxy_copy(pki, tmp_path / "shared-proxy")
    shared.chmod(0o644)
    with pytest.raises(CredentialError, match=r"Cannot use the X\.509 credential") as caught:
        Credentials(cert=str(shared), key=str(shared)).ssl_context()
    assert caught.value.code == errno.EACCES


def test_ssl_context_with_a_certificate_and_separate_key(pki: PKI) -> None:
    pair = Credentials(cert=str(pki.user_cert_path), key=str(pki.user_key_path))
    assert isinstance(pair.ssl_context(), ssl.SSLContext)


def test_ssl_context_is_rebuilt_when_the_proxy_is_renewed(pki: PKI, tmp_path: Path) -> None:
    """xrdsec's cache is keyed on the files' ``stat``: a renewed proxy gets a fresh context."""
    proxy = _proxy_copy(pki, tmp_path / "renewed")
    found = Credentials(cert=str(proxy), key=str(proxy), ca_dir=str(pki.ca_dir))
    first = found.ssl_context()
    os.utime(proxy, (1_000_000_000, 1_000_000_000))
    assert found.ssl_context() is not first


def test_ssl_context_with_the_system_store_too(
    pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The "system store" is whatever OpenSSL's ``SSL_CERT_FILE`` names: here, one CA.

    A CA directory is read lazily, so only the system store's CA is counted.
    """
    monkeypatch.setenv("SSL_CERT_FILE", str(pki.ca_file))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    grid_only = Credentials(ca_dir=str(pki.ca_dir)).ssl_context()
    assert grid_only.cert_store_stats()["x509_ca"] == 0
    context = Credentials(ca_dir=str(pki.ca_dir), system_ca=True).ssl_context()
    assert context.cert_store_stats()["x509_ca"] >= 1
