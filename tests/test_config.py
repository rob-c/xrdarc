"""client.conf: ARC's IniConfig grammar, the settings a REST client acts on, and services."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from xrdarc import config
from xrdarc.config import DEFAULT_TIMEOUT, Service, UserConfig, arc_dir, load_config, parse_ini
from xrdarc.errors import ARCError


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# -- arc_dir --------------------------------------------------------------------


def test_arc_dir_from_home() -> None:
    assert arc_dir({"HOME": "/h", "USERPROFILE": "/u"}) == Path("/h/.arc")


def test_arc_dir_from_userprofile() -> None:
    assert arc_dir({"HOME": "", "USERPROFILE": "/u"}) == Path("/u/.arc")


def test_arc_dir_falls_back_to_expanduser(home: Path) -> None:
    assert arc_dir({}) == home / ".arc"


def test_arc_dir_reads_the_process_environment(home: Path) -> None:
    assert arc_dir() == home / ".arc"


# -- parse_ini ------------------------------------------------------------------


def test_parse_ini_grammar() -> None:
    text = """
# a comment
   # an indented comment
joblist = /tmp/jobs.dat
loose line without equals
[ common ]
timeout=5
proxypath = "/quoted/path"
[computing/ce1]
url = https://ce1 = still the value
group = a b
group = c
key =
"""
    assert parse_ini(text) == {
        "common": {
            "joblist": ["/tmp/jobs.dat"],
            "timeout": ["5"],
            "proxypath": ['"/quoted/path"'],
        },
        "computing/ce1": {
            "url": ["https://ce1 = still the value"],
            "group": ["a b", "c"],
            "key": [""],
        },
    }


def test_parse_ini_empty_has_common() -> None:
    assert parse_ini("") == {"common": {}}


def test_parse_ini_comment_must_start_the_line() -> None:
    assert parse_ini("a = b # not a comment") == {"common": {"a": ["b # not a comment"]}}


def test_parse_ini_repeated_section_accumulates() -> None:
    assert parse_ini("[s]\nk=1\n[t]\n[s]\nk=2\n")["s"] == {"k": ["1", "2"]}


# -- load_config: defaults and files --------------------------------------------


def test_defaults_without_any_file(home: Path) -> None:
    conf = load_config()
    assert conf == UserConfig(joblist=home / ".arc" / "jobs.dat")
    assert conf.timeout == DEFAULT_TIMEOUT == 20.0
    assert (conf.proxy_path, conf.cert_path, conf.key_path, conf.ca_dir) == (None,) * 4
    assert conf.services == {} and conf.common == {}


def test_user_file_settings(home: Path) -> None:
    _write(
        home / ".arc" / "client.conf",
        "joblist = ~/my/jobs.dat\nproxypath = ~/proxy\ncertificatepath = /c.pem\n"
        "keypath = /k.pem\ncacertificatesdirectory = /ca\ntimeout = 2.5\n"
        "jobdownloaddirectory = /dl\nverbosity = DEBUG\n",
    )
    conf = load_config()
    assert conf.joblist == home / "my" / "jobs.dat"
    assert conf.proxy_path == str(home / "proxy")
    assert (conf.cert_path, conf.key_path, conf.ca_dir) == ("/c.pem", "/k.pem", "/ca")
    assert conf.timeout == 2.5
    assert conf.download_dir == "/dl"
    assert conf.common["verbosity"] == ["DEBUG"]


def test_last_value_wins_and_empty_means_unset(home: Path) -> None:
    _write(home / ".arc" / "client.conf", "keypath = /a\nkeypath = /b\nproxypath =\n")
    conf = load_config()
    assert conf.key_path == "/b"
    assert conf.proxy_path is None


def test_environ_names_the_user_directory(tmp_path: Path) -> None:
    _write(tmp_path / ".arc" / "client.conf", "timeout = 7\n")
    conf = load_config(environ={"HOME": str(tmp_path)})
    assert conf.timeout == 7.0
    assert conf.joblist == tmp_path / ".arc" / "jobs.dat"


def test_user_file_overrides_system_file_key_by_key(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = _write(home / "system.conf", "timeout = 9\nkeypath = /sys/key\n[computing/a]\nurl=x\n")
    monkeypatch.setattr(config, "SYSTEM_CONFIG", system)
    _write(home / ".arc" / "client.conf", "timeout = 3\n[computing/b]\nurl = y\n")
    conf = load_config()
    assert conf.timeout == 3.0
    assert conf.key_path == "/sys/key"
    assert set(conf.services) == {"a", "b"}


def test_explicit_file_replaces_both_defaults(home: Path, tmp_path: Path) -> None:
    _write(home / ".arc" / "client.conf", "timeout = 3\nkeypath = /user\n")
    explicit = _write(tmp_path / "other.conf", "timeout = 4\n")
    conf = load_config(explicit)
    assert conf.timeout == 4.0
    assert conf.key_path is None


def test_explicit_file_missing_is_enoent(tmp_path: Path) -> None:
    missing = tmp_path / "nope.conf"
    with pytest.raises(ARCError) as caught:
        load_config(str(missing))
    assert caught.value.errno == errno.ENOENT
    assert str(caught.value) == f"Configuration file {missing} does not exist"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads anything")
def test_explicit_file_unreadable_is_eacces(tmp_path: Path) -> None:
    locked = _write(tmp_path / "locked.conf", "timeout = 1\n")
    locked.chmod(0)
    try:
        with pytest.raises(ARCError) as caught:
            load_config(locked)
    finally:
        locked.chmod(0o600)
    assert caught.value.errno == errno.EACCES
    assert str(caught.value) == f"Cannot read configuration file {locked}: Permission denied"


def test_unreadable_default_file_is_an_error_too(home: Path) -> None:
    (home / ".arc" / "client.conf").mkdir(parents=True)
    with pytest.raises(ARCError) as caught:
        load_config()
    assert caught.value.errno == errno.EISDIR
    assert str(caught.value).startswith(f"Cannot read configuration file {home}/.arc/client.conf")


def test_non_utf8_bytes_do_not_break_reading(tmp_path: Path) -> None:
    conf_file = tmp_path / "latin1.conf"
    conf_file.write_bytes(b"# caf\xe9\njobdownloaddirectory = /d\xe9\n")
    conf = load_config(conf_file)
    assert conf.download_dir is not None
    assert os.fsencode(conf.download_dir) == b"/d\xe9"


# -- timeout ----------------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "-1", "soon", "nan", "inf", "-inf"])
def test_bad_timeout(tmp_path: Path, value: str) -> None:
    conf_file = _write(tmp_path / "c.conf", f"timeout = {value}\n")
    with pytest.raises(ARCError) as caught:
        load_config(conf_file)
    assert caught.value.errno == errno.EIO
    assert str(caught.value) == (
        f"{conf_file}: timeout = {value} is not a positive number of seconds"
    )


def test_empty_timeout_is_the_default(tmp_path: Path) -> None:
    assert load_config(_write(tmp_path / "c.conf", "timeout =\n")).timeout == DEFAULT_TIMEOUT


# -- services -----------------------------------------------------------------------


SERVICES = """
[computing/main]
url = https://main.example.org
default = Yes
group = atlas  uk
[computing/backup]
url = https://backup.example.org:8443/arex
group = uk
group = spare
default = no
[computing/other]
url = other.example.org
default = 1
[computing/nourl]
default = yes
[computing]
url = https://noalias
[registry/index]
url = https://index
[computing/emptyurl]
url =
"""


def _services(tmp_path: Path) -> UserConfig:
    return load_config(_write(tmp_path / "s.conf", SERVICES))


def test_computing_blocks_become_services(tmp_path: Path) -> None:
    conf = _services(tmp_path)
    assert conf.services == {
        "main": Service("main", "https://main.example.org", True, ("atlas", "uk")),
        "backup": Service("backup", "https://backup.example.org:8443/arex", False, ("uk", "spare")),
        "other": Service("other", "other.example.org", True, ()),
    }


@pytest.mark.parametrize("flag", ["yes", "TRUE", "1"])
def test_default_flag_spellings(tmp_path: Path, flag: str) -> None:
    conf = load_config(_write(tmp_path / "d.conf", f"[computing/x]\nurl=u\ndefault={flag}\n"))
    assert conf.services["x"].default is True


def test_resolve_alias_group_or_name(tmp_path: Path) -> None:
    conf = _services(tmp_path)
    assert conf.resolve("main") == ["https://main.example.org"]
    assert conf.resolve("uk") == [
        "https://main.example.org",
        "https://backup.example.org:8443/arex",
    ]
    assert conf.resolve("spare") == ["https://backup.example.org:8443/arex"]
    assert conf.resolve("ce.elsewhere.org") == ["ce.elsewhere.org"]


def test_defaults_are_the_default_services(tmp_path: Path) -> None:
    assert _services(tmp_path).defaults() == ["https://main.example.org", "other.example.org"]
    assert UserConfig(joblist=Path("j")).defaults() == []
