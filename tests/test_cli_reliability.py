"""The command line's 0.4.0 fixes: the exit-code table, token options, and safe ``sub``."""

from __future__ import annotations

import errno
import io
import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from xrdcore import retry
from xrdsec.testing.pki import PKI

from _arex import USER_DN
from _client_helpers import XRSL, dead_ce, job_of, messages, run
from xrdarc import cli
from xrdarc.cli import _common
from xrdarc.cli._common import ExitCode, UsageError, exit_code_for
from xrdarc.client import ARCClient
from xrdarc.errors import (
    ARCError,
    CredentialError,
    DescriptionError,
    HTTPError,
    JobNotFoundError,
    NotAllowedError,
)
from xrdarc.joblist import JobList
from xrdarc.rest import RESTClient
from xrdarc.testing.arex import FakeARex

pytest_plugins = ["_arex", "_cli_fixtures"]
pytestmark = pytest.mark.usefixtures("restore_logging")

Run = Callable[..., tuple[int, str, str]]
RunJSON = Callable[..., tuple[int, dict[str, Any]]]


def _jobs(ce: FakeARex) -> list[str]:
    return [f"{ce.url}/rest/1.0/jobs/{job_id}" for job_id in ce.jobs]


# ---------------------------------------------------------------------------
# The exit-code table
# ---------------------------------------------------------------------------


def test_the_table_is_fixed() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "FAILED": 1,
        "USAGE": 2,
        "CREDENTIALS": 3,
        "DESCRIPTION": 4,
        "CE": 5,
        "LOCAL": 6,
        "TIMEOUT": 7,
        "INTERNAL": 70,
        "INTERRUPTED": 130,
        "BROKEN_PIPE": 141,
    }


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (UsageError("no jobs"), ExitCode.USAGE),
        (CredentialError("no proxy"), ExitCode.CREDENTIALS),
        (NotAllowedError(403, "Forbidden", url="https://ce"), ExitCode.CREDENTIALS),
        (DescriptionError("bad"), ExitCode.DESCRIPTION),
        (JobNotFoundError("which?"), ExitCode.FAILED),
        (HTTPError(500, "Oops", url="https://ce"), ExitCode.CE),
        (ARCError("Connection failed", errno.ECONNABORTED, url="https://ce"), ExitCode.CE),
        (ARCError("job list", errno.EACCES), ExitCode.LOCAL),
        (ARCError("2 jobs still not finished", errno.ETIMEDOUT), ExitCode.TIMEOUT),
        (PermissionError(errno.EACCES, "Permission denied"), ExitCode.LOCAL),
        (RuntimeError("bug"), ExitCode.INTERNAL),
    ],
)
def test_errors_map_to_the_table(exc: BaseException, code: ExitCode) -> None:
    assert exit_code_for(exc) == code


def test_usage_errors_exit_2(xrdarc: Run) -> None:
    code, out, err = xrdarc("stat")
    assert (code, out) == (2, "")
    assert err == "xrdarc stat: No jobs given; name jobs, or use -a for all of them\n"
    assert xrdarc("sub", "-C", "ce.example")[0] == 2
    assert xrdarc("sub", "-e", XRSL)[0] == 2
    assert xrdarc("info")[0] == 2
    assert xrdarc("sync")[0] == 2


def test_a_job_not_in_the_list_exits_1(xrdarc_json: RunJSON) -> None:
    code, doc = xrdarc_json("stat", "nosuch")
    assert code == 1
    [error] = [r for r in doc["records"] if r["kind"] == "error"]
    assert error["error_type"] == "JobNotFoundError"


def test_a_ce_error_exits_5(xrdarc: Run) -> None:
    code, _, err = xrdarc("sub", "-C", dead_ce(), "-e", XRSL, "--no-delegation")
    assert code == 5
    assert "Connection failed" in err


def test_a_description_error_exits_4(xrdarc: Run, ce: FakeARex) -> None:
    code, _, err = xrdarc("sub", "-C", ce.url, "-e", '&(executable="missing.sh")')
    assert code == 4
    assert "missing.sh" in err


def test_a_wait_timeout_exits_7(xrdarc: Run, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    code, _, err = xrdarc("wait", url, "--interval", "0", "--max-wait", "0")
    assert code == 7
    assert "1 jobs still not finished" in err


class _Floor:
    """A jitter source that always answers the bottom of the window: no extra wait."""

    def uniform(self, a: float, b: float) -> float:
        return a


@pytest.fixture
def no_backoff() -> Iterator[None]:
    """Every jittered pause - the transport's and ``wait``'s - drawn as zero: no sleeping."""
    previous = retry.use_rng(_Floor())
    yield
    retry.use_rng(previous)


@pytest.mark.usefixtures("no_backoff")
def test_wait_says_when_it_will_ask_again(xrdarc: Run, ce: FakeARex) -> None:
    _, url = job_of(ce, state="FINISHED", exit_code=0)
    # One whole poll fails (the first try and the session's three retries), quickly.
    ce.fault("POST", r"action=info", status=503, times=4)
    code, out, _ = xrdarc("wait", url, "--interval", "0")
    assert code == 0
    first, second = out.splitlines()
    assert first.startswith(f"{url}: not answering (HTTP 503")
    assert first.endswith("; will ask again")
    assert second == f"{url}: Finished"


def test_a_missing_description_file_exits_6(xrdarc: Run, tmp_path: Path) -> None:
    code, _, err = xrdarc("sub", "-C", "ce.example", str(tmp_path / "missing.xrsl"))
    assert code == 6
    assert "Cannot read" in err


def test_a_broken_pipe_is_quiet(xrdarc: Run, ce: FakeARex, monkeypatch: pytest.MonkeyPatch) -> None:
    _, url = job_of(ce, files={"out.txt": b"x"})

    def closed(*args: object) -> int:
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    monkeypatch.setattr(ARCClient, "cat", closed)
    code, out, err = xrdarc("cat", url)
    assert (code, out, err) == (141, "", "")


def test_a_plain_os_error_is_one_line(xrdarc: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(self: ARCClient, *args: object, **kwargs: object) -> None:
        raise PermissionError(errno.EACCES, "Permission denied", "/some/file")

    monkeypatch.setattr(ARCClient, "status", denied)
    code, _, err = xrdarc("stat", "https://ce.example/arex/rest/1.0/jobs/1")
    assert code == 6
    assert err == "xrdarc stat: Permission denied: /some/file\n"
    monkeypatch.setattr(
        ARCClient, "status", lambda self, jobs: (_ for _ in ()).throw(OSError("odd"))
    )
    code, _, err = xrdarc("stat", "https://ce.example/arex/rest/1.0/jobs/1")
    assert (code, err) == (6, "xrdarc stat: odd\n")


def test_an_unexpected_error_exits_70_without_a_traceback(
    xrdarc: Run, xrdarc_json: RunJSON, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bug(self: ARCClient, *args: object, **kwargs: object) -> None:
        raise RuntimeError("something broke")

    monkeypatch.setattr(ARCClient, "status", bug)
    code, _, err = xrdarc("stat", "https://ce.example/arex/rest/1.0/jobs/1")
    assert code == 70
    assert err.startswith("xrdarc stat: internal error: RuntimeError: something broke")
    assert "Traceback" not in err
    code, doc = xrdarc_json("stat", "https://ce.example/arex/rest/1.0/jobs/1")
    assert code == 70
    assert [r["error_type"] for r in doc["records"] if r["kind"] == "error"] == ["RuntimeError"]


# ---------------------------------------------------------------------------
# Token options
# ---------------------------------------------------------------------------


def _token_of(tmp_path: Path, *argv: str) -> str | None:
    parser, _ = cli.build_parser()
    command = _common.Command("info", parser.parse_args(["info", *argv]))
    try:
        return command.client().credentials.token
    finally:
        command.close()


@pytest.fixture
def fresh_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_common, "_WARNED", set())


@pytest.mark.usefixtures("fresh_warning")
def test_token_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "token"
    path.write_text("  file-token\n")
    with caplog.at_level(logging.WARNING, "xrdarc"):
        assert _token_of(tmp_path, "--token-file", str(path)) == "file-token"
    assert caplog.text == ""


@pytest.mark.parametrize(("content", "match"), [(None, "Cannot read"), ("\n", "is empty")])
def test_a_bad_token_file(tmp_path: Path, content: str | None, match: str) -> None:
    path = tmp_path / "token"
    if content is not None:
        path.write_text(content)
    with pytest.raises(CredentialError, match=match):
        _token_of(tmp_path, "--token-file", str(path))


def test_token_from_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("stdin-token\nignored\n"))
    assert _token_of(tmp_path, "--token", "-") == "stdin-token"
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(CredentialError, match="standard input"):
        _token_of(tmp_path, "--token", "-")


@pytest.mark.usefixtures("fresh_warning")
def test_a_literal_token_is_warned_about_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, "xrdarc"):
        assert _token_of(tmp_path, "--token", "literal") == "literal"
        assert _token_of(tmp_path, "--token", "literal") == "literal"
    assert caplog.text.count("--token-file") == 1
    assert "literal" not in caplog.text


def test_token_and_token_file_exclude_each_other(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["stat", "--token", "a", "--token-file", "b"])
    assert caught.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_token_file_authenticates(
    capsys: pytest.CaptureFixture[str], make_ce: Callable[..., FakeARex], pki: PKI, tmp_path: Path
) -> None:
    ce = make_ce(tokens={"tok": USER_DN}, tls=pki.server_context(require_client=False))
    path = tmp_path / "token"
    path.write_text("tok\n")
    argv = ["info", ce.url, "--ca-dir", str(pki.ca_dir), "--token-file", str(path)]
    code, out, _ = run(capsys, *argv, "--token-authentication")
    assert code == 0
    assert "fake-arex" in out


# ---------------------------------------------------------------------------
# sub: IDs as jobs are submitted, all-or-nothing preparation, one delegation
# ---------------------------------------------------------------------------


def test_sub_reports_jobs_before_a_later_failure(
    xrdarc: Run, ce: FakeARex, tmp_path: Path, jobs_dat: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = RESTClient.submit
    calls: list[int] = []

    def second_fails(self: RESTClient, *args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 2:
            raise ARCError("Connection failed", errno.ECONNABORTED, url=self.ce)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(RESTClient, "submit", second_fails)
    ids = tmp_path / "ids"
    code, out, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, "-e", XRSL, "-o", str(ids))
    assert code == 5
    [url] = _jobs(ce)
    assert out == f"Job submitted with jobid: {url}\n"
    assert ids.read_text() == f"{url}\n"
    assert [j.url for j in JobList(jobs_dat)] == [url]
    assert "Connection failed" in err


def test_sub_fails_before_submitting_when_the_ids_file_cannot_be_opened(
    xrdarc: Run, ce: FakeARex, tmp_path: Path
) -> None:
    code, _, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, "-o", str(tmp_path / "no" / "ids"))
    assert code == 6
    assert "Cannot open" in err
    assert ce.requests == []


def test_sub_prepares_every_description_first(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    bad = tmp_path / "bad.xrsl"
    bad.write_text('&(executable="missing.sh")')
    code, out, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, str(bad))
    assert code == 4
    assert out == ""
    assert "missing.sh" in err
    assert ce.requests == []


def test_sub_delegates_once(xrdarc: Run, ce: FakeARex) -> None:
    code, _, _ = xrdarc("sub", "-C", ce.url, "-e", XRSL, "-e", XRSL)
    assert code == 0
    assert len(ce.jobs) == 2
    assert len(ce.delegations) == 1


def test_sub_min_lifetime(xrdarc: Run, ce: FakeARex) -> None:
    code, _, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, "--min-lifetime", "100d")
    assert code == 3
    assert "required" in err
    assert ce.requests == []
    code, _, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, "--min-lifetime", "soon")
    assert code == 2
    assert "--min-lifetime" in err


def test_sub_json_records_survive_a_fatal_error(
    xrdarc_json: RunJSON, ce: FakeARex, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = RESTClient.submit
    calls: list[int] = []

    def second_fails(self: RESTClient, *args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 2:
            raise ARCError("Connection failed", errno.ECONNABORTED, url=self.ce)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(RESTClient, "submit", second_fails)
    code, doc = xrdarc_json("sub", "-C", ce.url, "-e", XRSL, "-e", XRSL)
    assert code == 5
    [record] = [r for r in doc["records"] if r["kind"] == "result"]
    assert record["ok"] is True
    assert "Job submitted with jobid" in messages(doc)
