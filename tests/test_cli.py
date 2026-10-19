"""The ``xrdarc`` program: dispatch, exit codes, shared options, and the job commands."""

from __future__ import annotations

import argparse
import getpass
import logging
import runpy
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from xrdhttp.session import UnverifiedTLSWarning
from xrdsec.testing.pki import PKI

from _arex import USER_DN
from _client_helpers import dead_ce, job_of, messages, results, run, run_json
from xrdarc import __version__, cli
from xrdarc.cli import _common, jobs
from xrdarc.client import ARCClient
from xrdarc.config import load_config
from xrdarc.creds import Auth, discover
from xrdarc.errors import CredentialError
from xrdarc.joblist import Job, JobList
from xrdarc.states import JobState
from xrdarc.testing.arex import FakeARex

pytest_plugins = ["_arex", "_cli_fixtures"]
pytestmark = pytest.mark.usefixtures("restore_logging")

Run = Callable[..., tuple[int, str, str]]
RunJSON = Callable[..., tuple[int, dict[str, Any]]]
Listed = Callable[..., list[Job]]


# ---------------------------------------------------------------------------
# Dispatch and exit codes
# ---------------------------------------------------------------------------


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys)
    assert code == 2
    assert "usage: xrdarc" in out
    assert "sub" in out


@pytest.mark.parametrize("argv", [["-V"], ["--version"], ["stat", "-V"]])
def test_version(capsys: pytest.CaptureFixture[str], argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)
    assert caught.value.code == 0
    assert capsys.readouterr().out == f"xrdarc {__version__}\n"


def test_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["stat", "--no-such-option"])
    assert caught.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_usage_error_as_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, doc = run_json(capsys, "stat", "--no-such-option")
    assert code == 2
    [error] = [r for r in doc["records"] if r["kind"] == "error"]
    assert "unrecognized arguments" in error["message"]


def test_python_dash_m(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["xrdarc"])
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("xrdarc.cli", run_name="__main__")
    assert caught.value.code == 2
    assert "usage: xrdarc" in capsys.readouterr().out


def test_fatal_error_exits_with_its_table_code(xrdarc: Run) -> None:
    code, out, err = xrdarc("stat")
    assert code == 2
    assert out == ""
    assert err == "xrdarc stat: No jobs given; name jobs, or use -a for all of them\n"


def test_fatal_error_as_json(xrdarc_json: RunJSON) -> None:
    code, doc = xrdarc_json("stat", "nosuch")
    assert code == 1
    [error] = [r for r in doc["records"] if r["kind"] == "error"]
    assert error["error_type"] == "JobNotFoundError"
    assert error["operation"] == "stat"
    assert "not in the job list" in messages(doc, "stderr")


def test_interrupt_exits_130(xrdarc: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(ARCClient, "status", interrupted)
    code, _, err = xrdarc("stat", "https://ce.example/arex/rest/1.0/jobs/1")
    assert code == 130
    assert err == "xrdarc stat: interrupted\n"


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------


def _parse(*argv: str) -> argparse.Namespace:
    parser, _ = cli.build_parser()
    return parser.parse_args(list(argv))


@pytest.mark.parametrize(
    ("argv", "level"),
    [
        ((), logging.WARNING),
        (("-v",), logging.INFO),
        (("-vv",), logging.DEBUG),
        (("-d", "ERROR"), logging.ERROR),
        (("-d", "VERBOSE", "-v"), logging.DEBUG),
    ],
)
def test_log_levels(argv: tuple[str, ...], level: int) -> None:
    _common.configure(_parse("stat", *argv))
    assert logging.getLogger("xrdarc").level == level
    # The libraries' loggers follow: ``-d DEBUG`` shows xrdhttp's retries and
    # redirects and xrdsec's credential search, not only xrdarc's own lines.
    assert {name: logging.getLogger(name).level for name in _common.LOGGERS} == dict.fromkeys(
        ("xrdarc", "xrdcore", "xrdhttp", "xrdsec"), level
    )


def test_log_handler_is_added_once_and_follows_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    logger = logging.getLogger("xrdarc")
    _common.configure(_parse("stat"))
    _common.configure(_parse("stat"))
    stderr_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
    assert len(stderr_handlers) == 1
    code, _ = run_json(capsys, "stat", "-d", "INFO")
    assert code == 2
    logger.warning("after the report")
    assert capsys.readouterr().err == "WARNING: after the report\n"


def test_password_needs_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(CredentialError, match="no terminal"):
        _common._password()


def test_password_is_asked_for(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "secret")
    assert _common._password() == b"secret"


def test_client_options(tmp_path: Path, pki: PKI) -> None:
    conf = tmp_path / "client.conf"
    conf.write_text("[common]\ntimeout = 7\n")
    command = _common.Command(
        "stat",
        _parse(
            "stat",
            "-z",
            str(conf),
            "-j",
            str(tmp_path / "j.dat"),
            "--cert",
            str(pki.user_cert_path),
            "--key",
            str(pki.user_key_path),
            "--ca-dir",
            str(pki.ca_dir),
            "--insecure",
            "--x509-authentication",
            "--rest-version",
            "1.0",
        ),
    )
    client = command.client()
    assert command.client() is client
    assert client.credentials.cert == str(pki.user_cert_path)
    assert client.credentials.key == str(pki.user_key_path)
    assert client.credentials.auth is Auth.X509
    assert not client.credentials.verify
    assert client.session.timeout == 7
    assert client.version == "1.0"
    assert client.joblist is not None
    assert client.joblist.path == tmp_path / "j.dat"
    command.close()


def test_proxy_and_token_options(tmp_path: Path, pki: PKI) -> None:
    args = _parse("stat", "--proxy", str(pki.proxy_path), "--key", "ignored", "--token", "tok")
    command = _common.Command("stat", args)
    credentials = command.client().credentials
    assert (credentials.cert, credentials.key) == (str(pki.proxy_path), str(pki.proxy_path))
    assert credentials.token == "tok"
    command.close()
    _common.Command("stat", args).close()


def test_token_authentication(
    capsys: pytest.CaptureFixture[str], make_ce: Callable[..., FakeARex], pki: PKI
) -> None:
    ce = make_ce(tokens={"tok": USER_DN}, tls=pki.server_context(require_client=False))
    argv = ["info", ce.url, "--ca-dir", str(pki.ca_dir), "--token", "tok"]
    code, out, _ = run(capsys, *argv, "--token-authentication")
    assert code == 0
    assert "Computing service: fake-arex" in out
    code, _, err = run(capsys, *argv[:-2], "--no-authentication")
    assert code == 1
    assert "xrdarc info:" in err


def test_insecure_needs_no_ca(
    capsys: pytest.CaptureFixture[str], ce: FakeARex, pki: PKI, restore_logging: None
) -> None:
    code, _, err = run(capsys, "info", ce.url, "--proxy", str(pki.proxy_path))
    assert code == 1
    assert "TLS handshake failed" in err
    # Every unverified connection warns: the user is told, not silenced.
    with pytest.warns(UnverifiedTLSWarning):
        code, out, _ = run(capsys, "info", ce.url, "--proxy", str(pki.proxy_path), "--insecure")
    assert code == 0
    assert "fake-arex" in out


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_jobids_from_file(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    _, first = job_of(ce)
    _, second = job_of(ce)
    ids = tmp_path / "ids"
    ids.write_text(f"# my jobs\n{first}\n\n  {second}  \n   # done\n")
    code, out, _ = xrdarc("stat", "-i", str(ids))
    assert code == 0
    assert out.count("Job: ") == 2
    assert out.endswith("Status of 2 jobs was queried, 2 jobs returned information\n")


def test_jobids_file_missing(xrdarc: Run, tmp_path: Path) -> None:
    code, _, err = xrdarc("stat", "-i", str(tmp_path / "nope"))
    assert code == 6
    assert "Cannot read" in err


def test_state_filter(xrdarc: Run, ce: FakeARex, listed: Listed) -> None:
    running = job_of(ce, state="RUNNING")[1]
    executed = job_of(ce, state="EXECUTED")[1]
    finished = job_of(ce, state="FINISHED")[1]
    listed(running, executed, finished)
    code, out, _ = xrdarc("stat", "-s", "running")
    assert code == 0
    assert [line for line in out.splitlines() if line.startswith("Job:")] == [
        f"Job: {running}",
        f"Job: {executed}",
    ]
    code, out, _ = xrdarc("stat", "-s", "EXECUTED", "-s", "Finished")
    assert out.count("Job: ") == 2
    assert f"Job: {running}" not in out


def test_ce_filter(xrdarc: Run, ce: FakeARex, listed: Listed) -> None:
    mine = job_of(ce)[1]
    listed(mine, "https://elsewhere.example:443/arex/rest/1.0/jobs/x")
    code, out, _ = xrdarc("stat", "-C", ce.url)
    assert code == 0
    assert out.startswith(f"Job: {mine}\n")


def test_state_matches() -> None:
    job = Job(ce="https://ce.example:443/arex", id="1", state=JobState.RUNNING)
    assert _common.state_matches(job, [])
    assert _common.state_matches(job, ["RUNNING"])
    assert not _common.state_matches(job, ["queuing"])


# ---------------------------------------------------------------------------
# stat
# ---------------------------------------------------------------------------


def test_stat_text(xrdarc: Run, ce: FakeARex) -> None:
    _, url = job_of(ce, state="FAILED", failure="Out of memory\nKilled", exit_code=137)
    code, out, _ = xrdarc("stat", url)
    assert code == 0
    assert out == (
        f"Job: {url}\n Name: hello\n State: Failed\n Exit Code: 137\n"
        " Job Error: Out of memory\n Job Error: Killed\n\n"
        "Status of 1 jobs was queried, 1 jobs returned information\n"
    )


def test_stat_long(xrdarc: Run, ce: FakeARex, listed: Listed) -> None:
    _, url = job_of(ce, state="FINISHED", exit_code=0)
    listed(url, delegations=("d1",))
    code, out, _ = xrdarc("stat", "-l", "-a")
    assert code == 0
    assert " Specific state: FINISHED\n" in out
    assert f" Owner: {USER_DN}\n" in out
    assert " Stdout: out.txt\n" in out
    assert " Delegation IDs: d1\n" in out
    assert " Results must be retrieved before: " in out
    assert " Started:" not in out


def test_stat_unknown_and_unreachable(xrdarc: Run, ce: FakeARex) -> None:
    gone = f"{ce.url}/rest/1.0/jobs/gone"
    down = f"{dead_ce()}/rest/1.0/jobs/x"
    code, out, err = xrdarc("stat", "--rest-version", "1.1", gone, down)
    assert code == 1
    assert out == "Status of 2 jobs was queried, 0 jobs returned information\n"
    assert f"xrdarc stat: {gone}: job information not found: " in err
    assert "Connection failed" in err


def test_stat_json(xrdarc_json: RunJSON, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    gone = f"{ce.url}/rest/1.0/jobs/gone"
    code, doc = xrdarc_json("stat", url, gone)
    assert code == 1
    first, second = results(doc)
    assert first["job"] == url
    assert (first["ok"], first["state"], first["rest_state"]) == (True, "Running", "RUNNING")
    assert first["owner"] == USER_DN
    assert (second["job"], second["ok"]) == (gone, False)
    assert doc["summary"]["ok"] is False


def test_print_job_extras(capsys: pytest.CaptureFixture[str]) -> None:
    job = Job(
        ce="https://ce.example:443/arex",
        id="1",
        state=JobState.QUEUING,
        waiting_position=3,
        execution_nodes=("n1", "n2"),
        used_wall_time=0,
    )
    jobs._print_job(_common.Command("stat", argparse.Namespace()), job, True)
    out = capsys.readouterr().out
    assert " Waiting Position: 3\n" in out
    assert " Execution nodes: n1, n2\n" in out
    assert " Used wall time (s): 0\n" in out


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


def test_wait_reports_changes(
    xrdarc: Run, make_ce: Callable[..., FakeARex], listed: Listed
) -> None:
    ce = make_ce(progression=("ACCEPTING", "EXITINGLRMS", "EXECUTED", "FINISHED"))
    _, url = job_of(ce, exit_code=0)
    gone = f"{ce.url}/rest/1.0/jobs/gone"
    listed(url, gone)
    code, out, _ = xrdarc("wait", "-a", "--interval", "0")
    assert code == 1
    lines = out.splitlines()
    assert lines[0] == f"{url}: Running"
    assert lines[1].startswith(f"{gone}: unknown (")
    assert lines[2:] == [f"{url}: Finished"]


def test_wait_success_and_failure(xrdarc_json: RunJSON, ce: FakeARex) -> None:
    _, good = job_of(ce, state="FINISHED", exit_code=0)
    _, bad_exit = job_of(ce, state="FINISHED", exit_code=3)
    _, failed = job_of(ce, state="FAILED", failure="boom")
    code, doc = xrdarc_json("wait", good, bad_exit, failed)
    assert code == 1
    assert [r["ok"] for r in results(doc)] == [True, False, False]
    code, doc = xrdarc_json("wait", good)
    assert code == 0


def test_wait_gives_up(xrdarc: Run, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    code, out, err = xrdarc("wait", url, "--interval", "0", "--max-wait", "0")
    assert code == 7
    assert out == f"{url}: Running\n"
    assert "1 jobs still not finished" in err


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


def test_get(xrdarc: Run, ce: FakeARex, listed: Listed, tmp_path: Path) -> None:
    fake, done = job_of(ce, state="FINISHED", files={"out.txt": b"hi"})
    running = job_of(ce, state="RUNNING")[1]
    listed(done, running)
    code, out, err = xrdarc("get", "-a", "-D", str(tmp_path / "dl"))
    assert code == 1
    assert out == (
        f"Results stored at: {tmp_path / 'dl' / fake.id}\n"
        "Jobs processed: 2, successfully retrieved: 1, successfully cleaned: 1\n"
    )
    assert f"{running}: retrieval failed: The job is not finished (Running)" in err
    assert [j.url for j in JobList(tmp_path / "jobs.dat")] == [running]


def test_get_keep_names_and_diagnose(
    xrdarc_json: RunJSON, ce: FakeARex, tmp_path: Path, chdir: Path
) -> None:
    _, url = job_of(ce, state="FINISHED")
    code, doc = xrdarc_json("get", url, "-k", "-J", "--diagnose", "--workers", "1")
    assert code == 0
    [record] = results(doc)
    assert record["path"] == "hello"
    assert (chdir / "hello" / "diagnose" / "status").is_file()
    assert "successfully cleaned: 0" in messages(doc)
    code, doc = xrdarc_json("get", url, "-k", "-J", "-f")
    assert code == 0


def test_get_into_the_configured_directory(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    conf = tmp_path / "client.conf"
    conf.write_text(f"jobdownloaddirectory = {tmp_path / 'results'}\n")
    fake, url = job_of(ce, state="FINISHED")
    code, _, _ = xrdarc("get", url, "-z", str(conf))
    assert code == 0
    assert (tmp_path / "results" / fake.id).is_dir()


# ---------------------------------------------------------------------------
# cat, ls, diagnose
# ---------------------------------------------------------------------------


def test_cat(xrdarc: Run, ce: FakeARex) -> None:
    files = {"out.txt": b"OUT\n", "err.txt": b"ERR\n", "data/x": b"X\n"}
    _, url = job_of(ce, files=files)
    assert xrdarc("cat", url) == (0, "OUT\n", "")
    assert xrdarc("cat", "-e", url) == (0, "ERR\n", "")
    assert xrdarc("cat", "-f", "data/x", url) == (0, "X\n", "")
    code, out, _ = xrdarc("cat", "-l", url)
    assert code == 0
    assert "Job state change" in out


def test_cat_several_and_failures(xrdarc: Run, ce: FakeARex) -> None:
    _, first = job_of(ce, files={"out.txt": b"1\n"})
    _, second = job_of(ce, '&(executable="/bin/x")')
    code, out, err = xrdarc("cat", first, second)
    assert code == 1
    assert out == f"==> {first} <==\n1\n==> {second} <==\n"
    assert err == f"xrdarc cat: {second}: The job does not name a stdout file\n"


def test_cat_json(xrdarc_json: RunJSON, ce: FakeARex) -> None:
    _, url = job_of(ce, files={"out.txt": b"OUT\n"})
    code, doc = xrdarc_json("cat", url)
    assert code == 0
    [content] = [r for r in doc["records"] if r["kind"] == "content"]
    assert (content["job"], content["what"], content["stream"]) == (url, "stdout", "stdout")


def test_ls(xrdarc: Run, xrdarc_json: RunJSON, ce: FakeARex) -> None:
    _, url = job_of(ce, files={"a": b"123", "d/b": b""})
    code, out, _ = xrdarc("ls", url)
    assert code == 0
    assert out == f"{3:>12}  a\n{0:>12}  d/b\n"
    code, doc = xrdarc_json("ls", url, "d")
    assert [(r["path"], r["size"]) for r in results(doc)] == [("d/b", 0)]


def test_diagnose(xrdarc: Run, ce: FakeARex) -> None:
    fake, url = job_of(ce)
    code, out, _ = xrdarc("diagnose", url)
    assert code == 0
    assert f"==> description <==\n{fake.description}\n" in out
    assert "==> failed <==" not in out
    code, out, _ = xrdarc("diagnose", url, "status", "local")
    assert out.startswith("==> status <==\n")
    assert code == 0


def test_diagnose_failures(xrdarc: Run, xrdarc_json: RunJSON, ce: FakeARex) -> None:
    _, url = job_of(ce)
    code, out, err = xrdarc("diagnose", url, "failed")
    assert (code, out) == (1, "")
    assert err.startswith("xrdarc diagnose: failed: ")
    ce.fault("GET", r"/diagnose/local", status=403, reason="Nope")
    code, doc = xrdarc_json("diagnose", url)
    assert code == 1
    [error] = [r for r in doc["records"] if r["kind"] == "error"]
    assert error["item"] == "local"


# ---------------------------------------------------------------------------
# kill, resume, renew, clean
# ---------------------------------------------------------------------------


def test_kill(xrdarc: Run, ce: FakeARex, listed: Listed) -> None:
    running = job_of(ce, state="RUNNING")
    queued = job_of(ce, state="QUEUING")
    listed(running[1], queued[1])
    code, out, _ = xrdarc("kill", "-a", "-s", "Running")
    assert code == 0
    assert out == "Jobs processed: 1, successfully killed: 1\n"
    assert running[0].kill_requested
    assert not queued[0].kill_requested


def test_kill_failure(xrdarc: Run, ce: FakeARex) -> None:
    fake, url = job_of(ce, state="RUNNING")
    fake.refuse["kill"] = "Too late"
    code, out, err = xrdarc("kill", url)
    assert code == 1
    assert out == "Jobs processed: 1, successfully killed: 0\n"
    assert err == f"xrdarc kill: {url}: kill failed: Too late\n"


def test_resume(xrdarc_json: RunJSON, ce: FakeARex) -> None:
    fake, url = job_of(ce, '&(executable="/bin/x")(rerun="2")')
    ce.fail_job(fake.id)
    code, doc = xrdarc_json("resume", url)
    assert code == 0
    assert results(doc) == [
        {
            "sequence": 1,
            "kind": "result",
            "operation": "resume",
            "job": url,
            "ok": True,
            "reason": "Queued for restarting",
        }
    ]
    assert messages(doc) == "Jobs processed: 1, resumed: 1\n"


def test_renew(xrdarc: Run, ce: FakeARex, listed: Listed, pki: PKI) -> None:
    with ARCClient(
        config=load_config(),
        credentials=discover(load_config()),
        joblist=False,
    ) as arc:
        delegation_id = arc.delegate(ce.url)
    _, url = job_of(ce, f'&(executable="/bin/x")(delegationid="{delegation_id}")')
    code, out, _ = xrdarc("renew", url)
    assert (code, out) == (0, "Jobs processed: 1, renewed: 1\n")
    assert ce.delegations[delegation_id].renewals == 1


def test_clean(xrdarc: Run, ce: FakeARex, listed: Listed, jobs_dat: Path) -> None:
    finished = job_of(ce, state="FINISHED")[1]
    running = job_of(ce, state="RUNNING")[1]
    listed(finished, running)
    code, out, _ = xrdarc("clean", "-s", "finished")
    assert (code, out) == (0, "Jobs processed: 1, deleted: 1\n")
    assert [j.url for j in JobList(jobs_dat)] == [running]


def test_clean_force(xrdarc: Run, ce: FakeARex, listed: Listed, jobs_dat: Path) -> None:
    fake, stubborn = job_of(ce, state="FINISHED")
    fake.refuse["clean"] = "Busy"
    listed(stubborn)
    code, out, err = xrdarc("clean", "-a")
    assert code == 1
    assert "clean failed: Busy" in err
    code, out, err = xrdarc("clean", "-a", "-f")
    assert (code, out, err) == (0, "Jobs processed: 1, deleted: 1\n", "")
    assert len(JobList(jobs_dat)) == 0
    _, fine = job_of(ce, state="FINISHED")
    code, out, err = xrdarc("clean", fine, "-f")
    assert (code, out, err) == (0, "Jobs processed: 1, deleted: 1\n", "")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------


def test_sync(xrdarc: Run, ce: FakeARex, make_ce: Callable[..., FakeARex], jobs_dat: Path) -> None:
    other = make_ce()
    _, url = job_of(ce)
    _, elsewhere = job_of(other)
    code, out, _ = xrdarc("sync", ce.url, "-C", other.url)
    assert code == 0
    assert out == f"Added {url}\nAdded {elsewhere}\n2 jobs added to the job list\n"
    code, out, _ = xrdarc("sync", ce.url)
    assert out == "0 jobs added to the job list\n"
    code, out, _ = xrdarc("sync", "-T", other.url, ce.url)
    assert out.endswith("2 jobs added to the job list\n")
    assert len(JobList(jobs_dat)) == 2


def test_sync_needs_a_ce(xrdarc: Run, xrdarc_json: RunJSON, ce: FakeARex, tmp_path: Path) -> None:
    code, _, err = xrdarc("sync")
    assert code == 2
    assert "No computing element given" in err
    conf = tmp_path / "client.conf"
    conf.write_text(f"[computing/mine]\nurl = {ce.url}\ndefault = yes\n")
    job_of(ce)
    code, doc = xrdarc_json("sync", "-z", str(conf))
    assert code == 0
    assert results(doc)[0]["ce"] == ce.url
