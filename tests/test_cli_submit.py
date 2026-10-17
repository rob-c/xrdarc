"""``xrdarc sub`` (arcsub) and ``xrdarc info`` (arcinfo)."""

from __future__ import annotations

import errno
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from _client_helpers import XRSL, dead_ce, messages, results
from xrdarc.client import ARCClient
from xrdarc.info import CEInfo, Endpoint, Queue
from xrdarc.joblist import JobList
from xrdarc.testing.arex import CEInfo as FakeInfo
from xrdarc.testing.arex import FakeARex, FakeQueue

pytest_plugins = ["_arex", "_cli_fixtures"]

Run = Callable[..., tuple[int, str, str]]
RunJSON = Callable[..., tuple[int, dict[str, Any]]]
MULTI = '+(&(executable="/bin/a")(jobname="a"))(&(executable="/bin/b")(jobname="b"))'


def _jobs(ce: FakeARex) -> list[str]:
    return [f"{ce.url}/rest/1.0/jobs/{job_id}" for job_id in ce.jobs]


# ---------------------------------------------------------------------------
# sub
# ---------------------------------------------------------------------------


def test_sub_file(xrdarc: Run, ce: FakeARex, tmp_path: Path, jobs_dat: Path) -> None:
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    description = tmp_path / "job.xrsl"
    description.write_text('&(executable="run.sh")(jobname="j")')
    code, out, err = xrdarc("sub", "-C", ce.url, str(description))
    assert (code, err) == (0, "")
    [url] = _jobs(ce)
    assert out == f"Job submitted with jobid: {url}\n"
    assert [j.url for j in JobList(jobs_dat)] == [url]
    [fake] = ce.jobs.values()
    assert fake.uploads == ["/run.sh"]
    assert fake.delegations


def test_sub_several(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    description = tmp_path / "multi.xrsl"
    description.write_text(MULTI)
    ids = tmp_path / "ids"
    ids.write_text("earlier\n")
    code, out, _ = xrdarc(
        "sub", "-C", ce.url, "-e", XRSL, "-f", str(description), "-o", str(ids), "--no-delegation"
    )
    assert code == 0
    assert out.endswith("3 of 3 jobs were submitted\n")
    assert ids.read_text().splitlines() == ["earlier", *_jobs(ce)]
    assert ce.delegations == {}


def test_sub_rejected(xrdarc_json: RunJSON, ce: FakeARex, tmp_path: Path) -> None:
    ce.reject_next("Too many jobs")
    ids = tmp_path / "ids"
    code, doc = xrdarc_json("sub", "-C", ce.url, "-e", MULTI, "-q", "main", "-o", str(ids))
    assert code == 1
    rejected, accepted = results(doc)
    assert (rejected["ok"], rejected["job"], rejected["reason"]) == (False, None, "Too many jobs")
    assert (accepted["ok"], accepted["description"]) == (True, "-e #1")
    assert "xrdarc sub: -e #1: job not submitted: Too many jobs" in messages(doc, "stderr")
    assert "1 of 2 jobs were submitted" in messages(doc)
    assert ids.read_text() == f"{accepted['job']}\n"


def test_sub_all_rejected_writes_no_ids(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    ce.reject_next("No")
    code, out, err = xrdarc("sub", "-C", ce.url, "-e", XRSL, "-o", str(tmp_path / "ids"))
    assert (code, out) == (1, "")
    assert "job not submitted: No" in err
    assert not (tmp_path / "ids").exists()


def test_sub_dry_run(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text("x")
    description = tmp_path / "job.xrsl"
    description.write_text('&(executable="run.sh")')
    code, out, _ = xrdarc("sub", "--dry-run", "-q", "grid", str(description), "-e", XRSL)
    assert code == 0
    assert '(queue = "grid")' in out
    assert f"# upload {tmp_path / 'run.sh'} -> run.sh\n" in out
    assert ce.requests == []


def test_sub_dry_run_json(xrdarc_json: RunJSON, tmp_path: Path, chdir: Path) -> None:
    code, doc = xrdarc_json("sub", "--dry-run", "-e", XRSL)
    assert code == 0
    [record] = results(doc)
    assert record["description"] == "-e #1"
    assert record["uploads"] == []


def test_sub_needs_a_description(xrdarc: Run, tmp_path: Path) -> None:
    code, _, err = xrdarc("sub", "-C", "ce.example")
    assert code == errno.EINVAL
    assert "No job description given" in err
    code, _, err = xrdarc("sub", "-C", "ce.example", str(tmp_path / "missing.xrsl"))
    assert code == errno.ENOENT
    assert "Cannot read" in err


def test_sub_needs_a_ce(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    code, _, err = xrdarc("sub", "-e", XRSL)
    assert code == errno.EINVAL
    assert "No computing element given; use -C" in err
    conf = tmp_path / "client.conf"
    conf.write_text(
        f"[computing/other]\nurl = {dead_ce()}\n[computing/mine]\nurl = {ce.url}\ndefault = yes\n"
    )
    code, out, _ = xrdarc("sub", "-z", str(conf), "-e", XRSL)
    assert code == 0
    assert out == f"Job submitted with jobid: {_jobs(ce)[0]}\n"


def test_sub_to_an_alias(xrdarc: Run, ce: FakeARex, tmp_path: Path) -> None:
    conf = tmp_path / "client.conf"
    conf.write_text(f"[computing/mine]\nurl = {ce.url}\n")
    code, _, _ = xrdarc("sub", "-z", str(conf), "-C", "mine", "-e", XRSL)
    assert code == 0
    assert len(ce.jobs) == 1


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def test_info(xrdarc: Run, make_ce: Callable[..., FakeARex]) -> None:
    queues = [
        FakeQueue("main", vos=("atlas",)),
        FakeQueue("long", max_wall_time=2**31 - 1),
        FakeQueue("short", max_wall_time=None),
    ]
    ce = make_ce(info=FakeInfo(queues=queues))
    code, out, _ = xrdarc("info", ce.url)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "Computing service: fake-arex"
    assert lines[1] == f"  Information endpoint: {ce.url} (org.nordugrid.arcrest)"
    assert lines[2].startswith(f"  Submission endpoint: {ce.url}")
    assert "  Queue: main: 0 running, 0 waiting, max wall time 259200 s" in lines
    assert "  Queue: long: 0 running, 0 waiting, no wall time limit" in lines
    assert "  Queue: short: 0 running, 0 waiting" in lines
    assert not any("share of" in line or "Runtime environment" in line for line in lines)


def test_info_long(xrdarc: Run, ce: FakeARex) -> None:
    code, out, _ = xrdarc("info", "-l", "-C", ce.url)
    assert code == 0
    assert "(share of main)" in out
    assert "  Runtime environment: ENV/PROXY\n" in out


def test_info_json(xrdarc_json: RunJSON, ce: FakeARex) -> None:
    code, doc = xrdarc_json("info", ce.url)
    assert code == 0
    [record] = results(doc)
    assert record["ce"] == ce.url
    assert record["name"] == "fake-arex"
    assert "ENV/PROXY" in record["runtime_environments"]
    assert {q["name"] for q in record["queues"]} >= {"main"}
    assert record["endpoints"][0]["versions"]


def test_info_failure_and_defaults(
    xrdarc: Run, ce: FakeARex, make_ce: Callable[..., FakeARex], tmp_path: Path
) -> None:
    code, _, err = xrdarc("info")
    assert code == errno.EINVAL
    assert "No computing element given; name one" in err
    broken = make_ce()
    broken.fault("GET", r"/info", status=403, reason="Not for you")
    down = broken.url
    conf = tmp_path / "client.conf"
    conf.write_text(
        f"[computing/a]\nurl = {ce.url}\ndefault = yes\n"
        f"[computing/b]\nurl = {down}\ndefault = yes\n"
    )
    code, out, err = xrdarc("info", "-z", str(conf), "--rest-version", "1.1")
    assert code == 1
    assert out.startswith("Computing service: fake-arex\n")
    assert err.startswith(f"xrdarc info: {down}: HTTP 403 Not for you")


def test_info_with_little_published(xrdarc: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    queue = Queue("q", None, None, None, None, None, None, None, None, False)
    bare = CEInfo(None, (Endpoint("x", "other", (), None, None, ()),), (queue,), (), None, 0, 0)
    monkeypatch.setattr(ARCClient, "info", lambda self, ce: bare)
    code, out, _ = xrdarc("info", "https://ce.example/arex")
    assert code == 0
    assert out == (
        "Computing service: https://ce.example:443/arex\n"
        "  Information endpoint: https://ce.example:443/arex (org.nordugrid.arcrest)\n"
        "  Queue: q: 0 running, 0 waiting\n"
    )
