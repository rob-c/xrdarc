"""Plain helpers for the ``ARCClient`` and command-line tests.

Jobs straight into a fake CE, a CE that is down, and the ``xrdarc``
command line run in process with its output picked apart.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest

from _arex import USER_DN
from xrdarc import cli
from xrdarc.testing.arex import FakeARex, FakeJob

__all__ = ["XRSL", "dead_ce", "job_of", "messages", "results", "run", "run_json"]

#: A job with no uploads, so the fake needs nothing but the POST.
XRSL = '&(executable="/bin/echo")(jobname="hello")(stdout="out.txt")(stderr="err.txt")'


def dead_ce() -> str:
    """The URL of a CE nobody listens for: a port that was free a moment ago."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"https://127.0.0.1:{port}/arex"


def job_of(ce: FakeARex, description: str = XRSL, **kwargs: Any) -> tuple[FakeJob, str]:
    """A job of the test user in the fake's store, and its job URL."""
    job = ce.add_job(USER_DN, description, **kwargs)
    return job, f"{ce.url}/rest/1.0/jobs/{job.id}"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """``xrdarc argv...``: the exit code, stdout and stderr."""
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    """``xrdarc argv... --json``: the exit code and the one JSON document it printed."""
    code = cli.main([*argv, "--json"])
    out, err = capsys.readouterr()
    assert err == ""
    doc: dict[str, Any] = json.loads(out)
    assert doc["schema"] == "storage-client-report"
    assert doc["summary"]["exit_code"] == code
    return code, doc


def results(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``result`` records of a report."""
    return [r for r in doc["records"] if r["kind"] == "result"]


def messages(doc: dict[str, Any], stream: str = "stdout") -> str:
    """What a report's human-readable messages on ``stream`` say, joined."""
    return "".join(
        r["text"] for r in doc["records"] if r["kind"] == "message" and r["stream"] == stream
    )
