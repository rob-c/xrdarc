"""End-to-end tests against a real ARC CE, skipped unless ``XRDARC_INTEROP=1``.

They use the caller's real credentials (ordinary discovery: ``X509_USER_PROXY``,
``X509_CERT_DIR``, tokens ...), and submit small jobs to::

    XRDARC_INTEROP_CE      the CE (required), e.g. ce.example.org or https://ce:443/arex
    XRDARC_INTEROP_QUEUE   a queue to use (optional)
    XRDARC_INTEROP_RTE     a runtime environment that exports X509_USER_PROXY on the
                           worker, e.g. ENV/PROXY (optional; enables the delegation test)
    XRDARC_INTEROP_TIMEOUT seconds to wait for a job (default 1800)

Every job is cleaned at the end, and the job list is a temporary file, so
the user's ``~/.arc/jobs.dat`` is not touched. See docs/DEVELOPING.md.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

import xrdarc
from xrdarc import ARCClient, Job, JobState
from xrdarc.creds import discover

pytestmark = pytest.mark.interop

CE = os.environ.get("XRDARC_INTEROP_CE", "")
QUEUE = os.environ.get("XRDARC_INTEROP_QUEUE") or None
RTE = os.environ.get("XRDARC_INTEROP_RTE") or None
TIMEOUT = float(os.environ.get("XRDARC_INTEROP_TIMEOUT", "1800"))


@pytest.fixture(scope="module")
def real_env() -> Iterator[dict[str, str]]:
    """The developer's environment, which the autouse hermetic fixture hides per test."""
    if not CE:
        pytest.skip("set XRDARC_INTEROP_CE to the CE to test against")
    yield dict(os.environ)


@pytest.fixture
def arc(real_env: dict[str, str], tmp_path: Path) -> Iterator[ARCClient]:
    credentials = discover(environ=real_env)
    with ARCClient(
        config=xrdarc.load_config(environ=real_env),
        credentials=credentials,
        joblist=tmp_path / "jobs.dat",
    ) as client:
        yield client
        leftovers = client.known()
        if leftovers:
            client.kill([j for j in leftovers if not j.state.terminal])
            client.clean(leftovers)


def _submit(arc: ARCClient, text: str, base: Path) -> Job:
    [result] = arc.submit(CE, text, base=base, queue=QUEUE)
    assert result.ok, result.reason
    assert result.job is not None
    return result.job


def _finish(arc: ARCClient, job: Job) -> Job:
    [outcome] = arc.wait([job], interval=10, timeout=TIMEOUT)
    assert outcome.ok, outcome.reason
    return outcome.job


def test_info_names_the_rest_endpoint(arc: ARCClient) -> None:
    info = arc.info(CE)
    endpoint = info.rest_endpoint()
    assert endpoint is not None
    assert endpoint.url
    assert info.queues


def test_hello_world_round_trip(arc: ARCClient, tmp_path: Path) -> None:
    job = _submit(
        arc,
        '&(executable="/bin/sh")(arguments="-c" "echo hello-xrdarc; id -un")'
        '(stdout="out.txt")(stderr="err.txt")(gmlog="gmlog")(jobname="xrdarc-interop-hello")',
        tmp_path,
    )
    done = _finish(arc, job)
    assert done.state is JobState.FINISHED
    assert done.exit_code == 0
    [got] = arc.get([done], tmp_path / "results")
    assert got.ok, got.reason
    assert got.path is not None
    assert "hello-xrdarc" in (got.path / "out.txt").read_text()
    assert (got.path / "gmlog" / "errors").is_file()


def test_inputs_are_uploaded_and_outputs_come_back(arc: ARCClient, tmp_path: Path) -> None:
    payload = os.urandom(3 << 20)
    (tmp_path / "in.bin").write_bytes(payload)
    (tmp_path / "run.sh").write_text("#!/bin/sh\nsha256sum in.bin > sum.txt\ncp in.bin copy.bin\n")
    job = _submit(
        arc,
        '&(executable="run.sh")(inputfiles=("in.bin" ""))'
        '(outputfiles=("sum.txt" "")("copy.bin" ""))(stdout="out.txt")'
        '(jobname="xrdarc-interop-upload")',
        tmp_path,
    )
    done = _finish(arc, job)
    assert done.state is JobState.FINISHED, done.errors
    [got] = arc.get([done], tmp_path / "results")
    assert got.path is not None
    digest = hashlib.sha256(payload).hexdigest()
    assert (got.path / "sum.txt").read_text().split()[0] == digest
    assert (got.path / "copy.bin").read_bytes() == payload


def test_a_failing_job_reports_its_exit_code(arc: ARCClient, tmp_path: Path) -> None:
    job = _submit(
        arc,
        '&(executable="/bin/sh")(arguments="-c" "echo about-to-fail; exit 3")'
        '(stdout="out.txt")(jobname="xrdarc-interop-fail")',
        tmp_path,
    )
    done = _finish(arc, job)
    assert done.state is JobState.FAILED
    assert done.exit_code == 3
    assert arc.diagnose(done, "failed")


def test_a_running_job_can_be_inspected_and_killed(arc: ARCClient, tmp_path: Path) -> None:
    job = _submit(
        arc,
        '&(executable="/bin/sh")(arguments="-c" "echo started; sleep 900")'
        '(stdout="out.txt")(jobname="xrdarc-interop-kill")',
        tmp_path,
    )
    [outcome] = arc.kill([job])
    assert outcome.ok, outcome.reason
    done = _finish(arc, job)
    assert done.state is JobState.KILLED


def test_renewal_replaces_the_delegated_proxy(arc: ARCClient, tmp_path: Path) -> None:
    job = _submit(
        arc,
        '&(executable="/bin/sh")(arguments="-c" "sleep 120")(jobname="xrdarc-interop-renew")',
        tmp_path,
    )
    [outcome] = arc.renew([job])
    assert outcome.ok, outcome.reason
    arc.kill([job])


@pytest.mark.skipif(RTE is None, reason="set XRDARC_INTEROP_RTE (e.g. ENV/PROXY)")
def test_the_delegated_proxy_verifies_on_the_worker(arc: ARCClient, tmp_path: Path) -> None:
    (tmp_path / "check.sh").write_text(
        "#!/bin/sh\n"
        'openssl verify -allow_proxy_certs -CApath "$X509_CERT_DIR" '
        '-untrusted "$X509_USER_PROXY" "$X509_USER_PROXY" 2>&1 | tail -1\n'
    )
    job = _submit(
        arc,
        f'&(executable="check.sh")(runtimeenvironment="{RTE}")(stdout="out.txt")'
        '(jobname="xrdarc-interop-delegation")',
        tmp_path,
    )
    done = _finish(arc, job)
    [got] = arc.get([done], tmp_path / "results")
    assert got.path is not None
    assert re.search(r": OK$", (got.path / "out.txt").read_text().strip())
