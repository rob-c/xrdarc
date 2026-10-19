"""``ARCClient`` against the fake A-REX: every user-level operation and its failure modes."""

from __future__ import annotations

import dataclasses
import errno
import functools
import io
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from xrdsec.testing.pki import PKI

import xrdarc
from _arex import USER_DN, make_session
from _client_helpers import XRSL, dead_ce, job_of, never_sleep
from xrdarc.client import ARCClient, Outcome, Submission, _submit
from xrdarc.config import Service, UserConfig
from xrdarc.creds import Credentials
from xrdarc.errors import ARCError, CredentialError, DescriptionError, HTTPError, JobNotFoundError
from xrdarc.joblist import Job, JobList
from xrdarc.states import JobState
from xrdarc.testing.arex import FakeARex
from xrdarc.testing.fixtures import SessionFactory, make_credentials

pytest_plugins = ["_arex"]

MakeArc = Callable[..., ARCClient]
MakeCE = Callable[..., FakeARex]

ADL = (
    '<ActivityDescription xmlns="http://www.eu-emi.eu/es/2010/12/adl">'
    "<ActivityIdentification><Name>adljob</Name></ActivityIdentification>"
    "<Application><Executable><Path>/bin/true</Path></Executable></Application>"
    "</ActivityDescription>"
)
MULTI = '+(&(executable="/bin/a")(jobname="a"))(&(executable="/bin/b")(jobname="b"))'


def _posts(ce: FakeARex, action: str) -> list[bytes]:
    """The bodies of the job requests (not delegation ones) with ``action``."""
    return [
        r.body
        for r in ce.requests
        if r.method == "POST" and r.path.endswith("/jobs") and r.query.get("action") == action
    ]


def _urls(jobs: list[Job]) -> list[str]:
    return [job.url for job in jobs]


def _submit_one(arc: ARCClient, ce: FakeARex, text: str = XRSL, **kwargs: Any) -> Job:
    [submission] = arc.submit(ce.url, text, **kwargs)
    assert submission.ok, submission.reason
    assert submission.job is not None
    return submission.job


@pytest.fixture
def arc_session_factory(sleeps: list[float]) -> SessionFactory:
    """``make_arc``'s clients retry like ``session`` and record their pauses in ``sleeps``."""
    return functools.partial(make_session, sleeps=sleeps)


@pytest.fixture
def arc(make_arc: Callable[..., ARCClient]) -> ARCClient:
    return make_arc()


# ---------------------------------------------------------------------------
# The package and the constructor
# ---------------------------------------------------------------------------


def test_package_exports_the_client() -> None:
    assert xrdarc.ARCClient is ARCClient
    assert set(xrdarc.__all__) <= set(dir(xrdarc))
    assert xrdarc.__version__


def test_defaults_come_from_client_conf_and_discovery(grid_env: PKI, home: Path) -> None:
    with ARCClient() as arc:
        assert arc.credentials.cert == str(grid_env.proxy_path)
        assert arc.joblist is not None
        assert arc.joblist.path == home / ".arc" / "jobs.dat"
        assert arc.session.timeout == arc.config.timeout


@pytest.mark.parametrize("given", [None, False])
def test_no_job_list(make_arc: MakeArc, ce: FakeARex, given: bool | None) -> None:
    arc = make_arc(joblist=given)
    assert arc.joblist is None
    assert arc.known() == []
    _submit_one(arc, ce)
    assert arc.sync(ce.url, replace_all=True)


def test_job_list_as_path_or_object(make_arc: MakeArc, tmp_path: Path) -> None:
    own = make_arc(joblist=tmp_path / "a.dat").joblist
    assert own is not None
    assert own.path == tmp_path / "a.dat"
    shared = JobList(tmp_path / "b.dat")
    assert make_arc(joblist=shared).joblist is shared


def test_timeout_reaches_the_session(credentials: Credentials, tmp_path: Path) -> None:
    config = UserConfig(joblist=tmp_path / "jobs.dat")
    with ARCClient(config=config, credentials=credentials, timeout=3.5) as arc:
        assert arc.session.timeout == 3.5


def test_context_manager_closes_the_session(arc: ARCClient, ce: FakeARex) -> None:
    with arc as same:
        assert same is arc
    with pytest.raises(ARCError) as caught:
        arc.info(ce.url)
    assert caught.value.code == errno.EBADF


# ---------------------------------------------------------------------------
# Delegation and signing
# ---------------------------------------------------------------------------


def test_signer_is_cached_and_needs_x509(make_arc: MakeArc, pki: PKI) -> None:
    arc = make_arc()
    assert arc.signer() is arc.signer()
    tokenless = make_arc(credentials=Credentials(token="t", ca_dir=str(pki.ca_dir)))
    with pytest.raises(CredentialError, match=r"needs an X\.509"):
        tokenless.signer()


def test_signer_from_certificate_and_key(make_arc: MakeArc, pki: PKI) -> None:
    creds = make_credentials(pki, cert=str(pki.user_cert_path), key=str(pki.user_key_path))
    signer = make_arc(credentials=creds).signer()
    assert signer.identity == USER_DN


def test_delegation_failure_deletes_the_slot(arc: ARCClient, ce: FakeARex) -> None:
    ce.fault("PUT", r"/delegations/", status=400, reason="Bad chain")
    with pytest.raises(HTTPError, match="Bad chain"):
        arc.submit(ce.url, XRSL)
    assert ce.delegations == {}
    assert _posts(ce, "new") == []


def test_delegation_cleanup_failure_is_only_logged(
    arc: ARCClient, ce: FakeARex, caplog: pytest.LogCaptureFixture
) -> None:
    ce.fault("PUT", r"/delegations/", status=400, reason="Bad chain")
    ce.fault("POST", r"action=delete", status=403, reason="No")
    with caplog.at_level(logging.DEBUG, "xrdarc"), pytest.raises(HTTPError):
        arc.delegate(ce.url)
    assert "could not delete delegation" in caplog.text
    assert len(ce.delegations) == 1


def test_token_only_delegation(make_arc: MakeArc, make_ce: MakeCE, pki: PKI) -> None:
    ce = make_ce(tokens={"tok": USER_DN}, tls=pki.server_context(require_client=False))
    arc = make_arc(credentials=Credentials(token="tok", ca_dir=str(pki.ca_dir)))
    job = _submit_one(arc, ce)
    [delegation] = ce.delegations.values()
    assert delegation.type == "jwt"
    assert job.delegations == (delegation.id,)


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------


def test_submit_uploads_inputs_and_records_the_job(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text("#!/bin/sh\necho hi\n")
    sent: list[tuple[str, int]] = []
    text = '&(executable="run.sh")(jobname="j")(stdout="out")(gmlog="gmlog")'
    job = _submit_one(arc, ce, text, base=tmp_path, progress=lambda n, s: sent.append((n, s)))
    assert sent == [("run.sh", 18)]
    assert ce.jobs[job.id].uploads == ["/run.sh"]
    assert job.name == "j"
    assert job.log_dir == "gmlog"
    assert job.state is JobState.ACCEPTED
    assert job.delegations == tuple(ce.jobs[job.id].delegations)
    assert _urls(arc.known()) == [job.url]


def test_submit_reads_inputs_from_the_current_directory(
    arc: ARCClient, ce: FakeARex, chdir: Path
) -> None:
    (chdir / "run.sh").write_text("x")
    job = _submit_one(arc, ce, '&(executable="run.sh")')
    assert ce.jobs[job.id].uploads == ["/run.sh"]


def test_multi_xrsl_is_one_request(arc: ARCClient, ce: FakeARex) -> None:
    submissions = arc.submit(ce.url, MULTI)
    assert [s.job.name for s in submissions if s.job] == ["a", "b"]
    assert len(_posts(ce, "new")) == 1
    assert _posts(ce, "new")[0].startswith(b"+(&")
    assert len(arc.known()) == 2


def test_rejected_job_is_reported_not_raised(arc: ARCClient, ce: FakeARex) -> None:
    ce.reject_next("Too many jobs")
    first, second = arc.submit(ce.url, MULTI)
    assert not first.ok
    assert first.reason == "Too many jobs"
    assert second.ok
    assert [j.name for j in arc.known()] == ["b"]


def test_ce_answering_for_fewer_jobs(arc: ARCClient, ce: FakeARex) -> None:
    body = (
        b'{"job": [{"status-code": "201", "reason": "Created", "id": "abc", "state": "ACCEPTING"}]}'
    )
    ce.fault(
        "POST", r"action=new", status=201, body=body, headers={"Content-Type": "application/json"}
    )
    first, second = arc.submit(ce.url, MULTI, delegate=False)
    assert first.job is not None
    assert first.job.id == "abc"
    assert (second.ok, second.status) == (False, 0)
    assert second.reason == "The CE did not answer for this description"


def test_upload_failure_abandons_the_job(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text("x")
    ce.fault("PUT", r"/session/", status=403, reason="Not allowed")
    [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert isinstance(submission, Submission)
    assert not submission.ok
    assert submission.reason.startswith("Uploading input files failed:")
    assert "Not allowed" in submission.reason
    assert len(_posts(ce, "kill")) == 1
    assert len(_posts(ce, "clean")) == 1
    assert arc.known() == []


def test_abandon_failures_are_logged(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "run.sh").write_text("x")
    ce.fault("PUT", r"/session/", status=403)
    ce.fault("POST", r"action=(kill|clean)", status=403, reason="Denied", times=2)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert not submission.ok
    assert "kill: HTTP 403 Denied; clean: HTTP 403 Denied" in caplog.text
    [kept] = arc.known()
    assert "could not be removed from the CE" in kept.errors[0]


def test_bad_description_fails_before_the_ce_is_contacted(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    with pytest.raises(DescriptionError, match="missing"):
        arc.submit(ce.url, '&(executable="missing.sh")', base=tmp_path)
    assert ce.requests == []


def test_submit_without_delegation(arc: ARCClient, ce: FakeARex) -> None:
    job = _submit_one(arc, ce, delegate=False)
    assert job.delegations == ()
    assert ce.delegations == {}


def test_adl_on_rest_10_embeds_the_delegation(make_arc: MakeArc, ce: FakeARex) -> None:
    arc = make_arc(version="1.0")
    job = _submit_one(arc, ce, ADL)
    [posted] = _posts(ce, "new")
    assert job.delegations[0].encode() in posted
    assert b"DelegationID" in posted
    assert job.name == "adljob"


def test_adl_on_rest_11_passes_the_delegation_as_a_parameter(arc: ARCClient, ce: FakeARex) -> None:
    job = _submit_one(arc, ce, ADL)
    [request] = [r for r in ce.requests if r.query.get("action") == "new" and r.body]
    assert request.query["delegation_id"] == job.delegations[0]
    assert b"DelegationID" not in request.body


def test_several_descriptions_must_be_xrsl(arc: ARCClient, tmp_path: Path) -> None:
    [xrsl] = arc.prepare(XRSL, base=tmp_path)
    [adl] = arc.prepare(ADL, base=tmp_path)
    assert _submit._bundle([xrsl]) == xrsl.description
    with pytest.raises(DescriptionError, match="only be submitted together as xRSL"):
        _submit._bundle([xrsl, adl])
    twice = _submit._bundle([xrsl, dataclasses.replace(xrsl, description=" &(a=b)")])
    assert twice.startswith("+(&")


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def _three(arc: ARCClient, ce: FakeARex, other: FakeARex) -> list[Job]:
    jobs = [s.job for s in arc.submit(ce.url, MULTI, delegate=False) if s.job]
    jobs += [s.job for s in arc.submit(other.url, XRSL, delegate=False) if s.job]
    return jobs


def test_select_by_url_id_and_name(arc: ARCClient, ce: FakeARex, make_ce: MakeCE) -> None:
    a, b, hello = _three(arc, ce, make_ce())
    assert _urls(arc.select([a.url, b.id, "hello", "a"])) == _urls([a, b, hello])
    assert _urls(arc.select(everything=True)) == _urls([a, b, hello])
    assert arc.select() == []


def test_select_unknown(arc: ARCClient, ce: FakeARex) -> None:
    stranger = f"{ce.url}/rest/1.0/jobs/elsewhere"
    [job] = arc.select([stranger])
    assert (job.ce, job.id) == (ce.url, "elsewhere")
    with pytest.raises(JobNotFoundError, match="'nosuch' is not in the job list"):
        arc.select(["nosuch"])


def test_select_by_ce_alias_and_group(
    make_arc: MakeArc, ce: FakeARex, make_ce: MakeCE, tmp_path: Path
) -> None:
    other = make_ce()
    services = {
        "one": Service("one", ce.url, groups=("both",)),
        "two": Service("two", other.url, groups=("both",)),
    }
    arc = make_arc(config=UserConfig(joblist=tmp_path / "jobs.dat", services=services))
    a, b, hello = _three(arc, ce, other)
    assert _urls(arc.select(ces=["one"])) == _urls([a, b])
    assert _urls(arc.select(ces=["both"])) == _urls([a, b, hello])
    assert _urls(arc.select(["hello", "a"], ces=["two"])) == [hello.url]
    assert _urls(arc.select(states=["finished"])) == _urls([a, b, hello])


# ---------------------------------------------------------------------------
# Status and waiting
# ---------------------------------------------------------------------------


def test_status_refreshes_and_reports_unknown_jobs(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    missing = Job(ce=ce.url, id="gone")
    known, unknown = arc.status([Job.from_url(url), missing])
    assert known.ok
    assert known.job.state is JobState.RUNNING
    assert known.job.owner == USER_DN
    assert (unknown.ok, unknown.status) == (False, 404)
    assert unknown.reason


def test_status_with_a_ce_that_is_down(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce)
    down = Job(ce=dead_ce(), id="x")
    alive, dead = arc.status([Job.from_url(url), down])
    assert alive.ok
    assert not dead.ok
    assert "Connection failed" in dead.reason


def test_wait_polls_until_terminal(make_arc: MakeArc, make_ce: MakeCE) -> None:
    ce = make_ce(progression=("ACCEPTING", "RUNNING", "FINISHED"))
    arc = make_arc()
    _, url = job_of(ce)
    rounds: list[list[str]] = []
    pauses: list[float] = []
    final = arc.wait(
        [Job.from_url(url), Job(ce=ce.url, id="gone")],
        interval=0.5,
        callback=lambda outcomes: rounds.append([o.job.state.value for o in outcomes]),
        sleep=pauses.append,
    )
    assert [o.job.state for o in final] == [JobState.FINISHED, JobState.UNDEFINED]
    assert not final[1].ok
    assert rounds[0][1] == "Undefined"
    assert len(rounds[-1]) == 1
    assert pauses == [0.5] * (len(rounds) - 1)


def test_wait_times_out(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    now = [100.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    with pytest.raises(ARCError, match="1 jobs still not finished") as caught:
        arc.wait([Job.from_url(url)], interval=2, timeout=5, sleep=sleep, clock=lambda: now[0])
    assert caught.value.code == errno.ETIMEDOUT
    assert now[0] == 104.0


def test_wait_without_timeout_or_callback(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, state="FINISHED")
    [done] = arc.wait([Job.from_url(url)], sleep=never_sleep)
    assert done.job.state is JobState.FINISHED


# ---------------------------------------------------------------------------
# Bulk management
# ---------------------------------------------------------------------------


def test_kill_refuses_finished_jobs(arc: ARCClient, ce: FakeARex) -> None:
    running, running_url = job_of(ce, state="RUNNING")
    finished = Job.from_url(job_of(ce, state="FINISHED")[1], state=JobState.FINISHED)
    killed, refused = arc.kill([Job.from_url(running_url), finished])
    assert (killed.ok, killed.status) == (True, 202)
    assert running.kill_requested
    assert (refused.ok, refused.reason) == (False, "The job is already finished")
    assert len(_posts(ce, "kill")) == 1


def test_bulk_with_a_ce_that_is_down(arc: ARCClient) -> None:
    [outcome] = arc.resume([Job(ce=dead_ce(), id="x")])
    assert not outcome.ok
    assert "Connection failed" in outcome.reason


def test_clean_forgets_cleaned_and_unknown_jobs(arc: ARCClient, ce: FakeARex) -> None:
    jobs = [s.job for s in arc.submit(ce.url, MULTI, delegate=False) if s.job]
    stubborn = Job(ce=ce.url, id=_submit_one(arc, ce, delegate=False).id)
    ce.jobs[stubborn.id].refuse["clean"] = "Busy"
    gone = Job(ce=ce.url, id="gone")
    arc._record([gone])
    outcomes = arc.clean([*jobs, stubborn, gone])
    assert [o.ok for o in outcomes] == [True, True, False, False]
    assert outcomes[2].reason == "Busy"
    assert outcomes[3].status == 404
    assert [j.id for j in arc.known()] == [stubborn.id]


def test_clean_can_keep_the_job_list(arc: ARCClient, ce: FakeARex) -> None:
    job = _submit_one(arc, ce, delegate=False)
    [outcome] = arc.clean([job], forget=False)
    assert outcome.ok
    assert _urls(arc.known()) == [job.url]


def test_resume_restarts_failed_jobs(arc: ARCClient, ce: FakeARex) -> None:
    fake, url = job_of(ce, '&(executable="/bin/x")(rerun="1")')
    ce.fail_job(fake.id)
    [ok] = arc.resume([Job.from_url(url)])
    assert ok.ok
    assert fake.restarts == 1
    [again] = arc.resume([Job.from_url(url)])
    assert (again.ok, again.reason) == (False, "Job has not failed")


# ---------------------------------------------------------------------------
# Delegation renewal
# ---------------------------------------------------------------------------


def test_renew_once_per_delegation(arc: ARCClient, ce: FakeARex) -> None:
    jobs = [s.job for s in arc.submit(ce.url, MULTI) if s.job]
    outcomes = arc.renew(jobs)
    assert all(o.ok for o in outcomes), outcomes
    [delegation] = ce.delegations.values()
    assert delegation.renewals == 1


def test_renew_asks_the_ce_for_the_delegations(arc: ARCClient, ce: FakeARex) -> None:
    delegation_id = arc.delegate(ce.url)
    _, url = job_of(ce, f'&(executable="/bin/x")(delegationid="{delegation_id}")')
    [outcome] = arc.renew([Job.from_url(url)])
    assert outcome.ok
    assert ce.delegations[delegation_id].renewals == 1


def test_renew_without_any_delegation(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce)
    [plain] = arc.renew([Job.from_url(url)])
    assert (plain.ok, plain.reason) == (False, "The CE knows of no delegation for this job")


def test_renew_says_why_the_delegations_are_unknown(arc: ARCClient, ce: FakeARex) -> None:
    gone, down = arc.renew([Job(ce=ce.url, id="gone"), Job(ce=dead_ce(), id="x")])
    assert not gone.ok
    assert gone.reason not in ("", "The CE knows of no delegation for this job")
    assert not down.ok
    assert "Connection failed" in down.reason


def test_renew_failure(arc: ARCClient, ce: FakeARex) -> None:
    job = Job(ce=ce.url, id="x", delegations=("d1",))
    ce.fault("POST", r"action=renew", status=403, reason="Renewal refused")
    down = Job(ce=dead_ce(), id="x", delegations=("d1",))
    refused, unreachable = arc.renew([job, down])
    assert (refused.ok, refused.reason) == (False, "Renewal refused")
    assert not unreachable.ok
    assert "Connection failed" in unreachable.reason


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

FILES = {"out.txt": b"hello\n", "sub/dir/data": b"12345"}


def test_files_walks_the_session(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, files=FILES)
    assert sorted(arc.files(Job.from_url(url))) == [("out.txt", 6), ("sub/dir/data", 5)]
    assert list(arc.files(Job.from_url(url), "sub")) == [("sub/dir/data", 5)]


def test_retrieve_downloads_the_session(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    _, url = job_of(ce, files=FILES, state="FINISHED")
    seen: list[tuple[str, int]] = []
    job = Job.from_url(url)
    target = arc.retrieve(job, tmp_path / "dl", progress=lambda p, n: seen.append((p, n)))
    assert target == tmp_path / "dl" / job.id
    assert (target / "sub" / "dir" / "data").read_bytes() == b"12345"
    assert sorted(seen) == [("out.txt", 6), ("sub/dir/data", 5)]
    assert not (target / "diagnose").exists()


def test_retrieve_refuses_an_existing_target(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    _, url = job_of(ce, files=FILES)
    job = Job.from_url(url)
    (tmp_path / "named").mkdir()
    (tmp_path / "named" / "stale").write_text("old")
    with pytest.raises(ARCError, match="already exists") as caught:
        arc.retrieve(job, tmp_path, name="named")
    assert caught.value.code == errno.EEXIST
    target = arc.retrieve(job, tmp_path, name="named", force=True)
    # As arcget -f: the job's files are written into it, what else is there stays.
    assert sorted(p.name for p in target.iterdir()) == ["out.txt", "stale", "sub"]


def test_retrieve_saves_gmlog_from_diagnose(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    fake, url = job_of(ce, '&(executable="/bin/x")(gmlog="logs/gm")', state="FINISHED")
    job = Job.from_url(url, log_dir="./logs//gm")
    target = arc.retrieve(job, tmp_path)
    saved = sorted(p.name for p in (target / "logs" / "gm").iterdir())
    assert "errors" in saved
    assert "failed" not in saved
    assert (target / "logs" / "gm" / "description").read_text() == fake.description


@pytest.mark.parametrize("log_dir", [None, "../escape", "/diagnose", "/"])
def test_diagnose_flag_saves_into_diagnose(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, log_dir: str | None
) -> None:
    _, url = job_of(ce)
    target = arc.retrieve(Job.from_url(url, log_dir=log_dir), tmp_path, diagnose=True)
    assert (target / "diagnose" / "status").is_file()
    assert sorted(p.name for p in target.iterdir()) == ["diagnose"]


def test_unsafe_log_dir_without_diagnose_saves_nothing(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    _, url = job_of(ce)
    target = arc.retrieve(Job.from_url(url, log_dir="a/../../x"), tmp_path)
    assert list(target.iterdir()) == []


def test_diagnose_errors_other_than_404_propagate(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    _, url = job_of(ce)
    ce.fault("GET", r"/diagnose/failed", status=403, reason="Nope")
    with pytest.raises(HTTPError, match="Nope"):
        arc.retrieve(Job.from_url(url), tmp_path, diagnose=True)


def test_get_downloads_and_cleans(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    job = _submit_one(arc, ce, delegate=False)
    ce.set_state(job.id, "FINISHED", exit_code=0)
    (ce.session_dir(job.id) / "out.txt").write_text("hi")
    [outcome] = arc.get([job], tmp_path / "dl", use_names=True, workers=0)
    assert outcome.ok, outcome.reason
    assert outcome.path == tmp_path / "dl" / "hello"
    assert (outcome.path / "out.txt").read_text() == "hi"
    assert outcome.reason == ""
    assert arc.known() == []
    assert len(_posts(ce, "clean")) == 1


def test_get_skips_jobs_that_are_not_ready(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    running = Job.from_url(job_of(ce, state="RUNNING")[1])
    wiped = Job.from_url(job_of(ce, state="WIPED")[1])
    missing = Job(ce=ce.url, id="gone")
    outcomes = arc.get([running, wiped, missing], tmp_path, keep=True)
    assert [o.ok for o in outcomes] == [False, False, False]
    assert outcomes[0].reason == "The job is not finished (Running)"
    assert outcomes[1].reason == "The job's files have been deleted on the CE"
    assert outcomes[2].status == 404
    assert _posts(ce, "clean") == []


def test_get_reports_download_and_clean_failures(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    exists, exists_url = job_of(ce, state="FINISHED")
    stubborn, stubborn_url = job_of(ce, state="FAILED")
    stubborn.refuse["clean"] = "Busy"
    (tmp_path / exists.id).mkdir()
    blocked, cleaned = arc.get([Job.from_url(exists_url), Job.from_url(stubborn_url)], tmp_path)
    assert not blocked.ok
    assert "already exists" in blocked.reason
    assert cleaned.ok
    assert cleaned.reason == "not cleaned: Busy"
    assert cleaned.path == tmp_path / stubborn.id


def test_cat_stdout_stderr_joblog_and_paths(arc: ARCClient, ce: FakeARex) -> None:
    files = {"out.txt": b"OUT", "err.txt": b"ERR", "other": b"OTHER"}
    _, url = job_of(ce, files=files)
    job = Job.from_url(url, stdout="out.txt", stderr="err.txt")
    for what, expected in [("stdout", b"OUT"), ("stderr", b"ERR"), ("other", b"OTHER")]:
        out = io.BytesIO()
        assert arc.cat(job, out, what) == len(expected)
        assert out.getvalue() == expected
    log = io.BytesIO()
    assert arc.cat(job, log, "joblog") == len(log.getvalue()) > 0
    assert b"ACCEPTED" in log.getvalue()


def test_cat_asks_the_ce_for_the_stdout_name(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, files={"out.txt": b"OUT"})
    out = io.BytesIO()
    arc.cat(Job.from_url(url), out)
    assert out.getvalue() == b"OUT"


def test_cat_without_a_stdout(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, '&(executable="/bin/x")')
    with pytest.raises(ARCError, match="does not name a stderr file") as caught:
        arc.cat(Job.from_url(url), io.BytesIO(), "stderr")
    assert caught.value.code == errno.ENOENT


def test_diagnose_item(arc: ARCClient, ce: FakeARex) -> None:
    fake, url = job_of(ce)
    assert arc.diagnose(Job.from_url(url), "description").decode() == fake.description


# ---------------------------------------------------------------------------
# Information and synchronisation
# ---------------------------------------------------------------------------


def test_info(arc: ARCClient, ce: FakeARex) -> None:
    info = arc.info(ce.url)
    assert info.name == "fake-arex"
    assert [q.name for q in info.queues if not q.vo_share] == ["main"]


def test_sync_adds_new_jobs(arc: ARCClient, ce: FakeARex) -> None:
    assert arc.sync(ce.url) == []
    known = _submit_one(arc, ce)
    _, url = job_of(ce)
    [new] = arc.sync(ce.url)
    assert new.url == url
    assert arc.sync(ce.url) == []
    assert {j.url for j in arc.known()} == {known.url, url}


def test_sync_replace_all(arc: ARCClient, ce: FakeARex) -> None:
    arc._record([Job(ce=ce.url, id="stale")])
    delegation_id = arc.delegate(ce.url)
    _, url = job_of(ce, f'&(executable="/bin/x")(delegationid="{delegation_id}")')
    [new] = arc.sync(ce.url, replace_all=True)
    assert new.delegations == (delegation_id,)
    assert [j.url for j in arc.known()] == [url]


def test_outcome_defaults() -> None:
    outcome = Outcome(Job(ce="https://ce.example:443/arex", id="1"), True)
    assert (outcome.reason, outcome.path, outcome.status) == ("", None, 0)
