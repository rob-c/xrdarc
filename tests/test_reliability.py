"""Job-lifecycle reliability and hostile-CE safety of ``ARCClient``.

Each test here pins one failure that was found in review and fixed in
0.4.0: jobs lost from the job list around submission, paths a CE could use
to write outside the download directory, ``wait`` giving up on one
transient error, Ctrl-C during ``get``, and the smaller submission checks.
The CE is the in-process fake A-REX; a *hostile* CE is the fake answering
with a canned body through :meth:`~xrdarc.testing.arex.FakeARex.fault`.
"""

from __future__ import annotations

import errno
import functools
import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from xrdcore import retry
from xrdsec import proxies
from xrdsec.testing.pki import PKI

from _arex import Ceiling, make_session
from _client_helpers import XRSL, job_of, never_sleep
from xrdarc.client import ARCClient, Submission
from xrdarc.client._model import _FetchPlan
from xrdarc.creds import Credentials
from xrdarc.errors import ARCError, CredentialError, DescriptionError
from xrdarc.joblist import Job, JobList
from xrdarc.proxy import Signer, load_signer, write_proxy
from xrdarc.rest import RESTClient, is_safe_name
from xrdarc.states import JobState
from xrdarc.testing.arex import FakeARex
from xrdarc.testing.fixtures import SessionFactory

pytest_plugins = ["_arex"]

MakeArc = Callable[..., ARCClient]
#: Two jobs that both upload ``run.sh``.
TWO_UPLOADS = '+(&(executable="run.sh")(jobname="a"))(&(executable="run.sh")(jobname="b"))'


@pytest.fixture
def arc_session_factory(sleeps: list[float]) -> SessionFactory:
    """``make_arc``'s clients retry like ``session`` and record their pauses in ``sleeps``."""
    return functools.partial(make_session, sleeps=sleeps)


@pytest.fixture
def arc(make_arc: MakeArc) -> ARCClient:
    return make_arc()


@pytest.fixture
def ceiling() -> Iterator[None]:
    previous = retry.use_rng(Ceiling())
    yield
    retry.use_rng(previous)


def _posted_ids(ce: FakeARex, action: str) -> list[str]:
    """Every job id named in the bulk POSTs with ``action``."""
    found: list[str] = []
    for request in ce.requests:
        if request.method == "POST" and request.query.get("action") == action:
            found.extend(entry["id"] for entry in json.loads(request.body)["job"])
    return found


def _json_fault(ce: FakeARex, method: str, pattern: str, doc: object, **kwargs: Any) -> None:
    body = json.dumps(doc).encode()
    headers = {"Content-Type": "application/json"}
    ce.fault(
        method, pattern, status=kwargs.pop("status", 201), body=body, headers=headers, **kwargs
    )


def _listing(ce: FakeARex, *entries: tuple[str, str], times: int = 1) -> None:
    """Make the next session listing(s) of any job list ``entries`` as ``(tag, name)``."""
    items = "".join(f'<{tag} size="1">{name}</{tag}>' for tag, name in entries)
    ce.fault(
        "GET",
        r"/session/$",
        status=200,
        body=f"<list>{items}</list>".encode(),
        headers={"Content-Type": "application/xml"},
        times=times,
    )


# ---------------------------------------------------------------------------
# P0: no accepted job goes unrecorded
# ---------------------------------------------------------------------------


def test_an_unusable_job_list_stops_submission_before_the_ce_is_contacted(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "jobs.dat").write_text("<jobs><job/></jobs>")
    with pytest.raises(ARCError, match="not an SQLite job list"):
        arc.submit(ce.url, XRSL)
    assert ce.requests == []


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="POSIX file modes, as a non-root user"
)
def test_a_read_only_job_list_stops_submission(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    JobList(tmp_path / "jobs.dat").write([Job(ce=ce.url, id="old")])
    (tmp_path / "jobs.dat").chmod(0o444)
    with pytest.raises(ARCError, match="readonly"):
        arc.submit(ce.url, XRSL)
    assert ce.jobs == {}
    assert ce.delegations == {}


def test_a_locked_job_list_stops_submission(
    make_arc: MakeArc, ce: FakeARex, tmp_path: Path
) -> None:
    path = tmp_path / "locked.dat"
    JobList(path).write([Job(ce=ce.url, id="old")])
    holder = sqlite3.connect(path)
    holder.execute("BEGIN IMMEDIATE")
    try:
        arc = make_arc(joblist=JobList(path, timeout=0.05))
        with pytest.raises(ARCError, match="locked"):
            arc.submit(ce.url, XRSL)
    finally:
        holder.close()
    assert ce.jobs == {}


def test_jobs_are_recorded_before_their_inputs_go_up(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text("x")
    seen: list[list[str]] = []
    arc.submit(
        ce.url,
        TWO_UPLOADS,
        base=tmp_path,
        progress=lambda name, sent: seen.append([j.name or "" for j in arc.known()]),
    )
    assert seen[0] == ["a", "b"]


def test_ctrl_c_during_uploads_removes_every_unstaged_job(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text("x")

    def interrupt(name: str, sent: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        arc.submit(ce.url, TWO_UPLOADS, base=tmp_path, progress=interrupt)
    both = sorted(ce.jobs)
    assert len(both) == 2
    assert sorted(_posted_ids(ce, "kill")) == both
    assert sorted(_posted_ids(ce, "clean")) == both
    assert arc.known() == []


def test_ctrl_c_keeps_an_accepted_job_that_needed_no_inputs(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text("x")

    def interrupt(name: str, sent: int) -> None:
        raise KeyboardInterrupt

    text = '+(&(executable="run.sh")(jobname="a"))(&(executable="/bin/true")(jobname="b"))'
    with pytest.raises(KeyboardInterrupt):
        arc.submit(ce.url, text, base=tmp_path, progress=interrupt)
    assert [job.name for job in arc.known()] == ["b"]
    assert len(_posted_ids(ce, "kill")) == 1


def test_a_removed_job_that_cannot_be_forgotten_is_warned_about(
    arc: ARCClient,
    ce: FakeARex,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    (tmp_path / "run.sh").write_text("x")
    ce.fault("PUT", r"/session/", status=403)

    def broken(self: JobList, urls: Any) -> int:
        raise ARCError("locked", errno.EIO)

    monkeypatch.setattr(JobList, "remove", broken)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert not submission.ok
    assert "Could not remove" in caplog.text


def test_adl_inputs_have_no_size_to_check(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text("x")
    adl = (
        '<ActivityDescription xmlns="http://www.eu-emi.eu/es/2010/12/adl">'
        "<Application><Executable><Path>run.sh</Path></Executable></Application>"
        "<DataStaging><InputFile><Name>run.sh</Name></InputFile></DataStaging>"
        "</ActivityDescription>"
    )
    [submission] = arc.submit(ce.url, adl, base=tmp_path)
    assert submission.ok, submission.reason
    assert submission.job is not None
    assert ce.jobs[submission.job.id].uploads == ["/run.sh"]


def test_a_job_that_cannot_be_removed_stays_recorded_with_the_reason(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "run.sh").write_text("x")
    ce.fault("PUT", r"/session/", status=403, reason="Not allowed")
    ce.fault("POST", r"action=kill", status=503, times=10)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert not submission.ok
    [kept] = arc.known()
    assert kept.id in ce.jobs
    assert kept.errors[0].startswith("Uploading input files failed")
    assert "could not be removed from the CE" in kept.errors[0]
    assert kept.url in caplog.text


def test_a_per_job_refusal_to_kill_also_keeps_the_job(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text("x")
    ce.fault("PUT", r"/session/", status=403)
    real = RESTClient.kill

    def refuse(self: RESTClient, ids: Any) -> Any:
        for job_id in ids:
            ce.jobs[job_id].refuse["kill"] = "Busy"
        return real(self, ids)

    ce_jobs_before = set(ce.jobs)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(RESTClient, "kill", refuse)
        [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert not submission.ok
    [kept] = arc.known()
    assert kept.id not in ce_jobs_before
    assert "kill: Busy" in kept.errors[0]


def test_a_job_list_that_fails_after_the_check_is_warned_about(
    arc: ARCClient, ce: FakeARex, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(self: JobList, jobs: Any) -> None:
        raise ARCError("disk full", errno.ENOSPC)

    monkeypatch.setattr(JobList, "write", broken)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        [submission] = arc.submit(ce.url, XRSL)
    assert submission.ok
    assert submission.job is not None
    assert submission.job.url in caplog.text
    assert "xrdarc sync" in caplog.text


def test_submit_all_reports_each_submission_as_it_is_final(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    reported: list[tuple[int, Submission]] = []
    ce.reject_next("Too many jobs")
    results = arc.submit_all(
        ce.url,
        [(XRSL, None), ('+(&(executable="/bin/a"))(&(executable="/bin/b"))', tmp_path)],
        report=lambda index, sub: reported.append((index, sub)),
    )
    assert [index for index, _ in reported] == [0, 1, 1]
    assert [s for _, s in reported] == [s for group in results for s in group]
    assert [s.ok for _, s in reported] == [False, True, True]


# ---------------------------------------------------------------------------
# P2: all-or-nothing preparation, one delegation, cleanup on a failed POST
# ---------------------------------------------------------------------------


def test_every_description_is_prepared_before_any_is_submitted(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    with pytest.raises(DescriptionError, match=r"missing\.sh"):
        arc.submit_all(ce.url, [(XRSL, None), ('&(executable="missing.sh")', tmp_path)])
    assert ce.requests == []


def test_one_delegation_serves_the_whole_submission(arc: ARCClient, ce: FakeARex) -> None:
    results = arc.submit_all(ce.url, [(XRSL, None), (XRSL, None)])
    [delegation_id] = ce.delegations
    assert [s.job.delegations for group in results for s in group if s.job] == [
        (delegation_id,),
        (delegation_id,),
    ]


def test_a_failed_post_deletes_the_unused_delegation(arc: ARCClient, ce: FakeARex) -> None:
    ce.fault("POST", r"jobs\?action=new", status=500, reason="Broken")
    with pytest.raises(ARCError, match="Broken"):
        arc.submit(ce.url, XRSL)
    assert ce.delegations == {}


def test_a_failed_post_keeps_a_delegation_earlier_jobs_use(
    arc: ARCClient, ce: FakeARex, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = RESTClient.submit
    calls = []

    def second_fails(self: RESTClient, *args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 2:
            raise ARCError("Connection failed", errno.ECONNABORTED, url=self.ce)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(RESTClient, "submit", second_fails)
    with pytest.raises(ARCError, match="Connection failed"):
        arc.submit_all(ce.url, [(XRSL, None), (XRSL, None)])
    assert len(ce.delegations) == 1
    assert len(arc.known()) == 1


def test_a_delegation_that_cannot_be_deleted_is_only_logged(
    arc: ARCClient, ce: FakeARex, caplog: pytest.LogCaptureFixture
) -> None:
    ce.fault("POST", r"jobs\?action=new", status=500, reason="Broken")
    ce.fault("POST", r"action=delete", status=403)
    with caplog.at_level(logging.DEBUG, "xrdarc"), pytest.raises(ARCError, match="Broken"):
        arc.submit(ce.url, XRSL)
    assert "could not delete delegation" in caplog.text


# ---------------------------------------------------------------------------
# P2: the delegating proxy's lifetime
# ---------------------------------------------------------------------------


def _short_signer(pki: PKI, where: Path, lifetime: float, *, now: float | None = None) -> Signer:
    """A proxy of the PKI's user with ``lifetime`` seconds from ``now``, loaded for signing."""
    user = load_signer(pki.user_cert_path, pki.user_key_path)
    path = where / f"short-{lifetime}-{now}.pem"
    write_proxy(
        path, proxies.create_proxy(user, lifetime=lifetime, bits=1024, now=now, profile="arc")
    )
    return load_signer(path)


def test_an_expired_proxy_is_refused_before_the_ce_is_contacted(
    arc: ARCClient, ce: FakeARex, pki: PKI, tmp_path: Path
) -> None:
    arc._signer = _short_signer(pki, tmp_path, 60, now=time.time() - 3600)
    with pytest.raises(CredentialError, match="expired"):
        arc.submit(ce.url, XRSL)
    assert ce.requests == []


def test_a_proxy_below_the_minimum_is_refused(
    arc: ARCClient, ce: FakeARex, pki: PKI, tmp_path: Path
) -> None:
    arc._signer = _short_signer(pki, tmp_path, 600)
    arc.min_lifetime = 3600
    with pytest.raises(CredentialError, match="less than the 3600 s required"):
        arc.submit(ce.url, XRSL)
    assert ce.requests == []


def test_a_short_proxy_is_warned_about(
    arc: ARCClient, ce: FakeARex, pki: PKI, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    arc._signer = _short_signer(pki, tmp_path, 600)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        [submission] = arc.submit(ce.url, XRSL)
    assert submission.ok
    assert "proxy has only" in caplog.text
    left = arc.check_lifetime()
    assert left is not None
    assert 0 < left <= 600


def test_lifetime_is_not_checked_without_x509_or_delegation(
    make_arc: MakeArc, ce: FakeARex, pki: PKI, tmp_path: Path
) -> None:
    arc = make_arc(credentials=Credentials(ca_dir=str(pki.ca_dir), token="t"))
    assert arc.check_lifetime() is None
    expired = make_arc()
    expired._signer = _short_signer(pki, tmp_path, 60, now=time.time() - 3600)
    [submission] = expired.submit(ce.url, XRSL, delegate=False)
    assert submission.ok


# ---------------------------------------------------------------------------
# P2: input sizes, so A-REX can verify uploads
# ---------------------------------------------------------------------------


def test_inputs_are_sent_with_their_sizes(arc: ARCClient, ce: FakeARex, tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text("12345")
    [prepared] = arc.prepare('&(executable="run.sh")', base=tmp_path)
    assert '("run.sh" "5")' in prepared.description
    assert prepared.uploads[0].size == 5


def test_an_input_that_changed_size_is_not_uploaded(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "run.sh"
    script.write_text("x")
    real = arc.prepare

    def grow(*args: Any, **kwargs: Any) -> Any:
        prepared = real(*args, **kwargs)
        script.write_text(script.read_text() + "more")
        return prepared

    monkeypatch.setattr(arc, "prepare", grow)
    [submission] = arc.submit(ce.url, '&(executable="run.sh")', base=tmp_path)
    assert not submission.ok
    assert "changed size" in submission.reason
    assert ce.jobs == {} or all(job.uploads == [] for job in ce.jobs.values())
    assert arc.known() == []


# ---------------------------------------------------------------------------
# P0: paths a CE controls never leave the download directory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "a/b", "/abs", "..\\x", "a\\b", "C:x", "c:", "x\0y"],
)
def test_unsafe_names(name: str) -> None:
    assert not is_safe_name(name)


@pytest.mark.parametrize("name", ["out.txt", "with space", "...", "a..b", "Ünïcode", "-rf"])
def test_safe_names(name: str) -> None:
    assert is_safe_name(name)


@pytest.mark.parametrize("name", ["../evil", "/tmp/evil", "..", "sub/dir"])
def test_a_job_name_that_is_not_one_safe_component_is_refused(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, name: str
) -> None:
    _, url = job_of(ce, f'&(executable="/bin/x")(jobname="{name}")', state="FINISHED")
    area = tmp_path / "area"
    target = area / "dl"
    target.mkdir(parents=True)
    [outcome] = arc.get([Job.from_url(url)], target, use_names=True)
    assert not outcome.ok
    assert "Refusing" in outcome.reason
    assert sorted(p.name for p in area.iterdir()) == ["dl"]
    assert list(target.iterdir()) == []
    assert _posted_ids(ce, "clean") == []


def test_a_job_id_used_as_the_directory_is_checked(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    with pytest.raises(ARCError, match="Refusing") as caught:
        arc.retrieve(Job(ce=ce.url, id=".."), tmp_path)
    assert caught.value.code == errno.EINVAL


@pytest.mark.parametrize(
    "entry",
    [
        ("file", "../escaped"),
        ("file", "../../escaped-dir/x"),
        ("file", "/abs"),
        ("file", "a\\..\\..\\escaped"),
        ("dir", "../../escaped-dir"),
        ("dir", ".."),
        ("file", "."),
        ("file", "C:escaped"),
    ],
)
def test_a_hostile_listing_writes_nothing_outside_the_target(
    arc: ARCClient, ce: FakeARex, tmp_path: Path, entry: tuple[str, str]
) -> None:
    _, url = job_of(ce, state="FINISHED")
    area = tmp_path / "area"
    root = area / "a" / "b"
    root.mkdir(parents=True)
    _listing(ce, entry)
    with pytest.raises(ARCError, match="unsafe") as caught:
        arc.retrieve(Job.from_url(url), root)
    assert caught.value.code == errno.EPROTO
    assert sorted(p.name for p in area.iterdir()) == ["a"]
    assert sorted(p.name for p in (area / "a").iterdir()) == ["b"]
    assert list(root.iterdir()) == []


def test_a_symlink_in_the_target_is_not_followed_out(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    fake, url = job_of(ce, state="FINISHED", files={"link/x": b"data"})
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "dl" / fake.id
    target.mkdir(parents=True)
    (target / "link").symlink_to(outside)
    with pytest.raises(ARCError, match="outside") as caught:
        arc.retrieve(Job.from_url(url), tmp_path / "dl", force=True)
    assert caught.value.code == errno.EINVAL
    assert list(outside.iterdir()) == []


def test_force_overwrites_files_and_keeps_the_rest(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    fake, url = job_of(ce, state="FINISHED", files={"out.txt": b"new"})
    target = tmp_path / fake.id
    target.mkdir()
    (target / "out.txt").write_text("old")
    (target / "mine").write_text("keep me")
    arc.retrieve(Job.from_url(url), tmp_path, force=True)
    assert (target / "out.txt").read_text() == "new"
    assert (target / "mine").read_text() == "keep me"


def test_a_log_dir_with_a_backslash_or_drive_is_not_used(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    for log_dir in ("a\\..\\..\\x", "C:x/y"):
        _, url = job_of(ce, state="FINISHED")
        target = arc.retrieve(Job.from_url(url, log_dir=log_dir), tmp_path)
        assert list(target.iterdir()) == []


def test_an_unusable_job_id_from_the_ce_fails_the_submission(arc: ARCClient, ce: FakeARex) -> None:
    answer = {"job": [{"status-code": "201", "reason": "Created", "id": "../x", "state": "NEW"}]}
    _json_fault(ce, "POST", r"jobs\?action=new", answer)
    [submission] = arc.submit(ce.url, XRSL, delegate=False)
    assert not submission.ok
    assert "unusable job id" in submission.reason
    assert arc.known() == []


def test_sync_skips_unusable_job_ids(
    arc: ARCClient, ce: FakeARex, caplog: pytest.LogCaptureFixture
) -> None:
    fake, _ = job_of(ce)
    listing = {"job": [{"id": fake.id}, {"id": "../../x"}, {"id": "a/b"}]}
    _json_fault(ce, "GET", r"/jobs$", listing, status=200)
    with caplog.at_level(logging.WARNING, "xrdarc"):
        added = arc.sync(ce.url)
    assert [job.id for job in added] == [fake.id]
    assert "'../../x'" in caplog.text


# ---------------------------------------------------------------------------
# P1: wait rides out transient trouble, with backoff
# ---------------------------------------------------------------------------


def test_status_queries_are_retried_but_actions_are_not(
    arc: ARCClient, ce: FakeARex, sleeps: list[float]
) -> None:
    _, url = job_of(ce, state="RUNNING")
    ce.fault("POST", r"action=info", status=503)
    [fresh] = arc.status([Job.from_url(url)])
    assert fresh.ok
    assert len(sleeps) == 1
    ce.fault("POST", r"action=kill", status=503)
    [killed] = arc.kill([Job.from_url(url)])
    assert not killed.ok
    assert killed.transient


@pytest.mark.usefixtures("ceiling")
def test_wait_keeps_jobs_pending_through_transient_errors(arc: ARCClient, ce: FakeARex) -> None:
    fake, url = job_of(ce, state="RUNNING")
    # Every attempt of two polls in a row fails: one 503 storm, then a lost connection.
    ce.fault("POST", r"action=info", status=503, times=3)
    ce.fault("POST", r"action=info", drop=True, times=3)
    rounds: list[tuple[bool, bool]] = []
    pauses: list[float] = []

    def callback(outcomes: Any) -> None:
        rounds.append((outcomes[0].ok, outcomes[0].transient))
        if len(rounds) == 3:
            ce.set_state(fake.id, "FINISHED", exit_code=0)

    [done] = arc.wait([Job.from_url(url)], interval=10, callback=callback, sleep=pauses.append)
    assert done.ok
    assert done.job.state is JobState.FINISHED
    assert rounds[:2] == [(False, True), (False, True)]
    # interval + full-jitter backoff at its ceiling: 10 + 10, then 10 + 20; then calm again.
    assert pauses == [20.0, 30.0, 10.0]


@pytest.mark.usefixtures("ceiling")
def test_wait_backoff_is_capped_and_respects_the_deadline(
    arc: ARCClient, ce: FakeARex, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, url = job_of(ce, state="RUNNING")
    ce.fault("POST", r"action=info", status=502, times=10_000)
    now = [0.0]
    pauses: list[float] = []

    def sleep(seconds: float) -> None:
        pauses.append(seconds)
        now[0] += seconds

    monkeypatch.setattr("xrdarc.client._monitor.POLL_BACKOFF_CAP", 25.0)
    with pytest.raises(ARCError, match="still not finished"):
        arc.wait([Job.from_url(url)], interval=10, timeout=100, sleep=sleep, clock=lambda: now[0])
    assert pauses[:3] == [20.0, 30.0, 35.0]
    assert sum(pauses) <= 100


@pytest.mark.parametrize(("status", "transient"), [(500, True), (0, True), (403, False)])
def test_per_job_answers_decide_whether_a_job_is_settled(
    arc: ARCClient, ce: FakeARex, status: int, transient: bool
) -> None:
    fake, url = job_of(ce, state="RUNNING")
    entry: dict[str, str] = {"id": fake.id, "status-code": str(status), "reason": "Busy"}
    if status == 0:
        entry = {"id": "someone-else"}
    _json_fault(ce, "POST", r"action=info", {"job": [entry]})
    [outcome] = arc.status([Job.from_url(url)])
    assert (outcome.ok, outcome.transient) == (False, transient)


def test_a_permanent_refusal_settles_the_wait(arc: ARCClient, ce: FakeARex) -> None:
    _, url = job_of(ce, state="RUNNING")
    ce.fault("POST", r"action=info", status=403, reason="Go away")
    [outcome] = arc.wait([Job.from_url(url)], interval=0, sleep=never_sleep)
    assert (outcome.ok, outcome.transient) == (False, False)
    assert "Go away" in outcome.reason


# ---------------------------------------------------------------------------
# P1: Ctrl-C during get stops at once
# ---------------------------------------------------------------------------


def test_ctrl_c_during_get_cancels_the_queued_downloads(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    urls = [job_of(ce, state="FINISHED", files={"f": b"x", "g": b"y"})[1] for _ in range(3)]

    def interrupt(path: str, written: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        arc.get([Job.from_url(u) for u in urls], tmp_path / "dl", workers=1, progress=interrupt)
    assert len(list((tmp_path / "dl").iterdir())) == 1
    assert _posted_ids(ce, "clean") == []


def test_a_stopped_get_downloads_no_further_files(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    fake, url = job_of(ce, state="FINISHED", files={"f": b"x", "g": b"y"})
    stop = threading.Event()
    stop.set()
    outcome = arc._fetch(Job.from_url(url), _FetchPlan(tmp_path, stop=stop))
    assert not outcome.ok
    assert "interrupted" in outcome.reason
    assert not (tmp_path / fake.id).exists()


def test_a_download_stopped_midway_gives_up_before_the_next_file(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    _, url = job_of(ce, state="FINISHED", files={"f": b"x", "g": b"y"})
    plan = _FetchPlan(tmp_path, progress=lambda path, n: plan.stop.set())
    outcome = arc._fetch(Job.from_url(url), plan)
    assert not outcome.ok
    assert "interrupted" in outcome.reason


def test_get_downloads_several_jobs_concurrently(
    arc: ARCClient, ce: FakeARex, tmp_path: Path
) -> None:
    urls = [job_of(ce, state="FINISHED", files={"f": b"x"})[1] for _ in range(5)]
    outcomes = arc.get([Job.from_url(u) for u in urls], tmp_path / "dl", workers=2)
    assert all(o.ok for o in outcomes)
    assert [o.job.url for o in outcomes] == urls
    assert len(list((tmp_path / "dl").iterdir())) == 5


# ---------------------------------------------------------------------------
# P1: the bearer token never shows in a repr
# ---------------------------------------------------------------------------


def test_credentials_repr_hides_the_token() -> None:
    shown = repr(Credentials(token="s3cr3t-token"))
    assert "s3cr3t-token" not in shown
    assert "Credentials(" in shown
