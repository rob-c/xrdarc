"""The A-REX REST layer against the fake A-REX: wire shapes and the quirks absorbed."""

from __future__ import annotations

import errno
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from xrdsec.testing.pki import PKI

from _arex import USER_DN, add_job
from xrdarc import rest as rest_module
from xrdarc.errors import ARCError, HTTPError
from xrdarc.proxy import sign_request
from xrdarc.rest import BulkResult, Listing, RESTClient, SubmitResult, as_list
from xrdarc.testing.arex import FakeARex
from xrdarc.transport import Session

pytest_plugins = ["_arex"]

XRSL = '&(executable="/bin/echo")(jobname="hello")'
MakeCE = Callable[..., FakeARex]


def _answer(
    ce: FakeARex, method: str, pattern: str, doc: Any, status: int = 200, **kwargs: Any
) -> None:
    """Make the CE answer the next matching request with ``doc`` as JSON."""
    body = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    headers = {"Content-Type": "application/json", **kwargs.pop("headers", {})}
    ce.fault(method, pattern, status=status, body=body, headers=headers, **kwargs)


def _client(ce: FakeARex, session: Session, version: str | None = None) -> RESTClient:
    return RESTClient(ce.url, session, version=version)


def _sign(csr: str, pki: PKI) -> str:
    """The chain a client would upload for ``csr``: a proxy of the PKI's proxy, then its chain."""
    return sign_request(csr, pki.credential())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, []), ("", []), ("a", ["a"]), (["a", "b"], ["a", "b"]), ({}, [{}])],
)
def test_as_list(value: Any, expected: list[Any]) -> None:
    assert as_list(value) == expected


def test_result_ok() -> None:
    assert SubmitResult(201, "Created", "abc", "ACCEPTING").ok
    assert not SubmitResult(201, "Created", None, None).ok
    assert not SubmitResult(500, "No", "abc", None).ok
    assert BulkResult("a", 202, "Queued").ok
    assert not BulkResult("a", 505, "No").ok
    assert not BulkResult("a", 0, "").ok


# ---------------------------------------------------------------------------
# Version negotiation and decoding
# ---------------------------------------------------------------------------


def test_highest_common_version_is_chosen_once(ce: FakeARex, rest: RESTClient) -> None:
    assert rest.version == "1.1"
    assert rest.base == f"{ce.url}/rest/1.1"
    rest.info()
    assert [r.path for r in ce.requests] == ["/arex/rest", "/arex/rest/1.1/info"]
    assert ce.requests[0].header("Accept") == "application/json"


def test_an_old_ce_is_spoken_to_in_1_0(make_ce: MakeCE, session: Session) -> None:
    assert _client(make_ce(versions=("1.0",)), session).version == "1.0"


@pytest.mark.parametrize(("offered", "shown"), [(("2.0", "0.9"), "2.0, 0.9"), ((), "none")])
def test_no_common_version_is_refused(
    make_ce: MakeCE, session: Session, offered: tuple[str, ...], shown: str
) -> None:
    client = _client(make_ce(versions=offered), session)
    with pytest.raises(ARCError, match=f"offers REST versions {shown}; ") as caught:
        _ = client.version
    assert caught.value.errno == errno.EPROTONOSUPPORT
    assert caught.value.url == client.ce


def test_a_pinned_version_is_not_negotiated(ce: FakeARex, session: Session) -> None:
    client = _client(ce, session, version="1.0")
    client.jobs()
    assert [r.path for r in ce.requests] == ["/arex/rest/1.0/jobs"]


def test_versions_lists_what_the_ce_offers(ce: FakeARex, rest: RESTClient) -> None:
    assert rest.versions() == ["1.0", "1.1"]


def test_legacy_json_scalar_version(make_ce: MakeCE, session: Session) -> None:
    client = _client(make_ce(versions=("1.0",), legacy_json=True), session)
    assert client.versions() == ["1.0"]


@pytest.mark.parametrize(
    ("headers", "kind"), [({"Content-Type": "text/html"}, "text/html"), ({}, "unknown content")]
)
def test_html_answer_is_a_protocol_error(
    ce: FakeARex, rest: RESTClient, headers: dict[str, str], kind: str
) -> None:
    ce.fault("GET", "/rest$", status=200, body=b"<html><body>hi</body></html>", headers=headers)
    with pytest.raises(ARCError, match=f"other than JSON \\({kind}\\)") as caught:
        rest.versions()
    assert caught.value.errno == errno.EPROTO


@pytest.mark.parametrize("doc", [["1.1"], "1.1", 7])
def test_json_that_is_not_an_object_is_a_protocol_error(
    ce: FakeARex, rest: RESTClient, doc: Any
) -> None:
    _answer(ce, "GET", "/rest$", doc)
    with pytest.raises(ARCError, match="unexpected JSON") as caught:
        rest.versions()
    assert caught.value.errno == errno.EPROTO


# ---------------------------------------------------------------------------
# Information and job lists
# ---------------------------------------------------------------------------


def test_info_is_the_glue2_document(rest: RESTClient) -> None:
    doc = rest.info()
    assert "Domains" in doc


def test_jobs_lists_ids(ce: FakeARex, rest: RESTClient) -> None:
    first, second = add_job(ce), add_job(ce)
    ce.add_job("/CN=somebody else")
    assert sorted(rest.jobs()) == sorted([(first.id, None), (second.id, None)])
    assert "state" not in ce.requests[-1].query


def test_jobs_filtered_by_state(ce: FakeARex, rest: RESTClient) -> None:
    done = add_job(ce, state="FINISHED")
    add_job(ce, state="RUNNING")
    failed = add_job(ce, state="FAILED")
    found = rest.jobs(["FINISHED", "FAILED"])
    assert sorted(found) == sorted([(done.id, "FINISHED"), (failed.id, "FAILED")])
    assert ce.requests[-1].query["state"] == "FINISHED,FAILED"


def test_no_jobs_on_a_legacy_ce(make_ce: MakeCE, session: Session) -> None:
    assert _client(make_ce(legacy_json=True), session).jobs() == []


def test_single_job_on_a_legacy_ce(make_ce: MakeCE, session: Session) -> None:
    ce = make_ce(legacy_json=True)
    job = add_job(ce)
    assert _client(ce, session).jobs() == [(job.id, None)]


def test_job_entries_without_ids_are_skipped(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "GET", "/jobs", {"job": [{"state": "RUNNING"}, "junk", {"id": "abc"}]})
    assert rest.jobs() == [("abc", None)]


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------


def test_submit_on_1_1_sends_the_parameters(ce: FakeARex, rest: RESTClient) -> None:
    results = rest.submit(XRSL, queue="main", delegation_id="d1", instances=2, instances_min=1)
    sent = ce.requests[-1]
    assert sent.query == {
        "action": "new",
        "queue": "main",
        "delegation_id": "d1",
        "instances": "2",
        "instances_min": "1",
    }
    assert sent.header("Content-Type") == "application/xml"
    assert sent.body == XRSL.encode()
    assert len(results) == 2
    assert all(r.ok and r.id in ce.jobs and r.state == "ACCEPTING" for r in results)
    assert ce.jobs[results[0].id or ""].queue == "main"


def test_submit_on_1_1_leaves_out_unset_parameters(ce: FakeARex, rest: RESTClient) -> None:
    rest.submit(XRSL.encode())
    assert ce.requests[-1].query == {"action": "new"}


def test_submit_on_1_0_never_sends_1_1_parameters(ce: FakeARex, session: Session) -> None:
    client = _client(ce, session, version="1.0")
    (result,) = client.submit(XRSL, queue="main", delegation_id="d1", instances=2)
    assert ce.requests[-1].path == "/arex/rest/1.0/jobs"
    assert ce.requests[-1].query == {"action": "new"}
    assert result.ok


def test_submit_failures_carry_no_id(ce: FakeARex, rest: RESTClient) -> None:
    ce.reject_next("Not allowed here")
    (result,) = rest.submit(XRSL)
    assert result == SubmitResult(500, "Not allowed here", None, None)
    assert not result.ok


def test_submit_multi_keeps_description_order(ce: FakeARex, rest: RESTClient) -> None:
    ce.reject_next("first fails")
    results = rest.submit(f"+({XRSL[1:]})({XRSL[1:]})")
    assert [r.ok for r in results] == [False, True]


def test_submit_tolerates_odd_entries(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "POST", "action=new", {"job": ["junk", {"status-code": "x"}]}, status=201)
    assert rest.submit(XRSL) == [SubmitResult(0, "", None, None)] * 2


def test_submit_refused_as_a_whole(ce: FakeARex, rest: RESTClient) -> None:
    with pytest.raises(HTTPError, match="Payload is not recognized"):
        rest.submit("garbage")


# ---------------------------------------------------------------------------
# Bulk actions
# ---------------------------------------------------------------------------


def test_status_of_several_jobs(ce: FakeARex, rest: RESTClient) -> None:
    running = add_job(ce, state="RUNNING")
    done = add_job(ce, state="FINISHED")
    results = rest.status([running.id, "nosuchjob", done.id])
    assert [(r.id, r.status, r.state) for r in results] == [
        (running.id, 200, "RUNNING"),
        ("nosuchjob", 404, "None"),
        (done.id, 200, "FINISHED"),
    ]
    sent = ce.requests[-1]
    assert sent.query == {"action": "status"}
    assert sent.header("Content-Type") == "application/json"
    assert json.loads(sent.body) == {
        "job": [{"id": running.id}, {"id": "nosuchjob"}, {"id": done.id}]
    }


def test_job_info_returns_the_computing_activity(ce: FakeARex, rest: RESTClient) -> None:
    job = add_job(ce, state="FINISHED", exit_code=3)
    (result,) = rest.job_info([job.id])
    assert result.ok
    assert result.info["ExitCode"] == "3"
    (missing,) = rest.job_info(["nosuchjob"])
    assert (missing.status, missing.info) == (404, {})


def test_kill_clean_and_restart(ce: FakeARex, rest: RESTClient) -> None:
    job = add_job(ce, state="RUNNING")
    assert [(r.status, r.reason) for r in rest.kill([job.id])] == [(202, "Queued for killing")]
    assert [r.status for r in rest.restart([job.id])] == [505]
    assert [r.status for r in rest.clean([job.id])] == [202]
    assert [r.query["action"] for r in ce.requests[-3:]] == ["kill", "restart", "clean"]


def test_job_delegations(ce: FakeARex, rest: RESTClient) -> None:
    delegation_id, _ = rest.new_delegation()
    job = add_job(ce, description=f'&(executable="x")(delegationid="{delegation_id}")')
    (result,) = rest.job_delegations([job.id])
    assert result.delegations == (delegation_id,)


def test_bulk_is_split_into_chunks(
    ce: FakeARex, rest: RESTClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rest_module, "BULK_CHUNK", 2)
    jobs = [add_job(ce, state="RUNNING").id for _ in range(5)]
    _ = rest.version
    ce.clear()
    results = rest.status(jobs)
    assert [r.id for r in results] == jobs
    assert all(r.ok for r in results)
    sizes = [len(json.loads(r.body)["job"]) for r in ce.requests]
    assert sizes == [2, 2, 1]


def test_bulk_of_nothing_sends_nothing(ce: FakeARex, rest: RESTClient) -> None:
    assert rest.status([]) == []
    assert ce.requests == []


def test_ids_left_out_of_the_answer_get_status_0(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "POST", "action=status", {"job": []}, status=201)
    results = rest.status(["a", "b"])
    assert results == [
        BulkResult("a", 0, "The CE did not answer for this job"),
        BulkResult("b", 0, "The CE did not answer for this job"),
    ]


def test_legacy_empty_bulk_answer(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "POST", "action=status", b"", status=201)
    assert [r.status for r in rest.status(["a"])] == [0]


def test_answers_without_ids_are_matched_by_position(ce: FakeARex, rest: RESTClient) -> None:
    doc = {"job": [{"status-code": "200", "reason": "OK", "state": "RUNNING"}, "junk"]}
    _answer(ce, "POST", "action=status", doc, status=201)
    first, second, third = rest.status(["a", "b", "c"])
    assert (first.id, first.status, first.state) == ("a", 200, "RUNNING")
    assert (second.status, third.status) == (0, 0)


def test_a_single_legacy_entry_is_a_list(ce: FakeARex, rest: RESTClient) -> None:
    doc = {"job": {"id": "a", "status-code": "202", "reason": "Queued for killing"}}
    _answer(ce, "POST", "action=kill", doc, status=201)
    assert rest.kill(["a"]) == [BulkResult("a", 202, "Queued for killing")]


def test_answers_are_matched_by_id_before_position(ce: FakeARex, rest: RESTClient) -> None:
    doc = {"job": [{"id": "b", "status-code": "404"}, {"id": "a", "status-code": "200"}]}
    _answer(ce, "POST", "action=status", doc, status=201)
    assert [(r.id, r.status) for r in rest.status(["a", "b"])] == [("a", 200), ("b", 404)]


def test_an_answer_for_another_job_is_not_taken_by_position(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "POST", "action=status", {"job": [{"id": "x", "status-code": "200"}]}, status=201)
    assert [r.status for r in rest.status(["a"])] == [0]


@pytest.mark.parametrize("info", ["", "text", {"ComputingActivity": "text"}, {"Other": {}}])
def test_odd_info_documents_give_no_info(ce: FakeARex, rest: RESTClient, info: Any) -> None:
    doc = {"job": [{"id": "a", "status-code": "200", "info_document": info}]}
    _answer(ce, "POST", "action=info", doc, status=201)
    assert rest.job_info(["a"])[0].info == {}


def test_bulk_bad_status_code(ce: FakeARex, rest: RESTClient) -> None:
    _answer(ce, "POST", "action=status", {"job": [{"id": "a", "status-code": "?"}]}, status=201)
    assert rest.status(["a"])[0].status == 0


def test_bulk_refused_as_a_whole(ce: FakeARex, rest: RESTClient) -> None:
    ce.denied.add("JobInfo")
    with pytest.raises(HTTPError, match="Operation is not allowed"):
        rest.status(["a"])


# ---------------------------------------------------------------------------
# Session directory
# ---------------------------------------------------------------------------


@pytest.fixture
def job_id(ce: FakeARex) -> str:
    files = {"out.txt": b"hello\n", "sub/deeper/b.dat": b"xyz", "sub/a.txt": b""}
    job = add_job(ce, files=files)
    (job.session / "empty").mkdir()
    return job.id


def test_listing_has_sizes(ce: FakeARex, rest: RESTClient, job_id: str) -> None:
    listing = rest.listing(job_id)
    assert listing == Listing({"out.txt": 6}, ("empty", "sub"))
    sent = ce.requests[-1]
    assert sent.path == f"/arex/rest/1.1/jobs/{job_id}/session/"
    assert sent.header("Accept") == "application/xml"


def test_listing_of_a_subdirectory(rest: RESTClient, job_id: str) -> None:
    assert rest.listing(job_id, "/sub/") == Listing({"a.txt": 0}, ("deeper",))


def test_walk_recurses_depth_first(rest: RESTClient, job_id: str) -> None:
    assert list(rest.walk(job_id)) == [("out.txt", 6), ("sub/a.txt", 0), ("sub/deeper/b.dat", 3)]
    assert list(rest.walk(job_id, "/sub/")) == [("sub/a.txt", 0), ("sub/deeper/b.dat", 3)]


def test_listing_tolerates_odd_entries(ce: FakeARex, rest: RESTClient, job_id: str) -> None:
    body = (
        b"<list><file>nosize</file><file size='big'>bad</file><file> </file>"
        b"<dir/><link>x</link><dir> d </dir></list>"
    )
    ce.fault("GET", "/session/$", status=200, body=body)
    assert rest.listing(job_id) == Listing({"nosize": None, "bad": -1}, ("d",))


@pytest.mark.parametrize(
    "body",
    [b"<list><file>", b'<!DOCTYPE l [<!ENTITY e "x">]><list>&e;</list>', b"not xml"],
)
def test_unreadable_listing_is_a_protocol_error(
    ce: FakeARex, rest: RESTClient, job_id: str, body: bytes
) -> None:
    ce.fault("GET", "/session/$", status=200, body=body)
    with pytest.raises(ARCError, match="unreadable directory listing") as caught:
        rest.listing(job_id)
    assert caught.value.errno == errno.EPROTO


def test_get_read_and_stream_files(rest: RESTClient, job_id: str, tmp_path: Path) -> None:
    target = tmp_path / "copy.dat"
    assert rest.get_file(job_id, "sub/deeper/b.dat", target) == 3
    assert target.read_bytes() == b"xyz"
    assert rest.read_file(job_id, "out.txt") == b"hello\n"
    out = io.BytesIO()
    assert rest.stream_file(job_id, "./out.txt", out) == 6
    assert out.getvalue() == b"hello\n"


def test_missing_file_is_an_http_error(rest: RESTClient, job_id: str) -> None:
    with pytest.raises(HTTPError) as caught:
        rest.read_file(job_id, "nope")
    assert caught.value.status == 404


def test_put_and_delete_files(ce: FakeARex, rest: RESTClient, job_id: str, tmp_path: Path) -> None:
    source = tmp_path / "in.dat"
    source.write_bytes(b"input")
    assert rest.put_file(job_id, "inputs/in.dat", source) == 5
    session = ce.jobs[job_id].session
    assert (session / "inputs" / "in.dat").read_bytes() == b"input"
    rest.delete_file(job_id, "inputs/in.dat")
    assert not (session / "inputs" / "in.dat").exists()
    assert ce.requests[-1].method == "DELETE"


def test_session_paths_are_quoted(ce: FakeARex, rest: RESTClient, job_id: str) -> None:
    (ce.jobs[job_id].session / "a b#c?.txt").write_bytes(b"odd")
    assert rest.read_file(job_id, "a b#c?.txt") == b"odd"
    assert ce.requests[-1].target.endswith("/session/a%20b%23c%3F.txt")
    assert rest.session_url("id/x", "") == f"{rest.base}/jobs/id%2Fx/session"


@pytest.mark.parametrize("path", ["../other/out.txt", "sub/../../x", ".."])
def test_paths_out_of_the_session_are_refused(
    ce: FakeARex, rest: RESTClient, job_id: str, path: str
) -> None:
    ce.clear()
    with pytest.raises(ARCError, match="outside the job") as caught:
        rest.read_file(job_id, path)
    assert caught.value.errno == errno.EINVAL
    assert ce.requests == []


@pytest.mark.parametrize("path", ["", "/", "./"])
def test_whole_session_paths_are_refused_for_put_and_delete(
    ce: FakeARex, rest: RESTClient, job_id: str, tmp_path: Path, path: str
) -> None:
    ce.clear()
    with pytest.raises(ARCError, match="needs a file name") as caught:
        rest.put_file(job_id, path, tmp_path)
    assert caught.value.errno == errno.EINVAL
    with pytest.raises(ARCError, match="whole session directory") as caught:
        rest.delete_file(job_id, path)
    assert caught.value.errno == errno.EINVAL
    assert ce.requests == []


def test_diagnose(ce: FakeARex, rest: RESTClient) -> None:
    job = add_job(ce)
    job.diagnose["comment"] = "a comment"
    assert rest.diagnose(job.id, "comment") == b"a comment"
    assert ce.requests[-1].path == f"/arex/rest/1.1/jobs/{job.id}/diagnose/comment"


def test_unknown_diagnose_item_is_refused_locally(ce: FakeARex, rest: RESTClient) -> None:
    with pytest.raises(ARCError, match="Unknown diagnostic item") as caught:
        rest.diagnose("abc", "../../etc/passwd")
    assert caught.value.errno == errno.EINVAL
    assert ce.requests == []


# ---------------------------------------------------------------------------
# Delegations
# ---------------------------------------------------------------------------


def test_x509_delegation_round_trip(ce: FakeARex, rest: RESTClient, pki: PKI) -> None:
    delegation_id, csr = rest.new_delegation()
    assert ce.requests[-1].query == {"action": "new", "type": "x509"}
    assert csr.startswith("-----BEGIN CERTIFICATE REQUEST-----")
    chain = _sign(csr, pki)
    rest.put_delegation(delegation_id, chain)
    assert ce.requests[-1].header("Content-Type") == "application/x-pem-file"
    assert ce.delegations[delegation_id].uploads == 1
    assert rest.get_delegation(delegation_id) == chain
    assert rest.renew_delegation(delegation_id).startswith("-----BEGIN CERTIFICATE REQUEST")
    assert ce.delegations[delegation_id].renewals == 1
    assert rest.delegations() == [(delegation_id, "x509")]
    rest.delete_delegation(delegation_id)
    assert rest.delegations() == []


def test_new_delegation_on_1_0_names_no_type(ce: FakeARex, session: Session) -> None:
    delegation_id, _ = _client(ce, session, version="1.0").new_delegation()
    assert ce.requests[-1].query == {"action": "new"}
    assert ce.delegations[delegation_id].type == "x509"


def test_token_delegation(ce: FakeARex, rest: RESTClient) -> None:
    delegation_id = rest.new_token_delegation("my.jwt.token")
    assert ce.requests[-1].query == {"action": "new", "type": "jwt"}
    assert ce.delegations[delegation_id].token == "my.jwt.token"
    assert rest.delegations("jwt") == [(delegation_id, "jwt")]
    assert ce.requests[-1].query == {"type": "jwt"}
    assert rest.delegations("x509") == []


def test_token_delegation_needs_1_1(ce: FakeARex, session: Session) -> None:
    client = _client(ce, session, version="1.0")
    with pytest.raises(ARCError, match=r"needs REST 1\.1") as caught:
        client.new_token_delegation("t")
    assert caught.value.errno == errno.EOPNOTSUPP
    assert ce.requests == []


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Location": "https://ce:443/arex/rest/1.1/delegations/abc/"}, "abc"),
        ({"location": "/arex/rest/1.1/delegations/xyz"}, "xyz"),
    ],
)
def test_delegation_id_from_location(
    ce: FakeARex, rest: RESTClient, headers: dict[str, str], expected: str
) -> None:
    ce.fault("POST", "delegations", status=201, body=b"csr", headers=headers)
    assert rest.new_delegation() == (expected, "csr")


@pytest.mark.parametrize("headers", [{}, {"Location": "/"}])
def test_delegation_without_location_is_a_protocol_error(
    ce: FakeARex, rest: RESTClient, headers: dict[str, str]
) -> None:
    ce.fault("POST", "delegations", status=201, headers=headers)
    with pytest.raises(ARCError, match="did not say where") as caught:
        rest.new_token_delegation("t")
    assert caught.value.errno == errno.EPROTO


def test_delegation_listing_tolerates_odd_entries(ce: FakeARex, rest: RESTClient) -> None:
    doc = {"delegation": [{"id": "a"}, {"type": "jwt"}, "junk", {"id": "b", "type": ""}]}
    _answer(ce, "GET", "delegations", doc)
    assert rest.delegations() == [("a", "x509"), ("b", "x509")]


def test_delegation_ids_are_quoted(ce: FakeARex, rest: RESTClient) -> None:
    with pytest.raises(HTTPError):
        rest.get_delegation("a/b")
    assert ce.requests[-1].target.endswith("/delegations/a%2Fb?action=get")


def test_identity_is_the_proxy_owner(ce: FakeARex, rest: RESTClient) -> None:
    rest.jobs()
    assert ce.requests[-1].identity == USER_DN
