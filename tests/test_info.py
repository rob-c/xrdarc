"""GLUE2 JSON from A-REX: forced arrays, ARC6-style scalars and missing pieces alike."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from xrdarc.info import (
    REST_INTERFACE,
    CEInfo,
    Endpoint,
    Queue,
    parse_activity,
    parse_ce_info,
    parse_time,
)
from xrdarc.states import JobState

UTC = dt.UTC

REST_ENDPOINT = {
    "URL": "https://ce.example.org:443/arex",
    "InterfaceName": REST_INTERFACE,
    "InterfaceVersion": ["1.0", "1.1"],
    "HealthState": "ok",
    "ServingState": "production",
    "Capability": ["executionmanagement.jobcreation", "executionmanagement.jobdescription"],
}
EMIES_ENDPOINT = {
    "URL": "https://ce.example.org:443/arex",
    "InterfaceName": "org.ogf.glue.emies.activitycreation",
    "InterfaceVersion": "1.16",
    "Capability": "executionmanagement.jobcreation",
}
BATCH_SHARE = {
    "Name": "grid",
    "MappingQueue": "grid",
    "MaxWallTime": "86400",
    "MaxCPUTime": "172800",
    "DefaultWallTime": "3600",
    "RunningJobs": "4",
    "WaitingJobs": "1",
    "MaxRunningJobs": "100",
    "ServingState": "production",
}
VO_SHARE = {"Name": "grid_atlas", "MappingQueue": "grid", "MappingPolicy": {"Rule": "vo:atlas"}}
MANAGER = {
    "ApplicationEnvironments": {
        "ApplicationEnvironment": [
            {"AppName": "ENV/PROXY"},
            {"AppName": "APPS/HEP/ATLAS", "AppVersion": "21.0"},
            {"AppVersion": "1.0"},
            "not an object",
        ]
    }
}


def _glue(service: Any, *, arrays: bool) -> dict[str, Any]:
    """A GLUE2 info document, with every container a list (``arrays``) or a scalar."""

    def wrap(value: Any) -> Any:
        return [value] if arrays else value

    return {"Domains": {"AdminDomain": wrap({"Services": {"ComputingService": wrap(service)}})}}


def _service(*, arrays: bool) -> dict[str, Any]:
    def wrap(value: Any) -> Any:
        return [value] if arrays else value

    return {
        "Name": wrap("ce.example.org"),
        "TotalJobs": wrap("12"),
        "RunningJobs": wrap("4"),
        "WaitingJobs": wrap("8"),
        "ComputingEndpoint": [EMIES_ENDPOINT, REST_ENDPOINT, "junk"],
        "ComputingShare": [VO_SHARE, BATCH_SHARE],
        "ComputingManager": wrap(MANAGER),
    }


@pytest.mark.parametrize("arrays", [True, False], ids=["forced-arrays", "scalars"])
def test_ce_info_full(arrays: bool) -> None:
    info = parse_ce_info(_glue(_service(arrays=arrays), arrays=arrays))
    assert info.name == "ce.example.org"
    assert (info.total_jobs, info.running_jobs, info.waiting_jobs) == (12, 4, 8)
    assert info.runtime_environments == ("ENV/PROXY", "APPS/HEP/ATLAS-21.0")
    assert len(info.endpoints) == 2
    assert info.rest_endpoint() == Endpoint(
        url="https://ce.example.org:443/arex",
        interface=REST_INTERFACE,
        versions=("1.0", "1.1"),
        health="ok",
        serving="production",
        capabilities=(
            "executionmanagement.jobcreation",
            "executionmanagement.jobdescription",
        ),
    )


def test_scalar_endpoint_fields() -> None:
    info = parse_ce_info(_glue({"ComputingEndpoint": EMIES_ENDPOINT}, arrays=False))
    (endpoint,) = info.endpoints
    assert endpoint.versions == ("1.16",)
    assert endpoint.capabilities == ("executionmanagement.jobcreation",)
    assert (endpoint.health, endpoint.serving) == (None, None)
    assert info.rest_endpoint() is None


def test_queues_and_mapping_policy_shares() -> None:
    info = parse_ce_info(_glue(_service(arrays=True), arrays=True))
    vo, batch = info.queues
    assert vo == Queue("grid_atlas", "grid", None, None, None, None, None, None, None, True)
    assert batch == Queue("grid", "grid", 86400, 172800, 3600, 4, 1, 100, "production", False)
    assert info.queue("grid") is batch
    assert info.queue("grid_atlas") is None
    assert info.queue("missing") is None


def test_document_without_domains_wrapper() -> None:
    doc = {"AdminDomain": {"Services": {"ComputingService": {"Name": "bare"}}}}
    assert parse_ce_info(doc).name == "bare"


EMPTY = CEInfo(None, (), (), (), None, None, None)


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"Domains": []},
        {"Domains": {}},
        {"Domains": {"AdminDomain": "text"}},
        {"Domains": {"AdminDomain": []}},
        {"Domains": {"AdminDomain": {"Services": "text"}}},
        {"Domains": {"AdminDomain": {"Services": {"ComputingService": "text"}}}},
        {"Domains": {"AdminDomain": {"Services": {"ComputingService": []}}}},
        {"Domains": {"AdminDomain": {"Services": {"ComputingService": {}}}}},
    ],
)
def test_missing_pieces_give_an_empty_description(doc: dict[str, Any]) -> None:
    assert parse_ce_info(doc) == EMPTY


@pytest.mark.parametrize(
    "managers",
    [
        "not an object",
        {"ApplicationEnvironments": "text"},
        {"ApplicationEnvironments": {}},
        {"ApplicationEnvironments": {"ApplicationEnvironment": ""}},
        [{"ApplicationEnvironments": {"ApplicationEnvironment": {"AppName": " "}}}],
    ],
)
def test_runtime_environments_tolerate_bad_shapes(managers: Any) -> None:
    info = parse_ce_info(_glue({"ComputingManager": managers}, arrays=False))
    assert info.runtime_environments == ()


def test_runtime_environments_from_several_managers() -> None:
    managers = [
        {"ApplicationEnvironments": {"ApplicationEnvironment": {"AppName": "A", "AppVersion": ""}}},
        {"ApplicationEnvironments": {"ApplicationEnvironment": [{"AppName": ["B"]}]}},
    ]
    info = parse_ce_info(_glue({"ComputingManager": managers}, arrays=True))
    assert info.runtime_environments == ("A", "B")


@pytest.mark.parametrize(
    ("value", "number"),
    [
        ("42", 42),
        (["7", "8"], 7),
        (" 12.9 ", 12),
        ("1e3", 1000),
        (5, 5),
        ("lots", None),
        ("inf", None),
        ("nan", None),
        ("", None),
        ([], None),
        ({"Value": "3"}, None),
        (None, None),
    ],
)
def test_numbers(value: Any, number: int | None) -> None:
    share = {"Name": "q", "MaxWallTime": value}
    (queue,) = parse_ce_info(_glue({"ComputingShare": share}, arrays=False)).queues
    assert queue.max_wall_time == number


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-17T10:05:12Z", dt.datetime(2026, 10, 17, 10, 5, 12, tzinfo=UTC)),
        (["2026-10-17T10:05:12Z"], dt.datetime(2026, 10, 17, 10, 5, 12, tzinfo=UTC)),
        ("2026-10-17T10:05:12", dt.datetime(2026, 10, 17, 10, 5, 12, tzinfo=UTC)),
        ("2026-10-17T12:05:12+02:00", dt.datetime(2026, 10, 17, 10, 5, 12, tzinfo=UTC)),
        ("yesterday", None),
        ("", None),
        (None, None),
        ({"t": "x"}, None),
    ],
)
def test_parse_time(value: Any, expected: dt.datetime | None) -> None:
    parsed = parse_time(value)
    assert parsed == expected
    assert parsed is None or parsed.tzinfo is not None


def test_parse_time_keeps_the_offset() -> None:
    parsed = parse_time("2026-10-17T12:05:12+02:00")
    assert parsed is not None
    assert parsed.utcoffset() == dt.timedelta(hours=2)


ACTIVITY = {
    "State": ["emies:processing-running", "arcrest:RUNNING", "nordugrid:INLRMS:R"],
    "RestartState": ["emies:x", "arcrest:SUBMITTING"],
    "Name": "my job",
    "ExitCode": "0",
    "Error": ["first error", "second error", {"bad": 1}],
    "Owner": "/DC=org/CN=someone",
    "Queue": "grid",
    "StdIn": "/dev/null",
    "StdOut": "out.txt",
    "StdErr": "err.txt",
    "LogDir": "gmlog",
    "ExecutionNode": ["wn1", "wn2"],
    "WaitingPosition": "3",
    "SubmissionTime": "2026-10-17T10:00:00Z",
    "StartTime": "2026-10-17T10:01:00Z",
    "EndTime": "2026-10-17T10:02:00Z",
    "ComputingManagerEndTime": "2026-10-17T09:00:00Z",
    "WorkingAreaEraseTime": "2026-10-24T10:02:00Z",
    "ProxyExpirationTime": "2026-10-18T10:00:00Z",
    "UsedTotalWallTime": "60",
    "UsedTotalCPUTime": "55",
    "UsedMainMemory": "2048",
    "RequestedSlots": "1",
    "RequestedTotalWallTime": "3600",
    "LocalIDFromManager": "12345",
    "OtherMessages": ["SubmittedVia=org.nordugrid.arcrest"],
}


def test_activity_full_record() -> None:
    record = parse_activity(ACTIVITY)
    assert (record.rest_state, record.state) == ("RUNNING", JobState.RUNNING)
    assert record.restart_state == "SUBMITTING"
    assert (record.name, record.exit_code, record.owner) == ("my job", 0, "/DC=org/CN=someone")
    assert record.errors == ("first error", "second error")
    assert (record.queue, record.stdin, record.stdout, record.stderr, record.log_dir) == (
        "grid",
        "/dev/null",
        "out.txt",
        "err.txt",
        "gmlog",
    )
    assert record.execution_nodes == ("wn1", "wn2")
    assert record.waiting_position == 3
    assert record.submitted == dt.datetime(2026, 10, 17, 10, 0, tzinfo=UTC)
    assert record.started == dt.datetime(2026, 10, 17, 10, 1, tzinfo=UTC)
    assert record.ended == dt.datetime(2026, 10, 17, 10, 2, tzinfo=UTC)
    assert record.erase_time == dt.datetime(2026, 10, 24, 10, 2, tzinfo=UTC)
    assert record.proxy_expiry == dt.datetime(2026, 10, 18, 10, 0, tzinfo=UTC)
    assert (record.used_wall_time, record.used_cpu_time, record.used_memory) == (60, 55, 2048)
    assert (record.requested_slots, record.requested_wall_time) == (1, 3600)
    assert record.local_id == "12345"
    assert record.other_messages == ("SubmittedVia=org.nordugrid.arcrest",)


def test_activity_end_time_falls_back_to_the_batch_system() -> None:
    record = parse_activity({"ComputingManagerEndTime": "2026-10-17T09:00:00Z"})
    assert record.ended == dt.datetime(2026, 10, 17, 9, tzinfo=UTC)


def test_activity_scalar_state() -> None:
    record = parse_activity({"State": "arcrest:FINISHED"}, rest_state="RUNNING")
    assert (record.rest_state, record.state) == ("FINISHED", JobState.FINISHED)


def test_activity_without_arcrest_state_uses_the_given_one() -> None:
    record = parse_activity({"State": ["emies:terminal", "nordugrid:FINISHED"]}, "WIPED")
    assert (record.rest_state, record.state) == ("WIPED", JobState.DELETED)


def test_activity_empty() -> None:
    record = parse_activity({})
    assert (record.rest_state, record.state, record.restart_state) == (
        None,
        JobState.UNDEFINED,
        None,
    )
    assert record.errors == record.execution_nodes == record.other_messages == ()
    assert (record.name, record.exit_code, record.submitted, record.ended) == (None,) * 4


def test_activity_unknown_rest_state_is_other() -> None:
    record = parse_activity({"State": "arcrest:NEWFANGLED"})
    assert (record.rest_state, record.state) == ("NEWFANGLED", JobState.OTHER)
