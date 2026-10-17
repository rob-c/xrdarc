"""GLUE2 as A-REX renders it to JSON: the CE's description and a job's record.

Everything arrives as strings, containers may be a list or a single object
depending on the server's version, and absent fields are simply missing, so
every accessor here tolerates all three. Times are GLUE2 seconds for limits
and ISO 8601 UTC (``2026-10-17T10:05:12Z``) for instants.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .rest import as_list
from .states import JobState, generic_state

__all__ = ["CEInfo", "Endpoint", "JobRecord", "Queue", "parse_activity", "parse_ce_info"]

REST_INTERFACE = "org.nordugrid.arcrest"


def _first(value: Any) -> Any:
    items = as_list(value)
    return items[0] if items else None


def _text(value: Any) -> str | None:
    item = _first(value)
    if item is None or isinstance(item, (dict, list)):
        return None
    text = str(item).strip()
    return text or None


def _number(value: Any) -> int | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return int(float(text))
    except (ValueError, OverflowError):
        return None


def _texts(value: Any) -> tuple[str, ...]:
    return tuple(str(v).strip() for v in as_list(value) if isinstance(v, (str, int, float)))


def parse_time(value: Any) -> _dt.datetime | None:
    """An ISO 8601 instant as an aware UTC datetime; ``None`` if absent or malformed."""
    text = _text(value)
    if text is None:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A GLUE2 ComputingEndpoint: where and how the CE can be spoken to."""

    url: str
    interface: str
    versions: tuple[str, ...]
    health: str | None
    serving: str | None
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Queue:
    """A ComputingShare that a user can name in ``queue=``.

    Shares with a ``MappingPolicy`` are per-VO views of a batch queue; they
    are kept (``vo_share``) but a submission names ``mapping_queue``.
    """

    name: str
    mapping_queue: str | None
    max_wall_time: int | None
    max_cpu_time: int | None
    default_wall_time: int | None
    running: int | None
    waiting: int | None
    max_running: int | None
    serving: str | None
    vo_share: bool


@dataclass(frozen=True, slots=True)
class CEInfo:
    """What ``arcinfo`` shows about a CE."""

    name: str | None
    endpoints: tuple[Endpoint, ...]
    queues: tuple[Queue, ...]
    runtime_environments: tuple[str, ...]
    total_jobs: int | None
    running_jobs: int | None
    waiting_jobs: int | None

    def rest_endpoint(self) -> Endpoint | None:
        return next((e for e in self.endpoints if e.interface == REST_INTERFACE), None)

    def queue(self, name: str) -> Queue | None:
        return next((q for q in self.queues if q.name == name and not q.vo_share), None)


def _service(doc: Mapping[str, Any]) -> Mapping[str, Any]:
    domains = doc.get("Domains", doc)
    domain = _first(domains.get("AdminDomain")) if isinstance(domains, dict) else None
    services = domain.get("Services") if isinstance(domain, dict) else None
    service = _first(services.get("ComputingService")) if isinstance(services, dict) else None
    return service if isinstance(service, dict) else {}


def _endpoint(raw: Mapping[str, Any]) -> Endpoint:
    return Endpoint(
        url=_text(raw.get("URL")) or "",
        interface=_text(raw.get("InterfaceName")) or "",
        versions=_texts(raw.get("InterfaceVersion")),
        health=_text(raw.get("HealthState")),
        serving=_text(raw.get("ServingState")),
        capabilities=_texts(raw.get("Capability")),
    )


def _queue(raw: Mapping[str, Any]) -> Queue:
    return Queue(
        name=_text(raw.get("Name")) or "",
        mapping_queue=_text(raw.get("MappingQueue")),
        max_wall_time=_number(raw.get("MaxWallTime")),
        max_cpu_time=_number(raw.get("MaxCPUTime")),
        default_wall_time=_number(raw.get("DefaultWallTime")),
        running=_number(raw.get("RunningJobs")),
        waiting=_number(raw.get("WaitingJobs")),
        max_running=_number(raw.get("MaxRunningJobs")),
        serving=_text(raw.get("ServingState")),
        vo_share="MappingPolicy" in raw,
    )


def _applications(manager: Any) -> list[Any]:
    holder = manager.get("ApplicationEnvironments") if isinstance(manager, dict) else None
    return as_list(holder.get("ApplicationEnvironment")) if isinstance(holder, dict) else []


def _rte_name(app: Any) -> str | None:
    """``AppName-AppVersion`` (or the bare name) as RTEs are requested."""
    name = _text(app.get("AppName")) if isinstance(app, dict) else None
    if not name:
        return None
    version = _text(app.get("AppVersion"))
    return f"{name}-{version}" if version else name


def _environments(service: Mapping[str, Any]) -> tuple[str, ...]:
    apps = [app for m in as_list(service.get("ComputingManager")) for app in _applications(m)]
    return tuple(name for app in apps if (name := _rte_name(app)))


def parse_ce_info(doc: Mapping[str, Any]) -> CEInfo:
    """The CE description from ``GET info`` JSON; empty fields when absent."""
    service = _service(doc)
    endpoints = tuple(
        _endpoint(e) for e in as_list(service.get("ComputingEndpoint")) if isinstance(e, dict)
    )
    queues = tuple(_queue(q) for q in as_list(service.get("ComputingShare")) if isinstance(q, dict))
    return CEInfo(
        name=_text(service.get("Name")),
        endpoints=endpoints,
        queues=queues,
        runtime_environments=_environments(service),
        total_jobs=_number(service.get("TotalJobs")),
        running_jobs=_number(service.get("RunningJobs")),
        waiting_jobs=_number(service.get("WaitingJobs")),
    )


def _prefixed(values: Any, prefix: str) -> str | None:
    for value in _texts(values):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return None


@dataclass(frozen=True, slots=True)
class JobRecord:
    """A job as the CE describes it (GLUE2 ComputingActivity); unset fields are ``None``."""

    rest_state: str | None
    state: JobState
    restart_state: str | None
    name: str | None
    exit_code: int | None
    errors: tuple[str, ...]
    owner: str | None
    queue: str | None
    stdin: str | None
    stdout: str | None
    stderr: str | None
    log_dir: str | None
    execution_nodes: tuple[str, ...]
    waiting_position: int | None
    submitted: _dt.datetime | None
    started: _dt.datetime | None
    ended: _dt.datetime | None
    erase_time: _dt.datetime | None
    proxy_expiry: _dt.datetime | None
    used_wall_time: int | None
    used_cpu_time: int | None
    used_memory: int | None
    requested_slots: int | None
    requested_wall_time: int | None
    local_id: str | None
    other_messages: tuple[str, ...]


def parse_activity(doc: Mapping[str, Any], rest_state: str | None = None) -> JobRecord:
    """A job record from an ``action=info`` ComputingActivity.

    The state is the one prefixed ``arcrest:`` (A-REX lists several
    vocabularies side by side); ``rest_state`` stands in when there is none.
    """
    rest = _prefixed(doc.get("State"), "arcrest:") or rest_state
    return JobRecord(
        rest_state=rest,
        state=generic_state(rest),
        restart_state=_prefixed(doc.get("RestartState"), "arcrest:"),
        name=_text(doc.get("Name")),
        exit_code=_number(doc.get("ExitCode")),
        errors=_texts(doc.get("Error")),
        owner=_text(doc.get("Owner")),
        queue=_text(doc.get("Queue")),
        stdin=_text(doc.get("StdIn")),
        stdout=_text(doc.get("StdOut")),
        stderr=_text(doc.get("StdErr")),
        log_dir=_text(doc.get("LogDir")),
        execution_nodes=_texts(doc.get("ExecutionNode")),
        waiting_position=_number(doc.get("WaitingPosition")),
        submitted=parse_time(doc.get("SubmissionTime")),
        started=parse_time(doc.get("StartTime")),
        ended=parse_time(doc.get("EndTime")) or parse_time(doc.get("ComputingManagerEndTime")),
        erase_time=parse_time(doc.get("WorkingAreaEraseTime")),
        proxy_expiry=parse_time(doc.get("ProxyExpirationTime")),
        used_wall_time=_number(doc.get("UsedTotalWallTime")),
        used_cpu_time=_number(doc.get("UsedTotalCPUTime")),
        used_memory=_number(doc.get("UsedMainMemory")),
        requested_slots=_number(doc.get("RequestedSlots")),
        requested_wall_time=_number(doc.get("RequestedTotalWallTime")),
        local_id=_text(doc.get("LocalIDFromManager")),
        other_messages=_texts(doc.get("OtherMessages")),
    )
