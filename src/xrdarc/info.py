"""GLUE2 as A-REX renders it to JSON: the CE's description and a job's record.

Everything arrives as strings, containers may be a list or a single object
depending on the server's version, and absent fields are simply missing, so
every accessor here tolerates all three. Times are GLUE2 seconds for limits
and ISO 8601 UTC (``2026-10-17T10:05:12Z``) for instants.

Two documents are read: ``GET info`` (:func:`parse_ce_info` - the
``ComputingService`` with its endpoints, shares and runtime environments,
what ``arcinfo`` shows) and a job's ``ComputingActivity`` from
``action=info`` (:func:`parse_activity`, what ``arcstat -l`` shows and
:meth:`Job.update <xrdarc.joblist.Job.update>` folds into the job list).
Nothing here raises for a malformed document: a field that cannot be read
is unknown, because a CE's odd information system must not stop a user
from seeing the rest.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .rest import as_list
from .states import JobState, generic_state

__all__ = ["CEInfo", "Endpoint", "JobRecord", "Queue", "parse_activity", "parse_ce_info"]

#: GLUE2 ``InterfaceName`` of the A-REX REST interface. A CE publishes one
#: endpoint per interface (EMI-ES, the information system, REST...), and this
#: is the only one this client can submit through.
REST_INTERFACE = "org.nordugrid.arcrest"


def _first(value: Any) -> Any:
    """The first of a field that may repeat (ARC 7 forces lists, ARC 6 does not)."""
    items = as_list(value)
    return items[0] if items else None


def _text(value: Any) -> str | None:
    """A single text field, stripped; ``None`` if absent, blank or not text (an object)."""
    item = _first(value)
    # A nested object where text was expected is a different schema version,
    # not text: ``str()`` of it would put a Python repr in front of the user.
    if item is None or isinstance(item, (dict, list)):
        return None
    text = str(item).strip()
    return text or None


def _number(value: Any) -> int | None:
    """A numeric field (sent as a string, sometimes ``"3600.0"``), truncated to an integer."""
    text = _text(value)
    if text is None:
        return None
    try:
        # Through float: some infoproviders publish "3600.0"; truncation is
        # right for limits and counts, which are whole by nature.
        return int(float(text))
    except (ValueError, OverflowError):
        # OverflowError: ``int(float("inf"))``; an infoprovider printing
        # "inf" for "unlimited" is a value nobody can use, so unknown.
        return None


def _texts(value: Any) -> tuple[str, ...]:
    """Every scalar of a repeated field, as stripped text; objects among them are skipped."""
    return tuple(str(v).strip() for v in as_list(value) if isinstance(v, (str, int, float)))


def parse_time(value: Any) -> _dt.datetime | None:
    """An ISO 8601 instant as an aware UTC datetime; ``None`` if absent or malformed."""
    text = _text(value)
    if text is None:
        return None
    try:
        # Spelling ``Z`` as an offset keeps one code path for both the ``Z``
        # A-REX writes and the explicit offsets some infoproviders use.
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    # GLUE2 instants are UTC; one without a zone is taken as UTC, not local.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A GLUE2 ComputingEndpoint: where and how the CE can be spoken to."""

    url: str
    #: ``org.nordugrid.arcrest`` for the REST interface this client speaks.
    interface: str
    #: The interface versions (``1.0``, ``1.1``) the endpoint serves.
    versions: tuple[str, ...]
    #: GLUE2 ``HealthState`` (``ok``, ``warning``, ``critical``...).
    health: str | None
    #: GLUE2 ``ServingState``: ``production``, ``draining``, ``closed``...
    serving: str | None
    #: GLUE2 capability names (``executionmanagement.jobexecution``...), as
    #: published; kept for callers, nothing in xrdarc acts on them.
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Queue:
    """A ComputingShare that a user can name in ``queue=``.

    Shares with a ``MappingPolicy`` are per-VO views of a batch queue; they
    are kept (``vo_share``) but a submission names ``mapping_queue``.
    """

    #: The share's name; for a per-VO share, ``<queue>_<vo>``, not a queue.
    name: str
    #: The batch queue behind the share: what ``queue=`` names.
    mapping_queue: str | None
    #: Limits in seconds; 2**31-1 is GLUE2's "no limit". Kept as published
    #: rather than turned into ``None``: ``None`` already means "not published",
    #: and a brokering caller must be able to tell the two apart.
    max_wall_time: int | None
    max_cpu_time: int | None
    default_wall_time: int | None
    #: Jobs running and waiting in the share, as last published.
    running: int | None
    waiting: int | None
    max_running: int | None
    serving: str | None
    vo_share: bool


@dataclass(frozen=True, slots=True)
class CEInfo:
    """What ``arcinfo`` shows about a CE."""

    #: The service's ``Name``, as its administrators set it.
    name: str | None
    endpoints: tuple[Endpoint, ...]
    #: Every share, per-VO ones included (``Queue.vo_share``).
    queues: tuple[Queue, ...]
    #: Names a job can request (``runtimeenvironment="APPS/HEP/ATLAS-21.0.1"``).
    runtime_environments: tuple[str, ...]
    #: The service's job counters (all users).
    total_jobs: int | None
    running_jobs: int | None
    waiting_jobs: int | None

    def rest_endpoint(self) -> Endpoint | None:
        """The ARC REST endpoint, the one this client submits through, if published."""
        return next((e for e in self.endpoints if e.interface == REST_INTERFACE), None)

    def queue(self, name: str) -> Queue | None:
        """The batch queue called ``name`` (not one of its per-VO shares), if published."""
        return next((q for q in self.queues if q.name == name and not q.vo_share), None)


def _service(doc: Mapping[str, Any]) -> Mapping[str, Any]:
    """``Domains/AdminDomain/Services/ComputingService`` (the first of each), or ``{}``.

    A document without the ``Domains`` wrapper is accepted too: some
    renderings start at the domain.
    """
    # Each level may be a list or one object depending on the A-REX version
    # (see :func:`_first`), and any may be missing on a CE whose
    # infoprovider failed; every step checks for a dict before going deeper.
    domains = doc.get("Domains", doc)
    domain = _first(domains.get("AdminDomain")) if isinstance(domains, dict) else None
    services = domain.get("Services") if isinstance(domain, dict) else None
    service = _first(services.get("ComputingService")) if isinstance(services, dict) else None
    return service if isinstance(service, dict) else {}


def _endpoint(raw: Mapping[str, Any]) -> Endpoint:
    """One ``ComputingEndpoint``."""
    return Endpoint(
        url=_text(raw.get("URL")) or "",
        interface=_text(raw.get("InterfaceName")) or "",
        versions=_texts(raw.get("InterfaceVersion")),
        health=_text(raw.get("HealthState")),
        serving=_text(raw.get("ServingState")),
        capabilities=_texts(raw.get("Capability")),
    )


def _queue(raw: Mapping[str, Any]) -> Queue:
    """One ``ComputingShare``; a ``MappingPolicy`` makes it a per-VO share."""
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
        # The infoprovider gives every per-VO share a MappingPolicy naming its
        # VO, and the plain queue share none: its presence is the whole test.
        vo_share="MappingPolicy" in raw,
    )


def _applications(manager: Any) -> list[Any]:
    """A ``ComputingManager``'s ``ApplicationEnvironment`` entries (runtime environments)."""
    # GLUE2 nests them in a plural container element, which the JSON
    # rendering keeps as one more level of object.
    holder = manager.get("ApplicationEnvironments") if isinstance(manager, dict) else None
    return as_list(holder.get("ApplicationEnvironment")) if isinstance(holder, dict) else []


def _rte_name(app: Any) -> str | None:
    """``AppName-AppVersion`` (or the bare name) as RTEs are requested."""
    name = _text(app.get("AppName")) if isinstance(app, dict) else None
    if not name:
        return None
    version = _text(app.get("AppVersion"))
    # ``AppName-AppVersion`` is the form ``runtimeenvironment=`` names an RTE
    # in, so the two published fields are joined back into it.
    return f"{name}-{version}" if version else name


def _environments(service: Mapping[str, Any]) -> tuple[str, ...]:
    """Every runtime environment the CE's managers publish, as names a job can request."""
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
    """The first value starting with ``prefix``, without it (``arcrest:RUNNING`` -> ``RUNNING``)."""
    # Order is not significant: A-REX writes ``nordugrid:`` first today, but a
    # client that took the first value would break when that changes.
    for value in _texts(values):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return None


@dataclass(frozen=True, slots=True)
class JobRecord:
    """A job as the CE describes it (GLUE2 ComputingActivity); unset fields are ``None``."""

    #: A-REX's REST state (``EXITINGLRMS``), and the generic one it maps to.
    rest_state: str | None
    state: JobState
    #: The REST state a failed job failed in (where ``resume`` restarts it).
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
    #: When A-REX deletes the job's session directory: retrieve before then.
    erase_time: _dt.datetime | None
    #: When the delegated proxy expires (``renew`` pushes it out).
    proxy_expiry: _dt.datetime | None
    #: Usage so far: seconds, seconds, and memory in MB.
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
    # Field names are GLUE2's; ``ended`` falls back to the batch system's end
    # time, which A-REX publishes before its own once the LRMS job is over.
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
