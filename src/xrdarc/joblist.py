"""The local job list, in the SQLite format ARC's own tools use (``~/.arc/jobs.dat``).

Writing ARC's format rather than one of our own means a job submitted here
shows up in ``arcstat``, ``arcget`` and the rest, and one submitted with
``arcsub`` can be managed here. The table, the column names (misspellings
included) and the escaping are ``JobInformationStorageSQLite``'s: every
value is text, the characters ``' # CR LF BS NUL %`` are written as ``%`` and
two lower-case hex digits, unknown integers are ``-1``, unknown times empty,
and list-valued fields hold only their first element.

A job list in ARC's older XML format is refused with an explanation rather
than overwritten.
"""

from __future__ import annotations

import datetime as _dt
import errno
import os
import re
import sqlite3
import time
import urllib.parse
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from ._version import __version__
from .errors import ARCError
from .info import JobRecord
from .states import JobState
from .urls import job_url, parse_job_url

__all__ = ["Job", "JobList"]

REST_INTERFACE = "org.nordugrid.arcrest"

_COLUMNS = (
    "id",
    "idfromendpoint",
    "name",
    "statusinterface",
    "statusurl",
    "managementinterfacename",
    "managementurl",
    "serviceinformationinterfacename",
    "serviceinformationurl",
    "serviceinformationhost",
    "sessiondir",
    "stageindir",
    "stageoutdir",
    "descriptiondocument",
    "localsubmissiontime",
    "delegationid",
    "type",
    "localidfrommanager",
    "description",
    "state",
    "restartstate",
    "exitcode",
    "computingmanagerexitcode",
    "error",
    "waitingposition",
    "userdomain",
    "owner",
    "localowner",
    "requestedtotalwallltime",
    "requestedtotalcputime",
    "requestedslots",
    "requestedapplicationenvironment",
    "stdin",
    "stdout",
    "stderr",
    "logdir",
    "executionnode",
    "queue",
    "usedtotalwallltime",
    "usedtotalcputime",
    "usedmainmemory",
    "submissiontime",
    "computingmanagersubmissiontime",
    "starttime",
    "computingmanagerendtime",
    "endtime",
    "workingareaerasetime",
    "proxyexpirationtime",
    "submissionhost",
    "submissionclienttime",
    "othermessages",
    "activityoldid",
)

_SCHEMA = (
    f"CREATE TABLE IF NOT EXISTS jobs({', '.join(_COLUMNS)}, UNIQUE(id))",
    "CREATE INDEX IF NOT EXISTS serviceinformationhost ON jobs(serviceinformationhost)",
)
#: The columns of job lists written before ARC 6.x added the job's last known state.
_OLD_COLUMNS = _COLUMNS[:16]
_MIGRATION = (
    f"CREATE TABLE jobs_new({', '.join(_COLUMNS)}, UNIQUE(id))",
    f"INSERT INTO jobs_new ({', '.join(_OLD_COLUMNS)}) SELECT {', '.join(_OLD_COLUMNS)} FROM jobs",  # noqa: S608
    "DROP TABLE jobs",
    "ALTER TABLE jobs_new RENAME TO jobs",
    "CREATE INDEX IF NOT EXISTS serviceinformationhost ON jobs(serviceinformationhost)",
)
# Column names are this module's constants; every value goes through a placeholder.
_SELECT = f"SELECT {', '.join(_COLUMNS)} FROM jobs"  # noqa: S608
_REPLACE = f"REPLACE INTO jobs({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)})"  # noqa: S608
_SPECIAL = "'#\r\n\b\0%"
_SQLITE_MAGIC = b"SQLite format 3\0"
_PERIOD = re.compile(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?")


def escape(value: str) -> str:
    """ARC's SQL escaping: special characters as ``%xx``."""
    return "".join(f"%{ord(c):02x}" if c in _SPECIAL else c for c in value)


def unescape(value: str) -> str:
    """Undo ``escape``; a malformed escape is kept literally, as ARC does."""
    out, index = [], 0
    while index < len(value):
        char = value[index]
        digits = value[index + 1 : index + 3]
        if char == "%" and len(digits) == 2 and all(d in "0123456789abcdefABCDEF" for d in digits):
            out.append(chr(int(digits, 16)))
            index += 3
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _iso(when: _dt.datetime | None) -> str:
    return "" if when is None else when.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int(value: int | None) -> str:
    return "-1" if value is None else str(value)


def _period(seconds: int | None) -> str:
    return "PT" if seconds is None else f"PT{seconds}S"


def _parse_int(text: str) -> int | None:
    try:
        number = int(text)
    except ValueError:
        return None
    return None if number == -1 else number


def _parse_period(text: str) -> int | None:
    """ARC's ``Period`` text in seconds: ``PT1H30M``, ``PT45S``, or ``PT5400S`` as written here."""
    match = _PERIOD.fullmatch(text)
    if match is None or not any(match.groups()):
        return None
    hours, minutes, seconds = (int(group or 0) for group in match.groups())
    return hours * 3600 + minutes * 60 + seconds


def _parse_time(text: str) -> _dt.datetime | None:
    """A stored instant in UTC. ARC's tools write local time with no zone (``Time::UserTime``,
    ``2026-10-17 12:05:12``), this module UTC with a ``Z``; both read back correctly."""
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(_dt.UTC)


@dataclass(frozen=True, slots=True)
class Job:
    """A job as the client knows it: where it is, what it was, what it was last seen as.

    ``ce`` is the canonical CE URL and ``id`` the CE's id; ``url`` is the
    job URL ARC users quote. Fields after ``delegations`` are the CE's last
    report (``update`` refreshes them); ``state`` is ``UNDEFINED`` until
    the CE has been asked.
    """

    ce: str
    id: str
    name: str | None = None
    description: str = ""
    submitted: _dt.datetime | None = None
    delegations: tuple[str, ...] = ()
    state: JobState = JobState.UNDEFINED
    rest_state: str | None = None
    exit_code: int | None = None
    errors: tuple[str, ...] = ()
    queue: str | None = None
    owner: str | None = None
    stdin: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    log_dir: str | None = None
    execution_nodes: tuple[str, ...] = ()
    waiting_position: int | None = None
    submitted_on_ce: _dt.datetime | None = None
    started: _dt.datetime | None = None
    ended: _dt.datetime | None = None
    erase_time: _dt.datetime | None = None
    proxy_expiry: _dt.datetime | None = None
    used_wall_time: int | None = None
    used_cpu_time: int | None = None
    used_memory: int | None = None
    requested_slots: int | None = None
    requested_wall_time: int | None = None
    local_id: str | None = None
    restart_state: str | None = None
    other_messages: tuple[str, ...] = ()
    extra: dict[str, str] = field(default_factory=dict, compare=False)

    @property
    def url(self) -> str:
        return job_url(self.ce, self.id)

    @classmethod
    def from_url(cls, url: str, **fields: object) -> Job:
        parsed = parse_job_url(url)
        return cls(ce=parsed.ce, id=parsed.id, **fields)  # type: ignore[arg-type]

    def update(self, record: JobRecord) -> Job:
        """This job with the CE's latest report applied; absent fields keep their values."""
        changes = {
            name: getattr(record, source)
            for name, source in _RECORD_FIELDS.items()
            if getattr(record, source) not in (None, ())
        }
        changes["state"] = record.state
        changes["rest_state"] = record.rest_state
        return replace(self, **changes)


_RECORD_FIELDS = {
    "name": "name",
    "exit_code": "exit_code",
    "errors": "errors",
    "queue": "queue",
    "owner": "owner",
    "stdin": "stdin",
    "stdout": "stdout",
    "stderr": "stderr",
    "log_dir": "log_dir",
    "execution_nodes": "execution_nodes",
    "waiting_position": "waiting_position",
    "submitted_on_ce": "submitted",
    "started": "started",
    "ended": "ended",
    "erase_time": "erase_time",
    "proxy_expiry": "proxy_expiry",
    "used_wall_time": "used_wall_time",
    "used_cpu_time": "used_cpu_time",
    "used_memory": "used_memory",
    "requested_slots": "requested_slots",
    "requested_wall_time": "requested_wall_time",
    "local_id": "local_id",
    "restart_state": "restart_state",
    "other_messages": "other_messages",
}


def _first(values: Sequence[str]) -> str:
    return values[0] if values else ""


def _canonical(url: str) -> str | None:
    try:
        return parse_job_url(url).__str__()
    except ARCError:
        return None


#: Columns a ``Job`` does not model: what the row already holds (ARC may have filled
#: them in) is kept, and a new row gets these.
_UNMODELED = {
    "type": "",
    "description": "",
    "computingmanagerexitcode": "",
    "userdomain": "",
    "localowner": "",
    "requestedtotalcputime": "PT",
    "requestedapplicationenvironment": "",
    "computingmanagersubmissiontime": "",
    "computingmanagerendtime": "",
    "submissionhost": "",
    "submissionclienttime": f"xrdarc/{__version__}",
    "activityoldid": "",
}


def _row(job: Job) -> dict[str, str]:
    host = urllib.parse.urlsplit(job.ce).hostname or ""
    submitted = job.submitted or _dt.datetime.now(_dt.UTC)
    kept = {name: job.extra.get(name) or default for name, default in _UNMODELED.items()}
    row = {
        "id": job.url,
        "idfromendpoint": job.id,
        "name": job.name or "",
        "statusinterface": REST_INTERFACE,
        "statusurl": job.ce,
        "managementinterfacename": REST_INTERFACE,
        "managementurl": job.ce,
        "serviceinformationinterfacename": REST_INTERFACE,
        "serviceinformationurl": job.ce,
        "serviceinformationhost": host,
        "sessiondir": f"{job.url}/session",
        "stageindir": f"{job.url}/session",
        "stageoutdir": f"{job.url}/session",
        "descriptiondocument": job.description,
        "localsubmissiontime": str(int(submitted.timestamp())),
        "delegationid": _first(job.delegations),
        "localidfrommanager": job.local_id or "",
        "state": job.state.value,
        "restartstate": job.restart_state or "",
        "exitcode": _int(job.exit_code),
        "error": _first(job.errors),
        "waitingposition": _int(job.waiting_position),
        "owner": job.owner or "",
        "requestedtotalwallltime": _period(job.requested_wall_time),
        "requestedslots": _int(job.requested_slots),
        "stdin": job.stdin or "",
        "stdout": job.stdout or "",
        "stderr": job.stderr or "",
        "logdir": job.log_dir or "",
        "executionnode": _first(job.execution_nodes),
        "queue": job.queue or "",
        "usedtotalwallltime": _period(job.used_wall_time),
        "usedtotalcputime": _period(job.used_cpu_time),
        "usedmainmemory": _int(job.used_memory),
        "submissiontime": _iso(job.submitted_on_ce),
        "starttime": _iso(job.started),
        "endtime": _iso(job.ended),
        "workingareaerasetime": _iso(job.erase_time),
        "proxyexpirationtime": _iso(job.proxy_expiry),
        "othermessages": _first(job.other_messages),
    }
    return {**kept, **row}


def _tuple(text: str) -> tuple[str, ...]:
    return (text,) if text else ()


def _job(values: dict[str, str]) -> Job | None:
    """A job from a row; ``None`` for rows that are not ARC REST jobs (other interfaces)."""
    try:
        parsed = parse_job_url(values.get("id", ""))
    except ARCError:
        return None
    seconds = _parse_int(values.get("localsubmissiontime", ""))
    return Job(
        ce=parsed.ce,
        id=values.get("idfromendpoint") or parsed.id,
        name=values.get("name") or None,
        description=values.get("descriptiondocument", ""),
        submitted=None if seconds is None else _dt.datetime.fromtimestamp(seconds, _dt.UTC),
        delegations=_tuple(values.get("delegationid", "")),
        state=JobState.parse(values.get("state", "")),
        exit_code=_parse_int(values.get("exitcode", "")),
        errors=_tuple(values.get("error", "")),
        queue=values.get("queue") or None,
        owner=values.get("owner") or None,
        stdin=values.get("stdin") or None,
        stdout=values.get("stdout") or None,
        stderr=values.get("stderr") or None,
        log_dir=values.get("logdir") or None,
        execution_nodes=_tuple(values.get("executionnode", "")),
        waiting_position=_parse_int(values.get("waitingposition", "")),
        submitted_on_ce=_parse_time(values.get("submissiontime", "")),
        started=_parse_time(values.get("starttime", "")),
        ended=_parse_time(values.get("endtime", "")),
        erase_time=_parse_time(values.get("workingareaerasetime", "")),
        proxy_expiry=_parse_time(values.get("proxyexpirationtime", "")),
        used_wall_time=_parse_period(values.get("usedtotalwallltime", "")),
        used_cpu_time=_parse_period(values.get("usedtotalcputime", "")),
        used_memory=_parse_int(values.get("usedmainmemory", "")),
        requested_slots=_parse_int(values.get("requestedslots", "")),
        requested_wall_time=_parse_period(values.get("requestedtotalwallltime", "")),
        local_id=values.get("localidfrommanager") or None,
        restart_state=values.get("restartstate") or None,
        other_messages=_tuple(values.get("othermessages", "")),
        extra=values,
    )


def _migrate(connection: sqlite3.Connection) -> None:
    """Bring an old-format job list up to date, as ARC does on opening one.

    A table without ARC's newest column (``activityoldid``) is rebuilt with
    every column, the old ones carried over, in one transaction.
    """
    present = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    if _COLUMNS[-1] in present:
        return
    with connection:
        for statement in _MIGRATION:
            connection.execute(statement)


class JobList:
    """ARC's ``jobs.dat``: created on first write, shared safely with ARC's tools.

    Readers skip jobs on interfaces other than REST (an old EMI-ES or
    GridFTP entry), and leave them untouched when writing.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout = timeout

    def _check_format(self) -> None:
        try:
            with open(self.path, "rb") as handle:
                head = handle.read(len(_SQLITE_MAGIC))
        except FileNotFoundError:
            return
        except OSError as exc:
            raise self._open_error(exc.strerror, exc.errno) from exc
        if head and head != _SQLITE_MAGIC:
            raise ARCError(
                f"{self.path} is not an SQLite job list (an old ARC XML one?); "
                "convert it with ARC's arcsync, or name another file with -j",
                errno.EINVAL,
            )

    def _open_error(self, reason: object, code: int | None = errno.EIO) -> ARCError:
        return ARCError(f"Cannot open the job list {self.path}: {reason}", code or errno.EIO)

    def _connect(self) -> sqlite3.Connection:
        self._check_format()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=self.timeout)
        except OSError as exc:
            raise self._open_error(exc.strerror, exc.errno) from exc
        except sqlite3.Error as exc:
            raise self._open_error(exc) from exc
        try:
            for statement in _SCHEMA:
                connection.execute(statement)
            _migrate(connection)
        except sqlite3.Error as exc:
            connection.close()
            raise self._open_error(exc) from exc
        return connection

    def _stored_ids(self, connection: sqlite3.Connection) -> dict[str, str]:
        """Each stored job's canonical URL, to the id column exactly as it was written."""
        found: dict[str, str] = {}
        for (raw,) in connection.execute("SELECT id FROM jobs"):
            canonical = _canonical(unescape(raw or ""))
            if canonical is not None:
                found.setdefault(canonical, raw)
        return found

    def _rows(self, connection: sqlite3.Connection) -> Iterator[dict[str, str]]:
        cursor = connection.execute(_SELECT)
        for raw in cursor:
            yield {name: unescape(value or "") for name, value in zip(_COLUMNS, raw, strict=True)}

    def jobs(self) -> list[Job]:
        """Every REST job in the list, in insertion order; empty if there is no list."""
        if not self.path.exists():
            return []
        connection = self._connect()
        try:
            return [job for row in self._rows(connection) if (job := _job(row)) is not None]
        finally:
            connection.close()

    def __iter__(self) -> Iterator[Job]:
        return iter(self.jobs())

    def __len__(self) -> int:
        return len(self.jobs())

    def write(self, jobs: Iterable[Job]) -> None:
        """Add or replace ``jobs``, matched by job URL however ARC spelled the stored id."""
        rows = [_row(job) for job in jobs]
        if not rows:
            return
        connection = self._connect()
        try:
            stored = self._stored_ids(connection)
            values = [
                (stored.get(row["id"], escape(row["id"])), *(escape(row[c]) for c in _COLUMNS[1:]))
                for row in rows
            ]
            with connection:
                connection.executemany(_REPLACE, values)
        finally:
            connection.close()

    def remove(self, urls: Iterable[str]) -> int:
        """Drop the jobs with these job URLs; returns how many went."""
        wanted = {_canonical(url) for url in urls} - {None}
        if not wanted or not self.path.exists():
            return 0
        connection = self._connect()
        try:
            stored = [row[0] for row in connection.execute("SELECT id FROM jobs")]
            doomed = [(raw,) for raw in stored if _canonical(unescape(raw or "")) in wanted]
            with connection:
                connection.executemany("DELETE FROM jobs WHERE id = ?", doomed)
        finally:
            connection.close()
        return len(doomed)

    def clear(self) -> None:
        """Forget every job (``arcsync -T``)."""
        if self.path.exists():
            connection = self._connect()
            try:
                with connection:
                    connection.execute("DELETE FROM jobs")
            finally:
                connection.close()


def now() -> _dt.datetime:
    """The submission timestamp recorded for a new job (whole seconds, UTC)."""
    return _dt.datetime.fromtimestamp(int(time.time()), _dt.UTC)
