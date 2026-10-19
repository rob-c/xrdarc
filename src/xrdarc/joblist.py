"""The local job list, in the SQLite format ARC's own tools use (``~/.arc/jobs.dat``).

Writing ARC's format rather than one of our own means a job submitted here
shows up in ``arcstat``, ``arcget`` and the rest, and one submitted with
``arcsub`` can be managed here. The table, the column names (misspellings
included) and the escaping are ``JobInformationStorageSQLite``'s: every
value is text, the characters ``' # CR LF BS NUL %`` are written as ``%`` and
two lower-case hex digits, unknown integers are ``-1``, unknown times empty,
and list-valued fields hold only their first element.

Sharing the file with ARC's tools is safe because SQLite does the locking:
every write here is one transaction, a writer waits up to ``timeout`` for
another process's lock (``arcsub`` running in a second shell), and readers
never see half a job. The connection is opened per operation and closed
again, so no lock is held while a command talks to a CE.

Rows are matched by *canonical* job URL, not by the text stored: ARC
writes ``https://ce/arex/rest/1.0/jobs/<id>`` while an older tool may have
stored the port, a trailing slash or another REST version, and all of
those are the same job (:func:`~xrdarc.urls.parse_job_url`).

A job list in ARC's older XML format is refused with an explanation rather
than overwritten. :meth:`JobList.check` asks every question a later write
could fail on (format, permissions, the lock) up front: submission calls it
before it touches the CE, because a job the CE accepted but the list could
not record is a job the user cannot find again.
"""

from __future__ import annotations

import datetime as _dt
import errno
import os
import re
import sqlite3
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ._version import __version__
from .errors import ARCError
from .info import JobRecord
from .states import JobState
from .urls import job_url, parse_job_url

__all__ = ["Job", "JobList"]

#: What the ``*interface*`` columns say for a job managed over REST; ARC's
#: tools dispatch on it (an EMI-ES or GridFTP job names its own).
REST_INTERFACE = "org.nordugrid.arcrest"

#: ARC's columns, in its order and with its spelling - ``wallltime`` with
#: three l's is what ``JobInformationStorageSQLite`` created, and a column
#: spelt correctly would be a different column.
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

#: What a column name spliced into SQL text may be: a plain lowercase word.
_PLAIN_NAME = re.compile(r"[a-z]+")


def _sql(template: str, *, values: int = 0, **columns: Sequence[str]) -> str:
    """``template`` with each ``{name}`` a list of column names, and ``{values}`` placeholders.

    SQL cannot take identifiers as placeholders, so column names are spliced
    into the text: only this module's constants, each checked to be a plain
    lowercase word, so nothing but an identifier can get in. Every value
    goes through one of the ``values`` ``?`` placeholders instead.
    """
    for names in columns.values():
        for name in names:
            if not _PLAIN_NAME.fullmatch(name):
                raise ValueError(f"not a plain SQL column name: {name!r}")
    lists = {key: ", ".join(names) for key, names in columns.items()}
    return template.format(values=", ".join("?" * values), **lists)


#: ``IF NOT EXISTS`` throughout: the schema is applied on every open, so a
#: list ARC created, one this module created and a brand-new file all end up
#: the same. ``UNIQUE(id)`` is what makes ``REPLACE INTO`` an upsert; the
#: host index is ARC's, created the same way so the two schemas match.
_SCHEMA = (
    _sql("CREATE TABLE IF NOT EXISTS jobs({columns}, UNIQUE(id))", columns=_COLUMNS),
    "CREATE INDEX IF NOT EXISTS serviceinformationhost ON jobs(serviceinformationhost)",
)
#: The columns of job lists written before ARC 6.x added the job's last known state.
#: Only these are copied when :func:`_migrate` rebuilds an old table; the
#: rest start empty and are filled in the next time the job is asked about.
_OLD_COLUMNS = _COLUMNS[:16]
_MIGRATION = (
    _sql("CREATE TABLE jobs_new({columns}, UNIQUE(id))", columns=_COLUMNS),
    _sql("INSERT INTO jobs_new ({old}) SELECT {old} FROM jobs", old=_OLD_COLUMNS),
    "DROP TABLE jobs",
    "ALTER TABLE jobs_new RENAME TO jobs",
    "CREATE INDEX IF NOT EXISTS serviceinformationhost ON jobs(serviceinformationhost)",
)
_SELECT = _sql("SELECT {columns} FROM jobs", columns=_COLUMNS)
_REPLACE = _sql(
    "REPLACE INTO jobs({columns}) VALUES ({values})", columns=_COLUMNS, values=len(_COLUMNS)
)
#: What ARC escapes: its storage code builds SQL text by concatenation, so a
#: quote would end a literal and a line break or NUL split or truncate it;
#: ``%`` is the escape character itself. Values here go through placeholders and need none of
#: it, but must be escaped anyway so ARC's tools read back what was meant.
_SPECIAL = "'#\r\n\b\0%"
#: One escape: ``%`` and two hex digits (either case, as ARC reads them).
_ESCAPED = re.compile(r"%([0-9a-fA-F]{2})")
#: The first sixteen bytes of every SQLite 3 database file (its file-format spec).
_SQLITE_MAGIC = b"SQLite format 3\0"
#: The subset of ISO 8601 durations ARC's ``Period`` writes for wall and CPU
#: times: hours, minutes and seconds only, each optional (``PT`` alone is
#: "unknown"). Anything else reads as unknown.
_PERIOD = re.compile(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?")


def escape(value: str) -> str:
    """ARC's SQL escaping: special characters as ``%xx``."""
    return "".join(f"%{ord(c):02x}" if c in _SPECIAL else c for c in value)


def unescape(value: str) -> str:
    """Undo ``escape``; a malformed escape is kept literally, as ARC does."""
    # Any case of hex is accepted: escape() writes lower case, but a reader
    # must take whatever another tool wrote rather than fail the whole list.
    return _ESCAPED.sub(lambda match: chr(int(match[1], 16)), value)


# -- column codecs ---------------------------------------------------------------------------
# Each column holds text; these turn a Job field into it and back, in ARC's
# conventions. A reader must accept whatever ARC's own tools wrote, so every
# ``_read_*`` is lenient: a value it cannot read is "unknown", never an error
# that would make the whole job list unreadable.


def _write_text(value: str | None) -> str:
    """An optional string; unknown is empty."""
    return value or ""


def _read_text(text: str) -> str | None:
    """An optional string; empty is unknown."""
    return text or None


def _write_int(value: int | None) -> str:
    """An integer; unknown is ``-1``, ARC's sentinel."""
    return "-1" if value is None else str(value)


def _read_int(text: str) -> int | None:
    """An integer; ``-1`` or anything unreadable is unknown."""
    try:
        number = int(text)
    except ValueError:
        return None
    return None if number == -1 else number


def _write_period(seconds: int | None) -> str:
    """A duration as ARC's ``Period`` writes it (``PT5400S``); unknown is a bare ``PT``."""
    return "PT" if seconds is None else f"PT{seconds}S"


def _read_period(text: str) -> int | None:
    """ARC's ``Period`` text in seconds: ``PT1H30M``, ``PT45S``, or ``PT5400S`` as written here."""
    match = _PERIOD.fullmatch(text)
    if match is None or not any(match.groups()):
        return None
    hours, minutes, seconds = (int(group or 0) for group in match.groups())
    return hours * 3600 + minutes * 60 + seconds


def _write_time(when: _dt.datetime | None) -> str:
    """An instant as ISO 8601 UTC with a ``Z``; unknown is empty.

    UTC rather than ARC's zone-less local time: a job list outlives
    daylight-saving changes and may be read on another machine, and only a
    zone-qualified instant means the same thing in both places.
    """
    return "" if when is None else when.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_time(text: str) -> _dt.datetime | None:
    """A stored instant in UTC.

    ARC's tools write local time with no zone (``Time::UserTime``,
    ``2026-10-17 12:05:12``), this module UTC with a ``Z``; both read back
    correctly (a naive time is taken as local, as ARC meant it).
    """
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    # On a naive value (ARC's local time) ``astimezone`` assumes the local
    # zone, which is exactly what ARC meant when it wrote it.
    return parsed.astimezone(_dt.UTC)


def _write_first(values: Sequence[str]) -> str:
    """A list-valued field: ARC's table keeps only the first element."""
    return values[0] if values else ""


def _read_first(text: str) -> tuple[str, ...]:
    """A list-valued field read back: one element, or none."""
    return (text,) if text else ()


def _write_state(state: JobState) -> str:
    """The generic state's name, as ARC stores ``JobState::GetGeneralState``."""
    return state.value


@dataclass(frozen=True, slots=True)
class _Column:
    """How one column maps onto one :class:`Job` field: the field, and both directions."""

    field: str
    write: Callable[[Any], str]
    read: Callable[[str], Any]


_TEXT = (_write_text, _read_text)
_INT = (_write_int, _read_int)
_PERIODS = (_write_period, _read_period)
_TIME = (_write_time, _read_time)
_FIRST = (_write_first, _read_first)

#: The columns that are plainly one Job field each. The others - the job's
#: identity and where its CE is (``id``, the ``*url`` and ``*dir`` columns),
#: and the submission time - are derived in :func:`_row`/:func:`_job`.
_FIELD_COLUMNS: dict[str, _Column] = {
    column: _Column(name, *codec)
    for column, name, codec in (
        ("name", "name", _TEXT),
        ("descriptiondocument", "description", (str, str)),
        ("delegationid", "delegations", _FIRST),
        ("localidfrommanager", "local_id", _TEXT),
        ("state", "state", (_write_state, JobState.parse)),
        ("restartstate", "restart_state", _TEXT),
        ("exitcode", "exit_code", _INT),
        ("error", "errors", _FIRST),
        ("waitingposition", "waiting_position", _INT),
        ("owner", "owner", _TEXT),
        ("requestedtotalwallltime", "requested_wall_time", _PERIODS),
        ("requestedslots", "requested_slots", _INT),
        ("stdin", "stdin", _TEXT),
        ("stdout", "stdout", _TEXT),
        ("stderr", "stderr", _TEXT),
        ("logdir", "log_dir", _TEXT),
        ("executionnode", "execution_nodes", _FIRST),
        ("queue", "queue", _TEXT),
        ("usedtotalwallltime", "used_wall_time", _PERIODS),
        ("usedtotalcputime", "used_cpu_time", _PERIODS),
        ("usedmainmemory", "used_memory", _INT),
        ("submissiontime", "submitted_on_ce", _TIME),
        ("starttime", "started", _TIME),
        ("endtime", "ended", _TIME),
        ("workingareaerasetime", "erase_time", _TIME),
        ("proxyexpirationtime", "proxy_expiry", _TIME),
        ("othermessages", "other_messages", _FIRST),
    )
}


@dataclass(frozen=True, slots=True)
class Job:
    """A job as the client knows it: where it is, what it was, what it was last seen as.

    ``ce`` is the canonical CE URL and ``id`` the CE's id; ``url`` is the
    job URL ARC users quote. Fields after ``delegations`` are the CE's last
    report (``update`` refreshes them); ``state`` is ``UNDEFINED`` until
    the CE has been asked.
    """

    #: The canonical CE URL (``https://host:443/arex``) and the CE's job id.
    ce: str
    id: str
    #: ``jobname`` from the description; ``get -J`` names the directory after it.
    name: str | None = None
    #: The description as sent to the CE (GRIDMANAGER dialect), as ARC stores it.
    description: str = ""
    #: When this client submitted it (``localsubmissiontime``).
    submitted: _dt.datetime | None = None
    #: The delegations the job uses; ``renew`` refreshes them.
    delegations: tuple[str, ...] = ()
    state: JobState = JobState.UNDEFINED
    rest_state: str | None = None
    exit_code: int | None = None
    #: A-REX's failure lines, or a note this client added (an abandoned job).
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
    #: The row as last read, every column: kept so a rewrite does not lose
    #: what ARC's tools stored in columns this class does not model.
    extra: dict[str, str] = field(default_factory=dict, compare=False)

    @property
    def url(self) -> str:
        """The job URL users quote and ARC stores: ``<ce>/rest/1.0/jobs/<id>``."""
        return job_url(self.ce, self.id)

    @classmethod
    def from_url(cls, url: str, **fields: Any) -> Job:
        """A job known only by its URL (``-i FILE``, a URL on the command line); ``fields`` too.

        Raises ``DescriptionError`` for text that is not an ARC REST job URL.
        """
        parsed = parse_job_url(url)
        return cls(ce=parsed.ce, id=parsed.id, **fields)

    def update(self, record: JobRecord) -> Job:
        """This job with the CE's latest report applied; absent fields keep their values."""
        changes = {
            name: getattr(record, source)
            for name, source in _RECORD_FIELDS.items()
            if getattr(record, source) not in (None, ())
        }
        # A-REX leaves out what it does not know (yet): an absent field means
        # "not reported this time", not "cleared", so the last value stays.
        # The state is always the CE's latest word, UNDEFINED included.
        changes["state"] = record.state
        changes["rest_state"] = record.rest_state
        return replace(self, **changes)


#: ``Job`` field -> ``JobRecord`` field: what an ``action=info`` answer updates.
#: Nearly every name is the same; the CE's submission time is
#: ``submitted_on_ce`` here, because ``submitted`` is when *this* client sent it.
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


def _canonical(url: str) -> str | None:
    """A stored id as the canonical job URL, or ``None`` for one that is not a REST job's."""
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
    """``job`` as a row of ARC's table: every column, as text, unescaped.

    Columns the ``Job`` does not model keep what the row held (``job.extra``,
    which ARC's tools may have filled in), or get :data:`_UNMODELED`'s
    defaults for a new row. Every interface column names the REST interface
    and every location the CE (the session directory is the job URL's
    ``/session``), which is how ``arcstat`` knows to talk REST to it.
    """
    # ``or default``: a column ARC left empty gets the default rather than an
    # empty string where ARC's own writer would put one (``PT`` for a period).
    kept = {name: job.extra.get(name) or default for name, default in _UNMODELED.items()}
    fields = {
        column: spec.write(getattr(job, spec.field)) for column, spec in _FIELD_COLUMNS.items()
    }
    return {**kept, **_locations(job), **fields}


def _locations(job: Job) -> dict[str, str]:
    """The columns that say where the job and its CE are, and when it was submitted."""
    # The column always gets a number, so :func:`_job` can read it back;
    # a job with no recorded submission time is stamped now.
    submitted = job.submitted or _dt.datetime.now(_dt.UTC)
    # On REST all three directories are the job's one session resource.
    session = f"{job.url}/session"
    return {
        "id": job.url,
        "idfromendpoint": job.id,
        "statusinterface": REST_INTERFACE,
        "statusurl": job.ce,
        "managementinterfacename": REST_INTERFACE,
        "managementurl": job.ce,
        "serviceinformationinterfacename": REST_INTERFACE,
        "serviceinformationurl": job.ce,
        "serviceinformationhost": urllib.parse.urlsplit(job.ce).hostname or "",
        "sessiondir": session,
        "stageindir": session,
        "stageoutdir": session,
        # Epoch seconds, the form :func:`_job` reads back.
        "localsubmissiontime": str(int(submitted.timestamp())),
    }


def _job(values: dict[str, str]) -> Job | None:
    """A job from a row; ``None`` for rows that are not ARC REST jobs (other interfaces).

    The whole row is kept as ``extra``, so columns this module does not
    model survive a read-modify-write untouched.
    """
    try:
        parsed = parse_job_url(values.get("id", ""))
    except ARCError:
        return None
    # ``idfromendpoint`` is the CE's id as ARC stored it; the URL's last
    # segment stands in for a row that left it empty.
    seconds = _read_int(values.get("localsubmissiontime", ""))
    fields = {
        spec.field: spec.read(values.get(column, "")) for column, spec in _FIELD_COLUMNS.items()
    }
    return Job(
        ce=parsed.ce,
        id=values.get("idfromendpoint") or parsed.id,
        submitted=None if seconds is None else _dt.datetime.fromtimestamp(seconds, _dt.UTC),
        extra=values,
        **fields,
    )


def _migrate(connection: sqlite3.Connection) -> None:
    """Bring an old-format job list up to date, as ARC does on opening one.

    A table without ARC's newest column (``activityoldid``) is rebuilt with
    every column, the old ones carried over, in one transaction.
    """
    # ``table_info`` rows are (cid, name, type, notnull, default, pk). ARC
    # only ever appended columns, so the newest one present means all are.
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
        """Nothing is opened (or created) until first used; ``timeout`` is the lock wait."""
        self.path = Path(path)
        self.timeout = timeout

    def _check_format(self) -> None:
        """Refuse a file that exists and is not SQLite, before SQLite is let near it.

        ``sqlite3.connect`` would happily open an XML job list and fail later
        with "file is not a database"; worse, a write could follow. The first
        sixteen bytes say which it is.
        """
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
        """The error for a job list that cannot be used, naming it (``EIO`` without an errno)."""
        return ARCError(f"Cannot open the job list {self.path}: {reason}", code or errno.EIO)

    def _connect(self) -> sqlite3.Connection:
        """A connection to the list, with ARC's schema in place (created or migrated).

        The directory is created too (``~/.arc`` on a fresh account). Every
        failure is an ``ARCError`` naming the file, and the connection is
        closed again if the schema could not be set up.
        """
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
        # The first spelling wins when ARC stored one job twice; :meth:`remove`
        # deletes every spelling, so the duplicates do not outlive the job.
        for (raw,) in connection.execute("SELECT id FROM jobs"):
            canonical = _canonical(unescape(raw or ""))
            if canonical is not None:
                found.setdefault(canonical, raw)
        return found

    def _rows(self, connection: sqlite3.Connection) -> Iterator[dict[str, str]]:
        """Every row as ``column -> value``, unescaped (``NULL`` read as empty)."""
        cursor = connection.execute(_SELECT)
        for raw in cursor:
            yield {name: unescape(value or "") for name, value in zip(_COLUMNS, raw, strict=True)}

    def check(self) -> None:
        """Make sure jobs can be written now; ``ARCError`` explaining why not.

        Opens the list (creating it, its directory and ARC's schema if need
        be, migrating an old schema), then takes SQLite's write lock and
        writes a row inside a transaction that is rolled back. That is the
        only reliable test: a read-only file opens and even takes the lock
        without complaint, and only a real write says "readonly". Waits up
        to ``timeout`` for another process (``arcsub``, another ``xrdarc``)
        holding the lock, as a write would.
        """
        connection = self._connect()
        try:
            # IMMEDIATE takes the write lock now (waiting ``timeout`` for it)
            # instead of at the first write, which is the wait being tested.
            connection.execute("BEGIN IMMEDIATE")
            # Not a job URL, so even if the rollback were lost no reader here
            # would take it for a job (rows that do not parse are skipped).
            connection.execute("INSERT OR REPLACE INTO jobs(id) VALUES (?)", ("xrdarc-check",))
        except sqlite3.Error as exc:
            raise self._open_error(exc) from exc
        finally:
            connection.rollback()
            connection.close()

    def jobs(self) -> list[Job]:
        """Every REST job in the list, in insertion order; empty if there is no list."""
        # Reading must not create ``~/.arc/jobs.dat``: ``xrdarc stat`` on a fresh
        # account says "no jobs", it does not leave an empty database behind.
        if not self.path.exists():
            return []
        connection = self._connect()
        try:
            return [job for row in self._rows(connection) if (job := _job(row)) is not None]
        finally:
            connection.close()

    def __iter__(self) -> Iterator[Job]:
        """The jobs, read now (see :meth:`jobs`)."""
        return iter(self.jobs())

    def __len__(self) -> int:
        """How many REST jobs the list holds now."""
        return len(self.jobs())

    def write(self, jobs: Iterable[Job]) -> None:
        """Add or replace ``jobs``, matched by job URL however ARC spelled the stored id."""
        rows = [_row(job) for job in jobs]
        if not rows:
            return
        # A job already stored under another spelling of its URL is replaced
        # under that spelling, so ARC's tools keep finding it where they put it.
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
        # A URL that is not a REST job's cannot match a stored REST job, so it
        # is dropped here rather than raising.
        wanted = {_canonical(url) for url in urls} - {None}
        if not wanted or not self.path.exists():
            return 0
        connection = self._connect()
        try:
            # Every row for the job, however it was spelt: ARC may have stored it twice.
            rows = connection.execute("SELECT id FROM jobs")
            doomed = [(raw,) for (raw,) in rows if _canonical(unescape(raw or "")) in wanted]
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
    """The submission timestamp recorded for a new job (whole seconds, UTC).

    Whole seconds because ``localsubmissiontime`` stores whole seconds: a
    job written and read back then compares equal to the one in memory.
    """
    return _dt.datetime.fromtimestamp(int(time.time()), _dt.UTC)
