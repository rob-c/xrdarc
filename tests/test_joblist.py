"""The job list: ARC's own SQLite jobs.dat, shared row for row with ARC's C++ tools."""

from __future__ import annotations

import datetime as dt
import errno
import os
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from xrdarc import __version__, joblist
from xrdarc.errors import ARCError
from xrdarc.info import parse_activity
from xrdarc.joblist import Job, JobList, escape, now, unescape
from xrdarc.states import JobState

UTC = dt.UTC
CE = "https://ce.example.org:443/arex"
URL = f"{CE}/rest/1.0/jobs/abc"
REST = "org.nordugrid.arcrest"

# JOBS_COLUMNS in ARC's JobInformationStorageSQLite.cpp, misspellings and all.
ARC_JOBS_COLUMNS = (
    "id, idfromendpoint, name, statusinterface, statusurl, "
    "managementinterfacename, managementurl, "
    "serviceinformationinterfacename, serviceinformationurl, serviceinformationhost, "
    "sessiondir, stageindir, stageoutdir, "
    "descriptiondocument, localsubmissiontime, delegationid, "
    "type, localidfrommanager, description, state, restartstate, exitcode, "
    "computingmanagerexitcode, "
    "error, waitingposition, userdomain, owner, localowner, "
    "requestedtotalwallltime, requestedtotalcputime, requestedslots, "
    "requestedapplicationenvironment, "
    "stdin, stdout, stderr, logdir, executionnode, queue, "
    "usedtotalwallltime, usedtotalcputime, usedmainmemory, "
    "submissiontime, computingmanagersubmissiontime, starttime, computingmanagerendtime, endtime, "
    "workingareaerasetime, proxyexpirationtime, submissionhost, submissionclienttime, "
    "othermessages, activityoldid"
)
COLUMNS = ARC_JOBS_COLUMNS.split(", ")
ARC_SCHEMA = (
    f"CREATE TABLE IF NOT EXISTS jobs({ARC_JOBS_COLUMNS}, UNIQUE(id))",
    "CREATE INDEX IF NOT EXISTS serviceinformationhost ON jobs(serviceinformationhost)",
)


def _arc_escape(value: str) -> str:
    """``Arc::escape_chars(value, "'#\\r\\n\\b\\0", '%', false, escape_hex)``."""
    return "".join(f"%{ord(c):02x}" if c in "'#\r\n\b\0%" else c for c in value)


def _arc_write(path: Path, *rows: dict[str, str]) -> None:
    """Rows as ARC's C++ client writes them: every column, every value escaped."""
    insert = joblist._sql(
        "INSERT INTO jobs({columns}) VALUES ({values})", columns=COLUMNS, values=len(COLUMNS)
    )
    connection = sqlite3.connect(path)
    try:
        with connection:
            for statement in ARC_SCHEMA:
                connection.execute(statement)
            for row in rows:
                connection.execute(insert, [_arc_escape(row.get(c, "")) for c in COLUMNS])
    finally:
        connection.close()


def _raw(path: Path) -> list[dict[str, str]]:
    """Every row exactly as stored (still escaped)."""
    connection = sqlite3.connect(path)
    try:
        cursor = connection.execute(
            joblist._sql("SELECT {columns} FROM jobs ORDER BY rowid", columns=COLUMNS)
        )
        return [dict(zip(COLUMNS, row, strict=True)) for row in cursor]
    finally:
        connection.close()


def _arc_row(**changes: str) -> dict[str, str]:
    """A REST job row as ``arcsub`` / ``arcstat`` leave it."""
    row = {
        "id": URL,
        "idfromendpoint": "abc",
        "name": "arc's job #1",
        "statusinterface": REST,
        "statusurl": CE,
        "managementinterfacename": REST,
        "managementurl": CE,
        "serviceinformationinterfacename": REST,
        "serviceinformationurl": CE,
        "serviceinformationhost": "ce.example.org",
        "sessiondir": f"{URL}/session",
        "stageindir": f"{URL}/session",
        "stageoutdir": f"{URL}/session",
        "descriptiondocument": '&(executable="run.sh")\n(jobname="arc\'s job #1")',
        "localsubmissiontime": "1792231512",
        "delegationid": "deleg123",
        "localidfrommanager": "4242",
        "state": "Running",
        "restartstate": "",
        "exitcode": "-1",
        "error": "",
        "waitingposition": "-1",
        "userdomain": "atlas",
        "owner": "/DC=org/CN=someone",
        "localowner": "griduser",
        "requestedtotalwallltime": "PT1H30M",
        "requestedtotalcputime": "PT2H",
        "requestedslots": "1",
        "requestedapplicationenvironment": "ENV/PROXY",
        "stdout": "out.txt",
        "stderr": "err.txt",
        "logdir": "gmlog",
        "executionnode": "wn1.example.org",
        "queue": "grid",
        "usedtotalwallltime": "PT45S",
        "usedtotalcputime": "PT0S",
        "usedmainmemory": "2048",
        "submissiontime": "2026-10-17T10:05:12Z",
        "starttime": "2026-10-17 12:06:00",
        "submissionhost": "ui.example.org",
        "submissionclienttime": "arcsub-7.1.1",
        "othermessages": "SubmittedVia=org.nordugrid.arcrest",
    }
    row.update(changes)
    return row


GRIDFTP_ROW = {
    "id": "gsiftp://old.example.org:2811/jobs/xyz",
    "idfromendpoint": "xyz",
    "name": "legacy #job",
    "statusinterface": "org.nordugrid.gridftpjob",
    "statusurl": "ldap://old.example.org:2135",
    "state": "Finished",
}
EMIES_ROW = {
    "id": "https://ce.example.org:443/arex/emies/ABCDEF",
    "statusinterface": "org.ogf.glue.emies.activitymanagement",
}


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / ".arc" / "jobs.dat"


@pytest.fixture
def utc_plus_two() -> Iterator[None]:
    """A local time zone two hours east of UTC, as on a European submit host in summer."""
    if not hasattr(time, "tzset"):
        pytest.skip("platform without time.tzset (Windows)")
    old = os.environ.get("TZ")
    os.environ["TZ"] = "XRD-2"
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        time.tzset()


def _job(**fields: object) -> Job:
    return Job.from_url(URL, submitted=dt.datetime(2026, 10, 17, 10, tzinfo=UTC), **fields)


FULL = {
    "name": "it's #1\r\n100%",
    "description": "&(executable='run.sh')\0\b",
    "delegations": ("deleg-1", "deleg-2"),
    "state": JobState.FINISHED,
    "rest_state": "FINISHED",
    "exit_code": 0,
    "errors": ("first", "second"),
    "queue": "grid",
    "owner": "/DC=org/CN=someone",
    "stdin": "in",
    "stdout": "out",
    "stderr": "err",
    "log_dir": "gmlog",
    "execution_nodes": ("wn1", "wn2"),
    "waiting_position": 3,
    "submitted_on_ce": dt.datetime(2026, 10, 17, 10, 0, 1, tzinfo=UTC),
    "started": dt.datetime(2026, 10, 17, 10, 1, tzinfo=UTC),
    "ended": dt.datetime(2026, 10, 17, 10, 2, tzinfo=UTC),
    "erase_time": dt.datetime(2026, 10, 24, 10, 2, tzinfo=UTC),
    "proxy_expiry": dt.datetime(2026, 10, 18, tzinfo=UTC),
    "used_wall_time": 60,
    "used_cpu_time": 55,
    "used_memory": 2048,
    "requested_slots": 1,
    "requested_wall_time": 5400,
    "local_id": "12345",
    "restart_state": "SUBMITTING",
    "other_messages": ("one", "two"),
}


# -- escaping -------------------------------------------------------------------


def test_escape_matches_arc() -> None:
    assert escape("'#\r\n\b\0%") == "%27%23%0d%0a%08%00%25"
    assert escape("plain text: /path?a=b&c") == "plain text: /path?a=b&c"


def test_escape_round_trips_every_character() -> None:
    text = "".join(chr(c) for c in range(0x300))
    assert escape(text) == _arc_escape(text)
    assert unescape(escape(text)) == text


@pytest.mark.parametrize(
    ("stored", "value"),
    [
        ("%4A%4a", "JJ"),
        ("100%", "100%"),
        ("%4", "%4"),
        ("%zz", "%zz"),
        ("%%41", "%A"),
        ("", ""),
    ],
)
def test_unescape_tolerates_case_and_malformed_escapes(stored: str, value: str) -> None:
    assert unescape(stored) == value


# -- the schema and the rows written ------------------------------------------------


def test_new_list_has_arcs_schema(path: Path) -> None:
    JobList(path).write([_job()])
    connection = sqlite3.connect(path)
    try:
        names = [row[1] for row in connection.execute("PRAGMA table_info(jobs)")]
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(jobs)")}
    finally:
        connection.close()
    assert names == COLUMNS
    assert "serviceinformationhost" in indexes
    assert path.read_bytes().startswith(b"SQLite format 3\0")


def test_arc_tool_schema_is_accepted(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path)
    JobList(path).write([_job()])
    assert [row["id"] for row in _raw(path)] == [URL]


def test_row_written_for_a_new_job(path: Path) -> None:
    JobList(path).write([_job(name="n", delegations=("d1", "d2"), description="&(a=b)")])
    (row,) = _raw(path)
    assert row["id"] == URL
    assert row["idfromendpoint"] == "abc"
    for column in ("statusinterface", "managementinterfacename", "serviceinformationinterfacename"):
        assert row[column] == REST
    for column in ("statusurl", "managementurl", "serviceinformationurl"):
        assert row[column] == CE
    assert row["serviceinformationhost"] == "ce.example.org"
    for column in ("sessiondir", "stageindir", "stageoutdir"):
        assert row[column] == f"{URL}/session"
    assert row["descriptiondocument"] == "&(a=b)"
    assert row["localsubmissiontime"] == "1792231200"
    assert row["delegationid"] == "d1"
    assert row["submissionclienttime"] == f"xrdarc/{__version__}"


def test_unknown_values_use_arcs_placeholders(path: Path) -> None:
    JobList(path).write([_job()])
    (row,) = _raw(path)
    assert row["state"] == "Undefined"
    for column in ("exitcode", "waitingposition", "requestedslots", "usedmainmemory"):
        assert row[column] == "-1"
    for column in (
        "requestedtotalwallltime",
        "requestedtotalcputime",
        "usedtotalwallltime",
        "usedtotalcputime",
    ):
        assert row[column] == "PT"
    for column in ("submissiontime", "starttime", "endtime", "workingareaerasetime", "name"):
        assert row[column] == ""


def test_known_values_are_written_in_arcs_forms(path: Path) -> None:
    JobList(path).write([_job(**FULL)])
    (row,) = _raw(path)
    assert row["name"] == "it%27s %231%0d%0a100%25"
    assert row["descriptiondocument"] == "&(executable=%27run.sh%27)%00%08"
    assert (row["state"], row["restartstate"], row["exitcode"]) == ("Finished", "SUBMITTING", "0")
    assert (row["error"], row["executionnode"], row["othermessages"]) == ("first", "wn1", "one")
    assert row["requestedtotalwallltime"] == "PT5400S"
    assert (row["usedtotalwallltime"], row["usedtotalcputime"]) == ("PT60S", "PT55S")
    assert row["submissiontime"] == "2026-10-17T10:00:01Z"
    assert row["proxyexpirationtime"] == "2026-10-18T00:00:00Z"


def test_times_are_stored_in_utc(path: Path) -> None:
    east = dt.timezone(dt.timedelta(hours=5))
    JobList(path).write([_job(started=dt.datetime(2026, 10, 17, 15, 1, tzinfo=east))])
    assert _raw(path)[0]["starttime"] == "2026-10-17T10:01:00Z"


@pytest.mark.parametrize(
    ("ce", "host"),
    [("https://[::1]:8443/arex", "::1"), ("https://ce.example.org:443/a:b", "ce.example.org")],
)
def test_service_information_host(path: Path, ce: str, host: str) -> None:
    JobList(path).write([Job(ce=ce, id="j")])
    assert _raw(path)[0]["serviceinformationhost"] == host


def test_submission_time_defaults_to_now(path: Path) -> None:
    before = int(time.time())
    JobList(path).write([Job.from_url(URL)])
    stored = int(_raw(path)[0]["localsubmissiontime"])
    assert before <= stored <= int(time.time())


def test_now_is_whole_seconds_utc() -> None:
    stamp = now()
    assert stamp.tzinfo is UTC
    assert stamp.microsecond == 0
    assert abs(stamp.timestamp() - time.time()) < 5


# -- reading back ---------------------------------------------------------------------


def test_full_round_trip(path: Path) -> None:
    job = _job(**FULL)
    JobList(path).write([job])
    (back,) = JobList(path).jobs()
    # List-valued fields keep their first element only, as in ARC.
    expected = Job.from_url(
        URL,
        **{
            **FULL,
            "submitted": job.submitted,
            "rest_state": None,
            "delegations": ("deleg-1",),
            "errors": ("first",),
            "execution_nodes": ("wn1",),
            "other_messages": ("one",),
        },
    )
    assert back == expected
    assert back.name == "it's #1\r\n100%"
    assert back.started is not None and back.started.tzinfo is not None


def test_minimal_round_trip(path: Path) -> None:
    job = _job()
    JobList(path).write([job])
    assert JobList(path).jobs() == [job]


def test_order_len_and_iteration(path: Path) -> None:
    jobs = [Job.from_url(f"{CE}/rest/1.0/jobs/j{n}", submitted=now()) for n in range(3)]
    joblist = JobList(path, timeout=5.0)
    joblist.write(jobs[:2])
    joblist.write(jobs[2:])
    assert joblist.timeout == 5.0
    assert [job.id for job in joblist] == ["j0", "j1", "j2"]
    assert len(joblist) == 3


def test_writing_again_replaces(path: Path) -> None:
    joblist = JobList(path)
    joblist.write([_job(state=JobState.RUNNING)])
    joblist.write([_job(state=JobState.FINISHED)])
    assert [job.state for job in joblist.jobs()] == [JobState.FINISHED]
    assert len(_raw(path)) == 1


def test_no_list_yet(path: Path) -> None:
    joblist = JobList(path)
    assert joblist.jobs() == []
    assert len(joblist) == 0
    assert joblist.remove([URL]) == 0
    joblist.clear()
    joblist.write([])
    assert not path.exists()
    assert not path.parent.exists()


def test_empty_file_is_an_empty_list(path: Path) -> None:
    path.parent.mkdir(parents=True)
    path.touch()
    assert JobList(path).jobs() == []
    JobList(path).write([_job()])
    assert len(JobList(path)) == 1


# -- rows ARC's own tools wrote -------------------------------------------------------------


def test_reads_a_row_arc_wrote(path: Path, utc_plus_two: None) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row())
    (job,) = JobList(path).jobs()
    assert (job.ce, job.id, job.url) == (CE, "abc", URL)
    assert job.name == "arc's job #1"
    assert job.description == '&(executable="run.sh")\n(jobname="arc\'s job #1")'
    assert job.submitted == dt.datetime.fromtimestamp(1792231512, UTC)
    assert job.delegations == ("deleg123",)
    assert (job.state, job.exit_code, job.waiting_position) == (JobState.RUNNING, None, None)
    assert (job.requested_wall_time, job.used_wall_time, job.used_cpu_time) == (5400, 45, 0)
    assert (job.used_memory, job.requested_slots, job.local_id) == (2048, 1, "4242")
    assert job.submitted_on_ce == dt.datetime(2026, 10, 17, 10, 5, 12, tzinfo=UTC)
    # ARC writes Time::UserTime: local time with no zone.
    assert job.started == dt.datetime(2026, 10, 17, 10, 6, tzinfo=UTC)
    assert (job.ended, job.errors, job.restart_state) == (None, (), None)
    assert job.extra["userdomain"] == "atlas"


@pytest.mark.parametrize(
    ("stored", "seconds"),
    [
        ("PT1H", 3600),
        ("PT2M", 120),
        ("PT1H2M3S", 3723),
        ("PT0S", 0),
        ("PT", None),
        ("P1D", None),
        ("1H", None),
        ("PT1.5S", None),
        ("", None),
    ],
)
def test_arc_periods(path: Path, stored: str, seconds: int | None) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(requestedtotalwallltime=stored))
    assert JobList(path).jobs()[0].requested_wall_time == seconds


@pytest.mark.parametrize(
    ("stored", "number"), [("-1", None), ("", None), ("x", None), ("0", 0), ("17", 17)]
)
def test_arc_integers(path: Path, stored: str, number: int | None) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(exitcode=stored))
    assert JobList(path).jobs()[0].exit_code == number


def test_unparseable_times_and_submission_are_unknown(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(starttime="soon", localsubmissiontime="", idfromendpoint=""))
    (job,) = JobList(path).jobs()
    assert (job.started, job.submitted) == (None, None)
    assert job.id == "abc"


def test_rewriting_an_arc_row_replaces_it_and_keeps_arcs_columns(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row())
    joblist = JobList(path)
    (job,) = joblist.jobs()
    record = parse_activity({"State": "arcrest:FINISHED", "ExitCode": "0"})
    joblist.write([job.update(record)])
    (row,) = _raw(path)
    assert (row["id"], row["state"], row["exitcode"]) == (URL, "Finished", "0")
    assert row["name"] == "arc%27s job %231"
    for column in ("userdomain", "localowner", "submissionhost", "submissionclienttime"):
        assert row[column] == _arc_row()[column]
    assert (row["requestedtotalcputime"], row["requestedapplicationenvironment"]) == (
        "PT2H",
        "ENV/PROXY",
    )


def test_fresh_job_replaces_an_arc_row_spelled_differently(path: Path) -> None:
    spelled = "https://CE.example.org/arex/rest/1.1/jobs/abc/"
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(id=spelled), GRIDFTP_ROW)
    joblist = JobList(path)
    joblist.write([Job.from_url(URL, state=JobState.KILLED)])
    rows = {row["id"]: row for row in _raw(path)}
    # REPLACE re-inserts, so the row moves to the end, exactly as with ARC's tools.
    assert list(rows) == [GRIDFTP_ROW["id"], spelled]
    assert rows[spelled]["state"] == "Killed"
    assert [job.state for job in joblist.jobs()] == [JobState.KILLED]


def test_escaped_arc_id_is_replaced_not_duplicated(path: Path) -> None:
    odd = f"{CE}/rest/1.0/jobs/a%b"
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(id=odd, idfromendpoint="a%b"))
    joblist = JobList(path)
    (job,) = joblist.jobs()
    assert job.id == "a%b"
    joblist.write([job])
    assert [row["id"] for row in _raw(path)] == [f"{CE}/rest/1.0/jobs/a%25b"]


def test_non_rest_rows_are_skipped_and_left_intact(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, GRIDFTP_ROW, _arc_row(), EMIES_ROW)
    before = _raw(path)
    joblist = JobList(path)
    assert [job.url for job in joblist.jobs()] == [URL]
    joblist.write([Job.from_url(f"{CE}/rest/1.0/jobs/new")])
    assert joblist.remove([URL]) == 1
    after = _raw(path)
    assert [after[0], after[1]] == [before[0], before[2]]
    assert after[2]["id"] == f"{CE}/rest/1.0/jobs/new"


# -- remove and clear ---------------------------------------------------------------------


def test_remove_matches_any_spelling(path: Path) -> None:
    joblist = JobList(path)
    joblist.write([_job(), Job.from_url(f"{CE}/rest/1.0/jobs/keep")])
    assert joblist.remove(["https://ce.example.org/arex/rest/1.1/jobs/abc"]) == 1
    assert [job.id for job in joblist.jobs()] == ["keep"]


def test_remove_drops_every_arc_row_for_the_job(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, _arc_row(), _arc_row(id="https://ce.example.org/arex/rest/1.1/jobs/abc"))
    assert JobList(path).remove([URL, URL]) == 2
    assert _raw(path) == []


@pytest.mark.parametrize("urls", [[], ["not a job url"], [f"{CE}/rest/1.0/jobs/other"]])
def test_remove_nothing(path: Path, urls: list[str]) -> None:
    joblist = JobList(path)
    joblist.write([_job()])
    assert joblist.remove(urls) == 0
    assert len(joblist) == 1


def test_clear_forgets_every_row(path: Path) -> None:
    path.parent.mkdir(parents=True)
    _arc_write(path, GRIDFTP_ROW, _arc_row())
    joblist = JobList(path)
    joblist.clear()
    assert _raw(path) == []
    assert joblist.jobs() == []


# -- files that are not usable job lists ----------------------------------------------------


XML_JOBLIST = '<?xml version="1.0"?>\n<ArcJobs><Job><JobID>gsiftp://x/1</JobID></Job></ArcJobs>\n'


@pytest.mark.parametrize("action", ["jobs", "write", "remove", "clear"])
def test_xml_job_list_is_refused_and_kept(path: Path, action: str) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(XML_JOBLIST)
    joblist = JobList(path)
    calls = {
        "jobs": joblist.jobs,
        "write": lambda: joblist.write([_job()]),
        "remove": lambda: joblist.remove([URL]),
        "clear": joblist.clear,
    }
    with pytest.raises(ARCError) as caught:
        calls[action]()
    assert caught.value.errno == errno.EINVAL
    assert str(caught.value) == (
        f"{path} is not an SQLite job list (an old ARC XML one?); "
        "convert it with ARC's arcsync, or name another file with -j"
    )
    assert path.read_text() == XML_JOBLIST


def test_corrupt_sqlite_file(path: Path) -> None:
    path.parent.mkdir(parents=True)
    path.write_bytes(b"SQLite format 3\0" + b"\xff" * 200)
    with pytest.raises(ARCError) as caught:
        JobList(path).jobs()
    assert caught.value.errno == errno.EIO
    assert str(caught.value).startswith(f"Cannot open the job list {path}: ")


def test_list_is_a_directory(path: Path) -> None:
    path.mkdir(parents=True)
    with pytest.raises(ARCError) as caught:
        JobList(path).jobs()
    assert caught.value.errno == errno.EISDIR
    assert str(caught.value) == f"Cannot open the job list {path}: Is a directory"


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="running as root, which can read any file"
)
def test_unreadable_list(path: Path) -> None:
    JobList(path).write([_job()])
    path.chmod(0)
    try:
        with pytest.raises(ARCError) as caught:
            JobList(path).jobs()
    finally:
        path.chmod(0o600)
    assert caught.value.errno == errno.EACCES
    assert str(caught.value) == f"Cannot open the job list {path}: Permission denied"


def test_directory_cannot_be_created(tmp_path: Path) -> None:
    (tmp_path / "arc").symlink_to(tmp_path / "missing")
    joblist = JobList(tmp_path / "arc" / "jobs.dat")
    with pytest.raises(ARCError) as caught:
        joblist.write([_job()])
    assert caught.value.errno == errno.EEXIST
    assert str(caught.value).startswith(f"Cannot open the job list {joblist.path}: ")


def test_database_cannot_be_created(tmp_path: Path) -> None:
    path = tmp_path / "jobs.dat"
    path.symlink_to(tmp_path / "missing" / "jobs.dat")
    with pytest.raises(ARCError) as caught:
        JobList(path).write([_job()])
    assert caught.value.errno == errno.EIO
    assert str(caught.value) == f"Cannot open the job list {path}: unable to open database file"


# -- Job -----------------------------------------------------------------------------------------


def test_job_url_and_from_url() -> None:
    job = Job.from_url("https://ce.example.org/arex/rest/1.1/jobs/abc", name="n")
    assert (job.ce, job.id, job.name, job.url) == (CE, "abc", "n", URL)


def test_update_applies_the_ces_report_and_keeps_the_rest() -> None:
    job = _job(name="mine", queue="grid", exit_code=5, extra={"userdomain": "atlas"})
    record = parse_activity(
        {"State": "arcrest:FINISHED", "ExitCode": "0", "ExecutionNode": ["wn1"], "Name": "ce's"}
    )
    updated = job.update(record)
    assert (updated.state, updated.rest_state) == (JobState.FINISHED, "FINISHED")
    assert (updated.exit_code, updated.execution_nodes, updated.name) == (0, ("wn1",), "ce's")
    assert (updated.queue, updated.submitted) == ("grid", job.submitted)
    assert updated.extra == {"userdomain": "atlas"}


def test_update_with_no_state_resets_it() -> None:
    updated = _job(state=JobState.RUNNING, rest_state="RUNNING").update(parse_activity({}))
    assert (updated.state, updated.rest_state) == (JobState.UNDEFINED, None)


def test_extra_does_not_affect_equality() -> None:
    assert _job(extra={"a": "b"}) == _job()


@pytest.mark.parametrize("name", ["id; DROP TABLE jobs", "Id", "a b", ""])
def test_sql_text_takes_only_plain_column_names(name: str) -> None:
    with pytest.raises(ValueError, match="not a plain SQL column name"):
        joblist._sql("SELECT {columns} FROM jobs", columns=("id", name))


def test_an_old_format_job_list_is_migrated_as_arc_does(tmp_path: Path) -> None:
    path = tmp_path / "jobs.dat"
    old_columns = joblist._COLUMNS[:16]
    raw = sqlite3.connect(path)
    with raw:
        raw.execute(f"CREATE TABLE jobs({', '.join(old_columns)}, UNIQUE(id))")
        values = dict.fromkeys(old_columns, "")
        values.update(
            id="https://ce.example.org:443/arex/rest/1.0/jobs/abc",
            idfromendpoint="abc",
            name="old%20job",
            delegationid="d1",
        )
        raw.execute(
            joblist._sql("INSERT INTO jobs VALUES ({values})", values=len(old_columns)),
            [values[c] for c in old_columns],
        )
    raw.close()
    [job] = joblist.JobList(path).jobs()
    assert (job.id, job.name, job.delegations) == ("abc", "old job", ("d1",))
    check = sqlite3.connect(path)
    columns = [row[1] for row in check.execute("PRAGMA table_info(jobs)")]
    check.close()
    assert tuple(columns) == joblist._COLUMNS
