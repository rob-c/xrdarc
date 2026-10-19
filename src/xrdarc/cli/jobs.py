"""The job commands: stat, wait, get, cat, ls, diagnose, kill, clean, resume, renew, sync.

Each command is a ``setup_<name>`` that adds its options to an argparse
sub-parser and returns its ``run_<name>``; ``cli/__init__`` wires them up.
The runners do no work of their own: they select jobs (``Command.selected``,
ARC's ``-a``/``-i``/``-c``/``-s`` rules), call one :class:`~xrdarc.client.ARCClient`
operation, and turn its outcomes into ARC's text lines *and* one report
record per job, so ``--json`` and the text say the same thing.

Exit status follows ARC's tools: 0 when every job did what was asked, 1 when
any did not (``report_outcomes``); a fatal error is ``cli/__init__``'s.
The kill/resume/renew commands are identical apart from their wording, so
they are made by :func:`_bulk` rather than written out three times.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ..client import ARCClient, Outcome
from ..errors import ARCError, HTTPError
from ..joblist import Job
from ..rest import DIAGNOSE_ITEMS
from ..states import JobState
from ._common import (
    Command,
    Runner,
    UsageError,
    add_selection,
    output,
    report_outcomes,
    state_matches,
)


def _when(value: object) -> str | None:
    """A time for a report: its ``str`` (ISO 8601 with offset), or ``None``.

    JSON has no time type; ISO 8601 with its offset is the form every
    reader parses and the one a person can still read in ``--xml``.
    """
    return None if value is None else str(value)


def _job_fields(job: Job) -> dict[str, Any]:
    """Everything known about ``job``, as one report record's fields (JSON-ready).

    The keys are part of the report contract (``docs/compatibility.md``): a
    script reading ``xrdarc stat --json`` depends on them, so add, never
    rename.
    """
    return {
        "job": job.url,
        "id": job.id,
        "ce": job.ce,
        "name": job.name,
        "state": job.state.value,
        "rest_state": job.rest_state,
        "exit_code": job.exit_code,
        "errors": list(job.errors),
        "queue": job.queue,
        "owner": job.owner,
        "stdout": job.stdout,
        "stderr": job.stderr,
        "log_dir": job.log_dir,
        "execution_nodes": list(job.execution_nodes),
        "waiting_position": job.waiting_position,
        # The CE's own submission time, not when this client recorded the job.
        "submitted": _when(job.submitted_on_ce),
        "started": _when(job.started),
        "ended": _when(job.ended),
        "erase_time": _when(job.erase_time),
        "used_wall_time": job.used_wall_time,
        "used_cpu_time": job.used_cpu_time,
        "used_memory": job.used_memory,
        "delegations": list(job.delegations),
        "restart_state": job.restart_state,
    }


#: ``stat -l``'s extra lines: label as ``arcstat -l`` prints it, report field.
#: The order is ``arcstat -l``'s too, so someone used to ARC finds each line
#: where they expect it. The text reads these from the report fields, so
#: ``-l`` and ``--json`` can never disagree about a value.
_LONG = (
    ("Specific state", "rest_state"),
    ("Queue", "queue"),
    ("Owner", "owner"),
    ("Stdout", "stdout"),
    ("Stderr", "stderr"),
    ("Log directory", "log_dir"),
    ("Execution nodes", "execution_nodes"),
    ("Submitted", "submitted"),
    ("Started", "started"),
    ("End time", "ended"),
    ("Used wall time (s)", "used_wall_time"),
    ("Used CPU time (s)", "used_cpu_time"),
    ("Used memory (MB)", "used_memory"),
    ("Results must be retrieved before", "erase_time"),
    ("Restart state", "restart_state"),
    ("Delegation IDs", "delegations"),
)


def _print_job(command: Command, job: Job, long: bool) -> None:
    """One job the way ``arcstat`` (``-l``: ``arcstat -l``) prints it, then a blank line."""
    lines = _summary_lines(job)
    if long:
        lines.extend(_long_lines(_job_fields(job)))
    command.say("\n".join(lines) + "\n")


def _summary_lines(job: Job) -> list[str]:
    """``arcstat``'s lines for every job: URL, name, state, and what went wrong."""
    # Name is printed even when empty, so every job's block starts with the
    # same three lines for a script that parses them.
    lines = [f"Job: {job.url}", f" Name: {job.name or ''}", f" State: {job.state.value}"]
    if job.waiting_position is not None:
        lines.append(f" Waiting Position: {job.waiting_position}")
    if job.exit_code is not None:
        lines.append(f" Exit Code: {job.exit_code}")
    lines.extend(f" Job Error: {error}" for error in job.errors)
    return lines


def _long_lines(fields: dict[str, Any]) -> list[str]:
    """``-l``'s extra lines: each known :data:`_LONG` field, lists comma-joined."""
    lines = []
    for label, key in _LONG:
        value = fields[key]
        # Compared with the "unknown" markers, not by truth: 0 is a real exit
        # code or used time and must be shown.
        if value not in (None, [], ""):
            shown = ", ".join(map(str, value)) if isinstance(value, list) else value
            lines.append(f" {label}: {shown}")
    return lines


def _fresh(command: Command) -> list[Outcome]:
    """The selected jobs with their CEs' latest word, filtered by ``-s``."""
    jobs = command.selected()
    outcomes = command.client().status(jobs)
    # ``-s`` filters on the *fresh* state, so it is applied after asking;
    # a job the CE could not answer for is kept, so the failure is reported.
    wanted = getattr(command.args, "status", [])
    return [o for o in outcomes if not o.ok or state_matches(o.job, wanted)]


def setup_stat(parser: argparse.ArgumentParser) -> Runner:
    """``arcstat``'s options: the selection, and ``-l``.

    Every run asks the CEs: the job list's states are only what was last
    heard, and ``stat`` exists to replace them with the CE's word.
    """
    add_selection(parser)
    parser.add_argument("-l", "--long", action="store_true", help="every known detail")
    return run_stat


def run_stat(command: Command) -> int:
    """Each selected job's fresh state; 1 if any CE could not say."""
    outcomes = _fresh(command)
    # Every job is shown even if some CEs fail; the exit status says so after.
    answered = sum(_show_status(command, outcome) for outcome in outcomes)
    # ``arcstat``'s closing line, word for word: scripts grep it.
    command.say(f"Status of {len(outcomes)} jobs was queried, {answered} jobs returned information")
    return 0 if answered == len(outcomes) else 1


def _show_status(command: Command, outcome: Outcome) -> bool:
    """Print and record one job's status; whether its CE answered for it."""
    if not outcome.ok:
        # Recorded as a failure but not raised: the other jobs' states are
        # still wanted. "job information not found" is ``arcstat``'s wording.
        output.record(job=outcome.job.url, ok=False, reason=outcome.reason)
        command.say(
            f"{command.prog}: {outcome.job.url}: job information not found: {outcome.reason}",
            stderr=True,
        )
        return False
    output.record(ok=True, **_job_fields(outcome.job))
    _print_job(command, outcome.job, command.args.long)
    return True


def setup_wait(parser: argparse.ArgumentParser) -> Runner:
    """``wait``'s options (no ``-s``: waiting is for every selected job to end).

    ARC has no ``arcwait``; this is the polling loop scripts otherwise write
    around ``arcstat``, with transient CE trouble ridden out (see
    ``ARCClient.wait``). ``--max-wait`` ends it with exit status 7.
    """
    add_selection(parser, states=False)
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between polls")
    parser.add_argument("--max-wait", type=float, help="give up after this many seconds")
    return run_wait


def run_wait(command: Command) -> int:
    """Poll until every selected job has ended; 0 only if every one finished cleanly.

    A line is printed each time a job's state changes (not on every poll),
    including when its CE stops answering - ``wait`` keeps going then, and
    says so, rather than failing the job.

    ``--max-wait`` running out raises the client's ``ETIMEDOUT`` error,
    which :func:`~xrdarc.cli._common.exit_code_for` maps to 7, so a script
    can tell "gave up" from "a job failed" (1). Each job's record carries
    ``ok`` by :func:`_succeeded`, so a ``--json`` reader need not repeat the
    rule.
    """
    final = command.client().wait(
        command.selected(),
        interval=command.args.interval,
        timeout=command.args.max_wait,
        callback=_Changes(command),
    )
    good = 0
    for outcome in final:
        success = _succeeded(outcome)
        good += success
        output.record(ok=success, **_job_fields(outcome.job))
    return 0 if good == len(final) else 1


class _Changes:
    """``wait``'s callback: say each job's state when it differs from the last one said."""

    def __init__(self, command: Command) -> None:
        """Nothing said yet."""
        self.command = command
        # Keyed by URL, not name: job names need not be unique.
        self.seen: dict[str, str] = {}

    def __call__(self, outcomes: Sequence[Outcome]) -> None:
        """Called after every poll with every job's outcome."""
        for outcome in outcomes:
            state = _described(outcome)
            if self.seen.get(outcome.job.url) != state:
                self.seen[outcome.job.url] = state
                self.command.say(f"{outcome.job.url}: {state}")


def _described(outcome: Outcome) -> str:
    """What ``wait`` says about a job: its state, or why it is not known.

    Transient trouble (a timeout, a 5xx) is worded differently from a job
    the CE does not know, so someone watching can tell a flaky CE, which
    ``wait`` rides out, from a lost job, which it reports.
    """
    if outcome.transient:
        return f"not answering ({outcome.reason}); will ask again"
    return outcome.job.state.value if outcome.ok else f"unknown ({outcome.reason})"


def _succeeded(outcome: Outcome) -> bool:
    """Finished, with no errors and a zero (or unknown) exit code: what ``wait`` calls success.

    An unknown exit code is not held against the job: ``FINISHED`` with no
    errors is A-REX's own judgement that the job succeeded, and A-REX does
    not always know the code. A known non-zero code is a failure
    even though A-REX calls the job ``FINISHED`` - the payload failed.
    """
    job = outcome.job
    return (
        outcome.ok
        and job.state is JobState.FINISHED
        and not job.errors
        and job.exit_code in (None, 0)
    )


def setup_get(parser: argparse.ArgumentParser) -> Runner:
    """``arcget``'s options.

    ``-D``, ``-J``, ``-k`` and ``-f`` mean what they mean to ``arcget``;
    ``--diagnose`` and ``--workers`` are xrdarc's. ``-f`` overwrites files
    in an existing result directory rather than deleting it first, as
    ``arcget -f`` does, so files the user added there survive.
    """
    add_selection(parser)
    parser.add_argument("-D", "--dir", help="download directory (default: current directory)")
    parser.add_argument(
        "-J",
        "--use-jobname",
        action="store_true",
        help="name the result directories after the jobs",
    )
    parser.add_argument("-k", "--keep", action="store_true", help="do not clean the jobs")
    parser.add_argument(
        "-f", "--force", action="store_true", help="replace existing result directories"
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="also save A-REX's diagnostic files (into <job>/diagnose)",
    )
    # A few jobs at once hide each request's round trip; many would only
    # compete for the same CE and the same disk.
    parser.add_argument("--workers", type=int, default=4, help="jobs downloaded at once")
    return run_get


def run_get(command: Command) -> int:
    """Download the selected jobs (into ``-D`` or ``jobdownloaddirectory``), then clean them."""
    args = command.args
    # ``-D``, then ``client.conf``'s ``jobdownloaddirectory``, then here: arcget's order.
    directory = Path(args.dir or command.config.download_dir or ".")
    jobs = command.selected()
    outcomes = command.client().get(
        jobs,
        directory,
        keep=args.keep,
        use_names=args.use_jobname,
        force=args.force,
        diagnose=args.diagnose,
        workers=args.workers,
    )
    # ``arcget``'s line for every job whose files arrived, even one whose
    # clean afterwards failed: the results are there either way.
    for outcome in outcomes:
        if outcome.path is not None:
            command.say(f"Results stored at: {outcome.path}")
    return report_outcomes(
        command, outcomes, "retrieval", summary=_GetSummary(outcomes, args.keep), fields=_path
    )


def _path(outcome: Outcome) -> dict[str, Any]:
    """``get``'s extra report field: where the job's results went (``None``: nowhere)."""
    return {"path": None if outcome.path is None else str(outcome.path)}


class _GetSummary:
    """``arcget``'s last line: how many jobs were processed, retrieved and cleaned.

    A job is cleaned when it was retrieved and nothing went wrong after
    (``Outcome.reason`` says "not cleaned: ..." when the clean failed).
    """

    def __init__(self, outcomes: Sequence[Outcome], keep: bool) -> None:
        """Count once, from the final outcomes."""
        self.retrieved = sum(o.path is not None for o in outcomes)
        # With ``-k`` nothing was cleaned, whatever else the outcomes say.
        self.cleaned = 0 if keep else sum(o.ok and not o.reason for o in outcomes)

    def __call__(self, total: int, _ok: int) -> str:
        """The line, as ``report_outcomes`` asks for it."""
        return (
            f"Jobs processed: {total}, successfully retrieved: "
            f"{self.retrieved}, successfully cleaned: {self.cleaned}"
        )


def setup_cat(parser: argparse.ArgumentParser) -> Runner:
    """``arccat``'s options: which output, one of ``-o``/``-e``/``-l``/``-f``.

    They share one destination (``what``), so argparse refuses two at once
    instead of one silently winning; none means stdout, as in ``arccat``.
    ``-f`` is xrdarc's: any file of the session directory, even while the
    job runs.
    """
    add_selection(parser)
    which = parser.add_mutually_exclusive_group()
    which.add_argument(
        "-o",
        "--stdout",
        dest="what",
        action="store_const",
        const="stdout",
        help="the job's standard output (default)",
    )
    which.add_argument(
        "-e",
        "--stderr",
        dest="what",
        action="store_const",
        const="stderr",
        help="the job's standard error",
    )
    which.add_argument(
        "-l",
        "--joblog",
        dest="what",
        action="store_const",
        const="joblog",
        help="A-REX's log of the job (diagnose/errors)",
    )
    which.add_argument(
        "-f", "--file", dest="what", metavar="PATH", help="any file in the session directory"
    )
    return run_cat


def run_cat(command: Command) -> int:
    """Copy each selected job's output to standard output, bytes as they are.

    With several jobs each is introduced by ``==> URL <==``, as ``tail``
    does. Standard output is written as bytes (``sys.stdout.buffer``): a
    job's output need not be text, and must not be re-encoded. One job
    failing does not stop the others.
    """
    jobs = command.selected()
    what = command.args.what or "stdout"
    failed = 0
    for job in jobs:
        if len(jobs) > 1:
            command.say(f"==> {job.url} <==")
        failed += not _cat_one(command, job, what)
    return 1 if failed else 0


def _cat_one(command: Command, job: Job, what: str) -> bool:
    """One job's ``what`` to standard output; whether it worked (a failure is reported)."""
    # Per job, so an error record names the job and stream it belongs to.
    output.identify("cat", job=job.url, what=what)
    out = sys.stdout.buffer
    try:
        command.client().cat(job, out, what)
        # Flushed per job, so each job's bytes are out before the next job
        # (and the next CE request) starts, not held back until exit.
        out.flush()
    except ARCError as exc:
        output.error(exc)
        command.say(f"{command.prog}: {job.url}: {exc}", stderr=True)
        return False
    return True


def setup_ls(parser: argparse.ArgumentParser) -> Runner:
    """``ls JOB [PATH]``: one job, and a directory inside its session."""
    parser.add_argument("job", metavar="JOB", help="job URL, id or name")
    parser.add_argument("path", nargs="?", default="", help="directory inside the session")
    return run_ls


def run_ls(command: Command) -> int:
    """Every file below the path, with its size (``?`` when the CE did not say)."""
    client = command.client()
    # A job name may match several jobs; ``ls`` shows the first, as ``arcls`` does.
    # ``select`` raises for a name that matches nothing, so there is one.
    [job] = client.select([command.args.job])[:1]
    for path, size in client.files(job, command.args.path):
        output.record(job=job.url, path=path, size=size)
        command.say(f"{'?' if size is None else size:>12}  {path}")
    return 0


def setup_diagnose(parser: argparse.ArgumentParser) -> Runner:
    """``diagnose JOB [ITEM...]``: one job, and which of A-REX's control files."""
    parser.add_argument("job", metavar="JOB", help="job URL, id or name")
    parser.add_argument(
        "items",
        nargs="*",
        metavar="ITEM",
        help=f"what to show (default: all): {', '.join(DIAGNOSE_ITEMS)}",
    )
    return run_diagnose


def run_diagnose(command: Command) -> int:
    """Print the job's diagnose files; 1 if one asked for by name could not be had.

    Without names every item is tried and the ones the job does not have
    (404: no ``failed`` file for a job that did not fail) are skipped
    quietly; an item named on the command line that is missing is an error.
    """
    client = command.client()
    [job] = client.select([command.args.job])[:1]
    # Whether the user named the items decides what a 404 means (see
    # ``_show_item``): absent-by-nature when browsing, an error when asked for.
    explicit = bool(command.args.items)
    items = command.args.items or list(DIAGNOSE_ITEMS)
    failed = sum(not _show_item(command, client, job, item, explicit) for item in items)
    return 1 if failed else 0


def _show_item(command: Command, client: ARCClient, job: Job, item: str, explicit: bool) -> bool:
    """Print one diagnose item; ``False`` only for a failure worth reporting."""
    try:
        # A diagnose file can quote anything the job printed; one bad byte
        # must not cost the rest of it.
        text = client.diagnose(job, item).decode("utf-8", "replace")
    except HTTPError as exc:
        if exc.status == 404 and not explicit:
            return True
        output.error(exc, item=item)
        command.say(f"{command.prog}: {item}: {exc}", stderr=True)
        return False
    output.record(job=job.url, item=item, text=text)
    command.say(f"==> {item} <==\n{text.rstrip()}\n")
    return True


def _targets(command: Command) -> list[Job]:
    """The selected jobs; with ``-s``, only those its CE says are in one of those states."""
    if getattr(command.args, "status", None):
        # Only then is the CE asked first: without ``-s`` the action itself
        # tells us whether each job exists, at no extra round trip.
        return [o.job for o in _fresh(command) if o.ok]
    return command.selected()


def _forgotten(client: ARCClient, outcomes: Sequence[Outcome]) -> list[Outcome]:
    """``clean -f``: forget the jobs that could not be cleaned as well, and count them done."""
    failed = [o.job for o in outcomes if not o.ok]
    # The CE could not clean these (unreachable, or it forgot them already);
    # ``-f`` is the user saying "forget them anyway", as ``arcclean -f`` does.
    if client.joblist is not None and failed:
        client.joblist.remove(job.url for job in failed)
    # Every job now counts as done - none is in the list any more, which is
    # what ``-f`` asked for - but the reason says why the CE did not clean it.
    return [Outcome(o.job, True, o.reason) for o in outcomes]


def _bulk(
    name: str, verb: str, summary: str
) -> tuple[Callable[[argparse.ArgumentParser], Runner], Runner]:
    """A ``setup``/``run`` pair for a command that is one bulk :class:`ARCClient` method.

    ``name`` is the method, ``verb`` what a failure line calls the action,
    ``summary`` the last line's format (``{total}``, ``{ok}``). Closures
    rather than three near-identical pairs of functions, so a fix to one
    (the ``-s`` handling, say) cannot miss the other two.
    """

    def run(command: Command) -> int:
        """Act on the selected jobs (``-s`` filtered by fresh state).

        The method is looked up by name on the client at run time, so the
        three commands share one code path and differ only in wording.
        """
        outcomes = getattr(command.client(), name)(_targets(command))
        return report_outcomes(
            command,
            outcomes,
            verb,
            summary=lambda total, ok: summary.format(total=total, ok=ok),
        )

    def setup(parser: argparse.ArgumentParser) -> Runner:
        """The selection options, nothing else."""
        add_selection(parser)
        return run

    return setup, run


# ARC's own summary lines, word for word: ``arckill``, ``arcresume`` and
# ``arcrenew`` print them, and scripts written for those tools grep them.
setup_kill, run_kill = _bulk("kill", "kill", "Jobs processed: {total}, successfully killed: {ok}")
setup_resume, run_resume = _bulk("resume", "resume", "Jobs processed: {total}, resumed: {ok}")
setup_renew, run_renew = _bulk("renew", "renewal", "Jobs processed: {total}, renewed: {ok}")


def setup_clean(parser: argparse.ArgumentParser) -> Runner:
    """``arcclean``'s options, with ``-f``.

    A job the CE no longer knows is forgotten even without ``-f``
    (``ARCClient.clean`` treats a 404 as already clean); ``-f`` also forgets
    jobs whose CE cannot be asked at all.
    """
    add_selection(parser)
    parser.add_argument(
        "-f", "--force", action="store_true", help="also forget jobs whose CE cannot be asked"
    )
    return run_clean


def run_clean(command: Command) -> int:
    """Remove the jobs from their CEs and the job list (``-f``: from the list regardless)."""
    client = command.client()
    outcomes = client.clean(_targets(command))
    # ``-f`` is applied to the CE's answers, so a job the CE did clean is
    # reported as such and only the failures are forced out of the list.
    if command.args.force:
        outcomes = _forgotten(client, outcomes)
    return report_outcomes(
        command,
        outcomes,
        "clean",
        summary=lambda total, ok: f"Jobs processed: {total}, deleted: {ok}",
    )


def setup_sync(parser: argparse.ArgumentParser) -> Runner:
    """``arcsync``'s options: CEs (positional or ``-C``), and ``-T``.

    ``arcsync`` asks the CEs' information systems for jobs; A-REX's REST
    ``GET jobs`` answers the same question directly, for the
    authenticated user only, which is what is used.
    """
    parser.add_argument("ces", nargs="*", metavar="CE", help="CE URL or alias")
    parser.add_argument(
        "-c",
        "-C",
        "--computing-element",
        dest="ce",
        action="append",
        default=[],
        metavar="CE",
        help="CE to synchronise with",
    )
    parser.add_argument("-T", "--truncate", action="store_true", help="empty the job list first")
    return run_sync


def run_sync(command: Command) -> int:
    """Add every named CE's jobs for this user to the job list.

    No CE named means the ``default = yes`` CEs of ``client.conf``. ``-T``
    empties the list once, before the first CE is asked - not before each,
    which would keep only the last CE's jobs.
    """
    names = [*command.args.ces, *command.args.ce] or command.config.defaults()
    if not names:
        raise UsageError("No computing element given; name one, or use -C")
    ces = [ce for name in names for ce in command.config.resolve(name)]
    added = 0
    for index, ce in enumerate(ces):
        added += _sync_one(command, ce, truncate=command.args.truncate and index == 0)
    command.say(f"{added} jobs added to the job list")
    # 0 even when nothing was added: a CE with no jobs for this user is an
    # answer. A CE that cannot be asked raises and ends the command with
    # its error instead, leaving the jobs added so far in the list.
    return 0


def _sync_one(command: Command, ce: str, *, truncate: bool) -> int:
    """Add one CE's jobs, saying each; how many were new."""
    # The client asks the CE before it empties the list for ``replace_all``,
    # so with ``-T`` a first CE that cannot be asked leaves the old list intact.
    jobs = command.client().sync(ce, replace_all=truncate)
    for job in jobs:
        output.record(job=job.url, ce=job.ce)
        command.say(f"Added {job.url}")
    return len(jobs)
