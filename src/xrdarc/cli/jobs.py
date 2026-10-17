"""The job commands: stat, wait, get, cat, ls, diagnose, kill, clean, resume, renew, sync."""

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
from ._common import Command, Runner, add_selection, output, report_outcomes, state_matches


def _when(value: object) -> str | None:
    return None if value is None else str(value)


def _job_fields(job: Job) -> dict[str, Any]:
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
    fields = _job_fields(job)
    lines = [f"Job: {job.url}", f" Name: {job.name or ''}", f" State: {job.state.value}"]
    if job.waiting_position is not None:
        lines.append(f" Waiting Position: {job.waiting_position}")
    if job.exit_code is not None:
        lines.append(f" Exit Code: {job.exit_code}")
    lines.extend(f" Job Error: {error}" for error in job.errors)
    for label, key in _LONG if long else ():
        value = fields[key]
        if value not in (None, [], ""):
            shown = ", ".join(map(str, value)) if isinstance(value, list) else value
            lines.append(f" {label}: {shown}")
    command.say("\n".join(lines) + "\n")


def _fresh(command: Command) -> list[Outcome]:
    """The selected jobs with their CEs' latest word, filtered by ``-s``."""
    jobs = command.selected()
    outcomes = command.client().status(jobs)
    wanted = getattr(command.args, "status", [])
    return [o for o in outcomes if not o.ok or state_matches(o.job, wanted)]


def setup_stat(parser: argparse.ArgumentParser) -> Runner:
    add_selection(parser)
    parser.add_argument("-l", "--long", action="store_true", help="every known detail")
    return run_stat


def run_stat(command: Command) -> int:
    outcomes = _fresh(command)
    answered = 0
    for outcome in outcomes:
        if not outcome.ok:
            output.record(job=outcome.job.url, ok=False, reason=outcome.reason)
            command.say(
                f"{command.prog}: {outcome.job.url}: job information not found: {outcome.reason}",
                stderr=True,
            )
            continue
        answered += 1
        output.record(ok=True, **_job_fields(outcome.job))
        _print_job(command, outcome.job, command.args.long)
    command.say(f"Status of {len(outcomes)} jobs was queried, {answered} jobs returned information")
    return 0 if answered == len(outcomes) else 1


def setup_wait(parser: argparse.ArgumentParser) -> Runner:
    add_selection(parser, states=False)
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between polls")
    parser.add_argument("--max-wait", type=float, help="give up after this many seconds")
    return run_wait


def run_wait(command: Command) -> int:
    seen: dict[str, str] = {}

    def changed(outcomes: Sequence[Outcome]) -> None:
        for outcome in outcomes:
            state = outcome.job.state.value if outcome.ok else f"unknown ({outcome.reason})"
            if seen.get(outcome.job.url) != state:
                seen[outcome.job.url] = state
                command.say(f"{outcome.job.url}: {state}")

    final = command.client().wait(
        command.selected(),
        interval=command.args.interval,
        timeout=command.args.max_wait,
        callback=changed,
    )
    good = 0
    for outcome in final:
        success = outcome.ok and outcome.job.state is JobState.FINISHED and not outcome.job.errors
        success = success and outcome.job.exit_code in (None, 0)
        good += success
        output.record(ok=success, **_job_fields(outcome.job))
    return 0 if good == len(final) else 1


def setup_get(parser: argparse.ArgumentParser) -> Runner:
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
    parser.add_argument("--workers", type=int, default=4, help="jobs downloaded at once")
    return run_get


def run_get(command: Command) -> int:
    args = command.args
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
    for outcome in outcomes:
        if outcome.path is not None:
            command.say(f"Results stored at: {outcome.path}")
    retrieved = sum(o.path is not None for o in outcomes)
    cleaned = 0 if args.keep else sum(o.ok and not o.reason for o in outcomes)
    return report_outcomes(
        command,
        outcomes,
        "retrieval",
        summary=lambda total, _ok: (
            f"Jobs processed: {total}, successfully retrieved: "
            f"{retrieved}, successfully cleaned: {cleaned}"
        ),
        fields=lambda o: {"path": None if o.path is None else str(o.path)},
    )


def setup_cat(parser: argparse.ArgumentParser) -> Runner:
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
    jobs = command.selected()
    what = command.args.what or "stdout"
    failed = 0
    out = sys.stdout.buffer
    for job in jobs:
        if len(jobs) > 1:
            command.say(f"==> {job.url} <==")
        output.identify("cat", job=job.url, what=what)
        try:
            command.client().cat(job, out, what)
            out.flush()
        except ARCError as exc:
            failed += 1
            output.error(exc)
            command.say(f"{command.prog}: {job.url}: {exc}", stderr=True)
    return 1 if failed else 0


def setup_ls(parser: argparse.ArgumentParser) -> Runner:
    parser.add_argument("job", metavar="JOB", help="job URL, id or name")
    parser.add_argument("path", nargs="?", default="", help="directory inside the session")
    return run_ls


def run_ls(command: Command) -> int:
    client = command.client()
    [job] = client.select([command.args.job])[:1]
    for path, size in client.files(job, command.args.path):
        output.record(job=job.url, path=path, size=size)
        command.say(f"{'?' if size is None else size:>12}  {path}")
    return 0


def setup_diagnose(parser: argparse.ArgumentParser) -> Runner:
    parser.add_argument("job", metavar="JOB", help="job URL, id or name")
    parser.add_argument(
        "items",
        nargs="*",
        metavar="ITEM",
        help=f"what to show (default: all): {', '.join(DIAGNOSE_ITEMS)}",
    )
    return run_diagnose


def run_diagnose(command: Command) -> int:
    client = command.client()
    [job] = client.select([command.args.job])[:1]
    items = command.args.items or list(DIAGNOSE_ITEMS)
    explicit = bool(command.args.items)
    failed = 0
    for item in items:
        try:
            text = client.diagnose(job, item).decode("utf-8", "replace")
        except HTTPError as exc:
            if exc.status == 404 and not explicit:
                continue
            failed += 1
            output.error(exc, item=item)
            command.say(f"{command.prog}: {item}: {exc}", stderr=True)
            continue
        output.record(job=job.url, item=item, text=text)
        command.say(f"==> {item} <==\n{text.rstrip()}\n")
    return 1 if failed else 0


def _targets(command: Command) -> list[Job]:
    """The selected jobs; with ``-s``, only those its CE says are in one of those states."""
    if getattr(command.args, "status", None):
        return [o.job for o in _fresh(command) if o.ok]
    return command.selected()


def _forgotten(client: ARCClient, outcomes: Sequence[Outcome]) -> list[Outcome]:
    """``clean -f``: forget the jobs that could not be cleaned as well, and count them done."""
    failed = [o.job for o in outcomes if not o.ok]
    if client.joblist is not None and failed:
        client.joblist.remove(job.url for job in failed)
    return [Outcome(o.job, True, o.reason) for o in outcomes]


def _bulk(
    name: str, verb: str, summary: str
) -> tuple[Callable[[argparse.ArgumentParser], Runner], Runner]:
    def run(command: Command) -> int:
        outcomes = getattr(command.client(), name)(_targets(command))
        return report_outcomes(
            command,
            outcomes,
            verb,
            summary=lambda total, ok: summary.format(total=total, ok=ok),
        )

    def setup(parser: argparse.ArgumentParser) -> Runner:
        add_selection(parser)
        return run

    return setup, run


setup_kill, run_kill = _bulk("kill", "kill", "Jobs processed: {total}, successfully killed: {ok}")
setup_resume, run_resume = _bulk("resume", "resume", "Jobs processed: {total}, resumed: {ok}")
setup_renew, run_renew = _bulk("renew", "renewal", "Jobs processed: {total}, renewed: {ok}")


def setup_clean(parser: argparse.ArgumentParser) -> Runner:
    add_selection(parser)
    parser.add_argument(
        "-f", "--force", action="store_true", help="also forget jobs whose CE cannot be asked"
    )
    return run_clean


def run_clean(command: Command) -> int:
    client = command.client()
    outcomes = client.clean(_targets(command))
    if command.args.force:
        outcomes = _forgotten(client, outcomes)
    return report_outcomes(
        command,
        outcomes,
        "clean",
        summary=lambda total, ok: f"Jobs processed: {total}, deleted: {ok}",
    )


def setup_sync(parser: argparse.ArgumentParser) -> Runner:
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
    names = [*command.args.ces, *command.args.ce] or command.config.defaults()
    if not names:
        raise ARCError("No computing element given; name one, or use -C", 22)
    client = command.client()
    truncate = command.args.truncate
    added = 0
    for name in names:
        for ce in command.config.resolve(name):
            for job in client.sync(ce, replace_all=truncate):
                added += 1
                output.record(job=job.url, ce=job.ce)
                command.say(f"Added {job.url}")
            truncate = False
    command.say(f"{added} jobs added to the job list")
    return 0
