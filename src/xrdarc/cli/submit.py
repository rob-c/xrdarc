"""``xrdarc sub`` (arcsub) and ``xrdarc info`` (arcinfo).

``sub`` hands every description to ``ARCClient.submit_all`` at once, so a
bad file stops the whole command before anything is sent, and prints each
job (and appends it to ``-o``) the moment the client reports it, so a job
id is never known only to a process that is about to fail. ``-o`` itself
is opened before the CE is contacted (:class:`_IdsFile`) for the same
reason: "cannot write the ids" must be found out while no job exists.

``info`` prints ``arcinfo``'s summary of each CE's GLUE2 document and
records the parsed document; ``-l`` adds the per-VO shares and the
runtime environments ``arcinfo -l`` shows.
"""

from __future__ import annotations

import argparse
import errno
from pathlib import Path
from typing import Any, TextIO

from ..client import Submission
from ..errors import ARCError
from ..info import CEInfo, Queue
from ._common import Command, Runner, UsageError, output, period_option

#: GLUE2 publishes "no limit" as the largest 32-bit integer: the field must
#: be a number, so the infoprovider writes this stand-in for "unbounded".
#: Compared with ``>=`` rather than ``==``: anything at or past it is 68
#: years, never a real limit, whichever integer width wrote it.
_UNLIMITED = 2**31 - 1


def setup_sub(parser: argparse.ArgumentParser) -> Runner:
    """``arcsub``'s options, plus ``--dry-run`` and ``--min-lifetime``.

    ``-e`` and ``-f`` may be repeated and mixed with positional files, as
    with ``arcsub``; every description given becomes one or more jobs on
    the one CE chosen. ``--no-delegation`` is for jobs that stage nothing
    themselves: without a delegated proxy the CE cannot fetch or store a
    remote file for the job.
    """
    parser.add_argument("files", nargs="*", metavar="FILE", help="job description files")
    # ``-c`` and ``-C``: ARC releases have spelled the option both ways, and a
    # script written for either must keep working. Repeatable, as in arcsub,
    # though only the first CE is used (see :func:`_target`).
    parser.add_argument(
        "-c",
        "-C",
        "--computing-element",
        dest="ce",
        action="append",
        default=[],
        metavar="CE",
        help="CE to submit to (URL or alias)",
    )
    parser.add_argument(
        "-e",
        "--jobdescrstring",
        action="append",
        default=[],
        metavar="TEXT",
        help="a job description given on the command line",
    )
    parser.add_argument(
        "-f",
        "--jobdescrfile",
        action="append",
        default=[],
        metavar="FILE",
        help="a job description file (as positional FILE)",
    )
    # A queue named in the description wins; ``-q`` only fills the gap, so one
    # command line can submit descriptions written for different queues.
    parser.add_argument("-q", "--queue", help="queue to use when a description names none")
    # Appended to, never truncated: ``arcsub -o`` adds to an existing id file,
    # and scripts collect the ids of several submissions in one.
    parser.add_argument(
        "-o", "--jobids-to-file", metavar="FILE", help="append the new jobs' URLs to FILE"
    )
    parser.add_argument(
        "--no-delegation",
        action="store_true",
        help="do not delegate a proxy (the CE cannot stage remote data)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be sent to the CE, and submit nothing",
    )
    # Off by default because ``arcsub`` refuses only an expired proxy. The
    # floor is checked when the client delegates, so with ``--no-delegation``
    # (nothing signed, nothing that could expire mid-job) it has no effect.
    parser.add_argument(
        "--min-lifetime",
        metavar="PERIOD",
        help="refuse to submit when the proxy has less than this left, e.g. 2h "
        "(default: only an expired proxy is refused; under an hour is warned about)",
    )
    return run_sub


def _descriptions(args: argparse.Namespace) -> list[tuple[str, str, Path]]:
    """``(label, text, base directory)`` for every description given.

    ``-e`` strings first (relative inputs are found from the current
    directory), then files in command-line order (relative inputs are found
    beside the file, as ``arcsub`` finds them). Every file is read before
    anything is submitted, so an unreadable third file costs nothing.
    """
    found = [(f"-e #{n}", text, Path.cwd()) for n, text in enumerate(args.jobdescrstring, 1)]
    for name in [*args.files, *args.jobdescrfile]:
        path = Path(name)
        try:
            # The file's own directory, absolute: relative input names in it
            # are relative to the file (arcsub's rule), not to where the
            # command happens to run.
            found.append((name, path.read_text(encoding="utf-8"), path.resolve().parent))
        except OSError as exc:
            # No URL, so this exits as a local failure (6), not the CE's; the
            # errno is kept for ``--json`` readers, EIO when the OS gave none.
            raise ARCError(f"Cannot read {name}: {exc.strerror}", exc.errno or 5) from exc
    # argparse cannot say "a file or -e": each is optional on its own.
    if not found:
        raise UsageError("No job description given (name a file, or use -e)")
    return found


def _target(command: Command) -> str:
    """The CE to submit to: the first of ``-C`` (or the ``default`` CEs), aliases resolved.

    No brokering: ``arcsub`` with several CEs picks one by matchmaking,
    which this client does not do, so the first one named is used.
    """
    ces = command.args.ce or command.config.defaults()
    if not ces:
        raise UsageError("No computing element given; use -C (or set default = yes in client.conf)")
    # ``resolve`` turns an alias into its URL and a group into its members, in
    # ``client.conf`` order; the first of all of them is the one submitted to.
    # The ``default = yes`` CEs stand in only when no ``-C`` was given.
    resolved = [url for ce in ces for url in command.config.resolve(ce)]
    return resolved[0]


def _dry_run(command: Command, descriptions: list[tuple[str, str, Path]]) -> int:
    """Print each job exactly as it would be POSTed, and the files that would be uploaded.

    The client does the preparing, so a dry run cannot drift from a real
    submission: the same rewriting of the description, the same inputs to
    upload. No CE is chosen or contacted. A description that cannot be
    prepared ends the run with exit 4, as it would end a real one before
    anything was sent.
    """
    client = command.client()
    for label, text, base in descriptions:
        # Prepared exactly as for a real submission (no delegation id yet),
        # so what is shown is what A-REX would be sent.
        for prepared in client.prepare(text, base=base, queue=command.args.queue):
            uploads = [{"name": u.name, "source": str(u.source)} for u in prepared.uploads]
            output.record(description=label, text=prepared.description, uploads=uploads)
            command.say(prepared.description)
            for upload in prepared.uploads:
                command.say(f"# upload {upload.source} -> {upload.name}")
    return 0


def run_sub(command: Command) -> int:
    """Submit every description to one CE; 1 unless every job was submitted."""
    args = command.args
    # Every file is read (and a dry run answered) before a CE is even chosen.
    descriptions = _descriptions(args)
    if args.dry_run:
        return _dry_run(command, descriptions)
    ce = _target(command)
    client = command.client()
    if args.min_lifetime:
        client.min_lifetime = period_option(args.min_lifetime, "--min-lifetime")
    # ``submit_all`` reports by description index; the labels turn that back
    # into the file name (or ``-e #n``) the user typed.
    labels = [label for label, _, _ in descriptions]
    # ``-o`` is open for the whole submission: each id is appended (and
    # flushed) the moment its job is accepted, by the reporter.
    with _IdsFile(args.jobids_to_file) as ids:
        reporter = _Reporter(command, labels, ids)
        client.submit_all(
            ce,
            [(text, base) for _, text, base in descriptions],
            queue=args.queue,
            delegate=not args.no_delegation,
            report=reporter,
        )
    # ``arcsub`` prints the tally only when there was more than one job.
    if reporter.total > 1:
        command.say(f"{reporter.submitted} of {reporter.total} jobs were submitted")
    # Partial success is failure, as for every ARC tool: a script must not
    # read "3 of 4 submitted" as done.
    return 0 if reporter.submitted == reporter.total else 1


class _IdsFile:
    """``-o FILE``, opened for appending before anything is submitted.

    Opening it first turns "cannot write the ids" into an error before a
    job exists rather than after. A file this run created and never wrote
    to is removed again, so a run that submitted nothing leaves no trace.
    """

    def __init__(self, name: str | None) -> None:
        """Nothing is opened until the ``with`` block starts; ``None`` means no ``-o``."""
        self.path = Path(name) if name else None
        self.handle: TextIO | None = None
        self.created = False
        self.written = 0

    def __enter__(self) -> _IdsFile:
        """Open (creating if need be) for appending; ``ARCError`` if that is impossible."""
        if self.path is not None:
            # Decided before opening, which creates it: only a file this run
            # created may be removed again, since an existing one holds the
            # ids of earlier submissions.
            self.created = not self.path.exists()
            try:
                self.handle = open(self.path, "a", encoding="utf-8")
            except OSError as exc:
                raise ARCError(
                    f"Cannot open {self.path} for the job ids: {exc.strerror}",
                    exc.errno or errno.EIO,
                ) from exc
        return self

    def add(self, url: str) -> None:
        """Append one job URL and flush it, so it is on disk before the next job is tried."""
        if self.handle is not None:
            self.handle.write(f"{url}\n")
            self.handle.flush()
            self.written += 1

    def __exit__(self, *exc: object) -> None:
        """Close; remove the file again if this run created it and wrote nothing."""
        if self.handle is not None:
            self.handle.close()
            if self.created and not self.written and self.path is not None:
                self.path.unlink(missing_ok=True)


class _Reporter:
    """``ARCClient.submit_all``'s ``report``: one record and line per job, as it is decided.

    The id goes to ``-o`` before it is printed, so a closed stdout (a
    broken pipe) cannot cost the file its entry.
    """

    def __init__(self, command: Command, labels: list[str], ids: _IdsFile) -> None:
        """``labels[i]`` names description ``i`` in messages (a file name, or ``-e #n``)."""
        self.command = command
        self.labels = labels
        self.ids = ids
        self.total = 0
        self.submitted = 0

    def __call__(self, index: int, result: Submission) -> None:
        """Report one job of description ``index`` - submitted, or why not."""
        label = self.labels[index]
        # Counted here, not from the descriptions: one description may hold
        # several jobs (xRSL's ``+(...)(...)``), so the number of jobs is only
        # known as they are reported.
        self.total += 1
        url = result.job.url if result.job else None
        # The record first: with ``--json`` it is the result, and stdout may
        # be a pipe that is about to break.
        output.record(description=label, ok=result.ok, job=url, reason=result.reason or None)
        if url is None:
            self.command.say(
                f"{self.command.prog}: {label}: job not submitted: {result.reason}", stderr=True
            )
            return
        self.submitted += 1
        # The file before the terminal: a closed stdout must not cost ``-o`` its entry.
        self.ids.add(url)
        self.command.say(f"Job submitted with jobid: {url}")


def setup_info(parser: argparse.ArgumentParser) -> Runner:
    """``arcinfo``'s options: CEs (positional or ``-C``) and ``-l``.

    A name may be an alias or a group from ``client.conf``; a group is every
    CE in it, each asked in turn.
    """
    # CEs are accepted both positionally and with ``-C`` (both spellings, as
    # for ``sub``); the two lists are joined, positional ones first.
    parser.add_argument("ces", nargs="*", metavar="CE", help="CE URL or alias")
    parser.add_argument(
        "-c",
        "-C",
        "--computing-element",
        dest="ce",
        action="append",
        default=[],
        metavar="CE",
        help="CE to describe",
    )
    parser.add_argument("-l", "--long", action="store_true", help="queues and software too")
    return run_info


def _describe(command: Command, ce: str, info: CEInfo) -> None:
    """``arcinfo``'s text for one CE: service, endpoints, job counts, queues (and ``-l`` extras)."""
    long = command.args.long
    lines = [*_service_lines(ce, info)]
    # A VO share is a per-VO view of the same batch queue; listing them by
    # default would show every queue several times over, so only ``-l`` does.
    lines.extend(_queue_line(queue) for queue in info.queues if long or not queue.vo_share)
    if long:
        lines.extend(f"  Runtime environment: {rte}" for rte in info.runtime_environments)
    for line in lines:
        command.say(line)


def _service_lines(ce: str, info: CEInfo) -> list[str]:
    """The service's own lines: its name, where it was asked, the REST endpoint, job counts."""
    lines = [
        f"Computing service: {info.name or ce}",
        f"  Information endpoint: {ce} (org.nordugrid.arcrest)",
    ]
    # Only the REST endpoint is described, because it is the only interface
    # this client submits through. A CE that publishes none is still
    # described: the user learns it cannot be used from here.
    endpoint = info.rest_endpoint()
    if endpoint is not None:
        lines.append(
            f"  Submission endpoint: {endpoint.url} (status: {endpoint.health or 'unknown'}, "
            f"interface: {endpoint.interface}, versions: {', '.join(endpoint.versions)})"
        )
    # Job counts are optional in GLUE2; no line beats a line of "None".
    if info.total_jobs is not None:
        lines.append(
            f"  Jobs: {info.total_jobs} total, {info.running_jobs} running, "
            f"{info.waiting_jobs} waiting"
        )
    return lines


def _queue_line(queue: Queue) -> str:
    """One queue (or VO share of one), with its load and wall-time limit if it publishes one."""
    limit = _wall_limit(queue.max_wall_time)
    share = f" (share of {queue.mapping_queue})" if queue.vo_share else ""
    return (
        f"  Queue: {queue.name}{share}: {queue.running or 0} running, "
        f"{queue.waiting or 0} waiting{limit}"
    )


def _wall_limit(seconds: int | None) -> str:
    """``, max wall time N s`` for a published limit; GLUE2's 2**31-1 means none at all."""
    if not seconds:
        return ""
    return ", no wall time limit" if seconds >= _UNLIMITED else f", max wall time {seconds} s"


def run_info(command: Command) -> int:
    """Describe every named CE (default: the ``default`` ones); 1 if any could not be asked."""
    args = command.args
    names = [*args.ces, *args.ce] or command.config.defaults()
    if not names:
        raise UsageError("No computing element given; name one, or use -C")
    ces = [ce for name in names for ce in command.config.resolve(name)]
    # Every CE is asked even when an earlier one fails: describing a group is
    # a survey, and one CE being down is part of the answer, not the end of it.
    failed = sum(not _info_one(command, ce) for ce in ces)
    return 1 if failed else 0


def _info_one(command: Command, ce: str) -> bool:
    """Ask one CE, then record and print its description; whether it answered."""
    client = command.client()
    try:
        info = client.info(ce)
    except ARCError as exc:
        output.error(exc, ce=ce)
        command.say(f"{command.prog}: {ce}: {exc}", stderr=True)
        return False
    # The URL the client actually spoke to (an alias or a bare host expanded),
    # so the record and the text name a CE a later ``-C`` will reach.
    url = client.rest(ce).ce
    output.record(ce=url, **_info_fields(info))
    _describe(command, url, info)
    return True


def _info_fields(info: CEInfo) -> dict[str, Any]:
    """The report record of one CE: its endpoints, queues and runtime environments.

    Part of the ``--json`` report a script reads, like ``stat``'s fields: add
    keys, never rename them. Numbers stay numbers (``None`` where the CE
    published nothing) rather than the text's formatted values.
    """
    return {
        "name": info.name,
        "endpoints": [
            {
                "url": e.url,
                "interface": e.interface,
                "health": e.health,
                "versions": list(e.versions),
            }
            for e in info.endpoints
        ],
        "queues": [
            {
                "name": q.name,
                "mapping_queue": q.mapping_queue,
                "max_wall_time": q.max_wall_time,
                "running": q.running,
                "waiting": q.waiting,
                "vo_share": q.vo_share,
            }
            for q in info.queues
        ],
        "runtime_environments": list(info.runtime_environments),
    }
