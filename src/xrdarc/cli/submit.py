"""``xrdarc sub`` (arcsub) and ``xrdarc info`` (arcinfo)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from ..client import Submission
from ..errors import ARCError, DescriptionError
from ..info import CEInfo, Queue
from ._common import Command, Runner, output

#: GLUE2 publishes "no limit" as the largest 32-bit integer.
_UNLIMITED = 2**31 - 1


def setup_sub(parser: argparse.ArgumentParser) -> Runner:
    parser.add_argument("files", nargs="*", metavar="FILE", help="job description files")
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
    parser.add_argument("-q", "--queue", help="queue to use when a description names none")
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
    return run_sub


def _descriptions(args: argparse.Namespace) -> list[tuple[str, str, Path]]:
    """``(label, text, base directory)`` for every description given."""
    found = [(f"-e #{n}", text, Path.cwd()) for n, text in enumerate(args.jobdescrstring, 1)]
    for name in [*args.files, *args.jobdescrfile]:
        path = Path(name)
        try:
            found.append((name, path.read_text(encoding="utf-8"), path.resolve().parent))
        except OSError as exc:
            raise ARCError(f"Cannot read {name}: {exc.strerror}", exc.errno or 5) from exc
    if not found:
        raise DescriptionError("No job description given (name a file, or use -e)")
    return found


def _target(command: Command) -> str:
    ces = command.args.ce or command.config.defaults()
    if not ces:
        raise ARCError(
            "No computing element given; use -C (or set default = yes in client.conf)", 22
        )
    resolved = [url for ce in ces for url in command.config.resolve(ce)]
    return resolved[0]


def _dry_run(command: Command, descriptions: list[tuple[str, str, Path]]) -> int:
    client = command.client()
    for label, text, base in descriptions:
        for prepared in client.prepare(text, base=base, queue=command.args.queue):
            uploads = [{"name": u.name, "source": str(u.source)} for u in prepared.uploads]
            output.record(description=label, text=prepared.description, uploads=uploads)
            command.say(prepared.description)
            for upload in prepared.uploads:
                command.say(f"# upload {upload.source} -> {upload.name}")
    return 0


def run_sub(command: Command) -> int:
    args = command.args
    descriptions = _descriptions(args)
    if args.dry_run:
        return _dry_run(command, descriptions)
    ce = _target(command)
    client = command.client()
    total, urls = 0, []
    for label, text, base in descriptions:
        submissions = client.submit(
            ce, text, base=base, queue=args.queue, delegate=not args.no_delegation
        )
        total += len(submissions)
        urls.extend(_reported(command, label, submissions))
    if args.jobids_to_file and urls:
        with open(args.jobids_to_file, "a", encoding="utf-8") as handle:
            handle.writelines(f"{url}\n" for url in urls)
    if total > 1:
        command.say(f"{len(urls)} of {total} jobs were submitted")
    return 0 if len(urls) == total else 1


def _reported(command: Command, label: str, submissions: Sequence[Submission]) -> list[str]:
    """One record (and line) per job of a description; the URLs of those submitted."""
    urls = []
    for result in submissions:
        url = result.job.url if result.job else None
        output.record(description=label, ok=result.ok, job=url, reason=result.reason or None)
        if url is None:
            command.say(f"{command.prog}: {label}: job not submitted: {result.reason}", stderr=True)
            continue
        urls.append(url)
        command.say(f"Job submitted with jobid: {url}")
    return urls


def setup_info(parser: argparse.ArgumentParser) -> Runner:
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
    endpoint = info.rest_endpoint()
    say = command.say
    say(f"Computing service: {info.name or ce}")
    say(f"  Information endpoint: {ce} (org.nordugrid.arcrest)")
    if endpoint is not None:
        say(
            f"  Submission endpoint: {endpoint.url} (status: {endpoint.health or 'unknown'}, "
            f"interface: {endpoint.interface}, versions: {', '.join(endpoint.versions)})"
        )
    if info.total_jobs is not None:
        say(
            f"  Jobs: {info.total_jobs} total, {info.running_jobs} running, "
            f"{info.waiting_jobs} waiting"
        )
    for queue in info.queues:
        if command.args.long or not queue.vo_share:
            say(_queue_line(queue))
    if command.args.long:
        for rte in info.runtime_environments:
            say(f"  Runtime environment: {rte}")


def _queue_line(queue: Queue) -> str:
    limit = ""
    if queue.max_wall_time:
        unlimited = queue.max_wall_time >= _UNLIMITED
        limit = ", no wall time limit" if unlimited else f", max wall time {queue.max_wall_time} s"
    share = f" (share of {queue.mapping_queue})" if queue.vo_share else ""
    return (
        f"  Queue: {queue.name}{share}: {queue.running or 0} running, "
        f"{queue.waiting or 0} waiting{limit}"
    )


def run_info(command: Command) -> int:
    args = command.args
    names = [*args.ces, *args.ce] or command.config.defaults()
    if not names:
        raise ARCError("No computing element given; name one, or use -C", 22)
    client = command.client()
    failed = 0
    for name in names:
        for ce in command.config.resolve(name):
            try:
                info = client.info(ce)
            except ARCError as exc:
                failed += 1
                output.error(exc, ce=ce)
                command.say(f"{command.prog}: {ce}: {exc}", stderr=True)
                continue
            output.record(
                ce=client.rest(ce).ce,
                name=info.name,
                endpoints=[
                    {
                        "url": e.url,
                        "interface": e.interface,
                        "health": e.health,
                        "versions": list(e.versions),
                    }
                    for e in info.endpoints
                ],
                queues=[
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
                runtime_environments=list(info.runtime_environments),
            )
            _describe(command, client.rest(ce).ce, info)
    return 1 if failed else 0
