"""``xrdarc``: ARC's command-line tools as subcommands of one program.

``xrdarc sub`` is ``arcsub``, ``xrdarc stat`` is ``arcstat`` and so on, with
ARC's option spellings, so ``alias arcstat='xrdarc stat'`` works for most
uses. They are not installed under ARC's own names, so both can be on one
machine. Every subcommand takes ``--json`` / ``--xml`` for a versioned
machine-readable report (the format shared with xrdclient and xgfalclient).

Exit status: 0 when everything worked, 1 when some jobs failed, 2 for a
usage error, 130 after Ctrl-C, and otherwise the errno of a fatal error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from .._version import __version__
from ..errors import ARCError
from . import _common, jobs, proxy, submit
from ._common import Command, Runner, output

__all__ = ["main"]

#: subcommand -> (module setting it up, help line)
_COMMANDS: dict[str, tuple[Callable[[argparse.ArgumentParser], Runner], str]] = {
    "sub": (submit.setup_sub, "submit jobs (arcsub)"),
    "info": (submit.setup_info, "describe a CE: endpoints, queues, software (arcinfo)"),
    "stat": (jobs.setup_stat, "show job states (arcstat)"),
    "wait": (jobs.setup_wait, "wait for jobs to finish"),
    "get": (jobs.setup_get, "download finished jobs' results and clean them (arcget)"),
    "cat": (jobs.setup_cat, "print a job's stdout, stderr, log or any file (arccat)"),
    "ls": (jobs.setup_ls, "list a job's session directory"),
    "diagnose": (jobs.setup_diagnose, "print A-REX's diagnostic files for a job"),
    "kill": (jobs.setup_kill, "cancel jobs (arckill)"),
    "clean": (jobs.setup_clean, "remove finished jobs from the CE (arcclean)"),
    "resume": (jobs.setup_resume, "restart failed jobs (arcresume)"),
    "renew": (jobs.setup_renew, "renew jobs' delegated proxies (arcrenew)"),
    "sync": (jobs.setup_sync, "add a CE's jobs to the job list (arcsync)"),
    "proxy": (proxy.setup_proxy, "create or inspect an X.509 proxy (arcproxy)"),
}


def build_parser() -> tuple[argparse.ArgumentParser, dict[str, Runner]]:
    parser = output.Parser(prog="xrdarc", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=output.Parser)
    runners: dict[str, Runner] = {}
    for name, (setup, help_text) in _COMMANDS.items():
        child = sub.add_parser(name, help=help_text, description=help_text)
        runners[name] = setup(child)
        _common.add_common(child)
    parser.add_argument("-V", "--version", action="version", version=f"xrdarc {__version__}")
    output.flags(parser)
    return parser, runners


def _run(argv: Sequence[str]) -> int:
    parser, runners = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    _common.configure(args)
    command = Command(args.command, args)
    output.identify(args.command)
    try:
        return runners[args.command](command)
    except ARCError as exc:
        output.error(exc)
        command.say(f"{command.prog}: {exc}", stderr=True)
        return exc.code & 0xFF or 1
    except KeyboardInterrupt:
        command.say(f"{command.prog}: interrupted", stderr=True)
        return 130
    finally:
        command.close()


def main(argv: Sequence[str] | None = None) -> int:
    """The ``xrdarc`` console script."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return output.run_cli("xrdarc", arguments, lambda: _run(arguments))
