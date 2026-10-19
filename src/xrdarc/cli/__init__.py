"""``xrdarc``: ARC's command-line tools as subcommands of one program.

``xrdarc sub`` is ``arcsub``, ``xrdarc stat`` is ``arcstat`` and so on, with
ARC's option spellings, so ``alias arcstat='xrdarc stat'`` works for most
uses. They are not installed under ARC's own names, so both can be on one
machine. Every subcommand takes ``--json`` / ``--xml`` for a versioned
machine-readable report (the format shared with xrdclient and xgfalclient).

Exit status: 0 when everything worked, 1 when some jobs failed, 2 for a
usage error, 3-7 for fatal credential, description, CE, local and timeout
errors, 70 for a bug, 130 after Ctrl-C and 141 when the reader of a pipe
went away (``_common.ExitCode`` is the table; 0-2, 70, 130 and 141 are
:mod:`xrdcore.cli`'s, the same in every tool on the stack).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from xrdcore import cli as _cli

from .._version import __version__
from ..errors import ARCError
from . import _common, jobs, proxy, submit
from ._common import EXIT_CODES, Command, ExitCode, Runner, output

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
    """The whole command line: one sub-parser per command, and each command's runner.

    The parsers are xrdcore's report ``Parser``, whose usage errors become
    report records under ``--json``; the common options are added after a
    command's own, so its ``--help`` lists what is particular to it first.
    """
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
    """Parse ``argv``, run the command, and turn how it ended into an exit code.

    Every way out is mapped here - success, Ctrl-C, a closed pipe, any
    exception - so ``run_cli`` always has a code for the report's summary
    and the client is always closed. :func:`xrdcore.cli.run` owns Ctrl-C
    (130, after saying so) and the closed pipe (a quiet 141 - ``| head`` has
    what it wanted, and stdout is gone); every other exception is reported
    by :class:`xrdcore.cli.Fatal` in one line - ``internal error: Type:
    message`` for a bug, whose traceback is logged at ``-d DEBUG`` - with
    its code from xrdarc's table (``_common.EXIT_CODES``).
    """
    parser, runners = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        # ``xrdarc`` alone: show what there is, and exit as a usage error does.
        parser.print_help()
        return int(ExitCode.USAGE)
    _common.configure(args)
    command = Command(args.command, args)
    output.identify(args.command)
    runner = runners[args.command]
    fatal = _cli.Fatal(command.prog, EXIT_CODES, describe=_sentence, logger="xrdarc")
    try:
        return _cli.run(lambda: runner(command), interrupted=fatal.interrupted, fatal=fatal)
    finally:
        command.close()


def _sentence(exc: BaseException) -> str:
    """How a known failure reads: xrdarc's own message, or ``reason: file`` for a plain ``OSError``.

    ``str(OSError)`` is ``[Errno 2] No such file or directory: 'x'``, which
    is Python talking, not the tool.
    """
    if not isinstance(exc, OSError) or isinstance(exc, ARCError):
        return str(exc)
    return f"{exc.strerror}: {exc.filename}" if exc.filename else str(exc.strerror or exc)


def main(argv: Sequence[str] | None = None) -> int:
    """The ``xrdarc`` console script."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return output.run_cli("xrdarc", arguments, lambda: _run(arguments))
