"""What every ``xrdarc`` subcommand shares: options, client setup, job selection, reporting.

It also owns the exit-code table (:class:`ExitCode`: :mod:`xrdcore.cli`'s
shared codes plus xrdarc's own 3-7) and the rows that map an exception to
it (:data:`EXIT_CODES`, read by :func:`exit_code_for`), so every subcommand
ends the same way; ``cli/__init__`` applies them through
:func:`xrdcore.cli.run` and its :class:`xrdcore.cli.Fatal` handler.

:class:`Command` is the one object a runner gets: the parsed options, the
configuration (read on first use) and the client (built on first use, so a
command that never talks to a CE never needs a credential). Output goes
through ``output`` - :mod:`xrdcore.report`, the report contract shared with
the storage clients - so every runner writes text and ``--json``/``--xml``
records through the same calls.

Credentials on the command line follow ARC's options, with two additions
for tokens: ``--token-file PATH`` and ``--token -`` (standard input), which
keep a token out of the process list; a literal ``--token`` still works and
is warned about once.
"""

from __future__ import annotations

import argparse
import enum
import errno
import getpass
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xrdcore import cli as _cli
from xrdcore import log as _xrdlog
from xrdcore import report as output
from xrdcore.errors import CredentialError as _LibraryCredentialError
from xrdcore.log import get_logger

from .._version import __version__
from ..client import ARCClient, Outcome
from ..config import UserConfig, load_config
from ..creds import Auth, Credentials, discover
from ..errors import (
    ARCError,
    CredentialError,
    DescriptionError,
    JobNotFoundError,
    NotAllowedError,
)
from ..joblist import Job
from ..xrsl import parse_period

__all__ = [
    "EXIT_CODES",
    "Command",
    "ExitCode",
    "Runner",
    "UsageError",
    "add_common",
    "add_selection",
    "exit_code_for",
    "output",
    "report_outcomes",
]

_log = get_logger("xrdarc")


@_cli.extends(_cli.ExitCode)
class ExitCode(enum.IntEnum):
    """What ``xrdarc`` exits with: a fixed table, the same on every platform.

    ARC's own tools exit 0 on success and 1 on any failure; 0, 1 and 2 keep
    their meaning here (2 is argparse's usage error), and fatal errors get
    their own small numbers instead of an errno, whose values differ between
    Linux and macOS and collide with 1 and 2 (EPERM, ENOENT). 130 and 141
    are the shell's 128 + SIGINT and 128 + SIGPIPE. 0, 1, 2, 70, 130 and 141
    are :class:`xrdcore.cli.ExitCode`'s, shared with every tool on the stack
    (``extends`` refuses a table that drops or renumbers one); 3-7 are
    xrdarc's own. docs/compatibility.md documents the table; scripts may
    rely on it.
    """

    OK = _cli.ExitCode.OK
    #: Some jobs (or CEs) failed; the rest worked. Also: a named job is not in the list.
    FAILED = _cli.ExitCode.FAILED
    #: The command line is wrong: an unknown option, no jobs or no CE named.
    USAGE = _cli.ExitCode.USAGE
    #: No usable proxy, certificate or token, an expired one, or the CE refused it (401/403).
    CREDENTIALS = 3
    #: A job description that cannot be parsed or submitted as written.
    DESCRIPTION = 4
    #: The CE could not be reached, failed the request, or answered nonsense.
    CE = 5
    #: A local problem: the job list, a file to read or write, the disk.
    LOCAL = 6
    #: ``wait --max-wait`` ran out with jobs still running.
    TIMEOUT = 7
    #: A bug: an exception nothing expected (reported in one line, not a traceback).
    INTERNAL = _cli.ExitCode.INTERNAL
    #: Ctrl-C.
    INTERRUPTED = _cli.ExitCode.INTERRUPTED
    #: The reader of standard output went away (``xrdarc cat ... | head``).
    BROKEN_PIPE = _cli.ExitCode.BROKEN_PIPE


class UsageError(ARCError):
    """The command line asks for something impossible (exit code 2, like argparse's own)."""

    def __init__(self, message: str, code: int = errno.EINVAL, *, url: str | None = None) -> None:
        """``EINVAL`` by default: what a caller reading ``code`` expects of a bad argument.

        The exit status is not taken from ``code`` but from the class
        (:data:`EXIT_CODES`), so a usage error is 2 whatever errno it carries.
        """
        super().__init__(message, code, url=url)


def _arc_exit_code(exc: ARCError) -> ExitCode:
    """An otherwise unclassified ``ARCError``: the CE's when it names a URL, else local."""
    # The URL is the tell: every transport and HTTP error carries the one it
    # failed on, and nothing local does. Checked before the errno, because a
    # CE that times out is the CE's failure (5), not ``wait``'s timeout (7).
    if exc.url is not None:
        return ExitCode.CE
    return ExitCode.TIMEOUT if exc.code == errno.ETIMEDOUT else ExitCode.LOCAL


#: Exception classes and their exit codes, most specific first
#: (:func:`xrdcore.cli.exit_code` takes the first that matches; anything
#: unlisted is a bug, 70). ``UsageError`` is an ``ARCError`` too, and must
#: not be read as a local one. The library's ``CredentialError`` (xrdsec's,
#: past a boundary that did not translate it) counts as a credential failure
#: like xrdarc's own, which is one. A named job missing from the list is 1,
#: like a job that failed, rather than a local fault (6): the command and the
#: installation worked; one of the jobs asked for could not be acted on. Any
#: other ``ARCError`` is the CE's when it carries a URL (every transport and
#: HTTP error does) and local otherwise, except ``wait``'s own timeout; any
#: other ``OSError`` is local.
EXIT_CODES: tuple[_cli.ExitRule, ...] = (
    (UsageError, ExitCode.USAGE),
    (_LibraryCredentialError, ExitCode.CREDENTIALS),
    (NotAllowedError, ExitCode.CREDENTIALS),
    (DescriptionError, ExitCode.DESCRIPTION),
    (JobNotFoundError, ExitCode.FAILED),
    (ARCError, _arc_exit_code),
    (OSError, ExitCode.LOCAL),
)


def exit_code_for(exc: BaseException) -> ExitCode:
    """The exit code for an exception that ended a command (see :data:`EXIT_CODES`)."""
    return ExitCode(_cli.exit_code(exc, EXIT_CODES))


#: Warnings given once per process (a literal ``--token``).
_WARNED: set[str] = set()

#: The loggers ``-d``/``-v`` set: xrdarc's own, and the libraries' it is built
#: on. xrdhttp says when it retries or follows a redirect; at ``-d DEBUG`` a
#: user sees that between the requests :mod:`xrdarc.transport` logs, much as
#: ``arcsub -d DEBUG`` shows ARC's own HTTP traffic.
LOGGERS = ("xrdarc", "xrdcore", "xrdhttp", "xrdsec")

#: ``-d LEVEL`` as ARC spells the levels (``VERBOSE`` is ARC's step below INFO).
_LEVELS = {
    "FATAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "VERBOSE": logging.DEBUG,
    "DEBUG": logging.DEBUG,
}


def add_common(parser: argparse.ArgumentParser) -> None:
    """Options every subcommand takes, spelled as ARC spells them where ARC has them."""
    # One group, so ``--help`` lists the command's own options first.
    group = parser.add_argument_group("common options")
    group.add_argument("-z", "--conffile", help="client.conf to read instead of the defaults")
    group.add_argument("-j", "--joblist", help="job list file (default ~/.arc/jobs.dat)")
    # No default here: ``None`` leaves the client's own, so the number lives
    # in one place.
    group.add_argument("-t", "--timeout", type=float, help="seconds to wait for a CE")
    group.add_argument("-d", "--debug", choices=sorted(_LEVELS), help="log level")
    group.add_argument(
        "-v", "--verbose", action="count", default=0, help="more logging (-v info, -vv debug)"
    )
    # ARC's three switches each name the one mode; two at once has no meaning,
    # so argparse refuses it rather than letting the last one win silently.
    auth = group.add_mutually_exclusive_group()
    auth.add_argument(
        "--x509-authentication",
        dest="auth",
        action="store_const",
        const=Auth.X509,
        help="present only the X.509 proxy or certificate",
    )
    auth.add_argument(
        "--token-authentication",
        dest="auth",
        action="store_const",
        const=Auth.TOKEN,
        help="present only the bearer token",
    )
    auth.add_argument(
        "--no-authentication",
        dest="auth",
        action="store_const",
        const=Auth.NONE,
        help="present no credential",
    )
    group.add_argument("--proxy", "-P", help="proxy file (default: $X509_USER_PROXY, ...)")
    group.add_argument("--cert", help="user certificate, with --key, instead of a proxy")
    group.add_argument("--key", help="private key for --cert")
    # One token source at a time: with two, the user could not tell which
    # token the CE was shown.
    tokens = group.add_mutually_exclusive_group()
    tokens.add_argument(
        "--token",
        help="bearer token, or - to read it from standard input (default: WLCG token "
        "discovery); a literal token is visible to other users in the process list",
    )
    tokens.add_argument(
        "--token-file", metavar="PATH", help="read the bearer token from PATH (first line)"
    )
    group.add_argument("--ca-dir", help="trusted CA directory (default: $X509_CERT_DIR, ...)")
    # Only ever an explicit option - no variable or configuration setting
    # turns verification off - so it cannot be switched off behind a user.
    group.add_argument(
        "--insecure", action="store_true", help="do not verify the CE's certificate (test CEs only)"
    )
    # Normally negotiated from ``GET /rest``; forcing one is for a CE whose
    # list misleads, and for reproducing a problem against one version.
    group.add_argument(
        "--rest-version", choices=("1.0", "1.1"), help="REST version to speak (default: negotiate)"
    )
    group.add_argument("-V", "--version", action="version", version=f"xrdarc {__version__}")
    output.flags(parser)


def add_selection(parser: argparse.ArgumentParser, *, states: bool = True) -> None:
    """``arcstat``-style job selection.

    Every way of naming jobs combines: named jobs and ``-i`` files are
    joined, then ``-c`` and ``-s`` narrow the result. ``-c`` or ``-s`` with
    nothing named means "every job, filtered", as in ARC. ``states=False``
    leaves ``-s`` out for a command that must act on every selected job
    (``wait``).
    """
    parser.add_argument("jobs", nargs="*", metavar="JOB", help="job URL, id or name")
    parser.add_argument("-a", "--all", action="store_true", help="every job in the job list")
    parser.add_argument(
        "-i",
        "--jobids-from-file",
        action="append",
        default=[],
        metavar="FILE",
        help="read job URLs from FILE, one per line",
    )
    parser.add_argument(
        "-c",
        "-C",
        "--computing-element",
        dest="ce",
        action="append",
        default=[],
        metavar="CE",
        help="only jobs on this CE",
    )
    if states:
        # Matched against the state the CE reports now, not the one recorded
        # in the job list, which may be days old (see ``jobs._fresh``).
        parser.add_argument(
            "-s",
            "--status",
            action="append",
            default=[],
            metavar="STATE",
            help="only jobs in this state (generic or REST name)",
        )


def _password() -> bytes:
    """Ask on the terminal for an encrypted key's pass phrase, as ``arcproxy`` does.

    Called only when a key turns out to be encrypted (xrdsec asks at that
    moment). With no terminal - a batch job, a pipe - there is nobody to
    ask, and waiting on standard input would hang the job, so it is refused
    with the way out: a proxy has no pass phrase.
    """
    if not sys.stdin.isatty():
        raise CredentialError(
            "The private key is encrypted and there is no terminal to ask "
            "for its pass phrase; make a proxy first"
        )
    return getpass.getpass("Enter PEM pass phrase: ").encode()


def _configure_logging(args: argparse.Namespace) -> None:
    """Set the level of every logger in :data:`LOGGERS` from ``-d``/``-v``, with one stderr handler.

    :func:`xrdcore.log.configure` installs the handler (``LEVEL: message``,
    on whatever ``sys.stderr`` is at each record, redacted) and replaces its
    own from an earlier run, so running ``main`` repeatedly - the test suite
    does - does not repeat every line.
    """
    # ``-d`` beats ``-v``: an ARC level names exactly what is wanted. ``-v``
    # counts on xrdcore's scale: warnings, ``-v`` info, ``-vv`` debug.
    level = _LEVELS[args.debug] if args.debug else _xrdlog.verbosity_level(args.verbose)
    _xrdlog.configure(level, loggers=LOGGERS)


@dataclass
class Command:
    """A parsed invocation: its options, and the client built from them on demand."""

    name: str
    args: argparse.Namespace
    # Both made on first use and kept: building the client discovers
    # credentials, which can fail, and a command such as ``proxy`` or a
    # usage error must never trip over that.
    _client: ARCClient | None = None
    _config: UserConfig | None = None

    @property
    def prog(self) -> str:
        """``xrdarc <command>``: how error lines name the command."""
        return f"xrdarc {self.name}"

    @property
    def config(self) -> UserConfig:
        """``client.conf`` (``-z``, else the system and user files), read on first use."""
        if self._config is None:
            self._config = load_config(self.args.conffile)
        return self._config

    def client(self) -> ARCClient:
        """The client the options describe, made on first use (``proxy`` never needs one).

        Credentials are discovered here, not at start-up, so ``--help``, a
        usage error or ``xrdarc proxy`` never trip over a missing proxy.
        """
        if self._client is None:
            args = self.args
            self._client = ARCClient(
                config=self.config,
                credentials=self._credentials(),
                # ``True``: the configured list (``joblist`` in client.conf,
                # else ``~/.arc/jobs.dat``).
                joblist=args.joblist or True,
                timeout=args.timeout,
                version=args.rest_version,
                # Asked only if a user key, not a proxy, must sign a delegation.
                password=_password,
            )
        return self._client

    def _credentials(self) -> Credentials:
        """ARC's discovery, with ``--proxy``/``--cert``/``--key``/``--token`` taking precedence."""
        args = self.args
        return discover(
            self.config,
            auth=args.auth or Auth.AUTO,
            # A proxy is a certificate that holds its own key, so ``--proxy``
            # is passed as ``cert`` with no key; ``--key`` belongs to
            # ``--cert`` and would split a proxy from its key otherwise.
            cert=args.proxy or args.cert,
            key=args.key if args.cert else None,
            token=_token(args),
            ca_dir=args.ca_dir,
            verify=not args.insecure,
        )

    def close(self) -> None:
        """Release the client's connections, if one was made."""
        if self._client is not None:
            self._client.close()

    def say(self, text: str, *, stderr: bool = False) -> None:
        """One line for a person; with ``--json``/``--xml`` a ``message`` record instead."""
        output.message(text + "\n", stderr=stderr)

    def selected(self) -> list[Job]:
        """The jobs named by the selection options; ``ARCError`` if none are named."""
        args = self.args
        names = list(args.jobs)
        for path in args.jobids_from_file:
            names.extend(_lines(Path(path)))
        states = getattr(args, "status", None) or []
        # Acting on every job must be asked for (``-a``, or a filter): a
        # bare ``xrdarc kill`` killing everything would be a nasty surprise.
        if not names and not args.all and not args.ce and not states:
            raise UsageError("No jobs given; name jobs, or use -a for all of them")
        return self.client().select(names, everything=args.all, ces=args.ce, states=states)


def _token(args: argparse.Namespace) -> str | None:
    """The bearer token the options name: ``--token-file``, ``--token -`` (stdin), or literal.

    A token given literally is in ``ps`` output and the shell history, so
    using one is warned about (once per process); the warning never shows
    the token. ``None`` leaves the choice to WLCG token discovery.
    """
    if args.token_file:
        return _token_text(_read_token(Path(args.token_file)), args.token_file)
    if args.token == "-":
        return _token_text(sys.stdin.readline(), "standard input")
    if not args.token:
        return None
    _warn_once(
        "literal-token",
        "A token given with --token is visible to other users of this machine; "
        "prefer --token-file PATH or --token - (standard input)",
    )
    return str(args.token)


def _warn_once(key: str, message: str) -> None:
    """Log ``message`` as a warning the first time ``key`` comes up in this process."""
    if key not in _WARNED:
        _WARNED.add(key)
        _log.warning("%s", message)


def _read_token(path: Path) -> str:
    """The first line of a token file (WLCG token files hold the token alone).

    Only the first line, so a trailing newline - or a note an editor left
    after it - never becomes part of the ``Authorization`` header. Read
    failures are credential errors (exit 3), since the token is one.
    """
    try:
        return (path.read_text(encoding="utf-8").splitlines() or [""])[0]
    except OSError as exc:
        raise CredentialError(f"Cannot read the token file {path}: {exc.strerror}") from exc


def _token_text(text: str, where: str) -> str:
    """The token in ``text`` (surrounding whitespace removed); ``CredentialError`` if empty."""
    token = text.strip()
    if not token:
        raise CredentialError(f"The token from {where} is empty")
    return token


def period_option(text: str, option: str) -> int:
    """A duration option (``12h``, ``2d``, ``90m``; a bare number is seconds), in seconds.

    Anything that is not a positive duration is a usage error naming the
    option, not a job-description error (``parse_period`` is shared with
    xRSL, whose errors say "description").
    """
    try:
        seconds = parse_period(text, "seconds")
    except DescriptionError:
        seconds = 0
    if seconds <= 0:
        raise UsageError(f"{option} {text} is not a positive duration")
    return seconds


def _lines(path: Path) -> list[str]:
    """``-i FILE``: one job per line, blank lines and ``#`` comments skipped.

    Id files are often hand-edited (jobs commented out to retry later), and
    ``sub -o`` appends to them, so both are tolerated rather than sent to
    the CE as job names.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ARCError(f"Cannot read {path}: {exc.strerror}", exc.errno or 5) from exc
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def state_matches(job: Job, wanted: Sequence[str]) -> bool:
    """``-s``: exact, case-insensitive match on the generic or the REST state.

    Both names, because users know ARC's generic states (``Running``) and
    A-REX's own (``INLRMS``); exact rather than a prefix match, so a typo
    selects nothing visibly instead of something unexpected.
    """
    names = {job.state.value.lower(), (job.rest_state or "").lower()}
    return not wanted or any(w.lower() in names for w in wanted)


#: A command's body: it returns the exit status for the jobs (0 or 1); a
#: fatal error is raised instead and mapped by :func:`exit_code_for`.
Runner = Callable[["Command"], int]


def report_outcomes(
    command: Command,
    outcomes: Sequence[Outcome],
    verb: str,
    *,
    summary: Callable[[int, int], str],
    fields: Callable[[Outcome], dict[str, Any]] | None = None,
) -> int:
    """One record (or line) per job, then ARC's summary line; exit 1 if any failed.

    Every job gets a record, the successes too, so a ``--json`` reader sees
    the whole set; only failures get a text line (on stderr), as ARC's tools
    print them. ``summary`` is given ``(total, ok)`` and words the last line
    the way the matching ARC tool does.
    """
    failures = 0
    for outcome in outcomes:
        output.record(
            job=outcome.job.url,
            ok=outcome.ok,
            reason=outcome.reason or None,
            **(fields(outcome) if fields else {}),
        )
        failures += _say_failure(command, outcome, verb)
    command.say(summary(len(outcomes), len(outcomes) - failures))
    return 1 if failures else 0


def _say_failure(command: Command, outcome: Outcome, verb: str) -> bool:
    """Say on stderr why ``outcome`` failed, ARC-style; whether it did."""
    if not outcome.ok:
        command.say(
            f"{command.prog}: {outcome.job.url}: {verb} failed: {outcome.reason}", stderr=True
        )
    return not outcome.ok


def configure(args: argparse.Namespace) -> None:
    """Everything a parsed command line sets up before the command runs (logging, for now)."""
    _configure_logging(args)
