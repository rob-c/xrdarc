"""What every ``xrdarc`` subcommand shares: options, client setup, job selection, reporting."""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xrdclient.cli import _output as output

from .._version import __version__
from ..client import ARCClient, Outcome
from ..config import UserConfig, load_config
from ..creds import Auth, discover
from ..errors import ARCError, CredentialError
from ..joblist import Job

__all__ = ["Runner", "Command", "add_common", "add_selection", "output", "report_outcomes"]

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
    group = parser.add_argument_group("common options")
    group.add_argument("-z", "--conffile", help="client.conf to read instead of the defaults")
    group.add_argument("-j", "--joblist", help="job list file (default ~/.arc/jobs.dat)")
    group.add_argument("-t", "--timeout", type=float, help="seconds to wait for a CE")
    group.add_argument("-d", "--debug", choices=sorted(_LEVELS), help="log level")
    group.add_argument(
        "-v", "--verbose", action="count", default=0, help="more logging (-v info, -vv debug)"
    )
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
    group.add_argument("--token", help="bearer token (default: WLCG token discovery)")
    group.add_argument("--ca-dir", help="trusted CA directory (default: $X509_CERT_DIR, ...)")
    group.add_argument(
        "--insecure", action="store_true", help="do not verify the CE's certificate (test CEs only)"
    )
    group.add_argument(
        "--rest-version", choices=("1.0", "1.1"), help="REST version to speak (default: negotiate)"
    )
    group.add_argument("-V", "--version", action="version", version=f"xrdarc {__version__}")
    output.flags(parser)


def add_selection(parser: argparse.ArgumentParser, *, states: bool = True) -> None:
    """``arcstat``-style job selection."""
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
        parser.add_argument(
            "-s",
            "--status",
            action="append",
            default=[],
            metavar="STATE",
            help="only jobs in this state (generic or REST name)",
        )


def _password() -> bytes:
    if not sys.stdin.isatty():
        raise CredentialError(
            "The private key is encrypted and there is no terminal to ask "
            "for its pass phrase; make a proxy first"
        )
    return getpass.getpass("Enter PEM pass phrase: ").encode()


class _Stderr:
    """Whatever ``sys.stderr`` is when a record is logged, not when logging was set up.

    ``main`` may run many times in one process, and a ``--json`` run swaps
    ``sys.stderr`` for its report: a handler holding the stream it was made
    with would write into a finished report, or a closed stream, afterwards.
    """

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()


def _configure_logging(args: argparse.Namespace) -> None:
    level = (
        _LEVELS[args.debug]
        if args.debug
        else (
            logging.DEBUG if args.verbose > 1 else logging.INFO if args.verbose else logging.WARNING
        )
    )
    logger = logging.getLogger("xrdarc")
    logger.setLevel(level)
    if not any(getattr(h, "_xrdarc", False) for h in logger.handlers):
        handler = logging.StreamHandler(_Stderr())
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        handler._xrdarc = True  # type: ignore[attr-defined]
        logger.addHandler(handler)


@dataclass
class Command:
    """A parsed invocation: its options, and the client built from them on demand."""

    name: str
    args: argparse.Namespace
    _client: ARCClient | None = None
    _config: UserConfig | None = None

    @property
    def prog(self) -> str:
        return f"xrdarc {self.name}"

    @property
    def config(self) -> UserConfig:
        if self._config is None:
            self._config = load_config(self.args.conffile)
        return self._config

    def client(self) -> ARCClient:
        if self._client is None:
            args = self.args
            proxy = args.proxy or args.cert
            credentials = discover(
                self.config,
                auth=args.auth or Auth.AUTO,
                cert=proxy,
                key=args.key if args.cert else None,
                token=args.token,
                ca_dir=args.ca_dir,
                verify=not args.insecure,
            )
            self._client = ARCClient(
                config=self.config,
                credentials=credentials,
                joblist=args.joblist or True,
                timeout=args.timeout,
                version=args.rest_version,
                password=_password,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def say(self, text: str, *, stderr: bool = False) -> None:
        output.message(text + "\n", stderr=stderr)

    def selected(self) -> list[Job]:
        """The jobs named by the selection options; ``ARCError`` if none are named."""
        args = self.args
        names = list(args.jobs)
        for path in args.jobids_from_file:
            names.extend(_lines(Path(path)))
        states = getattr(args, "status", None) or []
        if not names and not args.all and not args.ce and not states:
            raise ARCError("No jobs given; name jobs, or use -a for all of them", 22)
        return self.client().select(names, everything=args.all, ces=args.ce, states=states)


def _lines(path: Path) -> list[str]:
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
    """``-s``: exact, case-insensitive match on the generic or the REST state."""
    names = {job.state.value.lower(), (job.rest_state or "").lower()}
    return not wanted or any(w.lower() in names for w in wanted)


Runner = Callable[["Command"], int]


def report_outcomes(
    command: Command,
    outcomes: Sequence[Outcome],
    verb: str,
    *,
    summary: Callable[[int, int], str],
    fields: Callable[[Outcome], dict[str, Any]] | None = None,
) -> int:
    """One record (or line) per job, then ARC's summary line; exit 1 if any failed."""
    failures = 0
    for outcome in outcomes:
        extra = fields(outcome) if fields else {}
        output.record(job=outcome.job.url, ok=outcome.ok, reason=outcome.reason or None, **extra)
        if not outcome.ok:
            failures += 1
            command.say(
                f"{command.prog}: {outcome.job.url}: {verb} failed: {outcome.reason}", stderr=True
            )
    command.say(summary(len(outcomes), len(outcomes) - failures))
    return 1 if failures else 0


def configure(args: argparse.Namespace) -> None:
    _configure_logging(args)
