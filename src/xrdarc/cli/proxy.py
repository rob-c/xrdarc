"""``xrdarc proxy`` (arcproxy): make an RFC 3820 proxy, with VOMS attributes, or inspect one.

The work is :mod:`xrdsec.proxytool`'s, shared with xrdclient's ``xrd-proxy``:
the user certificate search under ``arcproxy``'s conventions
(:data:`~xrdsec.proxytool.ARCPROXY` - never a proxy: a proxy of a proxy is
not what ``arcproxy`` makes), the VOMS requests, the proxy, where its file
goes and how it is read back, with xrdarc's errors from :mod:`xrdarc.proxy`.
This module is ``arcproxy``'s spelling of the options and the ``arcproxy
-I`` text.

The VOMS servers are asked with the user certificate and key *in memory*
(xrdsec presents them to OpenSSL through pipes), so making a VOMS proxy
writes exactly one file with a private key in it: the proxy itself.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import time
from collections.abc import Sequence
from pathlib import Path

from xrdcore.log import get_logger
from xrdsec import proxytool, voms_client

from ..creds import Auth, discover
from ..errors import credential_error
from ..proxy import PROFILE, ProxyInfo, Signer, load_signer, make_proxy, proxy_info, write_proxy
from ._common import Command, Runner, UsageError, _password, output, period_option

_log = get_logger("xrdarc")


def setup_proxy(parser: argparse.ArgumentParser) -> Runner:
    """Add ``arcproxy``'s options; the runner is :func:`run_proxy`."""
    parser.add_argument(
        "-I",
        "--info",
        action="store_true",
        help="describe the existing proxy instead of making one",
    )
    parser.add_argument("-r", "--remove", action="store_true", help="delete the proxy file")
    # One AC per ``-S``, asked for in order; a VO may be named twice with
    # different FQANs, as with ``arcproxy``.
    parser.add_argument(
        "-S",
        "--voms",
        action="append",
        default=[],
        metavar="VO[:FQAN]",
        help="add VOMS attributes from VO (repeatable), e.g. atlas:/atlas/Role=pilot",
    )
    parser.add_argument("--vomses", help="vomses file or directory (default: $X509_VOMSES, ...)")
    parser.add_argument("--lifetime", default="12h", help="proxy lifetime, e.g. 12h, 2d, 90m")
    parser.add_argument("--voms-lifetime", help="VOMS attribute lifetime (default: --lifetime)")
    parser.add_argument("--limited", action="store_true", help="make a limited proxy")
    # A fixed list rather than any number, so a typo (``--bits 248``) is a
    # usage error instead of a weak or unusual key.
    parser.add_argument(
        "--bits", type=int, default=2048, choices=(1024, 2048, 3072, 4096), help="key size"
    )
    return run_proxy


def _print_info(command: Command, info: ProxyInfo) -> None:
    """``arcproxy -I``'s lines, and one report record with the same facts."""
    # One clock reading for the proxy and every AC, so their "time left"
    # lines agree with each other.
    now = time.time()
    # Clamped at 0: an expired proxy has no time left, and a negative number
    # is one more case for every script reading the report.
    left = int(max(0.0, info.not_after - now))
    output.record(
        path=info.path,
        subject=info.subject,
        issuer=info.issuer,
        identity=info.identity,
        proxy_type=info.kind,  # not "kind": that names the report record's own kind
        not_after=_iso(info.not_after),
        time_left=left,
        key_bits=info.strength,
        voms=[
            {
                "vo": entry.vo,
                "subject": str(entry.holder),
                "issuer": str(entry.issuer),
                "fqans": [_fqan(fqan) for fqan in entry.fqans],
                "uri": entry.uri,
                "time_left": int(max(0.0, entry.not_after - now)),
            }
            for entry in info.voms
        ],
    )
    # ``arcproxy -I``'s labels, in its order, so a script that greps them
    # keeps working (checked against arcproxy 7.1.1).
    lines = [
        f"Subject: {info.subject}",
        f"Issuer: {info.issuer}",
        f"Identity: {info.identity}",
        f"Time left for proxy: {_duration(left)}",
        f"Proxy path: {info.path}",
        f"Proxy type: {info.kind}",
        f"Proxy key length: {info.strength}",
    ]
    for entry in info.voms:
        lines.append(f"====== AC extension information for VO {entry.vo} ======")
        lines.append(f"VO        : {entry.vo}")
        lines.append(f"subject   : {entry.holder}")
        lines.append(f"issuer    : {entry.issuer}")
        lines.append(f"uri       : {entry.uri}")
        lines.extend(f"attribute : {_fqan(fqan)}" for fqan in entry.fqans)
        lines.append(f"Time left for AC: {_duration(int(entry.not_after - now))}")
    command.say("\n".join(lines))


def _fqan(fqan: str) -> str:
    """An FQAN as ``arcproxy`` shows it: without a ``Role`` or ``Capability`` of ``NULL``.

    VOMS encodes every FQAN in full (``/lhcb/Role=NULL/Capability=NULL``),
    which is what ``voms-proxy-info`` prints and what the AC holds; ARC
    strips the empty parts, so ``-I`` says ``/lhcb``, and ``/lhcb/Role=pilot``
    for a role. The same form is what ``-S vo:fqan`` takes.
    """
    kept = [part for part in fqan.split("/") if part not in ("Role=NULL", "Capability=NULL")]
    return "/".join(kept)


def _iso(stamp: float) -> str:
    """An epoch time as ISO 8601 UTC (``2026-10-18T12:00:00+00:00``), for the report."""
    return _dt.datetime.fromtimestamp(stamp, _dt.UTC).isoformat()


def _duration(seconds: int) -> str:
    """``arcproxy``'s ``H hours M minutes S seconds`` (hours past 24 and all), or ``expired``.

    ARC 7's ``arcproxy -I`` never says "days": a week-long proxy has
    ``167 hours`` left, and a script that parses the line can rely on it.
    """
    if seconds <= 0:
        return "expired"
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours} hours {minutes} minutes {secs} seconds"


def _user_credential(command: Command) -> Signer:
    """The user certificate and key to sign with: ``--cert``/``--key``, else ARC's search.

    :func:`xrdsec.proxytool.find_user_pair` under ``arcproxy``'s
    conventions: ``--cert`` alone is one PEM holding certificate and key;
    otherwise the configuration's ``certificatepath``/``keypath``, then
    ``$X509_USER_CERT``/``$X509_USER_KEY``, ``~/.arc`` and ``~/.globus`` -
    never a proxy, whatever ``$X509_USER_PROXY`` says.
    """
    args, config = command.args, command.config
    try:
        cert, key = proxytool.find_user_pair(
            proxytool.ARCPROXY,
            cert=args.cert,
            key=args.key,
            configured=(config.cert_path, config.key_path),
        )
    except proxytool.NoCredentialError as exc:
        raise credential_error(exc) from exc
    return load_signer(cert, key, password=_password)


def _request(command: Command) -> proxytool.ProxyRequest:
    """``arcproxy``'s options as one :class:`xrdsec.proxytool.ProxyRequest`.

    Every value the user typed is checked here, before the key is loaded,
    so a typo is reported before anyone is asked for a pass phrase. One AC
    per ``-S``, asked for in order (a VO may be named twice with different
    FQANs, as with ``arcproxy``); ``--voms-lifetime`` defaults to the
    proxy's own. The VOMS servers are reached with the same TLS rules as a
    CE (:meth:`xrdarc.creds.Credentials.ssl_context`): the CEs' trust
    anchors, and Python 3.13's RFC 5280 strict mode off, because
    ``arcproxy`` (OpenSSL with its defaults) never applies it and a VOMS
    host certificate from an older grid CA would otherwise fail here alone.
    """
    args = command.args
    lifetime = period_option(args.lifetime, "--lifetime")
    try:
        voms = proxytool.voms_requests(args.voms, proxytool.ARCPROXY)
    except ValueError as exc:
        raise UsageError(f"-S: {exc}") from exc
    voms_lifetime = (
        period_option(args.voms_lifetime, "--voms-lifetime") if args.voms_lifetime else None
    )
    trust = discover(command.config, auth=Auth.NONE, ca_dir=args.ca_dir)
    return proxytool.ProxyRequest(
        lifetime=lifetime,
        bits=args.bits,
        limited=args.limited,
        profile=PROFILE,
        voms=voms,
        voms_lifetime=voms_lifetime,
        vomses=(args.vomses,) if args.vomses else (),
        timeout=args.timeout or voms_client.DEFAULT_TIMEOUT,
        ca_path=trust.ca_dir,
        system_ca=trust.system_ca,
        x509_strict=False,
    )


class _Said:
    """``arcproxy``'s line before each VOMS request, and its warnings as log warnings.

    A :class:`xrdsec.proxytool.Progress`. xrdsec's
    :class:`~xrdsec.voms_client.VOMSWarning`\\ s (an AC this machine cannot
    verify, a lifetime the server shortened) are logged rather than printed
    as Python warnings - also when a later VO fails the command.
    """

    def __init__(self, command: Command) -> None:
        """Say things through ``command``."""
        self.command = command

    def contacting(
        self, request: proxytool.VOMSRequest, servers: Sequence[voms_client.VOMSServer]
    ) -> None:
        """``Contacting VOMS server for <vo>``."""
        self.command.say(f"Contacting VOMS server for {request.vo}")

    def contacted(self, request: proxytool.VOMSRequest) -> None:
        """``arcproxy`` says nothing after an answer."""

    def warned(self, message: str) -> None:
        """A ``WARNING:`` log line."""
        _log.warning("%s", message)


def run_proxy(command: Command) -> int:
    """Remove (``-r``), describe (``-I``) or make the proxy; exit status 0 on success."""
    args = command.args
    # ``--proxy``, else ``$X509_USER_PROXY``, else ``/tmp/x509up_u<uid>`` - a
    # symbolic link followed only at a path somebody named.
    target = proxytool.proxy_target(args.proxy)
    if args.remove:
        # Like ``arcproxy -r``, removing a proxy that is not there succeeds.
        Path(target.path).unlink(missing_ok=True)
        output.record(path=target.path, removed=True)
        command.say(f"Removed {target.path}")
        return 0
    if args.info:
        # Nothing to describe is a credential problem (exit 3): the user has
        # no proxy, which is what the next command would fail on.
        _print_info(command, proxy_info(target.path, follow_symlinks=target.follow_symlinks))
        return 0
    request = _request(command)
    signer = _user_credential(command)
    try:
        proxy = make_proxy(signer, request, _Said(command))
    except ValueError as exc:
        # Only a malformed FQAN gets here (xrdarc.proxy translates the rest):
        # the user typed it, so it is a usage error (2), not a VOMS failure.
        raise UsageError(f"-S: {exc}") from exc
    write_proxy(target.path, proxy, follow_symlinks=target.follow_symlinks)
    # Described from the file, not from memory: what is reported is what the
    # next command will actually find there.
    info = proxy_info(target.path, follow_symlinks=target.follow_symlinks)
    until = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(info.not_after))
    command.say(f"Proxy generation succeeded\nYour proxy is valid until: {until}")
    _print_info(command, info)
    return 0
