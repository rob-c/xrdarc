"""``xrdarc proxy`` (arcproxy): make an RFC 3820 proxy, with VOMS attributes, or inspect one."""

from __future__ import annotations

import argparse
import datetime as _dt
import errno
import os
import tempfile
from pathlib import Path

from .. import voms
from ..config import arc_dir
from ..creds import Credentials, default_proxy_path, discover
from ..errors import ARCError, CredentialError
from ..proxy import ProxyInfo, Signer, create_proxy, proxy_info, write_proxy
from ..transport import Session
from ..xrsl import parse_period
from ._common import Command, Runner, _password, output


def setup_proxy(parser: argparse.ArgumentParser) -> Runner:
    parser.add_argument(
        "-I",
        "--info",
        action="store_true",
        help="describe the existing proxy instead of making one",
    )
    parser.add_argument("-r", "--remove", action="store_true", help="delete the proxy file")
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
    parser.add_argument(
        "--bits", type=int, default=2048, choices=(1024, 2048, 3072, 4096), help="key size"
    )
    return run_proxy


def _target(command: Command) -> Path:
    return Path(command.args.proxy) if command.args.proxy else default_proxy_path()


def _print_info(command: Command, info: ProxyInfo) -> None:
    left = int(info.remaining())
    output.record(
        path=info.path,
        subject=info.subject,
        issuer=info.issuer,
        identity=info.identity,
        proxy_type=info.kind,  # not "kind": that names the report record's own kind
        not_after=info.not_after.isoformat(),
        time_left=left,
        key_bits=info.key_bits,
        voms=[
            {"vo": v.vo, "fqans": list(v.fqans), "uri": v.uri, "time_left": int(v.remaining())}
            for v in info.voms
        ],
    )
    lines = [
        f"Subject: {info.subject}",
        f"Issuer: {info.issuer}",
        f"Identity: {info.identity}",
        f"Time left for proxy: {_duration(left)}",
        f"Proxy path: {info.path}",
        f"Proxy type: {info.kind}",
        f"Proxy key length: {info.key_bits}",
    ]
    for entry in info.voms:
        lines.append(f"====== AC extension information for VO {entry.vo} ======")
        lines.append(f"VO        : {entry.vo}")
        lines.extend(f"attribute : {fqan}" for fqan in entry.fqans)
        lines.append(f"Time left for AC: {_duration(int(entry.remaining()))}")
        lines.append(f"uri       : {entry.uri}")
    command.say("\n".join(lines))


def _duration(seconds: int) -> str:
    if seconds <= 0:
        return "expired"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    text = f"{hours} hours {minutes} minutes {secs} seconds"
    return f"{days} days {text}" if days else text


def _user_credential(command: Command) -> Signer:
    """The user certificate and key to sign with: never a proxy."""
    args = command.args
    if args.cert:
        return Signer.load(args.cert, args.key or args.cert, password=_password)
    env = dict(os.environ)
    env.pop("X509_USER_PROXY", None)
    home = arc_dir(env).parent
    pairs = [(env.get("X509_USER_CERT", ""), env.get("X509_USER_KEY", ""))]
    pairs += [
        (str(home / d / "usercert.pem"), str(home / d / "userkey.pem")) for d in (".globus", ".arc")
    ]
    for cert, key in pairs:
        if cert and key and os.path.isfile(cert) and os.path.isfile(key):
            return Signer.load(cert, key, password=_password)
    raise CredentialError(
        "No user certificate found: use --cert/--key, set X509_USER_CERT "
        "and X509_USER_KEY, or install ~/.globus/usercert.pem",
        errno.ENOENT,
    )


def _voms_extension(command: Command, signer: Signer, lifetime: int) -> bytes | None:
    """ACs for every ``-S``, fetched with a throwaway plain proxy."""
    if not command.args.voms:
        return None
    servers = voms.find_vomses(command.args.vomses)
    voms_lifetime = (
        parse_period(command.args.voms_lifetime, "seconds")
        if command.args.voms_lifetime
        else lifetime
    )
    descriptor, temporary = tempfile.mkstemp(prefix="xrdarc-proxy-")
    os.close(descriptor)
    try:
        write_proxy(temporary, create_proxy(signer, lifetime=600, bits=2048))
        trust = discover(
            command.config,
            cert=temporary,
            ca_dir=command.args.ca_dir,
            verify=not command.args.insecure,
        )
        credentials = Credentials(
            cert=temporary, key=temporary, ca_dir=trust.ca_dir, verify=trust.verify
        )
        acs = []
        with Session(credentials, timeout=command.args.timeout or 30.0) as session:
            for request in command.args.voms:
                name, _, fqan = request.partition(":")
                command.say(f"Contacting VOMS server for {name}")
                acs.append(
                    voms.fetch_ac(
                        session,
                        voms.servers_for(name, servers),
                        fqans=[fqan] if fqan else [],
                        lifetime=voms_lifetime,
                    )
                )
        return voms.ac_sequence(acs)
    finally:
        os.unlink(temporary)


def run_proxy(command: Command) -> int:
    args = command.args
    target = _target(command)
    if args.remove:
        target.unlink(missing_ok=True)
        output.record(path=str(target), removed=True)
        command.say(f"Removed {target}")
        return 0
    if args.info:
        if not target.is_file():
            raise CredentialError(f"There is no proxy at {target}", errno.ENOENT)
        _print_info(command, proxy_info(target))
        return 0
    lifetime = parse_period(args.lifetime, "seconds")
    if lifetime <= 0:
        raise ARCError(f"--lifetime {args.lifetime} is not a positive duration", errno.EINVAL)
    signer = _user_credential(command)
    extension = _voms_extension(command, signer, lifetime)
    write_proxy(
        target,
        create_proxy(
            signer,
            lifetime=lifetime,
            bits=args.bits,
            limited=args.limited,
            voms_extension=extension,
        ),
    )
    info = proxy_info(target)
    until = info.not_after.astimezone(_dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    command.say(f"Proxy generation succeeded\nYour proxy is valid until: {until}")
    _print_info(command, info)
    return 0
