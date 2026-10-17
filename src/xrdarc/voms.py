"""Fetching VOMS attribute certificates over VOMS' REST interface.

``arcproxy -S atlas`` reads the ``vomses`` configuration to find the VO's
servers, authenticates to one with a short-lived plain proxy, and asks
``GET https://<host>:<port>/generate-ac?fqans=...&lifetime=...`` for an
attribute certificate, which comes back base64 in ``<voms><ac>``. That is
the protocol ARC's ``ClientVOMSRESTful`` speaks and VOMS (and INDIGO IAM's
VOMS-AA) serve; the legacy GSI socket protocol is not implemented.

The ACs are placed in the new proxy's VOMS extension, a SEQUENCE holding a
SEQUENCE of ACs, as ``voms-proxy-init`` writes it.
"""

from __future__ import annotations

import base64
import binascii
import errno
import os
import shlex
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from xrdclient._xml import UnsafeXML
from xrdclient._xml import fromstring as _xml

from .config import arc_dir
from .errors import ARCError, CredentialError, HTTPError
from .transport import Session

__all__ = ["VOMSServer", "ac_sequence", "fetch_ac", "find_vomses", "parse_vomses", "servers_for"]

_DEFAULT_PORT = 8443


@dataclass(frozen=True, slots=True)
class VOMSServer:
    """One ``vomses`` line: ``"alias" "host" "port" "server DN" "vo"``."""

    alias: str
    host: str
    port: int
    dn: str
    vo: str


def parse_vomses(text: str, origin: str = "vomses") -> list[VOMSServer]:
    """The servers in a ``vomses`` file; blank and ``#`` lines are skipped.

    A line with fewer than five fields, or a port that is not a number,
    raises ``ARCError`` naming ``origin`` and the line number.
    """
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            fields = shlex.split(line)
            alias, host, port, dn, vo = fields[:5]
            found.append(VOMSServer(alias, host, int(port or _DEFAULT_PORT), dn, vo))
        except ValueError as exc:
            raise ARCError(f"{origin}:{number}: not a vomses line ({exc})", errno.EINVAL) from exc
    return found


def _candidates(environ: Mapping[str, str]) -> list[Path]:
    named = [environ.get(name, "").strip() for name in ("X509_VOMS_FILE", "X509_VOMSES")]
    home = arc_dir(environ).parent
    return [
        *(Path(n) for n in named if n),
        home / ".arc" / "vomses",
        home / ".voms" / "vomses",
        Path("/etc/vomses"),
        Path("/etc/grid-security/vomses"),
    ]


def _read(path: Path) -> list[VOMSServer]:
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    found = []
    for file in files:
        try:
            found.extend(parse_vomses(file.read_text(encoding="utf-8"), str(file)))
        except (OSError, UnicodeDecodeError) as exc:
            raise ARCError(f"Cannot read {file}: {exc}", errno.EIO) from exc
    return found


def find_vomses(
    path: str | os.PathLike[str] | None = None, environ: Mapping[str, str] | None = None
) -> list[VOMSServer]:
    """Every configured VOMS server: ``path``, or the first existing default location.

    A file or a directory of files, searched as ``arcproxy`` does:
    ``$X509_VOMS_FILE``, ``$X509_VOMSES``, ``~/.arc/vomses``, ``~/.voms/vomses``,
    ``/etc/vomses``, ``/etc/grid-security/vomses``.
    """
    env = os.environ if environ is None else environ
    if path is not None:
        return _read(Path(path))
    for candidate in _candidates(env):
        if candidate.exists():
            return _read(candidate)
    raise ARCError(
        "No vomses configuration found; set X509_VOMSES or install the VO's vomses file",
        errno.ENOENT,
    )


def servers_for(name: str, servers: Iterable[VOMSServer]) -> list[VOMSServer]:
    """The servers for a VO, matched by VO name or by alias; ``ARCError`` if none."""
    found = [s for s in servers if name in (s.vo, s.alias)]
    if not found:
        raise ARCError(f"No VOMS server for {name!r} in the vomses configuration", errno.ENOENT)
    return found


def _parse_response(body: bytes, url: str) -> bytes:
    try:
        root = _xml(body)
    except (UnsafeXML, SyntaxError) as exc:
        raise ARCError("The VOMS server sent an unreadable answer", errno.EPROTO, url=url) from exc
    code, message = root.findtext("error/code"), root.findtext("error/message")
    if code or message:
        raise CredentialError(
            f"VOMS refused: {code or 'error'}: {message or ''}".rstrip(": "), url=url
        )
    encoded = "".join((root.findtext("ac") or "").split())
    if not encoded:
        raise ARCError(
            "The VOMS server's answer holds no attribute certificate", errno.EPROTO, url=url
        )
    try:
        return base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise ARCError(
            "The VOMS server sent a malformed attribute certificate", errno.EPROTO, url=url
        ) from exc


def fetch_ac(
    session: Session,
    servers: Sequence[VOMSServer],
    *,
    fqans: Sequence[str] = (),
    lifetime: int | None = None,
) -> bytes:
    """An AC (DER) from the first of ``servers`` that grants one.

    ``session`` authenticates with the user's (plain) proxy. A server that
    cannot be reached, or answers with a server error, is skipped for the
    next; an explicit refusal (no such user, no such role) is final.
    """
    failures = []
    for server in servers:
        query = {"fqans": ",".join(fqans)} if fqans else {}
        if lifetime:
            query["lifetime"] = str(lifetime)
        suffix = f"?{urllib.parse.urlencode(query)}" if query else ""
        url = f"https://{server.host}:{server.port}/generate-ac{suffix}"
        try:
            response = session.request(
                "GET", url, headers={"Accept": "application/xml"}, expect=(200, 400, 403, 404)
            )
        except (HTTPError, ARCError) as exc:
            failures.append(f"{server.host}:{server.port}: {exc}")
            continue
        return _parse_response(response.body, url)
    raise ARCError("No VOMS server could be reached: " + "; ".join(failures), errno.EHOSTUNREACH)


def _der(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    length = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def ac_sequence(acs: Sequence[bytes]) -> bytes:
    """The VOMS extension value for ``acs``: SEQUENCE { SEQUENCE OF AttributeCertificate }."""
    return _der(0x30, _der(0x30, b"".join(acs)))
