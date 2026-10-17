"""vomses configuration, the VOMS REST protocol against a local server, the AC extension DER."""

from __future__ import annotations

import base64
import errno
import os
import socket
import ssl
import sys
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from xgfalclient.testing.pki import PKI

from xrdarc import voms
from xrdarc.creds import Credentials
from xrdarc.errors import ARCError, CredentialError
from xrdarc.transport import Session
from xrdarc.voms import VOMSServer

ATLAS = '"atlas" "voms.cern.ch" "15001" "/DC=ch/DC=cern/OU=computers/CN=voms.cern.ch" "atlas"'
AC = bytes(range(256)) * 2


# -- parse_vomses --------------------------------------------------------------------------


def test_parse_quoted_line() -> None:
    (server,) = voms.parse_vomses(ATLAS + ' "24"\n')
    assert server == VOMSServer(
        "atlas", "voms.cern.ch", 15001, "/DC=ch/DC=cern/OU=computers/CN=voms.cern.ch", "atlas"
    )


def test_parse_skips_comments_and_blank_lines() -> None:
    text = f"# servers\n\n   \n  # indented\n{ATLAS}\nalias host 8443 /CN=host vo\n"
    found = voms.parse_vomses(text)
    assert [s.alias for s in found] == ["atlas", "alias"]
    assert found[1] == VOMSServer("alias", "host", 8443, "/CN=host", "vo")


def test_parse_empty_port_is_default() -> None:
    (server,) = voms.parse_vomses('"a" "h" "" "/CN=h" "vo"')
    assert server.port == 8443


@pytest.mark.parametrize(
    "line",
    ['"a" "h" "15000" "/CN=h"', '"a" "h" "port" "/CN=h" "vo"', '"a" "h" "15000" "/CN=h" "vo'],
)
def test_parse_bad_line(line: str) -> None:
    with pytest.raises(ARCError, match=r"^/etc/vomses/x:3: not a vomses line") as caught:
        voms.parse_vomses(f"# c\n{ATLAS}\n{line}\n", "/etc/vomses/x")
    assert caught.value.code == errno.EINVAL


def test_parse_default_origin() -> None:
    with pytest.raises(ARCError, match=r"^vomses:1:"):
        voms.parse_vomses("short")


# -- find_vomses ---------------------------------------------------------------------------


def _vomses(path: Path, *names: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f'"{n}" "{n}.example" "15000" "/CN={n}" "{n}"\n' for n in names))
    return path


def _vos(servers: list[VOMSServer]) -> list[str]:
    return [s.vo for s in servers]


def test_find_explicit_file(tmp_path: Path) -> None:
    path = _vomses(tmp_path / "vomses", "atlas", "cms")
    assert _vos(voms.find_vomses(path, environ={})) == ["atlas", "cms"]
    assert _vos(voms.find_vomses(str(path), environ={})) == ["atlas", "cms"]


def test_find_directory_recursively(tmp_path: Path) -> None:
    _vomses(tmp_path / "vomses" / "b-cms", "cms")
    _vomses(tmp_path / "vomses" / "a-atlas", "atlas")
    _vomses(tmp_path / "vomses" / "sub" / "dteam", "dteam")
    assert _vos(voms.find_vomses(tmp_path / "vomses", environ={})) == ["atlas", "cms", "dteam"]


def test_find_env_voms_file_first(home: Path, tmp_path: Path) -> None:
    env = {
        "HOME": str(home),
        "X509_VOMS_FILE": str(_vomses(tmp_path / "file", "first")),
        "X509_VOMSES": str(_vomses(tmp_path / "vomses", "second")),
    }
    _vomses(home / ".arc" / "vomses", "home")
    assert _vos(voms.find_vomses(environ=env)) == ["first"]


def test_find_env_vomses(home: Path, tmp_path: Path) -> None:
    env = {
        "HOME": str(home),
        "X509_VOMS_FILE": "  ",
        "X509_VOMSES": str(_vomses(tmp_path / "dir" / "atlas", "atlas").parent),
    }
    assert _vos(voms.find_vomses(environ=env)) == ["atlas"]


def test_find_missing_env_file_falls_through(home: Path, tmp_path: Path) -> None:
    _vomses(home / ".voms" / "vomses", "home")
    env = {"HOME": str(home), "X509_VOMSES": str(tmp_path / "absent")}
    assert _vos(voms.find_vomses(environ=env)) == ["home"]


def test_find_arc_before_voms_directory(home: Path) -> None:
    _vomses(home / ".arc" / "vomses", "arc")
    _vomses(home / ".voms" / "vomses", "voms")
    assert _vos(voms.find_vomses(environ={"HOME": str(home)})) == ["arc"]


def test_find_reads_process_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X509_VOMSES", str(_vomses(tmp_path / "vomses", "env")))
    assert _vos(voms.find_vomses()) == ["env"]


def test_system_candidates_last(home: Path) -> None:
    found = voms._candidates({"HOME": str(home)})
    assert found == [
        home / ".arc" / "vomses",
        home / ".voms" / "vomses",
        Path("/etc/vomses"),
        Path("/etc/grid-security/vomses"),
    ]


def test_find_nothing(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = voms._candidates
    monkeypatch.setattr(
        voms, "_candidates", lambda env: [p for p in real(env) if not str(p).startswith("/etc")]
    )
    with pytest.raises(ARCError, match="No vomses configuration") as caught:
        voms.find_vomses(environ={"HOME": str(home)})
    assert caught.value.code == errno.ENOENT


def test_find_undecodable_file(tmp_path: Path) -> None:
    bad = tmp_path / "vomses"
    bad.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ARCError, match="Cannot read") as caught:
        voms.find_vomses(bad)
    assert caught.value.code == errno.EIO


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_find_unreadable_file(tmp_path: Path) -> None:
    locked = _vomses(tmp_path / "vomses", "atlas")
    locked.chmod(0)
    try:
        with pytest.raises(ARCError, match="Cannot read") as caught:
            voms.find_vomses(locked)
    finally:
        locked.chmod(0o600)
    assert caught.value.code == errno.EIO


def test_find_bad_line_names_file(tmp_path: Path) -> None:
    bad = tmp_path / "vomses"
    bad.write_text("too short\n")
    with pytest.raises(ARCError, match=f"{bad}:1:"):
        voms.find_vomses(bad)


# -- servers_for ---------------------------------------------------------------------------

SERVERS = [
    VOMSServer("atlas", "a1", 1, "/CN=a1", "atlas"),
    VOMSServer("atlas-backup", "a2", 2, "/CN=a2", "atlas"),
    VOMSServer("cms-voms", "c1", 3, "/CN=c1", "cms"),
]


def test_servers_for_vo() -> None:
    assert [s.host for s in voms.servers_for("atlas", SERVERS)] == ["a1", "a2"]


def test_servers_for_alias() -> None:
    assert [s.host for s in voms.servers_for("atlas-backup", SERVERS)] == ["a2"]
    assert [s.host for s in voms.servers_for("cms-voms", iter(SERVERS))] == ["c1"]


def test_servers_for_none() -> None:
    with pytest.raises(ARCError, match="No VOMS server for 'dteam'") as caught:
        voms.servers_for("dteam", SERVERS)
    assert caught.value.code == errno.ENOENT


# -- fetch_ac against a local VOMS REST server ---------------------------------------------


@dataclass
class _Answer:
    status: int
    body: bytes
    requests: list[tuple[str, str]] = field(default_factory=list)


class _Handler(BaseHTTPRequestHandler):
    server: _VOMS

    def do_GET(self) -> None:
        answer = self.server.answer
        answer.requests.append((self.path, self.headers.get("Accept", "")))
        self.send_response(answer.status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(answer.body)))
        self.end_headers()
        self.wfile.write(answer.body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _VOMS(ThreadingHTTPServer):
    """A VOMS REST endpoint: TLS per accepted connection, one canned answer."""

    daemon_threads = True

    def __init__(self, context: ssl.SSLContext, answer: _Answer) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.context = context
        self.answer = answer

    def get_request(self) -> tuple[socket.socket, object]:
        sock, address = super().get_request()
        try:
            return self.context.wrap_socket(sock, server_side=True), address
        except OSError:
            sock.close()
            raise


Start = Callable[[int, bytes], tuple[VOMSServer, _Answer]]


@pytest.fixture
def start(pki: PKI) -> Iterator[Start]:
    running: list[tuple[_VOMS, threading.Thread]] = []

    def launch(status: int, body: bytes) -> tuple[VOMSServer, _Answer]:
        answer = _Answer(status, body)
        server = _VOMS(pki.server_context(require_client=True), answer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        running.append((server, thread))
        port = server.server_address[1]
        return VOMSServer("test", "127.0.0.1", port, "/CN=host/localhost", "atlas"), answer

    yield launch
    for server, thread in running:
        server.shutdown()
        server.server_close()
        thread.join(5)


@pytest.fixture
def session(pki: PKI) -> Iterator[Session]:
    proxy = str(pki.proxy_path)
    credentials = Credentials(cert=proxy, key=proxy, ca_dir=str(pki.ca_dir))
    with Session(credentials, retries=0, timeout=10) as opened:
        yield opened


def _ok(der: bytes = AC) -> bytes:
    encoded = base64.encodebytes(der).decode()
    return f"<voms><ac>\n{encoded}</ac></voms>".encode()


def _unreachable() -> VOMSServer:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return VOMSServer("down", "127.0.0.1", port, "/CN=down", "atlas")


def test_fetch_ac(start: Start, session: Session) -> None:
    server, answer = start(200, _ok())
    fqans = ["/atlas", "/atlas/Role=production"]
    assert voms.fetch_ac(session, [server], fqans=fqans, lifetime=3600) == AC
    ((path, accept),) = answer.requests
    parsed = urllib.parse.urlsplit(path)
    assert parsed.path == "/generate-ac"
    query = urllib.parse.parse_qs(parsed.query)
    assert query == {"fqans": ["/atlas,/atlas/Role=production"], "lifetime": ["3600"]}
    assert accept == "application/xml"


def test_fetch_ac_without_query(start: Start, session: Session) -> None:
    server, answer = start(200, _ok())
    assert voms.fetch_ac(session, [server]) == AC
    assert answer.requests[0][0] == "/generate-ac"


def test_fetch_ac_fqans_only(start: Start, session: Session) -> None:
    server, answer = start(200, _ok())
    voms.fetch_ac(session, [server], fqans=["/atlas"], lifetime=0)
    assert answer.requests[0][0] == "/generate-ac?fqans=%2Fatlas"


def test_fetch_ac_lifetime_only(start: Start, session: Session) -> None:
    server, answer = start(200, _ok())
    voms.fetch_ac(session, [server], lifetime=60)
    assert answer.requests[0][0] == "/generate-ac?lifetime=60"


def _error(code: str = "", message: str = "") -> bytes:
    parts = (f"<code>{code}</code>" if code else "") + (
        f"<message>{message}</message>" if message else ""
    )
    return f"<voms><error>{parts}</error></voms>".encode()


def test_refusal_is_final(start: Start, session: Session) -> None:
    refusing, _ = start(403, _error("NoSuchUser", "Alice is not a member"))
    spare, spare_answer = start(200, _ok())
    with pytest.raises(CredentialError, match="VOMS refused: NoSuchUser: Alice is not") as caught:
        voms.fetch_ac(session, [refusing, spare])
    assert caught.value.code == errno.EACCES
    assert caught.value.url == f"https://127.0.0.1:{refusing.port}/generate-ac"
    assert spare_answer.requests == []


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (400, _error("BadRequest"), "VOMS refused: BadRequest"),
        (404, _error(message="no such role"), "VOMS refused: error: no such role"),
    ],
)
def test_partial_refusal(
    start: Start, session: Session, status: int, body: bytes, expected: str
) -> None:
    server, _ = start(status, body)
    with pytest.raises(CredentialError) as caught:
        voms.fetch_ac(session, [server])
    assert caught.value.user_message == expected


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (b"<voms></voms>", "holds no attribute certificate"),
        (b"<voms><ac>   </ac></voms>", "holds no attribute certificate"),
        (b"<voms><ac>!!!not base64!!!</ac></voms>", "malformed attribute certificate"),
        (b"<voms><ac>", "unreadable answer"),
        (b'<!DOCTYPE voms [<!ENTITY x "y">]><voms><ac>&x;</ac></voms>', "unreadable answer"),
    ],
)
def test_bad_answers(start: Start, session: Session, body: bytes, match: str) -> None:
    server, _ = start(200, body)
    with pytest.raises(ARCError, match=match) as caught:
        voms.fetch_ac(session, [server])
    assert caught.value.code == errno.EPROTO
    assert not isinstance(caught.value, CredentialError)
    assert caught.value.url is not None


def test_server_error_fails_over(start: Start, session: Session) -> None:
    broken, broken_answer = start(500, b"<html>oops</html>")
    working, working_answer = start(200, _ok(b"\x30\x00"))
    assert voms.fetch_ac(session, [broken, working], fqans=["/atlas"]) == b"\x30\x00"
    assert len(broken_answer.requests) == len(working_answer.requests) == 1


def test_unreachable_fails_over(start: Start, session: Session) -> None:
    working, _ = start(200, _ok())
    assert voms.fetch_ac(session, [_unreachable(), working]) == AC


def test_all_unreachable(session: Session) -> None:
    down = [_unreachable(), _unreachable()]
    with pytest.raises(ARCError, match="No VOMS server could be reached") as caught:
        voms.fetch_ac(session, down)
    assert caught.value.code == errno.EHOSTUNREACH
    for server in down:
        assert f"127.0.0.1:{server.port}:" in str(caught.value)


def test_no_servers(session: Session) -> None:
    with pytest.raises(ARCError) as caught:
        voms.fetch_ac(session, [])
    assert caught.value.code == errno.EHOSTUNREACH


# -- ac_sequence ---------------------------------------------------------------------------


def test_ac_sequence_short() -> None:
    assert voms.ac_sequence([b"\x30\x00"]) == bytes.fromhex("3004 3002 3000")
    assert voms.ac_sequence([]) == bytes.fromhex("3002 3000")
    assert voms.ac_sequence([b"\x30\x00", b"\x30\x00"]) == bytes.fromhex("3006 3004 30003000")


def test_ac_sequence_one_length_byte() -> None:
    ac = b"\x04" * 200
    assert voms.ac_sequence([ac]) == bytes.fromhex("3081cb 3081c8") + ac


def test_ac_sequence_two_length_bytes() -> None:
    ac = b"\x04" * 300
    assert voms.ac_sequence([ac]) == bytes.fromhex("3082 0130 3082 012c") + ac


def test_ac_sequence_boundary() -> None:
    assert voms.ac_sequence([b"\x04" * 125])[:4] == bytes.fromhex("307f 307d")
    assert voms.ac_sequence([b"\x04" * 126])[:5] == bytes.fromhex("308180 307e")
