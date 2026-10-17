"""The HTTPS transport against the fake A-REX: retries, errors, TLS and streaming."""

from __future__ import annotations

import errno
import io
import socket
from pathlib import Path

import pytest
from urllib3.exceptions import ProtocolError
from urllib3.response import HTTPResponse
from xgfalclient.testing.pki import PKI

from _arex import RETRIES, add_job, make_credentials, make_session
from xrdarc.creds import Credentials
from xrdarc.errors import ARCError, HTTPError, NotAllowedError
from xrdarc.testing.arex import FakeARex
from xrdarc.transport import USER_AGENT, Response, Session

pytest_plugins = ["_arex"]

JSON = {"Accept": "application/json"}


def _versions_url(ce: FakeARex) -> str:
    return f"{ce.url}/rest"


def _file_url(ce: FakeARex, name: str, files: dict[str, bytes] | None = None) -> str:
    job = add_job(ce, files=files)
    return f"{ce.url}/rest/1.0/jobs/{job.id}/session/{name}"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _broken_stream(error: BaseException) -> object:
    def stream(self: HTTPResponse, amt: int | None = 2**16, decode_content: bool | None = None):
        # One real chunk, then the connection "goes away".
        yield self.read(1)
        raise error

    return stream


# ---------------------------------------------------------------------------
# Plain requests
# ---------------------------------------------------------------------------


def test_request_reads_the_whole_answer(ce: FakeARex, session: Session) -> None:
    response = session.request("GET", _versions_url(ce), headers=JSON)
    assert (response.status, response.reason) == (200, "OK")
    assert response.headers["Content-Type"] == "application/json"
    assert '"1.1"' in response.text
    assert response.url == _versions_url(ce)
    assert ce.requests[-1].header("User-Agent") == USER_AGENT
    assert ce.requests[-1].header("Accept") == "application/json"


def test_response_text_replaces_undecodable_bytes() -> None:
    assert Response(200, "OK", {}, b"\xffok", "u").text == "�ok"


def test_connections_are_pooled(ce: FakeARex, session: Session) -> None:
    for _ in range(3):
        session.request("GET", _versions_url(ce))
    assert ce.connections == 1


def test_token_credentials_send_a_bearer_header(ce: FakeARex, pki: PKI) -> None:
    ce.tokens["secret"] = "/CN=token user"
    with make_session(make_credentials(pki, token="secret")) as session:
        session.request("GET", _versions_url(ce))
    assert ce.requests[-1].header("Authorization") == "Bearer secret"
    assert ce.requests[-1].identity == "/CN=token user"


def test_expected_statuses_are_returned(ce: FakeARex, session: Session) -> None:
    response = session.request("POST", _versions_url(ce), expect=(501,))
    assert response.status == 501


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_unexpected_status_carries_reason_and_body(ce: FakeARex, session: Session) -> None:
    ce.fault("GET", status=404, reason="No such thing", body=b"details here")
    with pytest.raises(HTTPError) as caught:
        session.request("GET", _versions_url(ce))
    error = caught.value
    assert type(error) is HTTPError
    assert (error.status, error.reason, error.body) == (404, "No such thing", "details here")
    assert error.errno == errno.ENOENT
    assert error.url == _versions_url(ce)
    assert len(ce.requests) == 1  # a 404 is not retried


@pytest.mark.parametrize("status", [401, 403])
def test_refusals_are_not_allowed_errors(ce: FakeARex, session: Session, status: int) -> None:
    ce.fault(status=status, reason="Go away")
    with pytest.raises(NotAllowedError) as caught:
        session.request("GET", _versions_url(ce))
    assert (caught.value.status, caught.value.reason) == (status, "Go away")
    assert caught.value.errno == errno.EACCES


def test_error_bodies_are_truncated(ce: FakeARex, session: Session) -> None:
    ce.fault(status=500, body=b"x" * 5000)
    with pytest.raises(HTTPError) as caught:
        session.request("GET", _versions_url(ce))
    assert caught.value.body == "x" * 2000


def test_a_read_failure_is_a_lost_connection(
    ce: FakeARex, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def read(self: HTTPResponse, *args: object, **kwargs: object) -> bytes:
        raise ProtocolError("connection reset")

    monkeypatch.setattr(HTTPResponse, "read", read)
    with pytest.raises(ARCError, match="Connection lost reading the response") as caught:
        session.request("GET", _versions_url(ce))
    assert caught.value.errno == errno.ECONNABORTED


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


def test_dropped_get_is_retried_with_backoff(
    ce: FakeARex, session: Session, sleeps: list[float]
) -> None:
    ce.fault("GET", drop=True, times=RETRIES)
    assert session.request("GET", _versions_url(ce)).status == 200
    assert len(ce.requests) == RETRIES + 1
    assert sleeps == [0.5, 1.0]


@pytest.mark.parametrize("status", [502, 503, 504])
def test_gateway_errors_are_retried(
    ce: FakeARex, session: Session, sleeps: list[float], status: int
) -> None:
    ce.fault("GET", status=status)
    assert session.request("GET", _versions_url(ce)).status == 200
    assert sleeps == [0.5]


@pytest.mark.parametrize("method", ["HEAD", "PUT", "DELETE", "PROPFIND", "OPTIONS"])
def test_every_idempotent_method_is_retried(ce: FakeARex, session: Session, method: str) -> None:
    ce.fault(method, status=503)
    response = session.request(method, _versions_url(ce), expect=(200, 501))
    assert response.status in (200, 501)
    assert [r.method for r in ce.requests] == [method, method]


def test_backoff_doubles_from_the_configured_base(ce: FakeARex, credentials: Credentials) -> None:
    sleeps: list[float] = []
    session = make_session(credentials, sleeps=sleeps, retries=3, backoff=0.1)
    ce.fault("GET", status=503, times=3)
    with session:
        session.request("GET", _versions_url(ce))
    assert sleeps == pytest.approx([0.1, 0.2, 0.4])


def test_gateway_error_on_the_last_attempt_is_raised(
    ce: FakeARex, session: Session, sleeps: list[float]
) -> None:
    ce.fault("GET", status=503, reason="Overloaded", times=RETRIES + 1)
    with pytest.raises(HTTPError) as caught:
        session.request("GET", _versions_url(ce))
    assert (caught.value.status, caught.value.reason) == (503, "Overloaded")
    assert len(ce.requests) == RETRIES + 1
    assert len(sleeps) == RETRIES


def test_drop_on_the_last_attempt_is_a_connection_failure(
    ce: FakeARex, session: Session, sleeps: list[float]
) -> None:
    ce.fault("GET", drop=True, times=RETRIES + 1)
    with pytest.raises(ARCError, match="Connection failed") as caught:
        session.request("GET", _versions_url(ce))
    assert caught.value.errno == errno.ECONNABORTED
    assert caught.value.url == _versions_url(ce)
    assert len(sleeps) == RETRIES


def test_post_is_never_retried_after_a_drop(
    ce: FakeARex, session: Session, sleeps: list[float]
) -> None:
    ce.fault("POST", drop=True)
    with pytest.raises(ARCError) as caught:
        session.request("POST", f"{ce.url}/rest/1.1/jobs?action=new", body=b"&(executable=x)")
    assert caught.value.errno == errno.ECONNABORTED
    assert len(ce.requests) == 1
    assert sleeps == []


def test_post_is_never_retried_after_a_gateway_error(ce: FakeARex, session: Session) -> None:
    ce.fault("POST", status=503)
    with pytest.raises(HTTPError) as caught:
        session.request("POST", f"{ce.url}/rest/1.1/jobs?action=new", body=b"&(executable=x)")
    assert caught.value.status == 503
    assert len(ce.requests) == 1
    assert ce.jobs == {}


def test_no_retries_means_one_attempt(ce: FakeARex, credentials: Credentials) -> None:
    sleeps: list[float] = []
    ce.fault("GET", drop=True)
    with (
        make_session(credentials, sleeps=sleeps, retries=0) as session,
        pytest.raises(ARCError, match="Connection failed"),
    ):
        session.request("GET", _versions_url(ce))
    assert sleeps == []


def test_refused_connections_are_retried_then_reported(
    session: Session, sleeps: list[float]
) -> None:
    url = f"https://127.0.0.1:{_free_port()}/arex/rest"
    with pytest.raises(ARCError, match="Connection failed") as caught:
        session.request("GET", url)
    assert caught.value.errno == errno.ECONNABORTED
    assert len(sleeps) == RETRIES


def test_retried_bytes_body_is_sent_again(ce: FakeARex, session: Session) -> None:
    url = _file_url(ce, "data.txt")
    ce.fault("PUT", status=503)
    session.request("PUT", url, body=b"payload", expect=(200, 201))
    assert [r.body for r in ce.requests] == [b"payload", b"payload"]


# ---------------------------------------------------------------------------
# TLS and the session's life
# ---------------------------------------------------------------------------


def test_untrusted_server_is_a_tls_failure(
    ce: FakeARex, pki: PKI, tmp_path: Path, sleeps: list[float]
) -> None:
    empty = tmp_path / "no-cas"
    empty.mkdir()
    with (
        make_session(make_credentials(pki, ca_dir=str(empty)), sleeps=sleeps) as session,
        pytest.raises(ARCError, match="TLS handshake failed") as caught,
    ):
        session.request("GET", _versions_url(ce))
    assert caught.value.errno == errno.EPROTO
    assert caught.value.url == _versions_url(ce)
    assert sleeps == []  # not worth retrying
    assert ce.requests == []


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
def test_verification_can_be_turned_off(ce: FakeARex, pki: PKI, tmp_path: Path) -> None:
    empty = tmp_path / "no-cas"
    empty.mkdir()
    credentials = make_credentials(pki, ca_dir=str(empty), verify=False)
    with make_session(credentials) as session:
        assert session.request("GET", _versions_url(ce)).status == 200


def test_closed_session_refuses_requests(ce: FakeARex, session: Session) -> None:
    session.request("GET", _versions_url(ce))
    session.close()
    with pytest.raises(ARCError, match="closed") as caught:
        session.request("GET", _versions_url(ce))
    assert caught.value.errno == errno.EBADF


def test_session_closed_before_use(credentials: Credentials) -> None:
    with make_session(credentials) as session:
        pass
    with pytest.raises(ARCError) as caught:
        session.request("GET", "https://127.0.0.1:1/arex/rest")
    assert caught.value.errno == errno.EBADF


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------


def test_upload_streams_a_file_with_its_length(
    ce: FakeARex, session: Session, tmp_path: Path
) -> None:
    source = tmp_path / "input.dat"
    source.write_bytes(b"0123456789")
    url = _file_url(ce, "input.dat")
    assert session.upload(url, source) == 10
    sent = ce.requests[-1]
    assert sent.header("Content-Length") == "10"
    assert sent.header("Content-Type") == "application/octet-stream"
    assert sent.body == b"0123456789"
    job = next(iter(ce.jobs.values()))
    assert (job.session / "input.dat").read_bytes() == b"0123456789"


def test_upload_of_an_empty_file_sends_a_zero_length(
    ce: FakeARex, session: Session, tmp_path: Path
) -> None:
    source = tmp_path / "empty"
    source.touch()
    url = _file_url(ce, "empty")
    assert session.upload(url, source) == 0
    assert ce.requests[-1].header("Content-Length") == "0"
    job = next(iter(ce.jobs.values()))
    assert (job.session / "empty").read_bytes() == b""


@pytest.mark.parametrize("drop", [True, False])
def test_retried_upload_rewinds_the_file(
    ce: FakeARex, session: Session, tmp_path: Path, drop: bool
) -> None:
    source = tmp_path / "input.dat"
    source.write_bytes(b"abc" * 1000)
    url = _file_url(ce, "input.dat")
    ce.fault("PUT", status=503, drop=drop)
    assert session.upload(url, source) == 3000
    assert [r.body for r in ce.requests] == [b"abc" * 1000] * 2
    job = next(iter(ce.jobs.values()))
    assert (job.session / "input.dat").read_bytes() == b"abc" * 1000


def test_upload_failure_is_raised(ce: FakeARex, session: Session, tmp_path: Path) -> None:
    source = tmp_path / "input.dat"
    source.write_bytes(b"x")
    ce.denied.add("DataWrite")
    with pytest.raises(NotAllowedError, match="Operation is not allowed"):
        session.upload(_file_url(ce, "input.dat"), source)


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------


@pytest.fixture
def output_url(ce: FakeARex) -> str:
    return _file_url(ce, "out.txt", {"out.txt": b"hello world\n" * 100})


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    """An empty directory to download into."""
    target = tmp_path / "dest"
    target.mkdir()
    return target


def test_download_lands_atomically(output_url: str, session: Session, dest: Path) -> None:
    target = dest / "out.txt"
    assert session.download(output_url, target) == 1200
    assert target.read_bytes() == b"hello world\n" * 100
    assert sorted(p.name for p in dest.iterdir()) == ["out.txt"]


def test_download_replaces_an_existing_file(output_url: str, session: Session, dest: Path) -> None:
    target = dest / "out.txt"
    target.write_bytes(b"old")
    session.download(output_url, target)
    assert target.read_bytes() == b"hello world\n" * 100


def test_download_error_creates_nothing(ce: FakeARex, session: Session, dest: Path) -> None:
    with pytest.raises(HTTPError) as caught:
        session.download(_file_url(ce, "missing"), dest / "missing")
    assert caught.value.status == 404
    assert list(dest.iterdir()) == []


def test_download_cut_off_mid_stream_cleans_up(
    output_url: str, session: Session, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = dest / "out.txt"
    target.write_bytes(b"previous")
    monkeypatch.setattr(HTTPResponse, "stream", _broken_stream(ProtocolError("reset")))
    with pytest.raises(ARCError, match="Connection lost downloading") as caught:
        session.download(output_url, target)
    assert caught.value.errno == errno.ECONNABORTED
    assert caught.value.url == output_url
    assert target.read_bytes() == b"previous"
    assert sorted(p.name for p in dest.iterdir()) == ["out.txt"]


def test_download_local_failure_cleans_up(
    output_url: str, session: Session, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(HTTPResponse, "stream", _broken_stream(OSError(errno.ENOSPC, "full")))
    with pytest.raises(OSError) as caught:
        session.download(output_url, dest / "out.txt")
    assert caught.value.errno == errno.ENOSPC
    assert list(dest.iterdir()) == []


def test_copy_to_writes_the_body(output_url: str, session: Session) -> None:
    out = io.BytesIO()
    assert session.copy_to(output_url, out) == 1200
    assert out.getvalue() == b"hello world\n" * 100


def test_copy_to_reports_a_lost_connection(
    output_url: str, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def read(self: HTTPResponse, *args: object, **kwargs: object) -> bytes:
        raise ProtocolError("reset")

    monkeypatch.setattr(HTTPResponse, "read", read)
    with pytest.raises(ARCError, match="Connection lost") as caught:
        session.copy_to(output_url, io.BytesIO())
    assert caught.value.errno == errno.ECONNABORTED


def test_copy_to_error_status(ce: FakeARex, session: Session) -> None:
    with pytest.raises(HTTPError):
        session.copy_to(_file_url(ce, "missing"), io.BytesIO())


def test_error_body_lost_mid_read_still_reports_the_status(
    ce: FakeARex, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def read(self: HTTPResponse, *args: object, **kwargs: object) -> bytes:
        raise ProtocolError("reset")

    ce.fault("GET", status=404, reason="Gone", body=b"lost")
    monkeypatch.setattr(HTTPResponse, "read", read)
    with pytest.raises(HTTPError) as caught:
        session.request("GET", _versions_url(ce))
    assert (caught.value.status, caught.value.reason, caught.value.body) == (404, "Gone", "")
