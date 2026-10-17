"""HTTPS to an ARC CE: one pooled, thread-safe session per set of credentials.

A-REX speaks plain HTTP/1.1 over TLS with client certificates, so the
transport is urllib3 with an ``SSLContext`` built from the grid credentials.
It adds what an ARC client needs on top:

* idempotent requests (GET, HEAD, PUT, DELETE, PROPFIND) are retried on a
  dropped connection or a 502/503/504, with backoff; a POST never is,
  because a repeated ``action=new`` would submit the jobs twice;
* every unexpected status becomes an ``HTTPError`` carrying the reason phrase,
  which is where A-REX puts its explanation;
* uploads stream from a file with a ``Content-Length`` (A-REX marks an input
  complete when the bytes written reach it), downloads stream into a file.
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import urllib3
from urllib3.exceptions import HTTPError as _Urllib3Error
from urllib3.exceptions import MaxRetryError, ProtocolError, SSLError

from ._version import __version__
from .creds import Credentials
from .errors import ARCError, HTTPError, NotAllowedError

__all__ = ["Response", "Session"]

_log = logging.getLogger("xrdarc")

USER_AGENT = f"xrdarc/{__version__}"
_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "PROPFIND", "OPTIONS"})
_CHUNK = 1 << 20


@dataclass(frozen=True, slots=True)
class Response:
    """A complete response: status line, headers and the whole body."""

    status: int
    reason: str
    headers: Mapping[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _reason(raw: urllib3.BaseHTTPResponse) -> str:
    return str(getattr(raw, "reason", "") or "")


def _drain(raw: urllib3.BaseHTTPResponse) -> bytes:
    """An error answer's body, or nothing if the connection dies while it is read."""
    try:
        return raw.read()
    except _Urllib3Error:
        return b""
    finally:
        raw.release_conn()


def _error(status: int, reason: str, url: str, body: bytes) -> HTTPError:
    text = body.decode("utf-8", "replace")[:2000]
    kind = NotAllowedError if status in (401, 403) else HTTPError
    return kind(status, reason, url=url, body=text)


def _lost(url: str, exc: Exception) -> ARCError:
    return ARCError(f"Connection lost downloading: {exc}", errno.ECONNABORTED, url=url)


class Session:
    """Requests to one or more CEs with one set of credentials.

    ``timeout`` bounds connecting and each read; ``retries`` is how many
    times an idempotent request is repeated after a transport failure.
    Safe to share between threads; ``close()`` (or ``with``) releases the
    pooled connections.
    """

    def __init__(
        self,
        credentials: Credentials,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        backoff: float = 0.5,
        pool: urllib3.PoolManager | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.credentials = credentials
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self._lock = threading.Lock()
        self._pool = pool
        self._closed = False

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._pool is not None:
                self._pool.clear()
            self._closed = True

    def _manager(self) -> urllib3.PoolManager:
        with self._lock:
            if self._closed:
                raise ARCError("The session is closed", errno.EBADF)
            if self._pool is None:
                context = self.credentials.ssl_context()
                self._pool = urllib3.PoolManager(
                    num_pools=16,
                    maxsize=8,
                    ssl_context=context,
                    assert_hostname=None if context.check_hostname else False,
                    cert_reqs=ssl.CERT_REQUIRED if self.credentials.verify else ssl.CERT_NONE,
                    retries=False,
                    timeout=urllib3.Timeout(connect=self.timeout, read=self.timeout),
                )
            return self._pool

    def _headers(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, **self.credentials.headers()}
        if extra:
            headers.update(extra)
        return headers

    def open(
        self,
        method: str,
        url: str,
        *,
        body: bytes | BinaryIO | None = None,
        headers: Mapping[str, str] | None = None,
        expect: Iterable[int] = (200,),
    ) -> urllib3.BaseHTTPResponse:
        """Send a request and return the unread response, for streaming.

        The caller must ``release_conn()`` (or read to the end). A status not
        in ``expect`` raises ``HTTPError`` after the error body is read.
        """
        wanted = frozenset(expect)
        attempts = 1 + (self.retries if method.upper() in _IDEMPOTENT else 0)
        attempt = 0
        while True:
            last = attempt >= attempts - 1
            raw = self._send(method, url, body, headers, retry=not last)
            if raw is not None:
                if raw.status in wanted:
                    return raw
                data = _drain(raw)
                if last or raw.status not in (502, 503, 504):
                    raise _error(raw.status, _reason(raw), url, data)
                _log.debug("%s %s: HTTP %d, retrying", method, url, raw.status)
            self._pause(attempt, body)
            attempt += 1

    def _pause(self, attempt: int, body: bytes | BinaryIO | None) -> None:
        if body is not None and not isinstance(body, bytes):
            body.seek(0)
        self._sleep(self.backoff * (2**attempt))

    def _send(
        self,
        method: str,
        url: str,
        body: bytes | BinaryIO | None,
        headers: Mapping[str, str] | None,
        *,
        retry: bool,
    ) -> urllib3.BaseHTTPResponse | None:
        """One attempt; ``None`` means "failed in a way worth retrying"."""
        try:
            return self._manager().urlopen(
                method,
                url,
                body=body,
                headers=self._headers(headers),
                preload_content=False,
                redirect=False,
            )
        except SSLError as exc:
            raise ARCError(f"TLS handshake failed: {exc}", errno.EPROTO, url=url) from exc
        except (ProtocolError, MaxRetryError, _Urllib3Error) as exc:
            if retry:
                _log.debug("%s %s: %s, retrying", method, url, exc)
                return None
            raise ARCError(f"Connection failed: {exc}", errno.ECONNABORTED, url=url) from exc

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | BinaryIO | None = None,
        headers: Mapping[str, str] | None = None,
        expect: Iterable[int] = (200,),
    ) -> Response:
        """Send a request and read the whole response."""
        raw = self.open(method, url, body=body, headers=headers, expect=expect)
        try:
            data = raw.read()
        except _Urllib3Error as exc:
            raise ARCError(
                f"Connection lost reading the response: {exc}", errno.ECONNABORTED, url=url
            ) from exc
        finally:
            raw.release_conn()
        return Response(raw.status, _reason(raw), dict(raw.headers.items()), data, url)

    def upload(self, url: str, source: Path, *, expect: Iterable[int] = (200, 201, 204)) -> int:
        """PUT a local file, streamed with its length; returns the bytes sent."""
        with open(source, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            headers = {"Content-Length": str(size), "Content-Type": "application/octet-stream"}
            # An empty file still needs a body for urllib3 to send Content-Length: 0.
            payload: bytes | BinaryIO = handle if size else b""
            self.request("PUT", url, body=payload, headers=headers, expect=expect)
        return size

    def download(self, url: str, target: Path) -> int:
        """GET into ``target`` via a temporary sibling, renamed into place when complete."""
        partial = target.with_name(target.name + ".part")
        raw = self.open("GET", url)
        written = 0
        try:
            with open(partial, "wb") as out:
                for chunk in raw.stream(_CHUNK):
                    out.write(chunk)
                    written += len(chunk)
        except BaseException as exc:
            # Never leave a partial file behind, whatever cut the download short.
            partial.unlink(missing_ok=True)
            if isinstance(exc, _Urllib3Error):
                raise _lost(url, exc) from exc
            raise
        finally:
            raw.release_conn()
        os.replace(partial, target)
        return written

    def copy_to(self, url: str, out: BinaryIO) -> int:
        """GET and write the body to an open binary stream (``arccat``)."""
        raw = self.open("GET", url)
        try:
            shutil.copyfileobj(raw, out, _CHUNK)
            return int(raw.tell())
        except _Urllib3Error as exc:
            raise _lost(url, exc) from exc
        finally:
            raw.release_conn()
