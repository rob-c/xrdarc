"""HTTPS to an ARC CE: one pooled, thread-safe session per set of credentials.

A-REX speaks plain HTTP/1.1 over TLS with client certificates. The pooling,
the retries and the TLS are :class:`xrdhttp.session.Session`'s, the session
every client on the stack shares; this module is the A-REX policy over it:

* idempotent requests (GET, HEAD, PUT, DELETE, PROPFIND, OPTIONS) are retried
  on a dropped or refused connection or a 429/502/503/504, with the stack's
  capped, jittered backoff (:mod:`xrdcore.retry`) - or as long as the CE's
  ``Retry-After`` asks, up to the same cap; a POST is not, because a
  repeated ``action=new`` would submit the jobs twice, unless the caller
  says it only reads (``idempotent=True``: the ``info`` and ``status`` bulk
  queries, which change nothing on the CE). A timeout, a refused TLS
  handshake and a local file that ran short are not retried: each fails the
  same way again;
* every unexpected status becomes an ``HTTPError`` carrying the reason phrase,
  which is where A-REX puts its explanation (:class:`_ARCErrors` is the
  status table, and A-REX's own wording for every other failure);
* redirects are not followed: A-REX never sends one, and following it would
  be a decision about where the credentials may go that is not needed;
* uploads stream from a file with a ``Content-Length`` (A-REX marks an input
  complete when the bytes written reach it) and no ``Expect: 100-continue``,
  downloads stream into a file and stop mid-file when their ``cancel`` hook
  fires (:mod:`xrdcore.cancel`).

TLS is :meth:`Credentials.ssl_context <xrdarc.creds.Credentials.ssl_context>`
(xrdsec's shared context builder), built once, on the first request. With
verification off (``--insecure``) every new connection warns
(:class:`xrdhttp.session.UnverifiedTLSWarning`): the user is told, never
silenced.
"""

from __future__ import annotations

import errno
import io
import os
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from xrdcore import cancel as _cancel
from xrdhttp import session as _http

from ._version import __version__
from .creds import Credentials
from .errors import ARCError, HTTPError, NotAllowedError

__all__ = ["Response", "Session"]

#: Sent on every request, so a CE administrator reading A-REX's logs can tell
#: this client's traffic (and its version) from ``arcsub``'s.
USER_AGENT = f"xrdarc/{__version__}"
#: Methods that may be sent twice (RFC 9110 section 9.2.2). PUT counts: an
#: upload re-sent whole leaves the same file.
_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "PROPFIND", "OPTIONS"})
#: Answers worth asking again after a pause: the CE is overloaded or restarting.
#: 500 is not among them: it reports a failure handling this very request,
#: which asking again would most likely repeat.
_RETRY_STATUSES = frozenset({429, 502, 503, 504})
#: The longest one pause between attempts may be, whatever ``Retry-After`` says:
#: a CE asking for an hour is no reason to hang a command for one.
BACKOFF_CAP = 30.0
#: Read and write size when streaming a body: big enough that a fast CE is
#: not throttled by Python calls, small enough to notice a cancel promptly.
_CHUNK = 1 << 20
#: How much of an error answer's body an ``HTTPError`` keeps: an error answer
#: can be a whole HTML page, and the text ends up in a one-line message and
#: the JSON report.
_ERROR_TEXT = 2000


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
        """The body as UTF-8, undecodable bytes replaced (a CSR, a token, an error page)."""
        return self.body.decode("utf-8", "replace")


class _ConnectionLost(ARCError):
    """A body cut off mid-read: the request was delivered, its answer did not all arrive.

    A class of its own so that a download can tell the CE's failure from a
    local one (a full disk) and word it as a download's.
    """


class _ARCErrors(_http.Errors):
    """A-REX's words for every failure the shared session reports."""

    def status(self, answer: _http.Answer) -> Exception:
        """An ``HTTPError`` (``NotAllowedError`` for 401/403) with the reason and the body."""
        kind = NotAllowedError if answer.status in (401, 403) else HTTPError
        return kind(answer.status, answer.reason, url=answer.url, body=answer.text[:_ERROR_TEXT])

    def transport(self, failure: _http.Failure) -> Exception:
        """``ECONNABORTED`` for a lost connection, ``EPROTO`` for a refused handshake.

        An untrusted CE or an expired proxy fails the handshake the same way
        every time, so that is told apart from the network: retrying it, or
        reporting it as a dropped connection, would only delay the message.
        """
        exc = failure.error
        if failure.reading:
            message = f"Connection lost reading the response: {exc}"
            return _ConnectionLost(message, errno.ECONNABORTED, url=failure.url)
        if isinstance(exc, ssl.SSLError) and not isinstance(exc, _TLS_DROPS):
            return ARCError(f"TLS handshake failed: {exc}", errno.EPROTO, url=failure.url)
        return ARCError(f"Connection failed: {exc}", errno.ECONNABORTED, url=failure.url)

    def closed(self, aborted: bool) -> Exception:
        """``EBADF``: the session was closed before this request."""
        return ARCError("The session is closed", errno.EBADF)


#: TLS failures that are the connection closing, not the handshake refusing.
_TLS_DROPS = (ssl.SSLEOFError, ssl.SSLZeroReturnError)
_ERRORS = _ARCErrors()


def _never(method: str, length: int | None) -> bool:
    """A-REX is never asked ``Expect: 100-continue``: it never redirects an upload."""
    return False


def _lost(url: str, exc: BaseException | None) -> ARCError:
    """The error for a body cut off mid-transfer: the CE (or the network) is at fault."""
    return ARCError(f"Connection lost downloading: {exc}", errno.ECONNABORTED, url=url)


def _interrupted(stop: Callable[[], bool] | None) -> None:
    """Raise ``ARCError`` ``EINTR`` if the download's cancel hook has fired.

    No URL on purpose: an interrupted download is the user's doing, not the
    CE's, so it must not be reported (or exit) as a CE failure.
    """
    if stop is not None and stop():
        raise ARCError("The download was interrupted", errno.EINTR)


def _file_body(stream: BinaryIO) -> _http.FileBody:
    """``stream`` from where it stands to its end, as a body the session can send twice.

    A retried request sends it again from the same offset (the session's
    ``send_file`` seeks), so the retry never sends a short body under the
    full length.
    """
    start = stream.tell()
    end = stream.seek(0, io.SEEK_END)
    stream.seek(start)
    return _http.FileBody(stream, start, end - start, slice=_CHUNK)


class Session:
    """Requests to one or more CEs with one set of credentials.

    ``timeout`` bounds connecting and each read; ``retries`` is how many
    times an idempotent request is repeated after a transport failure or a
    busy answer; ``backoff`` is the first pause's ceiling, doubling per
    attempt up to :data:`BACKOFF_CAP` (:func:`xrdcore.retry.delay`). ``sleep``
    is how a pause is spent (tests pass a recorder). Safe to share between
    threads; ``close()`` (or ``with``) releases the pooled connections. The
    settings are read when the first request is made.
    """

    def __init__(
        self,
        credentials: Credentials,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Nothing is connected until the first request (which builds the TLS context)."""
        self.credentials = credentials
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self._lock = threading.Lock()
        self._http: _http.Session | None = None
        self._closed = False

    def __enter__(self) -> Session:
        """The session itself; leaving the block closes it."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close, whether or not the block raised."""
        self.close()

    def close(self) -> None:
        """Drop the pooled connections; any later request raises ``EBADF``."""
        # Under the lock so a request starting concurrently either gets the
        # session before it is closed or sees ``_closed``, never a closed
        # session it would silently replace.
        with self._lock:
            self._closed = True
            shared = self._http
        if shared is not None:
            shared.close()

    def _transport(self) -> _http.Session:
        """The shared session, made on first use with the credentials' TLS context."""
        with self._lock:
            if self._closed:
                raise _ERRORS.closed(False)
            if self._http is None:
                # Built under the lock: two threads starting together would
                # otherwise each build a session and leak one's connections.
                self._http = self._build()
            return self._http

    def _build(self) -> _http.Session:
        """The shared session with A-REX's policy (see the module documentation)."""
        context = self.credentials.ssl_context()
        retry = _http.RetryPolicy(
            retries=self.retries,
            statuses=_RETRY_STATUSES,
            transport=True,
            backoff=self.backoff,
            cap=BACKOFF_CAP,
            methods=_IDEMPOTENT,
            sleep=self._sleep,
        )
        policy = _http.Policy(
            headers={"User-Agent": USER_AGENT},
            connect_timeout=self.timeout,
            timeout=self.timeout,
            expects=_never,
            retry=retry,
        )
        return _http.Session(tls=lambda url: context, policy=policy, errors=_ERRORS)

    def open(
        self,
        method: str,
        url: str,
        *,
        body: bytes | BinaryIO | None = None,
        headers: Mapping[str, str] | None = None,
        expect: Iterable[int] = (200,),
        idempotent: bool | None = None,
    ) -> _http.Response:
        """Send a request and return the unread response, for streaming.

        The caller must ``close()`` it (or read it to the end and then close
        it). A status not in ``expect`` raises ``HTTPError`` after the error
        body is read. ``idempotent`` overrides the method's own answer to
        "may this be sent twice?" (``None`` asks the method).
        """
        payload = body if body is None or isinstance(body, bytes) else _file_body(body)
        # ``extra`` headers last, so an endpoint's own Content-Type or Accept
        # wins; nothing an endpoint passes ever carries ``Authorization``.
        return self._transport().request(
            method,
            url,
            body=payload,
            headers=headers,
            auth=_http.Auth(headers=self.credentials.headers()),
            expect=frozenset(expect),
            idempotent=idempotent,
            follow=False,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | BinaryIO | None = None,
        headers: Mapping[str, str] | None = None,
        expect: Iterable[int] = (200,),
        idempotent: bool | None = None,
    ) -> Response:
        """Send a request and read the whole response (``idempotent`` as for ``open``)."""
        raw = self.open(
            method, url, body=body, headers=headers, expect=expect, idempotent=idempotent
        )
        # A body cut off here is not retried even for a GET: the request
        # already succeeded once, and the callers reading whole bodies are
        # small control documents a user can simply ask for again.
        with raw:
            data = raw.read()
        return Response(raw.status, raw.reason, dict(raw.headers.items()), data, url)

    def upload(self, url: str, source: Path, *, expect: Iterable[int] = (200, 201, 204)) -> int:
        """PUT a local file, streamed with its length; returns the bytes sent."""
        with open(source, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            # The length is what A-REX counts arrived bytes against to mark
            # the input complete; the session sends the file's as
            # ``Content-Length``, an empty file's as 0.
            body = _http.FileBody(handle, 0, size, slice=_CHUNK)
            headers = {"Content-Type": "application/octet-stream"}
            self._transport().request(
                "PUT",
                url,
                body=body,
                headers=headers,
                auth=_http.Auth(headers=self.credentials.headers()),
                expect=frozenset(expect),
                follow=False,
            ).close()
        return size

    def download(self, url: str, target: Path, *, cancel: _cancel.Cancel | None = None) -> int:
        """GET into ``target`` via a temporary sibling, renamed into place when complete.

        ``cancel`` (a :class:`threading.Event`, or a callable answering "stop
        now?") is watched while the body streams: when it fires the
        connection is shut down - which wakes a read blocked on a stalled CE
        at once - and the download ends with ``ARCError`` ``EINTR``. Either
        way no partial file is left behind.
        """
        # A sibling, so the final rename stays on one file system (atomic);
        # a reader of ``target`` sees either nothing or the whole file.
        partial = target.with_name(target.name + ".part")
        raw = self.open("GET", url)
        stop = _cancel.as_check(cancel)
        try:
            with _cancel.watching(stop, raw.shutdown), open(partial, "wb") as out:
                written = _stream(raw, out, stop)
            _interrupted(stop)  # a shutdown can look like a short, clean end of the body
        except BaseException as exc:
            # Never leave a partial file behind, whatever cut the download short.
            partial.unlink(missing_ok=True)
            if isinstance(exc, _ConnectionLost):
                _interrupted(stop)
                raise _lost(url, exc.__cause__) from exc.__cause__
            raise
        finally:
            raw.close()
        os.replace(partial, target)
        return written

    def copy_to(self, url: str, out: BinaryIO) -> int:
        """GET and write the body to an open binary stream (``arccat``)."""
        raw = self.open("GET", url)
        try:
            return _stream(raw, out, None)
        except _ConnectionLost as exc:
            # Bytes already written to ``out`` stay there: ``cat`` output that
            # reached a terminal or pipe cannot be taken back.
            raise _lost(url, exc.__cause__) from exc.__cause__
        finally:
            raw.close()


def _stream(raw: _http.Response, out: BinaryIO, stop: Callable[[], bool] | None) -> int:
    """Copy ``raw``'s body into ``out``, one buffer at a time; returns the bytes written.

    One buffer is reused for the whole body, and large reads of it go
    straight off the socket (:class:`xrdhttp.wire.DirectReader`). ``stop`` is
    asked between buffers, so a cancel that does not need to wake a blocked
    read is noticed within one.
    """
    buffer = bytearray(_CHUNK)
    view = memoryview(buffer)
    written = 0
    while count := raw.readinto(buffer):
        _interrupted(stop)
        out.write(view[:count])
        written += count
    return written
