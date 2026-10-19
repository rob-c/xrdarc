"""Request plumbing particular to A-REX: its router context, query syntax, paths and ranges.

The generic HTTP(S) server - TLS per connection, keep-alive, chunked bodies,
faults, the request log - is :class:`xrdsec.testing.https.FakeHTTPSServer`;
what is here is where A-REX parts from a generic server, each a port of the
named function in ``services/a-rex/rest/rest.cpp``:

* errors are reported in the HTTP *reason phrase*, with an empty body
  (``HTTPFault``, :func:`_fault`);
* a query starts at ``?`` or, failing that, at the first ``;``, and a
  repeated parameter keeps its first value (``GetPath``, :func:`_split_target`);
* a session path that climbs out with ``..`` is refused (``CanonicalDir``);
* ``Range`` is read loosely (:func:`_ranged`), and a ``PUT``'s
  ``Content-Range`` places a chunk, completed when the chunks cover the file
  (``FileChunks``: :func:`_merge`, :func:`_content_range`).
"""

from __future__ import annotations

import dataclasses
import re
import urllib.parse
from dataclasses import dataclass

from xrdhttp.testing import ranged_reply
from xrdsec.testing.https import Response

#: A PUT's ``Content-Range: bytes a-b/total`` (``*`` for an unknown total).
_CONTENT_RANGE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)")
#: The first range of a GET's ``Range: bytes=a-b``: all A-REX reads.
_RANGE = re.compile(r"bytes=(\d*)-(\d*)")


def _fault(status: int, reason: str, detail: str = "") -> Response:
    """``HTTPFault``: the text in the reason phrase, a body only with a detail."""
    if detail:
        return Response(status, detail.encode(), {"Content-Type": "text/plain"}, reason)
    return Response(status, reason=reason)


@dataclass
class _Ctx:
    """One request on its way through A-REX's router: the path is consumed segment by segment.

    ``headers`` is the request's, looked up case-insensitively through
    :meth:`header`; ``identity`` is who A-REX took the client for (``""``:
    nobody). ``version`` is set once the router has read ``/rest/<version>``.
    """

    method: str
    #: The decoded request path.
    path: str
    #: What is left of the path to route on.
    rest: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes
    identity: str
    version: str = ""

    def header(self, name: str, default: str | None = None) -> str | None:
        """Request header ``name`` (HTTP names ignore case), else ``default``."""
        wanted = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == wanted), default)

    def token(self) -> str:
        """``GetPathToken``: take the next path segment off :attr:`rest`."""
        token, _, remainder = self.rest.lstrip("/").partition("/")
        self.rest = remainder.lstrip("/")
        return token

    @property
    def v11(self) -> bool:
        """Spoken through REST 1.1 or later, where the extra query parameters count."""
        return self.version != "1.0"

    def param(self, name: str) -> str:
        """A 1.1-only query parameter (ignored, as on A-REX, through 1.0)."""
        return self.query.get(name, "") if self.v11 else ""


@dataclass
class _Submit:
    """A submission's 1.1 parameters: ``queue``, ``delegation_id``, ``instances[_min]``."""

    queue: str
    delegation: str
    minimum: int
    maximum: int


def _split_target(target: str) -> tuple[str, dict[str, str]]:
    """``GetPath``: the query starts at ``?``, else at the first ``;``."""
    cut = target.find("?")
    if cut < 0:
        cut = target.find(";")
    path, text = (target, "") if cut < 0 else (target[:cut], target[cut + 1 :])
    query: dict[str, str] = {}
    for item in text.split("&"):
        key, _, value = item.partition("=")
        query.setdefault(urllib.parse.unquote(key), urllib.parse.unquote(value))
    return urllib.parse.unquote(path), query


def _canonical(subpath: str) -> str | None:
    """``CanonicalDir``: the normalised relative path, or ``None`` if it climbs out."""
    parts: list[str] = []
    for part in subpath.split("/"):
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Half-open byte ranges sorted and joined where they touch: what of a file has arrived."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _content_range(value: str | None, length: int) -> tuple[int, int]:
    """Offset and total size of a PUT body."""
    match = _CONTENT_RANGE.fullmatch((value or "").strip())
    if match is None:
        return 0, length
    offset = int(match.group(1))
    total = match.group(3)
    return offset, offset + length if total == "*" else int(total)


def _ranged(data: bytes, header: str | None, mime: str) -> Response:
    """A file body for ``Range: header``, as A-REX answers it - not quite as RFC 9110 does.

    A-REX reads the first ``bytes=a-b`` only. A suffix range (``bytes=-n``)
    or none gets the whole file, ``200``; so does a range that happens to
    cover all of it. An inverted or out-of-file range is ``416``. The
    slicing and the ``Content-Range`` are :func:`xrdhttp.testing.ranged_reply`'s;
    the reason phrases are A-REX's.
    """
    match = _RANGE.match((header or "").strip())
    if match is None or not match.group(1):
        return _whole(data, mime)
    start, end = _span(match, len(data))
    if start == 0 and end == len(data):
        return _whole(data, mime)
    if start >= end:
        return Response(
            416, b"", {"Content-Range": f"bytes */{len(data)}"}, "Range not satisfiable"
        )
    reply = ranged_reply(data, f"bytes={start}-{end - 1}", content_type=mime)
    return dataclasses.replace(reply, reason="Partial content")


def _span(match: re.Match[str], size: int) -> tuple[int, int]:
    """``bytes=a-b`` (``b`` optional) as a half-open span, the end clipped to the file."""
    start = int(match.group(1))
    end = int(match.group(2)) + 1 if match.group(2) else size
    return start, min(end, size)


def _whole(data: bytes, mime: str) -> Response:
    """The whole file, ``200 OK``."""
    return Response(200, data, {"Content-Type": mime}, "OK")
