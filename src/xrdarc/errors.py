"""Exceptions raised by xrdarc.

Every error is an ``OSError`` with an ``errno``, so callers can catch the
whole family as they would a failed file operation, the command-line tools
can turn it into an exit status, and the JSON report carries a numeric code.
``user_message`` is the sentence a person should read; ``str()`` keeps the
technical detail.
"""

from __future__ import annotations

import errno as _errno
import functools

from xrdcore import errors as _core

__all__ = [
    "ARCError",
    "CredentialError",
    "DescriptionError",
    "HTTPError",
    "JobNotFoundError",
    "NotAllowedError",
    "credential_error",
    "errno_for_status",
]

#: HTTP status classes, in the errno a POSIX tool would report for them.
_STATUS_ERRNO = {
    400: _errno.EINVAL,
    401: _errno.EACCES,
    403: _errno.EACCES,
    404: _errno.ENOENT,
    405: _errno.EOPNOTSUPP,
    408: _errno.ETIMEDOUT,
    409: _errno.EEXIST,
    413: _errno.EFBIG,
    501: _errno.EOPNOTSUPP,
    503: _errno.EAGAIN,
    504: _errno.ETIMEDOUT,
    507: _errno.ENOSPC,
}


def errno_for_status(status: int) -> int:
    """The errno that stands for an HTTP status; ``EIO`` for anything unlisted."""
    return _STATUS_ERRNO.get(status, _errno.EIO)


class ARCError(OSError):
    """Something an ARC CE, the network or the local setup refused to do.

    ``code`` mirrors ``errno`` (the report layer reads either), ``url`` names
    the resource when there is one, and ``user_message`` is the sentence
    without the technical prefix.
    """

    def __init__(self, message: str, code: int = _errno.EIO, *, url: str | None = None) -> None:
        super().__init__(code, message)
        self.code = code
        self.url = url
        self.user_message = message

    def __str__(self) -> str:
        """The sentence, with the URL in brackets when there is one."""
        return self.user_message if self.url is None else f"{self.user_message} ({self.url})"

    def __reduce__(self) -> tuple[object, ...]:
        """Pickle through ``__init__`` (``OSError``'s default would lose ``url``)."""
        return (type(self), (self.user_message, self.code), {"url": self.url})


class CredentialError(ARCError, _core.CredentialError):
    """No usable X.509 proxy, certificate or token, or one that cannot be loaded.

    It is also an :class:`xrdcore.errors.CredentialError`, as the libraries'
    design asks of a client ("clients join it by multiple inheritance"): code
    written against the libraries - ``except xrdcore.errors.CredentialError``
    - catches xrdarc's too. The other direction is :func:`credential_error`,
    which turns what xrdsec raises into this class at xrdarc's boundary, so
    an xrdarc caller keeps its ``OSError``/``errno`` contract.
    """

    def __init__(self, message: str, code: int = _errno.EACCES, *, url: str | None = None) -> None:
        super().__init__(message, code, url=url)


def credential_error(exc: BaseException, context: str = "") -> CredentialError:
    """``exc`` - an error from xrdsec or from reading a credential - as a :class:`CredentialError`.

    xrdsec raises :class:`xrdcore.errors.CredentialError` (and its
    ``InsecureCredentialError``), :class:`FileNotFoundError`, plain
    ``OSError``\\ s from OpenSSL, and ``ValueError`` for a request or
    certificate it refuses; none of them is an ``ARCError``, so none would
    get xrdarc's exit code or report ``code``. The errno is the file's own
    when there is one (``ENOENT`` for a missing proxy), else ``EACCES``:
    every credential failure means "you cannot authenticate like this".
    An xrdarc ``CredentialError`` (a pass-phrase prompt's refusal) is
    returned unchanged. ``context`` is put in front of the message
    ("Cannot use the proxy /tmp/x509up_u1000: ...").
    """
    if isinstance(exc, CredentialError):
        return exc
    code, text = _os_detail(exc) if isinstance(exc, OSError) else (_errno.EACCES, str(exc))
    return CredentialError(f"{context}: {text}" if context else text, code)


def _os_detail(exc: OSError) -> tuple[int, str]:
    """An ``OSError``'s errno (``EACCES`` if it has none) and its message, naming the file.

    ``FileNotFoundError(2, "No such file or directory", path)`` reads
    ``No such file or directory: path``; an OpenSSL error with no
    ``strerror`` keeps its own text.
    """
    text = exc.strerror or str(exc)
    if exc.filename and str(exc.filename) not in text:
        text = f"{text}: {exc.filename}"
    return exc.errno or _errno.EACCES, text


class DescriptionError(ARCError, ValueError):
    """A job description that cannot be parsed or cannot be submitted as written."""

    def __init__(self, message: str, code: int = _errno.EINVAL, *, url: str | None = None) -> None:
        super().__init__(message, code, url=url)


class HTTPError(ARCError):
    """The CE answered with an HTTP status the operation did not expect.

    A-REX puts most of its explanation in the reason phrase rather than the
    body, so both are kept: ``reason`` and ``body`` (decoded, possibly empty).
    """

    def __init__(self, status: int, reason: str, *, url: str | None = None, body: str = "") -> None:
        detail = reason or "no reason given"
        if body and body.strip() and body.strip() != reason:
            detail = f"{detail}: {body.strip()}"
        super().__init__(f"HTTP {status} {detail}", errno_for_status(status), url=url)
        self.status = status
        self.reason = reason
        self.body = body

    def __reduce__(self) -> tuple[object, ...]:
        # Rebuilt through ``__init__`` with the body, so the message keeps its detail.
        rebuild = functools.partial(type(self), url=self.url, body=self.body)
        return (rebuild, (self.status, self.reason))


class NotAllowedError(HTTPError):
    """The CE authenticated the client but refused the operation (HTTP 401/403)."""


class JobNotFoundError(ARCError):
    """The CE does not know the job, or the local job list has no such entry."""

    def __init__(self, message: str, code: int = _errno.ENOENT, *, url: str | None = None) -> None:
        super().__init__(message, code, url=url)
