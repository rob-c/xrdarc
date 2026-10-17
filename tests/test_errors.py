"""The error family: every error an OSError with an errno, a sentence and a URL."""

from __future__ import annotations

import errno
import pickle

import pytest

from xrdarc.errors import (
    ARCError,
    CredentialError,
    DescriptionError,
    HTTPError,
    JobNotFoundError,
    NotAllowedError,
    errno_for_status,
)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, errno.EINVAL),
        (401, errno.EACCES),
        (403, errno.EACCES),
        (404, errno.ENOENT),
        (405, errno.EOPNOTSUPP),
        (408, errno.ETIMEDOUT),
        (409, errno.EEXIST),
        (413, errno.EFBIG),
        (501, errno.EOPNOTSUPP),
        (503, errno.EAGAIN),
        (504, errno.ETIMEDOUT),
        (507, errno.ENOSPC),
        (500, errno.EIO),
        (418, errno.EIO),
        (200, errno.EIO),
    ],
)
def test_errno_for_status(status: int, code: int) -> None:
    assert errno_for_status(status) == code


def test_arc_error_shape() -> None:
    error = ARCError("Something broke")
    assert isinstance(error, OSError)
    assert (error.errno, error.code, error.strerror) == (errno.EIO, errno.EIO, "Something broke")
    assert error.url is None
    assert error.user_message == "Something broke"
    assert str(error) == "Something broke"


def test_arc_error_with_url_and_code_stays_its_own_class() -> None:
    error = ARCError("Gone", errno.ENOENT, url="https://ce/x")
    # OSError(ENOENT, ...) would become FileNotFoundError; a subclass must not.
    assert type(error) is ARCError
    assert (error.errno, error.code) == (errno.ENOENT, errno.ENOENT)
    assert str(error) == "Gone (https://ce/x)"
    assert error.user_message == "Gone"


@pytest.mark.parametrize(
    ("cls", "code", "bases"),
    [
        (CredentialError, errno.EACCES, (ARCError,)),
        (DescriptionError, errno.EINVAL, (ARCError, ValueError)),
        (JobNotFoundError, errno.ENOENT, (ARCError,)),
    ],
)
def test_subclass_default_errno(cls: type[ARCError], code: int, bases: tuple[type, ...]) -> None:
    error = cls("message", url="u")
    assert error.errno == code
    assert isinstance(error, bases)
    assert str(error) == "message (u)"
    assert cls("m", errno.EPERM).errno == errno.EPERM


def test_http_error_message_from_reason_and_body() -> None:
    error = HTTPError(500, "Internal error", url="https://ce/arex", body="  stack  \n")
    assert error.user_message == "HTTP 500 Internal error: stack"
    assert str(error) == "HTTP 500 Internal error: stack (https://ce/arex)"
    assert (error.status, error.reason, error.body) == (500, "Internal error", "  stack  \n")
    assert error.errno == errno.EIO


@pytest.mark.parametrize(
    ("reason", "body", "message"),
    [
        ("Not Found", "", "HTTP 404 Not Found"),
        ("Not Found", "   ", "HTTP 404 Not Found"),
        ("Not Found", " Not Found\n", "HTTP 404 Not Found"),
        ("", "", "HTTP 404 no reason given"),
        ("", "missing", "HTTP 404 no reason given: missing"),
    ],
)
def test_http_error_message_variants(reason: str, body: str, message: str) -> None:
    error = HTTPError(404, reason, body=body)
    assert str(error) == message
    assert error.errno == errno.ENOENT


def test_not_allowed_is_an_http_error() -> None:
    error = NotAllowedError(403, "Forbidden")
    assert isinstance(error, HTTPError)
    assert error.errno == errno.EACCES
    assert str(error) == "HTTP 403 Forbidden"


@pytest.mark.parametrize(
    "error",
    [
        ARCError("plain", errno.EPERM, url="https://ce/a"),
        ARCError("no url"),
        CredentialError("No proxy"),
        DescriptionError("Bad xRSL", url="file.xrsl"),
        JobNotFoundError("No such job", url="https://ce/j"),
    ],
)
def test_arc_errors_pickle(error: ARCError) -> None:
    copy = pickle.loads(pickle.dumps(error))
    assert type(copy) is type(error)
    assert (copy.errno, copy.url, copy.user_message, str(copy)) == (
        error.errno,
        error.url,
        error.user_message,
        str(error),
    )


@pytest.mark.parametrize("cls", [HTTPError, NotAllowedError])
def test_http_errors_pickle_with_their_body(cls: type[HTTPError]) -> None:
    error = cls(403, "Forbidden", url="https://ce/arex", body="not in the VO")
    copy = pickle.loads(pickle.dumps(error))
    assert type(copy) is cls
    assert (copy.status, copy.reason, copy.body, copy.url) == (
        403,
        "Forbidden",
        "not in the VO",
        "https://ce/arex",
    )
    assert str(copy) == "HTTP 403 Forbidden: not in the VO (https://ce/arex)"
    assert (copy.errno, copy.strerror) == (error.errno, error.strerror)
