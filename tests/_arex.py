"""Shared fixtures for tests that drive xrdarc against the in-process fake A-REX.

Load it from a test module with::

    pytest_plugins = ["_arex"]

and ask for the fixtures by name. ``ce``, ``make_ce``, ``credentials`` and
``make_arc`` come from :mod:`xrdarc.testing.fixtures` (the conftest loads it
for every module; xrdwms's suite uses the same); this module adds:

* ``sleeps`` - the list every backoff pause of ``session`` is recorded in
  (nothing really sleeps); while it is in use the backoff's jitter is pinned
  to the top of its window (:class:`Ceiling`), so the pauses are exact;
* ``session`` - a :class:`~xrdarc.transport.Session` with those credentials,
  ``retries=RETRIES`` and ``sleeps.append`` as its sleep, closed afterwards;
* ``rest`` - a :class:`~xrdarc.rest.RESTClient` for ``ce`` on ``session``.

(A module that wants ``make_arc``'s clients to record their pauses in
``sleeps`` overrides ``arc_session_factory`` itself: this module is loaded
as a plugin, so a fixture here would apply to every module of the run.)

The plain helpers (:func:`make_session`, :func:`add_job`) serve tests that
need a variation of these; ``make_credentials`` is
:func:`xrdarc.testing.fixtures.make_credentials`. The module has
no assertions of its own (PYTEST_DONT_REWRITE), so importing names from it
as well as loading it as a plugin is fine.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from xrdcore import retry

from xrdarc.creds import Credentials
from xrdarc.rest import RESTClient
from xrdarc.testing.arex import FakeARex, FakeJob
from xrdarc.transport import Session

__all__ = [
    "RETRIES",
    "USER_DN",
    "Ceiling",
    "add_job",
    "make_session",
    "rest",
    "session",
    "sleeps",
]

#: The identity the fake CE sees for the PKI's proxy.
USER_DN = "/DC=org/DC=xrdsec/OU=People/CN=Test User"
#: Retries of the ``session`` fixture: three attempts in all.
RETRIES = 2


class Ceiling:
    """A jitter source that always answers the top of the window, so waits are exact."""

    def uniform(self, a: float, b: float) -> float:
        """``b``: the longest wait :func:`xrdcore.retry.delay` allows."""
        return b


def make_session(
    credentials: Credentials,
    *,
    sleeps: list[float] | None = None,
    retries: int = RETRIES,
    **kwargs: Any,
) -> Session:
    """A session that records its backoff pauses in ``sleeps`` instead of sleeping."""
    record = sleeps if sleeps is not None else []
    return Session(credentials, retries=retries, sleep=record.append, **kwargs)


def add_job(ce: FakeARex, **kwargs: Any) -> FakeJob:
    """A job owned by :data:`USER_DN`, straight into the fake's store."""
    return ce.add_job(USER_DN, **kwargs)


@pytest.fixture
def sleeps() -> Iterator[list[float]]:
    """The pauses a session made, with the backoff's jitter pinned to its ceiling."""
    previous = retry.use_rng(Ceiling())
    yield []
    retry.use_rng(previous)


@pytest.fixture
def session(credentials: Credentials, sleeps: list[float]) -> Iterator[Session]:
    with make_session(credentials, sleeps=sleeps) as opened:
        yield opened


@pytest.fixture
def rest(ce: FakeARex, session: Session) -> RESTClient:
    return RESTClient(ce.url, session)
