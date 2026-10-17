"""Shared fixtures for tests that drive xrdarc against the in-process fake A-REX.

Load it from a test module with::

    pytest_plugins = ["_arex"]

and ask for the fixtures by name:

* ``ce`` - a started :class:`~xrdarc.testing.arex.FakeARex` over TLS (the
  session PKI's host certificate), stopped after the test;
* ``make_ce(**kwargs)`` - another fake CE, with any ``FakeARex`` keyword
  (``versions=``, ``legacy_json=``, ``tokens=``, ``progression=`` ...);
* ``credentials`` - :class:`~xrdarc.creds.Credentials` for the PKI's proxy
  and CA directory (the fake sees the identity :data:`USER_DN`);
* ``sleeps`` - the list every backoff pause of ``session`` is recorded in
  (nothing really sleeps);
* ``session`` - a :class:`~xrdarc.transport.Session` with those credentials,
  ``retries=RETRIES`` and ``sleeps.append`` as its sleep, closed afterwards;
* ``rest`` - a :class:`~xrdarc.rest.RESTClient` for ``ce`` on ``session``.

The plain helpers (:func:`make_credentials`, :func:`make_session`,
:func:`add_job`) serve tests that need a variation of these. The module has
no assertions of its own (PYTEST_DONT_REWRITE), so importing names from it
as well as loading it as a plugin is fine.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from xgfalclient.testing.pki import PKI

from xrdarc.creds import Credentials
from xrdarc.rest import RESTClient
from xrdarc.testing.arex import FakeARex, FakeJob
from xrdarc.transport import Session

__all__ = [
    "RETRIES",
    "USER_DN",
    "add_job",
    "ce",
    "credentials",
    "make_ce",
    "make_credentials",
    "make_session",
    "rest",
    "session",
    "sleeps",
]

#: The identity the fake CE sees for the PKI's proxy.
USER_DN = "/DC=org/DC=xgfal/OU=People/CN=Test User"
#: Retries of the ``session`` fixture: three attempts in all.
RETRIES = 2


def make_credentials(pki: PKI, **overrides: Any) -> Credentials:
    """The PKI's proxy as the X.509 credential, its CA directory as trust anchors."""
    fields: dict[str, Any] = {
        "cert": str(pki.proxy_path),
        "key": str(pki.proxy_path),
        "ca_dir": str(pki.ca_dir),
    }
    fields.update(overrides)
    return Credentials(**fields)


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
def make_ce(tmp_path: Path, pki: PKI) -> Iterator[Callable[..., FakeARex]]:
    started: list[FakeARex] = []

    def factory(**kwargs: Any) -> FakeARex:
        kwargs.setdefault("tls", pki.server_context())
        fake = FakeARex(tmp_path / f"ce{len(started)}", **kwargs).start()
        started.append(fake)
        return fake

    yield factory
    for fake in started:
        fake.stop()


@pytest.fixture
def ce(make_ce: Callable[..., FakeARex]) -> FakeARex:
    return make_ce()


@pytest.fixture
def credentials(pki: PKI) -> Credentials:
    return make_credentials(pki)


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def session(credentials: Credentials, sleeps: list[float]) -> Iterator[Session]:
    with make_session(credentials, sleeps=sleeps) as opened:
        yield opened


@pytest.fixture
def rest(ce: FakeARex, session: Session) -> RESTClient:
    return RESTClient(ce.url, session)
