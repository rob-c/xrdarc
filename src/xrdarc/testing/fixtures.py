"""A pytest plugin for suites that drive xrdarc against the in-process fake CE.

xrdarc's own suite and xrdwms's (whose ARC backend is built on
:class:`~xrdarc.ARCClient`) need the same few things: a started
:class:`~xrdarc.testing.arex.FakeARex` over TLS, credentials the fake
accepts, ARC clients with a job list of their own, and the rule that tests
marked ``interop`` - which need a real CE - run only when asked for. Each
suite had its own copy; this module is the one both load::

    pytest_plugins = ["xrdsec.testing.fixtures", "xrdarc.testing.fixtures"]

It is not loaded automatically (no ``pytest11`` entry point), so installing
xrdarc changes nobody else's test runs. It needs pytest, and the ``pki``
and ``tmp_path`` fixtures - the former from :mod:`xrdsec.testing.fixtures`,
which must be loaded too.

Fixtures:

* ``make_ce(**kwargs)`` - a started fake CE over TLS (the PKI's host
  certificate), with any :class:`FakeARex` keyword; every one is stopped
  after the test;
* ``ce`` - one such CE;
* ``credentials`` - :func:`make_credentials` for the PKI: its proxy as the
  X.509 credential, its CA directory as trust anchors;
* ``arc_session_factory`` - how ``make_arc`` builds each client's session:
  by default no retries and no sleeping (:func:`quiet_session`); a suite
  that wants to see its backoff overrides this fixture;
* ``make_arc(**kwargs)`` - :class:`~xrdarc.ARCClient` objects for the fake
  CE with a job list in ``tmp_path`` (keywords as ``ARCClient``'s, plus
  ``credentials=``), each closed after the test.

And :func:`gate_interop`, which a suite's ``pytest_collection_modifyitems``
calls with its own opt-in variable. A conftest imports that function as well
as loading the module as a plugin; the module has no assertions of its own
(PYTEST_DONT_REWRITE), so pytest need not rewrite it and does not warn that it
was imported first.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from xrdsec.testing.pki import PKI

from xrdarc.client import ARCClient
from xrdarc.config import UserConfig
from xrdarc.creds import Credentials
from xrdarc.testing.arex import FakeARex
from xrdarc.transport import Session

__all__ = [
    "arc_session_factory",
    "ce",
    "credentials",
    "gate_interop",
    "make_arc",
    "make_ce",
    "make_credentials",
    "quiet_session",
]

#: Builds the session of one client from its credentials.
SessionFactory = Callable[[Credentials], Session]


def make_credentials(pki: PKI, **overrides: Any) -> Credentials:
    """The PKI's proxy as the X.509 credential and its CA directory as trust anchors.

    ``overrides`` replace any field (a token, another CA directory,
    ``verify=False``), for tests of what a different credential does.
    """
    fields: dict[str, Any] = {
        "cert": str(pki.proxy_path),
        "key": str(pki.proxy_path),
        "ca_dir": str(pki.ca_dir),
    }
    fields.update(overrides)
    return Credentials(**fields)


def quiet_session(credentials: Credentials) -> Session:
    """A session that never retries and never sleeps: a failure shows at once."""
    return Session(credentials, retries=0, sleep=lambda _seconds: None)


def gate_interop(items: Sequence[pytest.Item], *, variable: str, reason: str) -> None:
    """Mark the ``interop`` tests among ``items`` ``ambient``, and skip them unless opted in.

    An interop test talks to a real CE with the developer's own credentials,
    so the hermetic environment of :mod:`xrdsec.testing.fixtures` must leave
    it alone (``ambient``), and it runs only when ``variable`` is ``"1"``;
    otherwise it is skipped for ``reason``, which should name the variable.
    """
    interop = [item for item in items if item.get_closest_marker("interop")]
    for item in interop:
        item.add_marker(pytest.mark.ambient)
    if os.environ.get(variable) != "1":
        skip = pytest.mark.skip(reason=reason)
        for item in interop:
            item.add_marker(skip)


@pytest.fixture
def make_ce(tmp_path: Path, pki: PKI) -> Iterator[Callable[..., FakeARex]]:
    """Start fake CEs on demand (each in its own directory); stop them after the test."""
    started: list[FakeARex] = []

    def factory(**kwargs: Any) -> FakeARex:
        """One more started CE; ``kwargs`` are :class:`FakeARex`'s."""
        kwargs.setdefault("tls", pki.server_context())
        fake = FakeARex(tmp_path / f"ce{len(started)}", **kwargs).start()
        started.append(fake)
        return fake

    yield factory
    for fake in started:
        fake.stop()


@pytest.fixture
def ce(make_ce: Callable[..., FakeARex]) -> FakeARex:
    """A started fake CE with the default behaviour."""
    return make_ce()


@pytest.fixture
def credentials(pki: PKI) -> Credentials:
    """The credentials the fake CE accepts: :func:`make_credentials` for the PKI."""
    return make_credentials(pki)


@pytest.fixture
def arc_session_factory() -> SessionFactory:
    """How ``make_arc`` builds a client's session: :func:`quiet_session` unless overridden."""
    return quiet_session


@pytest.fixture
def make_arc(
    tmp_path: Path, credentials: Credentials, arc_session_factory: SessionFactory
) -> Iterator[Callable[..., ARCClient]]:
    """Build ARC clients for the fake CE, with a job list in ``tmp_path``; close them after."""
    made: list[ARCClient] = []

    def factory(**kwargs: Any) -> ARCClient:
        """One more client; ``credentials=`` and ``ARCClient``'s own keywords are honoured."""
        creds = kwargs.pop("credentials", credentials)
        kwargs.setdefault("config", UserConfig(joblist=tmp_path / "jobs.dat"))
        kwargs.setdefault("session", arc_session_factory(creds))
        client = ARCClient(credentials=creds, **kwargs)
        made.append(client)
        return client

    yield factory
    for client in made:
        client.close()
