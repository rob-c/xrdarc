"""xrdarc.testing.fixtures: the plugin xrdarc's and xrdwms's suites share."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from xrdarc.client import ARCClient
from xrdarc.creds import Credentials
from xrdarc.testing.arex import FakeARex
from xrdarc.testing.fixtures import gate_interop, quiet_session


class _Item:
    """Just enough of a collected test for :func:`gate_interop`."""

    def __init__(self, interop: bool) -> None:
        self.interop = interop
        self.marks: list[str] = []

    def get_closest_marker(self, name: str) -> object | None:
        return object() if name == "interop" and self.interop else None

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.marks.append(marker.name)


def _gate(monkeypatch: pytest.MonkeyPatch, value: str | None) -> list[list[str]]:
    """The marks two tests (one interop, one not) get with the opt-in set to ``value``."""
    if value is None:
        monkeypatch.delenv("SOME_INTEROP", raising=False)
    else:
        monkeypatch.setenv("SOME_INTEROP", value)
    items = [_Item(True), _Item(False)]
    gate_interop(
        cast("list[pytest.Item]", items), variable="SOME_INTEROP", reason="set SOME_INTEROP=1"
    )
    return [item.marks for item in items]


def test_interop_tests_are_ambient_and_skipped_unless_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _gate(monkeypatch, None) == [["ambient", "skip"], []]
    assert _gate(monkeypatch, "yes") == [["ambient", "skip"], []]
    assert _gate(monkeypatch, "1") == [["ambient"], []]


def test_make_arc_defaults_to_a_session_that_never_retries(
    make_arc: Callable[..., ARCClient], ce: FakeARex, credentials: Credentials
) -> None:
    client = make_arc()
    assert client.joblist is not None
    session = quiet_session(credentials)
    assert session.retries == 0
    session.close()
    assert ce.url.startswith("https://")
