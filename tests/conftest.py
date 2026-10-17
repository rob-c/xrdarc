"""Fixtures shared by every test module.

Every test is hermetic: no ambient proxy, token, CA directory, ``client.conf``
or job list from the developer's shell leaks in. A test that wants
credentials asks for ``grid_env`` (an in-process PKI) or builds them.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from xgfalclient import creds as gfal_creds
from xgfalclient.testing.pki import PKI, create_pki

from xrdarc import config, creds

_AMBIENT = (
    "X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY", "X509_CERT_DIR", "X509_VOMS_DIR",
    "X509_VOMSES", "X509_VOMS_FILE", "BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR",
    "TMPDIR", "ARC_LOCATION", "USERPROFILE",
)  # fmt: skip

#: A uid nobody has, so ``/tmp/x509up_u<uid>`` and ``/tmp/bt_u<uid>`` never exist.
UNUSED_UID = 7_654_321


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Interop tests need a real CE and the developer's credentials: opt in only."""
    if os.environ.get("XRDARC_INTEROP") == "1":
        return
    skip = pytest.mark.skip(reason="needs a real ARC CE; set XRDARC_INTEROP=1")
    for item in items:
        if item.get_closest_marker("interop"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _hermetic(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    home = tmp_path_factory.mktemp("home")
    if request.node.get_closest_marker("interop"):
        return home
    for name in _AMBIENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(creds, "_uid", lambda: str(UNUSED_UID))
    monkeypatch.setattr(gfal_creds, "_uid", lambda: UNUSED_UID)
    monkeypatch.setattr(config, "SYSTEM_CONFIG", home / "no-system-client.conf")
    # No grid CA directory of the machine running the tests.
    monkeypatch.setattr(gfal_creds, "find_ca_path", lambda environ=None: None)
    creds._CONTEXTS.clear()
    return home


@pytest.fixture
def home(_hermetic: Path) -> Path:
    return _hermetic


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    return create_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def grid_env(monkeypatch: pytest.MonkeyPatch, pki: PKI) -> Iterator[PKI]:
    for name, value in pki.environment().items():
        monkeypatch.setenv(name, value)
    yield pki


@pytest.fixture
def chdir(tmp_path: Path) -> Iterator[Path]:
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(old)
