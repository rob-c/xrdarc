"""Fixtures shared by every test module.

Every test is hermetic: no ambient proxy, token, CA directory, ``client.conf``
or job list from the developer's shell leaks in. A test that wants
credentials asks for ``grid_env`` (an in-process PKI) or builds them.

The credential side is :mod:`xrdsec.testing.fixtures`, the plugin every
suite on the stack loads: the environment is cleared, ``HOME`` is a fresh
directory, :data:`xrdsec.credentials.TMP_DIR` - the ``/tmp`` of
``/tmp/x509up_u<uid>`` and ``/tmp/bt_u<uid>`` - points at an empty
directory, so the developer's real proxy and token are never found, and
:data:`xrdsec.credentials.GRID_SECURITY_DIRS` replaces ``/etc/grid-security``
(and Homebrew's) with a directory of the test's own, so "no CA directory
anywhere" means the same on a grid node, a laptop and CI, and the VOMS code
never reads the host's ``vomsdir``. It also provides the ``home``,
``tmp_dir``, ``grid_security``, ``pki`` and ``grid_env`` fixtures.
:func:`pytest_xrdsec_hermetic` adds xrdarc's own inputs; interop tests are
marked ``ambient`` and keep the developer's real environment.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from xrdarc import config
from xrdarc.testing.fixtures import gate_interop

if TYPE_CHECKING:
    from xrdsec.testing.fixtures import Hermetic

# xrdarc.testing.fixtures: the fake CE, its credentials, ``make_arc`` and the
# interop gate, shared with xrdwms's suite.
pytest_plugins = ["xrdsec.testing.fixtures", "xrdarc.testing.fixtures"]

#: xrdarc's own inputs, cleared on top of the credential variables the
#: plugin clears: VOMS client settings that are not ``X509_*``, ``$TMPDIR``
#: (an ARC proxy location), the ARC installation, Windows' home, and the
#: switches with which Python 3.14 colours argparse help (CI sets FORCE_COLOR).
_OWN = (
    "VOMS_USERCONF",
    "TMPDIR",
    "ARC_LOCATION",
    "USERPROFILE",
    "FORCE_COLOR",
    "PYTHON_COLORS",
)

#: The name of this user's default proxy file (in the hermetic ``TMP_DIR``).
PROXY_NAME = f"x509up_u{os.geteuid()}"
#: The name of this user's last-resort token file (in the hermetic ``TMP_DIR``).
TOKEN_NAME = f"bt_u{os.geteuid()}"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Interop tests need a real CE and the developer's credentials: opt in only.

    They are ``ambient`` (the hermetic environment leaves them alone), and
    skipped unless ``XRDARC_INTEROP=1``.
    """
    gate_interop(
        items, variable="XRDARC_INTEROP", reason="needs a real ARC CE; set XRDARC_INTEROP=1"
    )


def pytest_xrdsec_hermetic(hermetic: Hermetic) -> None:
    """xrdarc's own inputs, on top of xrdsec's: its variables, and no system ``client.conf``."""
    hermetic.unset(*_OWN)
    hermetic.monkeypatch.setattr(config, "SYSTEM_CONFIG", hermetic.home / "no-system-client.conf")


@pytest.fixture
def chdir(tmp_path: Path) -> Iterator[Path]:
    """Run the test from inside ``tmp_path``."""
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(old)
