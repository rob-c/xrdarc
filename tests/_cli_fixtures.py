"""Fixtures for the command-line tests; load with ``pytest_plugins = ["_arex", "_cli_fixtures"]``.

* ``restore_logging`` - puts the ``xrdarc`` logger back as it was (``-d`` and
  ``-v`` change its level and add a handler);
* ``jobs_dat`` - the job list every ``xrdarc`` call below uses;
* ``xrdarc(*argv)`` - ``xrdarc <command> -j <jobs_dat> <args...>`` with the
  session PKI's proxy and CA directory in the environment: ``(code, out, err)``;
* ``xrdarc_json(*argv)`` - the same with ``--json``: ``(code, report)``;
* ``listed(*urls, **fields)`` - put jobs into ``jobs_dat`` as ``Job`` s.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from xgfalclient.testing.pki import PKI

from _client_helpers import run, run_json
from xrdarc.joblist import Job, JobList


@pytest.fixture
def restore_logging() -> Iterator[None]:
    logger = logging.getLogger("xrdarc")
    handlers, level = list(logger.handlers), logger.level
    yield
    logger.handlers[:] = handlers
    logger.setLevel(level)


@pytest.fixture
def jobs_dat(tmp_path: Path) -> Path:
    return tmp_path / "jobs.dat"


def _with_joblist(argv: tuple[str, ...], jobs_dat: Path) -> list[str]:
    return [argv[0], "-j", str(jobs_dat), *argv[1:]]


@pytest.fixture
def xrdarc(
    capsys: pytest.CaptureFixture[str], grid_env: PKI, jobs_dat: Path, restore_logging: None
) -> Callable[..., tuple[int, str, str]]:
    def call(*argv: str) -> tuple[int, str, str]:
        return run(capsys, *_with_joblist(argv, jobs_dat))

    return call


@pytest.fixture
def xrdarc_json(
    capsys: pytest.CaptureFixture[str], grid_env: PKI, jobs_dat: Path, restore_logging: None
) -> Callable[..., tuple[int, dict[str, Any]]]:
    def call(*argv: str) -> tuple[int, dict[str, Any]]:
        return run_json(capsys, *_with_joblist(argv, jobs_dat))

    return call


@pytest.fixture
def listed(jobs_dat: Path) -> Callable[..., list[Job]]:
    def put(*urls: str, **fields: Any) -> list[Job]:
        jobs = [Job.from_url(url, **fields) for url in urls]
        JobList(jobs_dat).write(jobs)
        return jobs

    return put
