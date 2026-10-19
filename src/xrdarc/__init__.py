"""xrdarc: a pure Python 3 client for NorduGrid ARC computing elements.

Submit, monitor, retrieve and manage jobs on ARC CEs over A-REX's REST
interface, with the grid's X.509/VOMS proxies or WLCG bearer tokens, and the
job list shared with ARC's own command-line tools::

    import xrdarc

    with xrdarc.ARCClient() as arc:
        [sub] = arc.submit("ce.example.org", '&(executable="/bin/hostname")(stdout="out")')
        [done] = arc.wait([sub.job])
        arc.get([done.job], "results")

Where to start reading: :mod:`xrdarc.client` (the operations), which drives
:mod:`xrdarc.rest` (one method per A-REX endpoint) over
:mod:`xrdarc.transport` (HTTPS), with :mod:`xrdarc.creds` deciding what to
present and :mod:`xrdarc.joblist` remembering what was submitted. The
command line (:mod:`xrdarc.cli`) is a thin layer over :class:`ARCClient`.
No TLS context is built and no CE is contacted until a client makes its
first request.
"""

from __future__ import annotations

from ._version import __version__
from .client import ARCClient, Outcome, Submission
from .config import UserConfig, load_config
from .creds import Auth, Credentials, discover
from .errors import (
    ARCError,
    CredentialError,
    DescriptionError,
    HTTPError,
    JobNotFoundError,
    NotAllowedError,
)
from .info import CEInfo, JobRecord, Queue
from .joblist import Job, JobList
from .rest import RESTClient
from .states import JobState
from .transport import Session

__all__ = [
    "ARCClient",
    "ARCError",
    "Auth",
    "CEInfo",
    "CredentialError",
    "Credentials",
    "DescriptionError",
    "HTTPError",
    "Job",
    "JobList",
    "JobNotFoundError",
    "JobRecord",
    "JobState",
    "NotAllowedError",
    "Outcome",
    "Queue",
    "RESTClient",
    "Session",
    "Submission",
    "UserConfig",
    "__version__",
    "discover",
    "load_config",
]
