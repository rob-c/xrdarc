"""xrdarc: a pure Python 3 client for NorduGrid ARC computing elements.

Submit, monitor, retrieve and manage jobs on ARC CEs over A-REX's REST
interface, with the grid's X.509/VOMS proxies or WLCG bearer tokens, and the
job list shared with ARC's own command-line tools::

    import xrdarc

    with xrdarc.ARCClient() as arc:
        [sub] = arc.submit("ce.example.org", '&(executable="/bin/hostname")(stdout="out")')
        [done] = arc.wait([sub.job])
        arc.get([done.job], "results")
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
    "__version__",
    # the client
    "ARCClient",
    "Outcome",
    "Submission",
    "RESTClient",
    "Session",
    # jobs and CEs
    "Job",
    "JobList",
    "JobRecord",
    "JobState",
    "CEInfo",
    "Queue",
    # configuration and credentials
    "UserConfig",
    "load_config",
    "Auth",
    "Credentials",
    "discover",
    # errors
    "ARCError",
    "CredentialError",
    "DescriptionError",
    "HTTPError",
    "JobNotFoundError",
    "NotAllowedError",
]
