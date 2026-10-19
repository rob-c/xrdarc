"""The client's results and plans: what an operation returns, and what it was asked to do.

:class:`Submission` and :class:`Outcome` are public (re-exported by
:mod:`xrdarc.client`): one per description submitted, one per job acted on.
The ``_*Plan`` values carry a call's options down through the helpers that
do the work, so no helper needs a long parameter list, and each is frozen -
a helper cannot change what the caller asked for half-way through.
"""

from __future__ import annotations

import errno
import threading
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from xrdcore.log import get_logger

from ..joblist import Job
from ..rest import RESTClient
from ..xrsl import PreparedJob

_log = get_logger("xrdarc")

#: Told ``(file name, bytes)`` after each upload or download, for a progress line.
Progress = Callable[[str, int], None]

#: A delegating credential with less than this many seconds left is warned
#: about: the delegated proxy cannot outlive it, so a job running longer
#: fails when it tries to stage its outputs out.
LOW_LIFETIME = 3600.0

#: The longest extra pause, in seconds, ``wait`` adds after polls that hit
#: transient trouble (a larger ``interval`` raises it to the interval).
POLL_BACKOFF_CAP = 600.0

#: Errors of a non-HTTP ``ARCError`` that say "the network, not the request":
#: worth asking again. Anything else (a TLS handshake refused because the
#: proxy expired, an answer that is not JSON) would fail the same way forever.
_TRANSIENT_ERRNOS = frozenset(
    {
        errno.ECONNABORTED,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ETIMEDOUT,
        errno.EAGAIN,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
    }
)


@dataclass(frozen=True, slots=True)
class Submission:
    """One description's fate: ``job`` is set when the CE accepted it and its inputs went up."""

    prepared: PreparedJob
    job: Job | None
    status: int
    reason: str

    @property
    def ok(self) -> bool:
        """Accepted by the CE *and* every input uploaded: the job will run."""
        return self.job is not None


#: Told each job's final ``Submission`` as soon as it is known, with the
#: position of its description in ``submit_all``'s list.
Report = Callable[[int, Submission], None]


@dataclass(frozen=True, slots=True)
class Outcome:
    """What one bulk operation did to one job.

    ``transient`` marks a failure worth retrying - the CE could not be
    reached, answered 5xx, or left the job out of its answer - as opposed
    to a definite answer such as "no such job". ``wait`` keeps polling a
    job whose last outcome was transient.
    """

    #: The job, updated with the CE's latest word when the operation asked for it.
    job: Job
    ok: bool
    #: Why not, in the CE's words (or the client's); empty on success.
    reason: str = ""
    #: Where ``get`` put the job's results.
    path: Path | None = None
    #: The CE's per-job code (0 when the whole request failed).
    status: int = 0
    transient: bool = False


@dataclass(frozen=True, slots=True)
class _SubmitPlan:
    """What one ``submit``/``submit_all`` call was asked to do, for every description in it."""

    queue: str | None
    delegate: bool
    progress: Progress | None
    report: Report | None


@dataclass(frozen=True, slots=True)
class _Batch:
    """A submission in flight on one CE: its REST client and the one delegation its jobs share."""

    client: RESTClient
    delegation_id: str | None
    plan: _SubmitPlan


@dataclass(frozen=True, slots=True)
class _FetchPlan:
    """How ``get``/``retrieve`` download each job.

    ``stop`` is set when ``get`` is interrupted: a download in progress
    notices it before its next file and gives up, so Ctrl-C does not wait
    for whole session directories to finish.
    """

    directory: Path
    use_names: bool = False
    force: bool = False
    diagnose: bool = False
    progress: Progress | None = None
    stop: threading.Event = field(default_factory=threading.Event)


def _group(jobs: Iterable[Job]) -> dict[str, list[Job]]:
    """Jobs by CE URL, in first-seen order: one bulk request per CE."""
    grouped: dict[str, list[Job]] = defaultdict(list)
    for job in jobs:
        grouped[job.ce].append(job)
    return grouped
