"""The fake A-REX's vocabulary: job states, constants, and the records tests read and change.

Everything here is plain data - no HTTP, no locking - so the endpoint
modules, the server and a test can all import it without cycles. The public
records (:class:`FakeJob`, :class:`FakeDelegation`, :class:`FakeQueue`,
:class:`CEInfo`, :class:`Request`) are re-exported by
:mod:`xrdarc.testing.arex`; tests may read and change any field between two
requests (the server takes its lock for each request, so a change made while
no request is in flight is seen whole).

The state table is the part to keep exact: it is how A-REX's own state
names (``status`` control file, the "fast" REST state ``GET /jobs?state=``
matches, the nordugrid state of the info document) relate, and the client's
state mapping is tested against it.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from xrdsec.testing.pki import test_key

#: The GLUE2 namespace of the information documents.
GLUE2_NS = "http://schemas.ogf.org/glue/2009/03/spec_2.0_r1"
#: The failure cause A-REX records for a killed job (it maps the job to ``KILLED``).
CANCEL_CAUSE = "Job is canceled by external request"

# REST state -> (GM state as in the ``status`` control file, fast REST state, nordugrid state).
# The fast state is what ``GET /jobs?state=`` matches: A-REX computes it from the GM
# state alone, so every in-LRMS state is RUNNING there. FINISHED, FAILED and KILLED
# share the GM state FINISHED; what tells them apart is the ``failed`` file, which
# is why ``FakeJob.fast_state`` reads the failure text.
_STATES: dict[str, tuple[str, str, str]] = {
    "ACCEPTING": ("ACCEPTED", "ACCEPTING", "ACCEPTED"),
    "ACCEPTED": ("PENDING:ACCEPTED", "ACCEPTED", "PENDING:ACCEPTED"),
    "PREPARING": ("PREPARING", "PREPARING", "PREPARING"),
    "PREPARED": ("PENDING:PREPARING", "PREPARED", "PENDING:PREPARING"),
    "SUBMITTING": ("SUBMIT", "SUBMITTING", "SUBMIT"),
    "QUEUING": ("INLRMS", "RUNNING", "INLRMS:Q"),
    "RUNNING": ("INLRMS", "RUNNING", "INLRMS:R"),
    "HELD": ("INLRMS", "RUNNING", "INLRMS:S"),
    "EXITINGLRMS": ("INLRMS", "RUNNING", "INLRMS:E"),
    "OTHER": ("INLRMS", "RUNNING", "INLRMS:O"),
    "EXECUTED": ("PENDING:INLRMS", "EXECUTED", "INLRMS:EXECUTED"),
    "FINISHING": ("FINISHING", "FINISHING", "FINISHING"),
    "KILLING": ("CANCELING", "KILLING", "KILLING"),
    "FINISHED": ("FINISHED", "FINISHED", "FINISHED"),
    "FAILED": ("FINISHED", "FAILED", "FAILED"),
    "KILLED": ("FINISHED", "KILLED", "KILLED"),
    "WIPED": ("DELETED", "WIPED", "DELETED"),
}

#: Every REST job state A-REX reports.
REST_STATES: tuple[str, ...] = tuple(_STATES)
#: States a job never leaves on its own.
TERMINAL_STATES = frozenset({"FINISHED", "FAILED", "KILLED", "WIPED"})
#: The usual life of a successful job, for ``progression=``. The ``PENDING``
#: states (ACCEPTED, PREPARED, EXECUTED) are left out: a CE shows them mostly
#: when its per-state limits hold jobs back, and a test that wants them names
#: its own progression.
DEFAULT_PROGRESSION = (
    "ACCEPTING",
    "PREPARING",
    "SUBMITTING",
    "QUEUING",
    "RUNNING",
    "FINISHING",
    "FINISHED",
)
#: The names ``jobs/<id>/diagnose/<name>`` accepts, in A-REX's order.
DIAGNOSE_ITEMS = (
    "failed",
    "local",
    "errors",
    "description",
    "diag",
    "comment",
    "status",
    "acl",
    "xml",
    "input",
    "output",
    "input_status",
    "output_status",
    "statistics",
)
#: Operation classes A-REX authorises separately; put names in :attr:`FakeARex.denied`.
OPERATIONS = ("JobInfo", "JobCreate", "JobCancel", "JobDelete", "DataInfo", "DataRead", "DataWrite")

#: Where the fake puts a restarted job, whatever its ``RestartState``: one
#: fixed state keeps restart tests simple, and a client must not assume more.
_RESTART_STATE = "PREPARING"
#: States in which the batch system has had the job: entering one sets
#: ``StartTime`` (once; see ``_base._stamp``).
_STARTED_STATES = frozenset(
    {"QUEUING", "RUNNING", "HELD", "EXITINGLRMS", "OTHER", "EXECUTED", "FINISHING"}
)
#: A finished job's session is kept a week before its ``WorkingAreaEraseTime``,
#: A-REX's default lifetime; :attr:`FakeARex.erase_after` changes it per fake.
_ERASE_AFTER = 7 * 86400.0


def _delegation_key(slot: int) -> rsa.RSAPrivateKey:
    """Frozen test key ``slot`` (:func:`xrdsec.testing.pki.test_key`): no keygen per test."""
    return test_key(slot)


def _iso(stamp: float) -> str:
    """An epoch time as A-REX writes it in GLUE2 and diagnose files: ISO 8601, UTC, ``Z``."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def _new_id(taken: dict[str, Any]) -> str:
    """Twelve lowercase hex digits, as ``rand_uid64().substr(4)`` gives.

    Random rather than sequential so a client cannot pass by assuming an
    order; the loop only matters on a collision, which a test never sees.
    """
    while True:
        candidate = secrets.token_hex(6)
        if candidate not in taken:
            return candidate


def _int(value: str, default: int) -> int:
    """``Arc::stringto``: the default unless the text is a number."""
    try:
        return int(value)
    except ValueError:
        return default


def _unique(items: list[str]) -> list[str]:
    """``items`` without repeats, first occurrence kept (delegation ids, upload names)."""
    return list(dict.fromkeys(items))


# ---------------------------------------------------------------------------
# Public data
# ---------------------------------------------------------------------------


@dataclass
class Request:
    """One request as the fake saw it."""

    method: str
    #: The decoded path, without the query.
    path: str
    #: Query parameters, decoded; a repeated key keeps its first value (as A-REX does).
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes
    #: Who A-REX took the client for: a certificate subject or a token's subject ("" if none).
    identity: str
    #: The request target exactly as sent.
    target: str

    def header(self, name: str) -> str | None:
        """A header, looked up case-insensitively."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


@dataclass
class FakeQueue:
    """A batch queue, published as a GLUE2 ComputingShare (and one more per VO)."""

    name: str
    #: Three days: a default queue publishes one limit, so a client's limit
    #: reading is exercised without a test having to ask for it.
    max_wall_time: int | None = 259200
    max_cpu_time: int | None = None
    min_wall_time: int | None = None
    default_wall_time: int | None = None
    max_total_jobs: int | None = None
    max_running_jobs: int | None = None
    max_waiting_jobs: int | None = None
    serving_state: str = "production"
    #: Each VO adds a share ``<name>_<vo>`` with a MappingPolicy ``vo:<vo>``.
    vos: tuple[str, ...] = ()
    #: More ComputingShare elements, name -> text.
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class CEInfo:
    """What ``GET /info`` publishes; :attr:`FakeARex.info` may instead hold raw XML."""

    name: str = "fake-arex"
    queues: list[FakeQueue] = field(default_factory=lambda: [FakeQueue("main", vos=("atlas",))])
    rtes: list[str] = field(default_factory=lambda: ["ENV/PROXY", "APPS/HEP/ATLAS-21.0.1"])
    health_state: str = "ok"
    serving_state: str = "production"
    quality_level: str = "production"
    lrms: str = "SLURM"
    total_cpus: int = 64


@dataclass(eq=False)
class FakeJob:
    """One job, as the fake's store holds it; tests may read and change any field."""

    id: str
    #: The submitter's identity; nobody else sees the job.
    owner: str
    #: The description as submitted (one sub-job of a multi-job request).
    description: str
    #: ``nordugrid:xrsl`` or ``emies:adl``.
    language: str
    #: The session directory on disk.
    session: Path
    name: str = ""
    queue: str = ""
    stdout: str = ""
    stderr: str = ""
    logdir: str = ""
    #: Restarts left (xRSL ``rerun``, ADL ``Rerun``).
    rerun: int = 0
    #: Delegation ids the job uses (from the description, else the 1.1 parameter).
    delegations: list[str] = field(default_factory=list)
    #: The REST state, as ``action=status`` reports it.
    state: str = "ACCEPTING"
    #: The failure text (``diagnose/failed``, ``Error`` in the info document).
    failure: str = ""
    #: The REST state the job failed in (``RestartState``).
    failed_state: str = ""
    exit_code: int | None = None
    submitted: float = field(default_factory=time.time)
    started: float | None = None
    ended: float | None = None
    #: A kill was asked for: the job becomes KILLED when next polled.
    kill_requested: bool = False
    #: A clean was asked for: the job (and its session) goes with the first
    #: request after it is terminal.
    clean_requested: bool = False
    restarts: int = 0
    #: Session files whose upload completed (``diagnose/input_status``).
    uploads: list[str] = field(default_factory=list)
    #: One line per state change (``diagnose/errors``).
    log: list[str] = field(default_factory=list)
    #: Diagnose files to serve instead of (or besides) the computed ones.
    diagnose: dict[str, str] = field(default_factory=dict)
    #: action -> reason: answer that bulk action (kill, clean) with a per-job 505.
    refuse: dict[str, str] = field(default_factory=dict)
    #: The REST version the job was submitted through.
    version: str = "1.0"
    #: Upload progress per session file: (size, merged written ranges); see
    #: ``_session._chunk``. Private, and left out of ``repr`` as noise.
    _chunks: dict[str, tuple[int, list[tuple[int, int]]]] = field(default_factory=dict, repr=False)

    @property
    def gm_state(self) -> str:
        """The A-REX (grid-manager) state, as the ``status`` control file has it."""
        return _STATES[self.state][0]

    @property
    def fast_state(self) -> str:
        """The REST state computed from the GM state alone (``GET /jobs?state=``)."""
        if self.state not in ("FAILED", "KILLED"):
            return _STATES[self.state][1]
        return "KILLED" if CANCEL_CAUSE in self.failure else "FAILED"

    @property
    def terminal(self) -> bool:
        """The job is in a state it never leaves on its own (:data:`TERMINAL_STATES`).

        Only a test, or ``restart`` of a FAILED job, moves it on; it is
        what a pending ``clean`` waits for.
        """
        return self.state in TERMINAL_STATES


@dataclass(eq=False)
class FakeDelegation:
    """One delegation slot.

    Created by ``action=new`` (or ``renew`` of an unknown id) before any
    certificate exists, so :attr:`chain` is empty until the client's
    ``PUT``; a test can read what the client sent as uploaded.
    """

    id: str
    owner: str
    #: ``x509`` or ``jwt``.
    type: str = "x509"
    #: The last CSR handed out (PEM).
    csr: bytes = b""
    #: The uploaded chain as sent (PEM), the signed proxy first.
    chain_pem: bytes = b""
    #: The uploaded chain, parsed.
    chain: list[x509.Certificate] = field(default_factory=list)
    #: For ``jwt``: the ``X-Token-Delegation`` value, verbatim.
    token: str = ""
    #: How many chains were accepted, and how many renewals asked for.
    uploads: int = 0
    renewals: int = 0
    created: float = field(default_factory=time.time)

    @property
    def certificate(self) -> x509.Certificate | None:
        """The delegated proxy certificate, once one was uploaded."""
        return self.chain[0] if self.chain else None
