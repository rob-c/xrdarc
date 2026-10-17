"""A fake ARC 7 A-REX REST service, in process, for tests.

:class:`FakeARex` is a threaded HTTP(S) server that answers the A-REX REST
interface (``<base>/rest``, ``<base>/rest/<version>/{info,jobs,delegations}``)
the way ``services/a-rex/rest/rest.cpp`` does, down to its quirks::

    with FakeARex(tmp_path, tls=pki.server_context()) as ce:
        ce.url                                   # https://127.0.0.1:<port>/arex
        ...                                      # drive a client against it
        ce.set_state(job_id, "FINISHED", exit_code=0)
        ce.requests[-1].path                     # what the client sent

What it reproduces:

* ``Accept`` negotiation (JSON, XML, else an HTML table) and A-REX's
  XML-to-JSON rendering: the root element dropped, every value a string,
  per-endpoint forced arrays, attributes of leaf elements dropped;
  ``legacy_json=True`` renders like an ARC 6 server instead (no forced
  arrays, an empty list as an empty body);
* errors as A-REX reports them, in the HTTP reason phrase with an empty body;
* bulk job actions (``POST jobs?action=...``) with the exact
  ``Content-Type`` rule and per-job status codes, job submission of ADL,
  single and multi xRSL (with the 1.1 ``queue``, ``delegation_id`` and
  ``instances`` parameters), job states that tests drive or that progress
  on each poll, asynchronous kill, clean and restart;
* the session directory (listing, ranged GET, ranged PUT with upload
  completion tracking, DELETE, PROPFIND) and the diagnose files;
* X.509 delegation (a CSR with an empty subject, the signed chain checked
  on upload) and 1.1 token delegation;
* authentication by client certificate (the end-entity subject of a proxy
  chain) or by bearer token, and fault injection (:meth:`FakeARex.fault`).

Every request is recorded in :attr:`FakeARex.requests`.

Where it knowingly differs from A-REX:

* descriptions are not really parsed: a few xRSL attributes are read with a
  regular expression and ADL with ElementTree, a ``+`` multi-job request is
  split on its top-level parentheses, and anything starting with ``&`` is a
  valid xRSL job;
* malformed client JSON yields no job ids at all (A-REX keeps what it
  parsed before the error); non-string scalars do lose their first
  character, as on A-REX;
* the ``status`` and ``info`` actions see a state change at once (A-REX's
  infoprovider can lag a cycle); kill and clean are applied when the job is
  next polled or the next request arrives, respectively;
* every request needs a credential, ``GET /rest`` and ``/info`` included;
* all delegations share one key; a job's delegations are the ids its
  description names (else the 1.1 ``delegation_id``), whether or not they exist.
"""

from __future__ import annotations

import contextlib
import http.client
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import ssl
import stat
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from xgfalclient.testing.pki import test_key
from xrdclient.crypto.rsa import private_key_pem

__all__ = [
    "CANCEL_CAUSE",
    "CEInfo",
    "DEFAULT_PROGRESSION",
    "DIAGNOSE_ITEMS",
    "FakeARex",
    "FakeDelegation",
    "FakeJob",
    "FakeQueue",
    "Fault",
    "GLUE2_NS",
    "OPERATIONS",
    "REST_STATES",
    "Request",
    "TERMINAL_STATES",
]

#: The GLUE2 namespace of the information documents.
GLUE2_NS = "http://schemas.ogf.org/glue/2009/03/spec_2.0_r1"
#: The failure cause A-REX records for a killed job (it maps the job to ``KILLED``).
CANCEL_CAUSE = "Job is canceled by external request"

# REST state -> (GM state as in the ``status`` control file, fast REST state, nordugrid state).
# The fast state is what ``GET /jobs?state=`` matches: A-REX computes it from the GM
# state alone, so every in-LRMS state is RUNNING there.
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
#: The usual life of a successful job, for ``progression=``.
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

_RESTART_STATE = "PREPARING"
_STARTED_STATES = frozenset(
    {"QUEUING", "RUNNING", "HELD", "EXITINGLRMS", "OTHER", "EXECUTED", "FINISHING"}
)
_ERASE_AFTER = 7 * 86400.0

_DAV_NS = "DAV:"
_FORMATS = {
    "application/json": ("json", "application/json"),
    "text/xml": ("xml", "application/xml"),
    "application/xml": ("xml", "application/xml"),
    "text/html": ("html", "text/html"),
}
_SHORT_NAMES = {
    "commonName": "CN",
    "countryName": "C",
    "domainComponent": "DC",
    "localityName": "L",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "stateOrProvinceName": "ST",
}
_PROXY_CN = re.compile(r"\d+|proxy|limited proxy")
_CONTENT_RANGE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)")
_RANGE = re.compile(r"bytes=(\d*)-(\d*)")
_DELEGATION_IDS = re.compile(r"delegationid\s*=\s*\"?([^\"\s()]+)", re.IGNORECASE)

_CS = "Domains/AdminDomain/Services/ComputingService"
_CE = _CS + "/ComputingEndpoint"
_CA = _CE + "/ComputingActivities/ComputingActivity"
_SHARE = _CS + "/ComputingShare"
_MANAGER = _CS + "/ComputingManager"
# The main containers of rest.cpp's ~190 forced-array paths for /info.
_INFO_ARRAYS = (
    "Domains/AdminDomain",
    "Domains/AdminDomain/Services/Service",
    "Domains/AdminDomain/Services/StorageService",
    "Domains/AdminDomain/Services/Contact",
    "Domains/AdminDomain/Services/OtherInfo",
    "Domains/UserDomain",
    _CS,
    _CS + "/Capability",
    _CS + "/StatusInfo",
    _CS + "/Contact",
    _CS + "/OtherInfo",
    _CS + "/Extensions/Extension",
    _CS + "/Associations/ServiceID",
    _CE,
    _CE + "/Capability",
    _CE + "/InterfaceVersion",
    _CE + "/InterfaceExtension",
    _CE + "/JobDescription",
    _CE + "/Semantics",
    _CE + "/SupportedProfile",
    _CE + "/TrustedCA",
    _CE + "/OtherInfo",
    _CE + "/AccessPolicy",
    _CE + "/AccessPolicy/Rule",
    _CE + "/Associations/ComputingShareID",
    _CA,
    _CA + "/State",
    _CA + "/RestartState",
    _CA + "/Error",
    _CA + "/ExecutionNode",
    _CA + "/OtherMessages",
    _CA + "/RequestedApplicationEnvironment",
    _SHARE,
    _SHARE + "/MappingPolicy",
    _SHARE + "/MappingPolicy/Rule",
    _SHARE + "/OtherInfo",
    _SHARE + "/Tag",
    _SHARE + "/Associations/ComputingEndpointID",
    _SHARE + "/Associations/ExecutionEnvironmentID",
    _MANAGER,
    _MANAGER + "/OtherInfo",
    _MANAGER + "/Benchmark",
    _MANAGER + "/ApplicationEnvironments/ApplicationEnvironment",
    _MANAGER + "/ApplicationEnvironments/ApplicationEnvironment/OtherInfo",
    _MANAGER + "/ExecutionEnvironments/ExecutionEnvironment",
    _MANAGER + "/ExecutionEnvironments/ExecutionEnvironment/Benchmark",
)

_KEYS: dict[int, rsa.RSAPrivateKey] = {}


def _delegation_key(slot: int) -> rsa.RSAPrivateKey:
    """Frozen test key ``slot`` as a ``cryptography`` key, converted once."""
    found = _KEYS.get(slot)
    if found is None:
        loaded = serialization.load_pem_private_key(private_key_pem(test_key(slot)), None)
        assert isinstance(loaded, rsa.RSAPrivateKey)
        found = _KEYS[slot] = loaded
    return found


def _iso(stamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def _new_id(taken: dict[str, Any]) -> str:
    """Twelve lowercase hex digits, as ``rand_uid64().substr(4)`` gives."""
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
    return list(dict.fromkeys(items))


# ---------------------------------------------------------------------------
# A small XML tree, rendered as A-REX renders its responses
# ---------------------------------------------------------------------------


@dataclass
class _Node:
    """An element: what A-REX builds before rendering it as JSON, XML or HTML."""

    name: str
    text: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[_Node] = field(default_factory=list)
    #: A default namespace declaration; XML shows it, JSON (like libxml2) does not.
    xmlns: str = ""

    def add(self, name: str, text: str = "", attrs: dict[str, str] | None = None) -> _Node:
        child = _Node(name, text, dict(attrs or {}))
        self.children.append(child)
        return child

    def first(self, name: str) -> _Node | None:
        return next((child for child in self.children if child.name == name), None)


def _jstr(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def _render_json(node: _Node, paths: tuple[str, ...], show_empty: bool, depth: int = 0) -> str:
    """A port of ``RenderToJson`` (rest.cpp): ``paths`` are the forced arrays below ``node``."""
    here = [path for path in paths if "/" not in path]
    if not node.children and not here:
        # A leaf: its attributes are lost, and an empty root is no body at all.
        return _jstr(node.text) if depth or node.text else ""
    members = [
        f"{_jstr(name)}:{_json_member(node, name, count, paths, show_empty, depth)}"
        for name, count in _json_counts(node, here, show_empty).items()
    ]
    if node.attrs:
        pairs = ",".join(f"{_jstr(key)}:{_jstr(value)}" for key, value in node.attrs.items())
        members.append(f'"_attributes":{{{pairs}}}')
    return "{" + ",".join(members) + "}"


def _json_counts(node: _Node, forced: list[str], show_empty: bool) -> dict[str, int]:
    """Children by name, in order; a forced array counts as two more (so it is a list)."""
    counts: dict[str, int] = {}
    for child in node.children:
        counts[child.name] = counts.get(child.name, 0) + 1
    for name in forced:
        if name in counts:
            counts[name] += 2
        elif show_empty:
            counts[name] = 2
    return counts


def _json_member(
    node: _Node, name: str, count: int, paths: tuple[str, ...], show_empty: bool, depth: int
) -> str:
    group = [child for child in node.children if child.name == name]
    if not group:
        return "[]"  # a forced array with nothing in it
    inner = tuple(path[len(name) + 1 :] for path in paths if path.startswith(name + "/"))
    items = [_render_json(child, inner, show_empty, depth + 1) for child in group]
    return items[0] if count == 1 else "[" + ",".join(items) + "]"


def _render_xml(node: _Node) -> str:
    attrs = "".join(f" {key}={quoteattr(value)}" for key, value in node.attrs.items())
    if node.xmlns:
        attrs = f" xmlns={quoteattr(node.xmlns)}" + attrs
    inner = escape(node.text) + "".join(_render_xml(child) for child in node.children)
    if not inner:
        return f"<{node.name}{attrs}/>"
    return f"<{node.name}{attrs}>{inner}</{node.name}>"


def _render_html(node: _Node, depth: int = 0) -> str:
    """``RenderToHtml``: what a client that forgets ``Accept`` gets."""
    if node.children:
        rows = "".join(
            f"<tr><td>{child.name}</td><td>{_render_html(child, depth + 1)}</td></tr>"
            for child in node.children
        )
        body = f'<table border="1">{rows}</table>'
    else:
        body = escape(node.text)
    if depth:
        return body
    return f"<HTML><HEAD>{node.name}</HEAD><BODY>{body}</BODY></HTML>"


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _from_element(element: ET.Element, namespace: str = "") -> _Node:
    own = element.tag[1:].partition("}")[0] if element.tag.startswith("{") else ""
    node = _Node(
        _local(element.tag),
        element.text or "",
        {_local(key): value for key, value in element.attrib.items()},
        xmlns=own if own != namespace else "",
    )
    node.children = [_from_element(child, own) for child in element]
    return node


def _parse_xml(data: bytes | str) -> _Node | None:
    try:
        return _from_element(ET.fromstring(data))
    except ET.ParseError:
        return None


# ---------------------------------------------------------------------------
# Client JSON, parsed as ParseFromJson parses it
# ---------------------------------------------------------------------------


def _json_scalar(value: object) -> str:
    """A string as is; anything else loses its first character (the rest.cpp bug)."""
    return value if isinstance(value, str) else json.dumps(value)[1:]


def _json_into(parent: _Node, name: str, value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _json_into(parent, name, item)
    elif isinstance(value, dict):
        child = parent.add(name)
        for key, item in value.items():
            _json_into(child, key, item)
    else:
        parent.add(name, _json_scalar(value))


def _json_tree(body: bytes) -> _Node:
    root = _Node("jobs")
    try:
        document = json.loads(body)
    except ValueError:
        return root  # rest.cpp keeps what it parsed; this keeps nothing
    if isinstance(document, dict):
        for key, value in document.items():
            _json_into(root, key, value)
    return root


def _job_ids(content_type: str | None, body: bytes) -> list[str]:
    """``ParseJobIds``: only exactly ``application/json``, ``application/xml`` or none."""
    if content_type == "application/json":
        root: _Node | None = _json_tree(body)
    elif content_type in (None, "", "application/xml"):
        root = _parse_xml(body)
    else:
        return []
    ids = []
    for job in root.children if root is not None else []:
        found = job.first("id") if job.name == "job" else None
        if found is not None and found.text:
            ids.append(found.text)
    return ids


# ---------------------------------------------------------------------------
# Job descriptions
# ---------------------------------------------------------------------------


@dataclass
class _Description:
    text: str
    language: str  # "nordugrid:xrsl" or "emies:adl"


@dataclass
class _Fields:
    """What the fake reads from a job description."""

    name: str = ""
    queue: str = ""
    stdout: str = ""
    stderr: str = ""
    logdir: str = ""
    rerun: int = 0
    delegations: list[str] = field(default_factory=list)


def _xrsl(text: str, attribute: str) -> str:
    """The first value of ``(attribute = value)``, quoted or not; ``""`` if absent."""
    pattern = (
        r"\(\s*" + attribute + r"\s*=\s*"
        r"(?:\"((?:[^\"]|\"\")*)\"|'((?:[^']|'')*)'|([^\s()\"']+))"
    )
    match = re.search(pattern, text, re.IGNORECASE)
    if match is None:
        return ""
    double, single, bare = match.groups()
    if double is not None:
        return str(double).replace('""', '"')
    if single is not None:
        return str(single).replace("''", "'")
    return str(bare)


def _xrsl_fields(text: str) -> _Fields:
    return _Fields(
        name=_xrsl(text, "jobname"),
        queue=_xrsl(text, "queue"),
        stdout=_xrsl(text, "stdout"),
        stderr=_xrsl(text, "stderr"),
        logdir=_xrsl(text, "gmlog"),
        rerun=_int(_xrsl(text, "rerun"), 0),
        delegations=_unique(_DELEGATION_IDS.findall(text)),
    )


def _adl_fields(text: str) -> _Fields | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    values: dict[str, str] = {}
    delegations: list[str] = []
    for element in root.iter():
        name, value = _local(element.tag), (element.text or "").strip()
        if name == "DelegationID":
            delegations.append(value)
        elif name == "ActivityIdentification":
            names = ((c.text or "").strip() for c in element if _local(c.tag) == "Name")
            values["JobName"] = next(names, "")
        values.setdefault(name, value)
    return _Fields(
        name=values.get("JobName", ""),
        queue=values.get("QueueName", ""),
        stdout=values.get("Output", ""),
        stderr=values.get("Error", ""),
        logdir=values.get("LoggingDirectory", ""),
        rerun=_int(values.get("Rerun", ""), 0),
        delegations=_unique([d for d in delegations if d]),
    )


def _top_level_groups(text: str) -> list[str]:
    """The contents of each top-level ``( ... )`` group, honouring double quotes."""
    groups: list[str] = []
    depth = start = 0
    quoted = False
    for index, char in enumerate(text):
        if char == '"':
            quoted = not quoted
        elif quoted:
            continue
        elif char == "(":
            depth += 1
            start = index + 1 if depth == 1 else start
        elif char == ")":
            depth -= 1
            if depth == 0:
                groups.append(text[start:index].strip())
    return groups


def _split_adl(text: str) -> tuple[list[_Description], bool]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [_Description(text, "emies:adl")], False  # fails per job, as A-REX's does
    if _local(root.tag) != "ActivityDescriptions":
        return [_Description(text, "emies:adl")], False
    return [_Description(ET.tostring(c, encoding="unicode"), "emies:adl") for c in root], True


def _split_xrsl(text: str) -> tuple[list[_Description], bool]:
    return [_Description(text, "nordugrid:xrsl")], False


def _split_multi_xrsl(text: str) -> tuple[list[_Description], bool]:
    groups = _top_level_groups(text.lstrip()[1:])
    return [_Description(group, "nordugrid:xrsl") for group in groups], True


_SPLITTERS: dict[str, Callable[[str], tuple[list[_Description], bool]]] = {
    "<": _split_adl,
    "&": _split_xrsl,
    "+": _split_multi_xrsl,
}


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
class Fault:
    """What to answer instead of the real thing, for the next ``times`` matching requests.

    ``method`` (``None`` for any) must equal the request method and
    ``path_pattern`` (``None`` for any) must be found, with :func:`re.search`,
    in the decoded request target (path and query).
    """

    method: str | None = None
    path_pattern: str | None = None
    #: The status to answer; ``None`` lets the request through (after ``delay``).
    status: int | None = 500
    #: The reason phrase; empty for the standard one.
    reason: str = ""
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    times: int = 1
    #: Hang up without answering.
    drop: bool = False
    #: Seconds to wait first.
    delay: float = 0.0

    def matches(self, method: str, target: str) -> bool:
        return (self.method is None or self.method == method) and (
            self.path_pattern is None or re.search(self.path_pattern, target) is not None
        )


@dataclass
class FakeQueue:
    """A batch queue, published as a GLUE2 ComputingShare (and one more per VO)."""

    name: str
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
        return self.state in TERMINAL_STATES


@dataclass(eq=False)
class FakeDelegation:
    """One delegation slot."""

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


# ---------------------------------------------------------------------------
# Request plumbing
# ---------------------------------------------------------------------------


@dataclass
class _Response:
    status: int
    reason: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


def _fault(status: int, reason: str, detail: str = "") -> _Response:
    """``HTTPFault``: the text in the reason phrase, a body only with a detail."""
    if detail:
        return _Response(status, reason, detail.encode(), {"Content-Type": "text/plain"})
    return _Response(status, reason)


@dataclass
class _Ctx:
    method: str
    #: The decoded request path.
    path: str
    #: What is left of the path to route on.
    rest: str
    query: dict[str, str]
    headers: Message
    body: bytes
    identity: str
    version: str = ""

    def token(self) -> str:
        """``GetPathToken``: take the next path segment off :attr:`rest`."""
        token, _, remainder = self.rest.lstrip("/").partition("/")
        self.rest = remainder.lstrip("/")
        return token

    @property
    def v11(self) -> bool:
        return self.version != "1.0"

    def param(self, name: str) -> str:
        """A 1.1-only query parameter (ignored, as on A-REX, through 1.0)."""
        return self.query.get(name, "") if self.v11 else ""


@dataclass
class _Submit:
    queue: str
    delegation: str
    minimum: int
    maximum: int


def _split_target(target: str) -> tuple[str, dict[str, str]]:
    """``GetPath``: the query starts at ``?``, else at the first ``;``."""
    cut = target.find("?")
    if cut < 0:
        cut = target.find(";")
    path, text = (target, "") if cut < 0 else (target[:cut], target[cut + 1 :])
    query: dict[str, str] = {}
    for item in text.split("&"):
        key, _, value = item.partition("=")
        query.setdefault(urllib.parse.unquote(key), urllib.parse.unquote(value))
    return urllib.parse.unquote(path), query


def _negotiate(headers: Message) -> tuple[str, str | None]:
    """``ProcessAcceptedFormat``: the first recognised ``Accept`` entry, else HTML."""
    for value in headers.get_all("Accept") or []:
        for item in str(value).split(","):
            found = _FORMATS.get(item.split(";", 1)[0].strip())
            if found is not None:
                return found
    return "html", None


def _peer_subject(connection: Any) -> str:
    """The client's end-entity subject: the leaf's, without proxy CNs, OpenSSL style."""
    getter = getattr(connection, "getpeercert", None)
    cert = getter() if getter is not None else None
    if not cert:
        return ""
    rdns = [(_SHORT_NAMES.get(key, key), value) for rdn in cert["subject"] for key, value in rdn]
    while len(rdns) > 1 and rdns[-1][0] == "CN" and _PROXY_CN.fullmatch(rdns[-1][1]):
        rdns.pop()
    return "".join(f"/{key}={value}" for key, value in rdns)


def _canonical(subpath: str) -> str | None:
    """``CanonicalDir``: the normalised relative path, or ``None`` if it climbs out."""
    parts: list[str] = []
    for part in subpath.split("/"):
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _content_range(value: str | None, length: int) -> tuple[int, int]:
    """Offset and total size of a PUT body."""
    match = _CONTENT_RANGE.fullmatch((value or "").strip())
    if match is None:
        return 0, length
    offset = int(match.group(1))
    total = match.group(3)
    return offset, offset + length if total == "*" else int(total)


def _ranged(data: bytes, header: str | None, mime: str) -> _Response:
    """A file body, honouring the first range of ``Range: bytes=a-b``."""
    match = _RANGE.match((header or "").strip())
    start = int(match.group(1)) if match and match.group(1) else 0
    end = int(match.group(2)) + 1 if match and match.group(1) and match.group(2) else len(data)
    end = min(end, len(data))
    if start == 0 and end == len(data):
        return _Response(200, "OK", data, {"Content-Type": mime})
    if start >= end:
        return _Response(
            416, "Range not satisfiable", b"", {"Content-Range": f"bytes */{len(data)}"}
        )
    headers = {"Content-Type": mime, "Content-Range": f"bytes {start}-{end - 1}/{len(data)}"}
    return _Response(206, "Partial content", data[start:end], headers)


def _propfind(root: _Node, href: str, path: Path, depth: int) -> None:
    """``ProcessPROPFIND``: one ``d:response`` per entry, recursing ``depth`` levels."""
    response = root.add("d:response")
    try:
        info = path.stat()
    except OSError:
        info = None
    if info is None or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        response.add("d:href", href)
        response.add("d:status", "HTTP/1.1 404 Not Found")
        return
    directory = stat.S_ISDIR(info.st_mode)
    response.add("d:href", href.rstrip("/") + ("/" if directory else ""))
    propstat = response.add("d:propstat")
    prop = propstat.add("d:prop")
    propstat.add("d:status", "HTTP/1.1 200 OK")
    prop.add("d:displayname", path.name)
    kind = prop.add("d:resourcetype")
    if directory:
        kind.add("d:collection")
    else:
        prop.add("d:getcontentlength", str(info.st_size))
    prop.add("d:getlastmodified", _iso(info.st_mtime))
    prop.add("d:creationdate", _iso(info.st_ctime))
    if directory and depth > 0:
        for name in sorted(os.listdir(path)):
            child = href.rstrip("/") + "/" + urllib.parse.quote(name)
            _propfind(root, child, path / name, depth - 1)


# ---------------------------------------------------------------------------
# The HTTP server
# ---------------------------------------------------------------------------


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    # Non-daemon and joined on close: a handler still answering when a test
    # ends must finish, not be cut off mid-way.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True
    app: FakeARex

    def finish_request(self, request: Any, client_address: Any) -> None:
        # The TLS handshake runs here, in the connection's own thread, so a
        # slow or broken client cannot hold up ``accept``.
        tls = self.app.tls
        if tls is not None:
            try:
                request = tls.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                return
        self.app._connected(request, True)
        try:
            super().finish_request(request, client_address)
        finally:
            self.app._connected(request, False)
            if tls is not None:
                request.close()  # socketserver closes only the socket it accepted

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client hanging up mid-request is part of what is being tested


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def version_string(self) -> str:
        return "xrdarc-fake-arex"

    def log_message(self, format: str, *args: Any) -> None:
        pass  # tests read ``FakeARex.requests``, not stderr

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while size := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16):
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            self.rfile.readline()  # the empty trailer section
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self) -> None:
        body = self._read_body()
        response = self.server.app._respond(
            self.command, self.path, self.headers, body, self.connection
        )
        if response is None:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.send_response(response.status, response.reason.replace("\r", " ").replace("\n", " "))
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_PROPFIND = do_PATCH = do_OPTIONS = do_GET


# ---------------------------------------------------------------------------
# The fake CE
# ---------------------------------------------------------------------------


_Bulk = Callable[["FakeARex", FakeJob, _Node], None]


class FakeARex:
    """A threaded fake ARC CE answering the A-REX REST interface under ``/arex``.

    ``root`` holds the session directories (``root/session/<job id>``).
    ``tls`` is a server context (``pki.server_context()``); ``None`` serves
    plain HTTP. Clients authenticate with a client certificate (identity =
    the end-entity subject, ``/DC=org/.../CN=Test User``) or with
    ``Authorization: Bearer <token>`` for a token in ``tokens`` (token ->
    identity); ``anonymous`` is the identity of a request with neither (by
    default such a request is refused with 403, as A-REX refuses it).
    """

    base_path = "/arex"

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        versions: tuple[str, ...] = ("1.0", "1.1"),
        legacy_json: bool = False,
        tokens: dict[str, str] | None = None,
        progression: tuple[str, ...] | None = None,
        maxjobs: int | None = None,
        info: CEInfo | str | None = None,
        anonymous: str | None = None,
        delegation_key_slot: int = 6,
    ) -> None:
        self.root = Path(root)
        (self.root / "session").mkdir(parents=True, exist_ok=True)
        self.tls = tls
        self.host = host
        #: REST versions served (``GET /rest`` lists them; others answer 404).
        self.versions = versions
        #: Render JSON as an ARC 6 server did: no forced arrays, an empty list as no body.
        self.legacy_json = legacy_json
        self.tokens: dict[str, str] = dict(tokens or {})
        #: States each status/info poll moves a job along (``None``: jobs stay put).
        self.progression = progression
        #: A-REX's ``maxjobs``: how many jobs (of all users) may exist.
        self.maxjobs = maxjobs
        #: What ``GET /info`` publishes: a :class:`CEInfo`, or a GLUE2 XML document.
        self.info: CEInfo | str = info if info is not None else CEInfo()
        self.anonymous = anonymous
        #: Operation classes (see :data:`OPERATIONS`) answered 403 "Operation is not allowed".
        self.denied: set[str] = set()
        #: Called with each submitted description; a returned text fails that job with it.
        self.policy: Callable[[str], str | None] | None = None
        #: Seconds from a job's end to its ``WorkingAreaEraseTime``.
        self.erase_after = _ERASE_AFTER
        #: The key behind every delegation CSR.
        self.delegation_key = _delegation_key(delegation_key_slot)
        self.jobs: dict[str, FakeJob] = {}
        self.delegations: dict[str, FakeDelegation] = {}
        self.requests: list[Request] = []
        self.faults: list[Fault] = []
        #: Connections accepted (after the TLS handshake).
        self.connections = 0
        self._rejections: list[str] = []
        self._lock = threading.RLock()
        self._live: set[Any] = set()
        self.httpd = _Server((host, port), _Handler)
        self.httpd.app = self
        self.port: int = self.httpd.server_address[1]
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, args=(0.02,), name="xrdarc-fake-arex", daemon=True
        )

    # -- lifecycle ----------------------------------------------------------------------

    def start(self) -> FakeARex:
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop listening and hang up on every open connection, as a dead CE would."""
        self.httpd.shutdown()
        with self._lock:
            live, self._live = list(self._live), set()
        for connection in live:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        self.httpd.server_close()  # joins the handler threads
        self._thread.join()

    def __enter__(self) -> FakeARex:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _connected(self, connection: Any, live: bool) -> None:
        with self._lock:
            if live:
                self.connections += 1
                self._live.add(connection)
            else:
                self._live.discard(connection)

    @property
    def url(self) -> str:
        """The CE URL: ``https://<host>:<port>/arex`` (``http://`` without TLS)."""
        scheme = "https" if self.tls is not None else "http"
        return f"{scheme}://{self.host}:{self.port}{self.base_path}"

    # -- test controls ----------------------------------------------------------------

    def fault(
        self,
        method: str | None = None,
        path_pattern: str | None = None,
        *,
        status: int | None = 500,
        reason: str = "",
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        times: int = 1,
        drop: bool = False,
        delay: float = 0.0,
    ) -> Fault:
        """Answer the next ``times`` matching requests with this instead (see :class:`Fault`)."""
        found = Fault(
            method=method,
            path_pattern=path_pattern,
            status=status,
            reason=reason,
            body=body,
            headers=dict(headers or {}),
            times=times,
            drop=drop,
            delay=delay,
        )
        with self._lock:
            self.faults.append(found)
        return found

    def reject_next(self, reason: str, times: int = 1) -> None:
        """Fail the next ``times`` submitted jobs with per-job 500 ``reason`` (and no id)."""
        with self._lock:
            self._rejections.extend([reason] * times)

    def add_job(
        self,
        owner: str,
        description: str = '&(executable="/bin/true")',
        *,
        state: str = "ACCEPTING",
        files: dict[str, bytes] | None = None,
        exit_code: int | None = None,
        failure: str | None = None,
    ) -> FakeJob:
        """Put a job straight into the store (no request), with session ``files``."""
        language = "emies:adl" if description.lstrip().startswith("<") else "nordugrid:xrsl"
        with self._lock:
            job = self._build(owner, _Description(description, language), _Submit("", "", 1, 1))
            if isinstance(job, str):
                raise ValueError(job)
            for name, data in (files or {}).items():
                target = job.session / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            if state != job.state or exit_code is not None or failure is not None:
                self.set_state(job.id, state, exit_code=exit_code, failure=failure)
            return job

    def set_state(
        self,
        job_id: str,
        state: str,
        *,
        exit_code: int | None = None,
        failure: str | None = None,
    ) -> FakeJob:
        """Move a job to REST ``state`` (``KeyError`` for no such job, ``ValueError`` state)."""
        if state not in _STATES:
            raise ValueError(f"not a REST state: {state!r}")
        with self._lock:
            job = self.jobs[job_id]
            self._transition(job, state, exit_code=exit_code, failure=failure)
            return job

    def fail_job(
        self, job_id: str, failure: str = "Job failed", *, exit_code: int | None = 1
    ) -> FakeJob:
        """Make a job FAILED in its current state (its ``RestartState``)."""
        return self.set_state(job_id, "FAILED", exit_code=exit_code, failure=failure)

    def session_dir(self, job_id: str) -> Path:
        return self.root / "session" / job_id

    def clear(self) -> None:
        """Forget the recorded requests."""
        with self._lock:
            self.requests.clear()

    # -- state machine ----------------------------------------------------------------

    def _transition(
        self,
        job: FakeJob,
        state: str,
        *,
        exit_code: int | None = None,
        failure: str | None = None,
        reason: str = "",
    ) -> None:
        before, now = job.gm_state, time.time()
        if state == "KILLED" and failure is None:
            failure = job.failure or CANCEL_CAUSE
        if state in ("FAILED", "KILLED") and not job.terminal:
            job.failed_state = job.state
        job.state = state
        if state in _STARTED_STATES and job.started is None:
            job.started = now
        job.ended = now if state in TERMINAL_STATES else None
        if failure is not None:
            job.failure = failure
        if exit_code is not None:
            job.exit_code = exit_code
        elif state == "FINISHED" and job.exit_code is None:
            job.exit_code = 0
        change = f"Job state change {before} -> {job.gm_state}"
        job.log.append(f"{_iso(now)} {change}   Reason: {reason}")

    def _observe(self, job: FakeJob) -> None:
        """A status or info poll: apply a pending kill, else make one step of progress."""
        if job.kill_requested:
            job.kill_requested = False
            self._transition(job, "KILLED", failure=CANCEL_CAUSE, reason="Cancelled by user")
        elif self.progression and job.state in self.progression[:-1]:
            step = self.progression[self.progression.index(job.state) + 1]
            self._transition(job, step, reason="Progress")

    def _purge(self) -> None:
        """A-REX honours a clean mark once the job has finished."""
        for job in [job for job in self.jobs.values() if job.clean_requested and job.terminal]:
            del self.jobs[job.id]
            shutil.rmtree(job.session, ignore_errors=True)

    def _lookup(self, job_id: str, identity: str) -> FakeJob | None:
        job = self.jobs.get(job_id)
        return job if job is not None and job.owner == identity else None

    # -- request entry --------------------------------------------------------------------

    def _identify(self, headers: Message, connection: Any) -> str | None:
        """The identity; "" with no credential; ``None`` for a bearer token not known."""
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return self.tokens.get(auth[7:].strip())
        return _peer_subject(connection) or (self.anonymous or "")

    def _take_fault(self, method: str, target: str) -> Fault | None:
        with self._lock:
            for index, candidate in enumerate(self.faults):
                if candidate.matches(method, target):
                    candidate.times -= 1
                    if candidate.times <= 0:
                        del self.faults[index]
                    return candidate
        return None

    def _respond(
        self, method: str, target: str, headers: Message, body: bytes, connection: Any
    ) -> _Response | None:
        path, query = _split_target(target)
        identity = self._identify(headers, connection)
        recorded = Request(method, path, query, dict(headers.items()), body, identity or "", target)
        with self._lock:
            self.requests.append(recorded)
        found = self._take_fault(method, urllib.parse.unquote(target))
        if found is not None:
            time.sleep(found.delay)
            if found.drop:
                return None
            if found.status is not None:
                reason = found.reason or http.client.responses.get(found.status, "")
                return _Response(found.status, reason, found.body, dict(found.headers))
        ctx = _Ctx(method, path, "", query, headers, body, identity or "")
        with self._lock:
            return self._process(ctx, identity)

    def _process(self, ctx: _Ctx, identity: str | None) -> _Response:
        base = self.base_path
        if ctx.path != base and not ctx.path.startswith(base + "/"):
            return _fault(404, "Not Found")
        ctx.rest = ctx.path[len(base) :]
        if ctx.token() != "rest":
            return _fault(404, "Not Found")
        if identity is None:
            return _fault(403, "Not authorized: token is not valid")
        if not identity:
            return _fault(403, "User can't be assigned configuration")
        self._purge()
        version = ctx.token()
        if not version:
            return self._versions(ctx)
        if version not in self.versions:
            return _fault(404, "Version Not Supported")
        ctx.version = version
        functionality = ctx.token()
        if not functionality:
            return _fault(404, "Not Found")
        handler = self._FUNCTIONALITIES.get(functionality)
        if handler is None:
            return _fault(404, "Functionality Not Supported")
        return handler(self, ctx)

    def _denied(self, operation: str) -> _Response | None:
        if operation in self.denied:
            detail = f"{operation} operation is not allowed for this user"
            return _fault(403, "Operation is not allowed", detail)
        return None

    def _render(
        self,
        ctx: _Ctx,
        root: _Node,
        arrays: tuple[str, ...],
        *,
        status: int = 200,
        show_empty: bool = True,
    ) -> _Response:
        kind, mime = _negotiate(ctx.headers)
        if kind == "json":
            paths = () if self.legacy_json else arrays
            text = _render_json(root, paths, show_empty)
        elif kind == "xml":
            text = _render_xml(root)
        else:
            text = _render_html(root)
        headers = {"Content-Type": mime} if mime else {}
        reason = "Created" if status == 201 else "OK"
        return _Response(status, reason, text.encode(), headers)

    # -- /rest and /info ----------------------------------------------------------------

    def _versions(self, ctx: _Ctx) -> _Response:
        if ctx.method not in ("GET", "HEAD"):
            return _fault(501, "Not Implemented")
        root = _Node("versions")
        for version in self.versions:
            root.add("version", version)
        return self._render(ctx, root, ("version",))

    def _info(self, ctx: _Ctx) -> _Response:
        if ctx.rest:
            return _fault(404, "Not Found")
        if ctx.method not in ("GET", "HEAD"):
            return _fault(501, "Not Implemented")
        if ctx.query.get("schema", "") not in ("", "glue2"):
            return _fault(501, "Schema not implemented")
        return self._render(ctx, self._glue2(), _INFO_ARRAYS, show_empty=False)

    def _glue2(self) -> _Node:
        if isinstance(self.info, str):
            return _parse_xml(self.info) or _Node("InfoRoot")
        info, now = self.info, _iso(time.time())
        stamp = {"CreationTime": now, "Validity": "10800"}
        root = _Node("InfoRoot")
        domains = root.add("Domains")
        domains.xmlns = GLUE2_NS
        domain = domains.add("AdminDomain", attrs={"BaseType": "Domain", **stamp})
        domain.add("ID", "urn:ad:UNDEFINEDVALUE")
        domain.add("Name", "UNDEFINEDVALUE")
        service = domain.add("Services").add(
            "ComputingService", attrs={"BaseType": "Service", **stamp}
        )
        service.add("ID", f"urn:ogf:ComputingService:{self.host}:arex")
        service.add("Name", info.name)
        for capability in ("executionmanagement.jobexecution", "executionmanagement.jobmanager"):
            service.add("Capability", capability)
        service.add("Type", "org.nordugrid.arex")
        service.add("QualityLevel", info.quality_level)
        self._glue2_totals(service, list(self.jobs.values()))
        shares = [share for queue in info.queues for share in self._glue2_shares(queue, stamp)]
        self._glue2_endpoint(service, stamp, [share.children[0].text for share in shares])
        service.children.extend(shares)
        self._glue2_manager(service, stamp)
        return root

    @staticmethod
    def _glue2_totals(node: _Node, jobs: list[FakeJob]) -> None:
        groups = {
            "TotalJobs": REST_STATES,
            "RunningJobs": ("RUNNING", "HELD", "EXITINGLRMS", "OTHER", "EXECUTED"),
            "WaitingJobs": ("QUEUING",),
            "StagingJobs": ("PREPARING", "PREPARED", "FINISHING"),
            "PreLRMSWaitingJobs": ("ACCEPTING", "ACCEPTED", "SUBMITTING"),
        }
        for name, states in groups.items():
            node.add(name, str(sum(job.state in states for job in jobs)))

    def _glue2_endpoint(self, service: _Node, stamp: dict[str, str], share_ids: list[str]) -> None:
        info = self.info
        assert isinstance(info, CEInfo)
        endpoint = service.add("ComputingEndpoint", attrs={"BaseType": "Endpoint", **stamp})
        endpoint.add("ID", f"urn:ogf:ComputingEndpoint:{self.host}:rest:{self.url}")
        endpoint.add("Name", "ARC REST")
        endpoint.add("URL", self.url)
        for capability in (
            "executionmanagement.jobcreation",
            "executionmanagement.jobdescription",
            "executionmanagement.jobmanagement",
            "information.discovery.resource",
            "information.lookup.job",
            "security.delegation",
        ):
            endpoint.add("Capability", capability)
        endpoint.add("Technology", "rest")
        endpoint.add("InterfaceName", "org.nordugrid.arcrest")
        for version in self.versions:
            endpoint.add("InterfaceVersion", version)
        endpoint.add("Semantics", "https://www.nordugrid.org/arc/arc7/tech/rest/rest.html")
        endpoint.add("Implementor", "NorduGrid")
        endpoint.add("ImplementationName", "nordugrid-arc")
        endpoint.add("ImplementationVersion", "7.1.1")
        endpoint.add("QualityLevel", info.quality_level)
        endpoint.add("HealthState", info.health_state)
        endpoint.add("ServingState", info.serving_state)
        endpoint.add("Staging", "staginginout")
        for language in ("nordugrid:xrsl", "emies:adl"):
            endpoint.add("JobDescription", language)
        self._glue2_totals(endpoint, list(self.jobs.values()))
        associations = endpoint.add("Associations")
        for share_id in share_ids:
            associations.add("ComputingShareID", share_id)

    def _glue2_shares(self, queue: FakeQueue, stamp: dict[str, str]) -> list[_Node]:
        limits = {
            "MaxWallTime": queue.max_wall_time,
            "MaxCPUTime": queue.max_cpu_time,
            "MinWallTime": queue.min_wall_time,
            "DefaultWallTime": queue.default_wall_time,
            "MaxTotalJobs": queue.max_total_jobs,
            "MaxRunningJobs": queue.max_running_jobs,
            "MaxWaitingJobs": queue.max_waiting_jobs,
        }
        mine = [job for job in self.jobs.values() if job.queue == queue.name]
        values = {key: str(value) for key, value in limits.items() if value is not None}
        values["ServingState"] = queue.serving_state
        values["RunningJobs"] = str(sum(job.state == "RUNNING" for job in mine))
        values["WaitingJobs"] = str(sum(job.state == "QUEUING" for job in mine))
        values.update(queue.extra)
        return [self._glue2_share(queue.name, vo, values, stamp) for vo in ("", *queue.vos)]

    def _glue2_share(
        self, queue: str, vo: str, values: dict[str, str], stamp: dict[str, str]
    ) -> _Node:
        """The queue's own share (``vo=""``) or its share for one VO, as A-REX names them."""
        name = f"{queue}_{vo}" if vo else queue
        share = _Node("ComputingShare", attrs={"BaseType": "Share", **stamp})
        share.add("ID", f"urn:ogf:ComputingShare:{self.host}:{name}")
        share.add("Name", name)
        share.add("MappingQueue", queue)
        for key, value in values.items():
            share.add(key, value)
        if vo:
            policy = share.add("MappingPolicy", attrs={"BaseType": "Policy", **stamp})
            policy.add("ID", f"urn:ogf:MappingPolicy:{self.host}:basic:{vo}")
            policy.add("Scheme", "basic")
            policy.add("Rule", f"vo:{vo}")
        return share

    def _glue2_manager(self, service: _Node, stamp: dict[str, str]) -> None:
        info = self.info
        assert isinstance(info, CEInfo)
        manager = service.add("ComputingManager", attrs={"BaseType": "Manager", **stamp})
        manager.add("ID", f"urn:ogf:ComputingManager:{self.host}:{info.lrms.lower()}")
        manager.add("ProductName", info.lrms)
        manager.add("TotalLogicalCPUs", str(info.total_cpus))
        environments = manager.add("ApplicationEnvironments")
        for index, rte in enumerate(info.rtes):
            name, _, version = rte.rpartition("-")
            if not (name and version[:1].isdigit()):
                name, version = rte, ""
            environment = environments.add("ApplicationEnvironment")
            environment.add("ID", f"urn:ogf:ApplicationEnvironment:{self.host}:rte:{index}")
            environment.add("AppName", name)
            if version:
                environment.add("AppVersion", version)
            environment.add("State", "installednotverified")

    # -- /jobs ------------------------------------------------------------------------------

    def _jobs(self, ctx: _Ctx) -> _Response:
        job_id = ctx.token()
        if job_id:
            return self._job(ctx, job_id)
        if ctx.method in ("GET", "HEAD"):
            return self._list_jobs(ctx)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        action = ctx.query.get("action", "")
        if action == "new":
            return self._submit(ctx)
        if action not in self._BULK:
            return _fault(501, "Action not implemented")
        return self._bulk(ctx, action)

    def _list_jobs(self, ctx: _Ctx) -> _Response:
        denied = self._denied("JobInfo")
        if denied is not None:
            return denied
        states = [state for state in ctx.query.get("state", "").split(",") if state]
        root = _Node("jobs")
        for job in self.jobs.values():
            if job.owner != ctx.identity or (states and job.fast_state not in states):
                continue
            node = root.add("job")
            node.add("id", job.id)
            if states:
                node.add("state", job.fast_state)
        return self._render(ctx, root, ("job",))

    # -- action=new ----------------------------------------------------------------------

    def _submit(self, ctx: _Ctx) -> _Response:
        denied = self._denied("JobCreate")
        if denied is not None:
            return denied
        if self.maxjobs is not None and len(self.jobs) >= self.maxjobs:
            return _fault(500, "No more jobs allowed")
        if not ctx.body:
            return _fault(500, "Missing payload")
        text = ctx.body.decode("utf-8", "replace")
        start = text.lstrip(" \t\r\n")[:1]
        if not start:
            return _fault(500, "Payload is empty")
        params = self._submit_params(ctx)
        if isinstance(params, _Response):
            return params
        splitter = _SPLITTERS.get(start)
        if splitter is None:
            return _fault(500, "Payload is not recognized")
        descriptions, multi = splitter(text)
        if multi and params.maximum > 1:
            return _fault(403, "No multiple descriptions and multiple instances simultaneously")
        if start == "+" and not descriptions:
            return _fault(500, "Failed to parse job description")
        root = _Node("jobs")
        if multi or params.maximum <= 1:
            self._submit_each(ctx, descriptions, params, root)
        else:
            self._submit_instances(ctx, descriptions[0], params, root)
        return self._render(ctx, root, ("job",), status=201)

    def _submit_params(self, ctx: _Ctx) -> _Submit | _Response:
        minimum = _int(ctx.param("instances_min"), 1)
        maximum = _int(ctx.param("instances"), 1)
        if maximum < 1 or minimum > maximum:
            return _fault(500, "Wrong number of instances specified")
        if self.maxjobs is not None:
            if len(self.jobs) + minimum > self.maxjobs:
                return _fault(403, "Number of requested instances exceeds allowed limit")
            maximum = min(maximum, self.maxjobs - len(self.jobs))
        return _Submit(ctx.param("queue"), ctx.param("delegation_id"), minimum, maximum)

    def _submit_each(
        self, ctx: _Ctx, descriptions: list[_Description], params: _Submit, root: _Node
    ) -> None:
        for description in descriptions:
            node = root.add("job")
            if self.maxjobs is not None and len(self.jobs) >= self.maxjobs:
                node.add("status-code", "500")
                node.add("reason", "No more jobs allowed")
                continue
            failure = self._rejection(description.text)
            job = self._build(ctx.identity, description, params, ctx.version, failure)
            self._created(node, job)

    def _submit_instances(
        self, ctx: _Ctx, description: _Description, params: _Submit, root: _Node
    ) -> None:
        failure = self._rejection(description.text)
        for _ in range(params.maximum):
            job = self._build(ctx.identity, description, params, ctx.version, failure)
            self._created(root.add("job"), job)
            if isinstance(job, str):
                return  # one failure answers for every instance

    def _rejection(self, text: str) -> str:
        if self._rejections:
            return self._rejections.pop(0)
        return (self.policy(text) or "") if self.policy is not None else ""

    @staticmethod
    def _created(node: _Node, job: FakeJob | str) -> None:
        if isinstance(job, str):
            node.add("status-code", "500")
            node.add("reason", job)
            return
        node.add("status-code", "201")
        node.add("reason", "Created")
        node.add("id", job.id)
        node.add("state", "ACCEPTING")

    def _queue_names(self) -> list[str]:
        return [queue.name for queue in self.info.queues] if isinstance(self.info, CEInfo) else []

    def _build(
        self,
        owner: str,
        description: _Description,
        params: _Submit,
        version: str = "1.0",
        failure: str = "",
    ) -> FakeJob | str:
        """Make a job, or say why A-REX would not."""
        if description.language == "emies:adl":
            fields = _adl_fields(description.text)
        else:
            fields = _xrsl_fields(description.text)
        if fields is None:
            return "Failed to parse job description"
        if failure:
            return failure
        queues = self._queue_names()
        queue = fields.queue or params.queue or (queues[0] if queues else "")
        if queues and queue not in queues:
            return f"Requested queue {queue} does not match any of available queues"
        job_id = _new_id(self.jobs)
        delegations = fields.delegations or ([params.delegation] if params.delegation else [])
        job = FakeJob(
            id=job_id,
            owner=owner,
            description=description.text,
            language=description.language,
            session=self.session_dir(job_id),
            name=fields.name,
            queue=queue,
            stdout=fields.stdout,
            stderr=fields.stderr,
            logdir=fields.logdir,
            rerun=fields.rerun,
            delegations=delegations,
            version=version,
        )
        job.session.mkdir(mode=0o700)
        job.log.append(f"{_iso(job.submitted)} Job state change UNDEFINED -> ACCEPTED   Reason: ")
        self.jobs[job_id] = job
        return job

    # -- bulk actions ------------------------------------------------------------------------

    def _bulk(self, ctx: _Ctx, action: str) -> _Response:
        operation, handler, missing = self._BULK[action]
        denied = self._denied(operation)
        if denied is not None:
            return denied
        root = _Node("jobs")
        for job_id in _job_ids(ctx.headers.get("Content-Type"), ctx.body):
            node = root.add("job")
            job = self._lookup(job_id, ctx.identity)
            if job is None:
                node.add("status-code", "404")
                node.add("reason", "Job not found")
                node.add("id", job_id)
                if missing is not None:
                    node.add(*missing)
                continue
            handler(self, job, node)
        return self._render(ctx, root, ("job",), status=201)

    @staticmethod
    def _ok(node: _Node, job: FakeJob, code: str = "200", reason: str = "OK") -> None:
        node.add("status-code", code)
        node.add("reason", reason)
        node.add("id", job.id)

    def _bulk_info(self, job: FakeJob, node: _Node) -> None:
        self._observe(job)
        self._ok(node, job)
        node.add("info_document").children.append(self._activity(job))

    def _bulk_status(self, job: FakeJob, node: _Node) -> None:
        self._observe(job)
        self._ok(node, job)
        node.add("state", job.state)

    def _bulk_kill(self, job: FakeJob, node: _Node) -> None:
        if "kill" in job.refuse:
            self._ok(node, job, "505", job.refuse["kill"])
            return
        job.kill_requested = not job.terminal
        self._ok(node, job, "202", "Queued for killing")

    def _bulk_clean(self, job: FakeJob, node: _Node) -> None:
        if "clean" in job.refuse:
            self._ok(node, job, "505", job.refuse["clean"])
            return
        job.clean_requested = True
        self._ok(node, job, "202", "Queued for cleaning")

    def _bulk_restart(self, job: FakeJob, node: _Node) -> None:
        if job.state != "FAILED":
            self._ok(node, job, "505", "Job has not failed")
        elif job.rerun <= 0:
            self._ok(node, job, "505", "No more restarts allowed")
        else:
            job.rerun -= 1
            job.restarts += 1
            job.failure, job.exit_code = "", None
            self._transition(job, _RESTART_STATE, reason="Restarted by user")
            self._ok(node, job, "202", "Queued for restarting")

    def _bulk_delegations(self, job: FakeJob, node: _Node) -> None:
        self._ok(node, job)
        for delegation_id in job.delegations:
            found = self.delegations.get(delegation_id)
            if found is not None and found.owner == job.owner:
                node.add("delegation_id", delegation_id)

    # action -> (operation class, per-job handler, what a missing job's entry adds)
    _BULK: dict[str, tuple[str, _Bulk, tuple[str, str] | None]] = {
        "info": ("JobInfo", _bulk_info, ("info_document", "")),
        "status": ("JobInfo", _bulk_status, ("state", "None")),
        "kill": ("JobCancel", _bulk_kill, None),
        "clean": ("JobDelete", _bulk_clean, None),
        "restart": ("JobCreate", _bulk_restart, None),
        "delegations": ("JobInfo", _bulk_delegations, None),
    }

    def _activity(self, job: FakeJob) -> _Node:
        """The job's GLUE2 ComputingActivity, as the infoprovider writes it."""
        node = _Node(
            "ComputingActivity",
            attrs={"BaseType": "Activity", "CreationTime": _iso(time.time()), "Validity": "10800"},
            xmlns=GLUE2_NS,
        )
        node.add("ID", f"urn:caid:{self.host}:org.nordugrid.arcrest:{job.id}")
        if job.name:
            node.add("Name", job.name)
        node.add("OtherInfo", "SubmittedVia=org.nordugrid.arcrest")
        node.add("Type", "single")
        node.add("IDFromEndpoint", f"urn:idfe:{job.id}")
        node.add("JobDescription", job.language)
        node.add("State", f"nordugrid:{_STATES[job.state][2]}")
        node.add("State", f"arcrest:{job.state}")
        if job.failed_state and job.state in ("FAILED", "KILLED"):
            node.add("RestartState", f"arcrest:{job.failed_state}")
        fields = [
            ("ExitCode", "" if job.exit_code is None else str(job.exit_code)),
            *(("Error", line) for line in job.failure.splitlines()),
            ("Owner", job.owner),
            ("LocalOwner", "arcuser"),
            ("StdOut", job.stdout),
            ("StdErr", job.stderr),
            ("LogDir", job.logdir),
            ("Queue", job.queue),
            ("SubmissionTime", _iso(job.submitted)),
            ("StartTime", _iso(job.started) if job.started else ""),
            ("EndTime", _iso(job.ended) if job.ended else ""),
            ("WorkingAreaEraseTime", _iso(job.ended + self.erase_after) if job.ended else ""),
        ]
        for name, value in fields:
            if value:
                node.add(name, value)
        node.add("Associations").add(
            "ComputingShareID", f"urn:ogf:ComputingShare:{self.host}:{job.queue}"
        )
        return node

    # -- jobs/<id>/... ---------------------------------------------------------------------

    def _job(self, ctx: _Ctx, job_id: str) -> _Response:
        sub = ctx.token()
        if not sub:
            return _fault(404, "Missing job sub-resource")
        if sub == "session":
            job = self._lookup(job_id, ctx.identity)
            # A-REX has no failure text for a job it cannot find: the reason is "OK".
            return self._session(ctx, job) if job is not None else _fault(404, "OK")
        if sub == "diagnose":
            return self._diagnose(ctx, job_id)
        return _fault(404, "Wrong job sub-resource requested")

    def _session(self, ctx: _Ctx, job: FakeJob) -> _Response:
        relative = _canonical(ctx.rest)
        if relative is None:
            return _fault(404, "Wrong path")
        handler = self._SESSION.get(ctx.method)
        if handler is None:
            return _fault(501, "Not Implemented")
        return handler(self, ctx, job, relative)

    def _session_get(self, ctx: _Ctx, job: FakeJob, relative: str) -> _Response:
        target = job.session / relative
        if target.is_dir():
            denied = self._denied("DataInfo")
            if denied is not None:
                return denied
            root = _Node("list")
            for entry in sorted(target.iterdir()):
                info = entry.lstat()
                if stat.S_ISREG(info.st_mode):
                    root.add("file", entry.name, {"size": str(info.st_size)})
                elif stat.S_ISDIR(info.st_mode):
                    root.add("dir", entry.name)
            return self._render(ctx, root, ("file", "dir"))
        denied = self._denied("DataRead")
        if denied is not None:
            return denied
        if target.is_file():
            ranges = ctx.headers.get("Range") if ctx.method == "GET" else None
            return _ranged(target.read_bytes(), ranges, "application/octet-stream")
        return _fault(404, "Not found")

    def _session_put(self, ctx: _Ctx, job: FakeJob, relative: str) -> _Response:
        denied = self._denied("DataWrite")
        if denied is not None:
            return denied
        target = job.session / relative
        offset, total = _content_range(ctx.headers.get("Content-Range"), len(ctx.body))
        try:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            handle = os.open(target, os.O_WRONLY | os.O_CREAT, 0o600)  # no O_TRUNC, as A-REX
        except OSError:
            return _fault(500, "Error creating file")
        with os.fdopen(handle, "wb") as stream:
            stream.seek(offset)
            stream.write(ctx.body)
        if self._chunk(job, relative, offset, len(ctx.body), total):
            job.uploads = _unique([*job.uploads, "/" + relative])
        return _Response(200, "OK")

    @staticmethod
    def _chunk(job: FakeJob, relative: str, offset: int, length: int, total: int) -> bool:
        """``FileChunks``: is the file complete after writing ``length`` at ``offset``?"""
        size, ranges = job._chunks.get(relative, (0, []))
        size = size or total
        if length == 0:
            return total == 0
        ranges = _merge([*ranges, (offset, offset + length)])
        size = max(size, offset + length)
        job._chunks[relative] = (size, ranges)
        return ranges == [(0, size)]

    def _session_delete(self, ctx: _Ctx, job: FakeJob, relative: str) -> _Response:
        denied = self._denied("DataWrite")
        if denied is not None:
            return denied
        target = job.session / relative
        try:
            target.unlink()
        except OSError:
            try:
                shutil.rmtree(target)
            except OSError:
                return _fault(500, "Failed to delete")
        return _Response(202, "Accepted")

    def _session_propfind(self, ctx: _Ctx, job: FakeJob, relative: str) -> _Response:
        denied = self._denied("DataInfo")
        if denied is not None:
            return denied
        depth = {"0": 0, "1": 1}.get(ctx.headers.get("Depth", ""), 10)
        root = _Node("d:multistatus", attrs={"xmlns:d": _DAV_NS})
        scheme, _, _ = self.url.partition("://")
        href = f"{scheme}://{self.host}:{self.port}{urllib.parse.quote(ctx.path)}"
        _propfind(root, href, job.session / relative, depth)
        body = '<?xml version="1.0"?>\n' + _render_xml(root)
        return _Response(200, "OK", body.encode(), {"Content-Type": "application/xml"})

    _SESSION: dict[str, Callable[[FakeARex, _Ctx, FakeJob, str], _Response]] = {
        "GET": _session_get,
        "HEAD": _session_get,
        "PUT": _session_put,
        "DELETE": _session_delete,
        "PROPFIND": _session_propfind,
    }

    def _diagnose(self, ctx: _Ctx, job_id: str) -> _Response:
        name = ctx.rest
        if name not in DIAGNOSE_ITEMS:
            return _fault(404, "Diagnostic item not found")
        if ctx.method not in ("GET", "HEAD"):
            return _fault(501, "Not Implemented")
        denied = self._denied("JobInfo")
        if denied is not None:
            return denied
        job = self._lookup(job_id, ctx.identity)
        if job is None:
            return _fault(404, "OK")
        text = self._diagnose_files(job).get(name)
        if text is None:
            return _fault(404, "Not found")
        mime = "application/xml" if name == "xml" else "text/plain"
        return _ranged(text.encode(), ctx.headers.get("Range"), mime)

    def _diagnose_files(self, job: FakeJob) -> dict[str, str]:
        local = {
            "globalid": f"{self.url}/rest/1.0/jobs/{job.id}",
            "headnode": self.url,
            "interface": "org.nordugrid.arcrest",
            "queue": job.queue,
            "subject": job.owner,
            "jobname": job.name,
            "rerun": str(job.rerun),
            "delegationid": " ".join(job.delegations),
            "sessiondir": str(job.session),
        }
        files = {
            "description": job.description,
            "status": job.gm_state,
            "errors": "".join(line + "\n" for line in job.log),
            "local": "".join(f"{key}={value}\n" for key, value in local.items()),
            "xml": _render_xml(self._activity(job)),
        }
        if job.failure:
            files["failed"] = job.failure
        if job.exit_code is not None:
            files["diag"] = f"exitcode={job.exit_code}\n"
        if job.uploads:
            files["input_status"] = "".join(name + "\n" for name in job.uploads)
        files.update(job.diagnose)
        return files

    # -- /delegations -------------------------------------------------------------------------

    def _delegations_endpoint(self, ctx: _Ctx) -> _Response:
        delegation_id = ctx.token()
        if delegation_id:
            return self._delegation(ctx, delegation_id)
        if ctx.method in ("GET", "HEAD"):
            return self._list_delegations(ctx)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        if ctx.query.get("action", "") != "new":
            return _fault(501, "Action not implemented")
        denied = self._denied("JobCreate")
        if denied is not None:
            return denied
        kind = ctx.param("type")
        if kind in ("", "x509"):
            delegation = self._new_delegation(ctx.identity, "x509")
            headers = {
                "Content-Type": "application/x-pem-file",
                "Location": f"{ctx.path}/{delegation.id}",
            }
            return _Response(201, "Created", self._csr(delegation), headers)
        if kind != "jwt":
            return _fault(501, "Unknown delegation type specified")
        token = ctx.headers.get("X-Token-Delegation")
        if token is None:
            return _fault(501, "Missing X-Token-Delegation header in delegation request")
        delegation = self._new_delegation(ctx.identity, "jwt")
        delegation.token = token
        return _Response(201, "Created", b"", {"Location": f"{ctx.path}/{delegation.id}"})

    def _new_delegation(self, owner: str, kind: str, delegation_id: str = "") -> FakeDelegation:
        delegation = FakeDelegation(delegation_id or _new_id(self.delegations), owner, kind)
        self.delegations[delegation.id] = delegation
        return delegation

    def _csr(self, delegation: FakeDelegation) -> bytes:
        """A PKCS#10 request with an empty subject, SHA-256, for the delegation key."""
        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(self.delegation_key, hashes.SHA256())
        )
        delegation.csr = request.public_bytes(serialization.Encoding.PEM)
        return delegation.csr

    def _list_delegations(self, ctx: _Ctx) -> _Response:
        denied = self._denied("JobInfo")
        if denied is not None:
            return denied
        wanted = ctx.param("type")
        root = _Node("delegations")
        for delegation in self.delegations.values():
            if delegation.owner == ctx.identity and wanted in ("", delegation.type):
                node = root.add("delegation")
                node.add("id", delegation.id)
                node.add("type", delegation.type)
        return self._render(ctx, root, ("delegation",))

    def _delegation(self, ctx: _Ctx, delegation_id: str) -> _Response:
        if ctx.rest:
            return _fault(404, "Not Found")
        found = self.delegations.get(delegation_id)
        delegation = found if found is not None and found.owner == ctx.identity else None
        if ctx.method == "PUT":
            return self._delegation_put(ctx, delegation)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        action = self._DELEGATION_ACTIONS.get(ctx.query.get("action", ""))
        if action is None:
            return _fault(501, "Action not implemented")
        operation, handler = action
        denied = self._denied(operation)
        if denied is not None:
            return denied
        if delegation is None and found is not None:
            delegation_id = ""  # somebody else's: it cannot be had
        return handler(self, ctx, delegation, delegation_id)

    def _delegation_put(self, ctx: _Ctx, delegation: FakeDelegation | None) -> _Response:
        denied = self._denied("JobCreate")
        if denied is not None:
            return denied
        if not ctx.body:
            return _fault(500, "Missing payload")
        chain = self._accept(delegation, ctx.body)
        if delegation is None or chain is None:
            return _fault(500, "Failed accepting delegation")
        delegation.chain, delegation.chain_pem = chain, ctx.body
        delegation.uploads += 1
        return _Response(200, "OK")

    def _accept(
        self, delegation: FakeDelegation | None, body: bytes
    ) -> list[x509.Certificate] | None:
        """The uploaded chain if A-REX would take it: our key, signed by the next one."""
        if delegation is None or delegation.type != "x509":
            return None
        try:
            chain = x509.load_pem_x509_certificates(body)
        except ValueError:
            return None
        spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if chain[0].public_key().public_bytes(*spki) != (
            self.delegation_key.public_key().public_bytes(*spki)
        ):
            return None
        try:
            if len(chain) > 1:
                chain[0].verify_directly_issued_by(chain[1])
        except (ValueError, TypeError, InvalidSignature):
            return None
        return chain

    def _delegation_get(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> _Response:
        if delegation is None:
            return _fault(404, "No delegation found")
        body = delegation.token.encode() if delegation.type == "jwt" else delegation.chain_pem
        return _Response(200, "OK", body, {"Content-Type": "application/x-pem-file"})

    def _delegation_renew(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> _Response:
        if not delegation_id:
            return _fault(500, "Failed generating delegation request")
        if delegation is None:
            # A-REX makes a slot for an id it does not know.
            delegation = self._new_delegation(ctx.identity, "x509", delegation_id)
        delegation.renewals += 1
        pem = {"Content-Type": "application/x-pem-file"}
        return _Response(201, "Created", self._csr(delegation), pem)

    def _delegation_delete(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> _Response:
        if delegation is None:
            return _fault(404, "No such delegation")
        if any(delegation.id in job.delegations for job in self.jobs.values()):
            return _fault(500, "Failed deleting delegation")  # locked by a job
        del self.delegations[delegation.id]
        return _Response(202, "Accepted")

    _DELEGATION_ACTIONS: dict[
        str,
        tuple[str, Callable[[FakeARex, _Ctx, FakeDelegation | None, str], _Response]],
    ] = {
        "get": ("JobInfo", _delegation_get),
        "renew": ("JobCreate", _delegation_renew),
        "delete": ("JobDelete", _delegation_delete),
    }

    _FUNCTIONALITIES: dict[str, Callable[[FakeARex, _Ctx], _Response]] = {
        "info": _info,
        "jobs": _jobs,
        "delegations": _delegations_endpoint,
    }
