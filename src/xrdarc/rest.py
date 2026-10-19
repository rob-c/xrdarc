"""The A-REX REST interface, one method per endpoint.

This layer speaks the wire protocol and nothing more: it negotiates the REST
version, sends bodies in the exact shapes A-REX parses, and normalises what
comes back. The quirks it absorbs, so nothing above it has to:

* the response format is HTML unless ``Accept`` says otherwise, so every
  request names JSON (or XML, for the one listing whose JSON loses sizes);
* bulk bodies are parsed only with a Content-Type of exactly
  ``application/json``, and non-string JSON scalars lose their first
  character, so ids are always sent as JSON strings;
* every value comes back as a string, and a repeated element is a list only
  when the server forces it - ARC 6 servers never did - so anything that can
  repeat is normalised to a list, and an empty body means an empty list;
* bulk operations answer HTTP 201 whatever happened, with the real outcome
  per job in ``status-code`` (``505`` included), aligned by position;
* errors are explained in the HTTP reason phrase, not the body.

Names the CE chooses - job ids and session directory entries - end up as
local file and directory names when results are downloaded, so they are
checked here, where they arrive: each must be one safe path component
(:func:`is_safe_name`). A hostile or broken CE cannot name ``..``, an
absolute path or a Windows drive and so make the client write outside the
download directory.
"""

from __future__ import annotations

import errno
import json
import re
import urllib.parse
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from xrdcore.cancel import Cancel
from xrdcore.log import get_logger
from xrdcore.safexml import UnsafeXML
from xrdcore.safexml import fromstring as _xml

from .errors import ARCError
from .transport import Response, Session
from .urls import ce_url

__all__ = [
    "SUPPORTED_VERSIONS",
    "BulkResult",
    "Listing",
    "RESTClient",
    "SubmitResult",
    "as_list",
    "is_safe_name",
]

_log = get_logger("xrdarc")

#: The REST versions this client speaks, most preferred first. 1.1 adds the
#: submission query parameters (queue, delegation, instance counts), token
#: delegations and the extra ``jobs`` filters; 1.0 is what ARC 6 servers offer.
SUPPORTED_VERSIONS = ("1.1", "1.0")

#: Ids per bulk request: A-REX reads at most 1 MiB of a bulk body. 500 ids
#: of ``{"id":"<12 hex>"}`` are ~12 KiB, far inside it, while still turning
#: a thousand-job ``arcstat -a`` into two round trips rather than one each.
BULK_CHUNK = 500

#: The ``diagnose`` items A-REX serves, as ``rest.cpp`` lists them.
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

#: Bulk actions that only read: safe to send again after a dropped connection or a 5xx.
#: The others change the job; a retry after an answer was lost could, for
#: ``restart``, restart a job that had already been restarted and failed again.
READ_ONLY_ACTIONS = frozenset({"info", "status", "delegations"})

#: Without ``Accept`` A-REX answers with an HTML table (see the module docstring).
_JSON = {"Accept": "application/json"}
#: ``C:`` and friends: on Windows a drive prefix makes ``Path(root) / name`` leave ``root``.
_DRIVE = re.compile(r"[A-Za-z]:")
#: Separators on any platform, and the byte no file system allows.
_UNSAFE_CHARACTERS = frozenset("/\\\0")


# Checked by hand rather than by comparing ``Path(name).name == name``: that
# answer depends on the platform the client runs on, and a name that is
# harmless on Linux (``C:x``, ``a\\b``) must be refused there too, since the
# same job list may be retrieved on Windows later.
def is_safe_name(name: str) -> bool:
    """Whether ``name`` is exactly one path component, harmless on every platform.

    Refused: the empty name, ``.`` and ``..``, anything containing ``/``,
    ``\\`` or NUL (so no absolute path either), and a leading drive letter
    (``C:x``). Everything else - spaces, dots inside the name, non-ASCII,
    a leading ``-`` - is a legitimate file name and is accepted.
    """
    return (
        name not in ("", ".", "..")
        and _UNSAFE_CHARACTERS.isdisjoint(name)
        and _DRIVE.match(name) is None
    )


#: The bulk body's type must be *exactly* this - no ``charset`` - or A-REX
#: parses no ids at all and answers an empty 201.
_JSON_BODY = {"Accept": "application/json", "Content-Type": "application/json"}


def as_list(value: Any) -> list[Any]:
    """A field that may repeat, as a list: ``None`` and ``""`` are empty."""
    # ``""`` is how A-REX's JSON renders an element that is present but empty.
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _int(value: Any, default: int = 0) -> int:
    """A JSON field as an integer: A-REX sends numbers as strings (``"201"``), maybe padded."""
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _decode(response: Response) -> dict[str, Any]:
    """The JSON object in ``response``; ``{}`` for the empty body old servers send."""
    # ARC 6 answers an empty list with an empty body, not ``{}``.
    if not response.body.strip():
        return {}
    try:
        doc = json.loads(response.body)
    except ValueError as exc:
        kind = response.headers.get("Content-Type", "unknown content")
        raise ARCError(
            f"The CE answered with something other than JSON ({kind})",
            errno.EPROTO,
            url=response.url,
        ) from exc
    if not isinstance(doc, dict):
        raise ARCError("The CE answered with unexpected JSON", errno.EPROTO, url=response.url)
    return doc


def _unnamed(entries: list[Any], position: int) -> dict[str, Any]:
    """The bulk answer at ``position`` if it names no job; one naming another job is not ours."""
    # Positional matching is a fallback for entries without an id; a shorter
    # answer than the request (a CE that stopped part-way) leaves the rest
    # unmatched, never shifted onto the wrong job.
    entry = entries[position] if position < len(entries) else None
    return entry if isinstance(entry, dict) and not entry.get("id") else {}


def _session_path(path: str) -> str:
    """``path`` inside a session directory, percent-encoded; ``..`` is refused."""
    # POSIX rules whatever the client's platform: these are A-REX's paths.
    # A leading ``/`` and ``.`` segments are dropped rather than refused: the
    # path is always relative to the session directory, so they mean nothing.
    parts = [p for p in PurePosixPath(path).parts if p not in ("/", ".")]
    if ".." in parts:
        raise ARCError(f"Refusing a session path outside the job: {path!r}", errno.EINVAL)
    # Each part quoted on its own (``safe=""``), so a ``%`` or ``?`` in a file
    # name reaches A-REX as part of the name rather than as URL syntax.
    return "/".join(urllib.parse.quote(p, safe="") for p in parts)


@dataclass(frozen=True, slots=True)
class SubmitResult:
    """One description's outcome from ``action=new``; ``id`` is ``None`` if it failed."""

    status: int
    reason: str
    id: str | None
    state: str | None

    @property
    def ok(self) -> bool:
        """Created: a 201 with an id (A-REX's per-job code, not the HTTP status)."""
        return self.status == 201 and self.id is not None


def _submitted(entry: Any) -> SubmitResult:
    """One ``action=new`` answer; a job id that is not one safe name fails the job.

    Such a job may exist on the CE, but the client could never download it
    safely (its id becomes a directory name), so it is reported as not
    submitted rather than recorded.
    """
    fields = entry if isinstance(entry, dict) else {}
    status = _int(fields.get("status-code"))
    reason = str(fields.get("reason") or "")
    job_id = str(fields["id"]) if fields.get("id") else None
    if job_id is not None and not is_safe_name(job_id):
        reason = f"The CE answered with an unusable job id {job_id!r}"
        status, job_id = 0, None
    return SubmitResult(status, reason, job_id, fields.get("state") or None)


@dataclass(frozen=True, slots=True)
class BulkResult:
    """One job's outcome from a bulk action, with whatever fields that action adds."""

    id: str
    status: int
    reason: str
    state: str | None = None
    info: Mapping[str, Any] = field(default_factory=dict)
    delegations: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """A 2xx per-job code; ``202`` is "queued" (kill, clean), which counts."""
        return 200 <= self.status < 300


@dataclass(frozen=True, slots=True)
class Listing:
    """A session directory level: file names with sizes, and subdirectory names."""

    files: Mapping[str, int | None]
    dirs: tuple[str, ...]


class RESTClient:
    """The REST interface of one CE.

    ``ce`` is anything ``arcsub -C`` accepts. ``version`` pins the REST
    version; by default the highest one both sides support is used, asked
    for once on first use.
    """

    def __init__(self, ce: str, session: Session, *, version: str | None = None) -> None:
        """Nothing is sent until the first request (which negotiates the version, if unpinned).

        Lazy so that a command that only reads the job list, or fails a local
        check first, never touches the network.
        """
        self.ce = ce_url(ce)
        self.session = session
        self._version = version

    # -- versions ----------------------------------------------------------

    def versions(self) -> list[str]:
        """The REST versions the CE offers (``GET <ce>/rest``)."""
        doc = _decode(self.session.request("GET", f"{self.ce}/rest", headers=_JSON))
        return [str(v) for v in as_list(doc.get("version"))]

    @property
    def version(self) -> str:
        """The version spoken: pinned, or negotiated on first use."""
        # Not locked: two threads racing here both ask and both get the same
        # answer, which costs one extra request and nothing else.
        if self._version is None:
            self._version = _choose_version(self.versions(), self.ce)
        return self._version

    @property
    def base(self) -> str:
        """``<ce>/rest/<version>``: every endpoint is below it."""
        return f"{self.ce}/rest/{self.version}"

    def _url(self, path: str, **query: str | None) -> str:
        """``base/path`` with the query parameters that are not ``None``, encoded."""
        params = {k: v for k, v in query.items() if v is not None}
        suffix = f"?{urllib.parse.urlencode(params)}" if params else ""
        return f"{self.base}/{path}{suffix}"

    # -- information -------------------------------------------------------

    def info(self) -> dict[str, Any]:
        """The CE's GLUE2 document, as JSON (``GET info``)."""
        return _decode(self.session.request("GET", self._url("info"), headers=_JSON))

    def jobs(self, states: Iterable[str] = ()) -> list[tuple[str, str | None]]:
        """The ids of this user's jobs on the CE, with states when filtered by them."""
        # A comma-separated ``state=`` filter is REST 1.1's; 1.0 ignores it, which
        # is why each entry's state is read back rather than assumed.
        wanted = ",".join(states) or None
        doc = _decode(self.session.request("GET", self._url("jobs", state=wanted), headers=_JSON))
        listed = (self._listed(entry) for entry in as_list(doc.get("job")))
        return [found for found in listed if found is not None]

    def _listed(self, entry: Any) -> tuple[str, str | None] | None:
        """One ``jobs`` entry as ``(id, state)``; ``None`` for one without a usable id.

        An id that is not one safe name is skipped with a warning: it would
        become a directory name on download (see the module docstring).
        """
        if not isinstance(entry, dict) or not entry.get("id"):
            return None
        job_id = str(entry["id"])
        if not is_safe_name(job_id):
            _log.warning("ignoring the unusable job id %r listed by %s", job_id, self.ce)
            return None
        return job_id, entry.get("state")

    # -- submission and bulk actions ----------------------------------------

    def submit(
        self,
        description: str | bytes,
        *,
        queue: str | None = None,
        delegation_id: str | None = None,
        instances: int | None = None,
        instances_min: int | None = None,
    ) -> list[SubmitResult]:
        """POST one description (ADL, ``&`` xRSL, ``+`` multi-xRSL, or several ADLs).

        ``queue``, ``delegation_id`` and the instance counts are REST 1.1
        parameters; on 1.0 they are not sent and the description must carry
        them. Results are in description order; failures carry no id.
        """
        extra: dict[str, str | None] = {}
        # 1.0 has no such parameters: there the queue and delegation must be
        # in the description itself, which preparing it arranges.
        if self.version != "1.0":
            counts = {"instances": instances, "instances_min": instances_min}
            extra = {"queue": queue, "delegation_id": delegation_id}
            extra.update({k: str(v) for k, v in counts.items() if v is not None})
        body = description.encode() if isinstance(description, str) else description
        # Never retried (POST, not marked idempotent): a repeated ``action=new``
        # after a lost answer would submit every job twice. The Content-Type
        # is what A-REX wants for any description, xRSL included.
        response = self.session.request(
            "POST",
            self._url("jobs", action="new", **extra),
            body=body,
            headers={"Accept": "application/json", "Content-Type": "application/xml"},
            expect=(201,),
        )
        return [_submitted(entry) for entry in as_list(_decode(response).get("job"))]

    def _bulk(self, action: str, ids: Sequence[str]) -> Iterator[tuple[str, dict[str, Any]]]:
        """Each id with its entry of the answer (``{}`` if the CE left it out), in chunks.

        Read-only actions are marked idempotent so the transport may repeat
        them after a dropped connection; ``kill``/``clean``/``restart`` are
        not repeated, since the first attempt may have taken effect.
        """
        for start in range(0, len(ids), BULK_CHUNK):
            chunk = list(ids[start : start + BULK_CHUNK])
            # Ids as JSON strings: A-REX's parser drops the first character of
            # any other scalar (see the module docstring).
            body = json.dumps({"job": [{"id": str(i)} for i in chunk]}).encode()
            response = self.session.request(
                "POST",
                self._url("jobs", action=action),
                body=body,
                headers=_JSON_BODY,
                expect=(200, 201),
                idempotent=action in READ_ONLY_ACTIONS,
            )
            yield from _matched(chunk, as_list(_decode(response).get("job")))

    def bulk(self, action: str, ids: Sequence[str]) -> list[BulkResult]:
        """``POST jobs?action=<action>`` for ``ids``, one result per id, in order.

        An id the CE left out of its answer gets status 0 and an explanatory reason.
        """
        return [_bulk_result(job_id, entry) for job_id, entry in self._bulk(action, ids)]

    def status(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=status``: each job's REST state (``BulkResult.state``)."""
        return self.bulk("status", ids)

    def job_info(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=info``: each job's GLUE2 ``ComputingActivity`` (``BulkResult.info``)."""
        return self.bulk("info", ids)

    def kill(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=kill``: asynchronous; a 202 means queued for killing."""
        return self.bulk("kill", ids)

    def clean(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=clean``: the job and its session go once it has finished."""
        return self.bulk("clean", ids)

    def restart(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=restart``: a failed job with ``rerun`` left starts again where it failed."""
        return self.bulk("restart", ids)

    def job_delegations(self, ids: Sequence[str]) -> list[BulkResult]:
        """``action=delegations``: the delegation ids each job uses (``BulkResult.delegations``)."""
        return self.bulk("delegations", ids)

    # -- session directory and diagnostics ------------------------------------

    def session_url(self, job_id: str, path: str = "") -> str:
        """The URL of ``path`` in the job's session directory (``..`` refused, parts quoted)."""
        quoted = _session_path(path)
        job = urllib.parse.quote(job_id, safe="")
        return f"{self.base}/jobs/{job}/session" + (f"/{quoted}" if quoted else "")

    def listing(self, job_id: str, path: str = "") -> Listing:
        """One level of the session directory, with file sizes (asked for as XML)."""
        # XML, not JSON: A-REX's JSON rendering drops the ``size`` attribute of
        # a leaf element, which is exactly where the size is.
        response = self.session.request(
            "GET", self.session_url(job_id, path) + "/", headers={"Accept": "application/xml"}
        )
        try:
            root = _xml(response.body)
        except (UnsafeXML, SyntaxError) as exc:
            raise ARCError(
                "The CE sent an unreadable directory listing", errno.EPROTO, url=response.url
            ) from exc
        entries = [(child, _entry_name(child, response.url)) for child in root]
        # Anything other than ``file``/``dir`` (a future entry kind) is ignored
        # rather than guessed at; a download then simply leaves it out.
        files = {name: _size(child) for child, name in entries if name and child.tag == "file"}
        dirs = tuple(name for child, name in entries if name and child.tag == "dir")
        return Listing(files, dirs)

    def walk(self, job_id: str, path: str = "") -> Iterator[tuple[str, int | None]]:
        """Every file under ``path`` in the session directory, depth first."""
        # One request per directory level: A-REX has no recursive listing.
        level = self.listing(job_id, path)
        prefix = f"{path.strip('/')}/" if path.strip("/") else ""
        for name, size in level.files.items():
            yield prefix + name, size
        for name in level.dirs:
            yield from self.walk(job_id, prefix + name)

    def get_file(
        self, job_id: str, path: str, target: Path, *, cancel: Cancel | None = None
    ) -> int:
        """Download one session file into ``target``; ``cancel`` stops it mid-file.

        See :meth:`Session.download <xrdarc.transport.Session.download>`.
        """
        return self.session.download(self.session_url(job_id, path), target, cancel=cancel)

    def read_file(self, job_id: str, path: str) -> bytes:
        """A whole session file, in memory (small files: ``cat`` streams instead)."""
        return self.session.request("GET", self.session_url(job_id, path)).body

    def stream_file(self, job_id: str, path: str, out: BinaryIO) -> int:
        """A session file copied into ``out`` as it arrives; the bytes written."""
        return self.session.copy_to(self.session_url(job_id, path), out)

    def put_file(self, job_id: str, path: str, source: Path) -> int:
        """Upload ``source`` as session file ``path`` (streamed, with its length); bytes sent."""
        # An empty path would address the session directory itself, which
        # A-REX does not treat as a file; refuse it before the request.
        if not _session_path(path):
            raise ARCError("An upload needs a file name", errno.EINVAL)
        return self.session.upload(self.session_url(job_id, path), source)

    def delete_file(self, job_id: str, path: str) -> None:
        """Delete one session file; the directory itself is refused (that is ``clean``)."""
        if not _session_path(path):
            raise ARCError("Refusing to delete the whole session directory", errno.EINVAL)
        self.session.request("DELETE", self.session_url(job_id, path), expect=(200, 202, 204))

    def diagnose(self, job_id: str, item: str) -> bytes:
        """One of A-REX's per-job control files (``DIAGNOSE_ITEMS``)."""
        # Checked locally: an unknown item would only come back as a 404,
        # which by status alone reads like a missing job.
        if item not in DIAGNOSE_ITEMS:
            raise ARCError(f"Unknown diagnostic item {item!r}", errno.EINVAL)
        job = urllib.parse.quote(job_id, safe="")
        return self.session.request("GET", f"{self.base}/jobs/{job}/diagnose/{item}").body

    # -- delegations ---------------------------------------------------------

    def delegations(self, kind: str | None = None) -> list[tuple[str, str]]:
        """``(id, type)`` of this user's delegations on the CE."""
        doc = _decode(
            self.session.request("GET", self._url("delegations", type=kind), headers=_JSON)
        )
        found = []
        for entry in as_list(doc.get("delegation")):
            # REST 1.0 lists no type: everything there is an X.509 delegation.
            if isinstance(entry, dict) and entry.get("id"):
                found.append((str(entry["id"]), str(entry.get("type") or "x509")))
        return found

    @staticmethod
    def _delegation_id(response: Response) -> str:
        """The new delegation's id: the last segment of the 201's ``Location``."""
        # ``Response.headers`` is a plain dict: it keeps the server's spelling of the name.
        location = response.headers.get("Location") or response.headers.get("location") or ""
        # The Location may be absolute or a path, so only its path's last
        # segment is trusted; host and scheme play no part in the id.
        found = urllib.parse.urlsplit(location).path.rstrip("/").rpartition("/")[2]
        if not found:
            raise ARCError(
                "The CE created a delegation but did not say where", errno.EPROTO, url=response.url
            )
        return found

    def new_delegation(self) -> tuple[str, str]:
        """Ask for a new X.509 delegation slot: ``(id, PEM certificate request)``."""
        # REST 1.0 has no ``type`` parameter (every delegation is X.509 there).
        kind = None if self.version == "1.0" else "x509"
        response = self.session.request(
            "POST", self._url("delegations", action="new", type=kind), expect=(201,)
        )
        return self._delegation_id(response), response.text

    def new_token_delegation(self, token: str) -> str:
        """Store a bearer token as a delegation (REST 1.1 only): its id."""
        if self.version == "1.0":
            raise ARCError(
                "Token delegation needs REST 1.1, which this CE does not offer",
                errno.EOPNOTSUPP,
                url=self.ce,
            )
        # The token travels in a header, not the body or the URL, so it never
        # appears in a server's access log of request lines.
        response = self.session.request(
            "POST",
            self._url("delegations", action="new", type="jwt"),
            headers={"X-Token-Delegation": token},
            expect=(201,),
        )
        return self._delegation_id(response)

    def _delegation_url(self, delegation_id: str, action: str | None = None) -> str:
        """``delegations/<id>``, with ``?action=`` when given."""
        quoted = urllib.parse.quote(delegation_id, safe="")
        return self._url(f"delegations/{quoted}", action=action)

    def put_delegation(self, delegation_id: str, chain_pem: str) -> None:
        """Upload the signed proxy chain (new certificate first) into a slot."""
        self.session.request(
            "PUT",
            self._delegation_url(delegation_id),
            body=chain_pem.encode(),
            headers={"Content-Type": "application/x-pem-file"},
            expect=(200, 201, 204),
        )

    def get_delegation(self, delegation_id: str) -> str:
        """The certificate chain stored in a slot (never its key)."""
        url = self._delegation_url(delegation_id, "get")
        return self.session.request("POST", url).text

    def renew_delegation(self, delegation_id: str) -> str:
        """A fresh certificate request for an existing slot, to sign and PUT."""
        url = self._delegation_url(delegation_id, "renew")
        return self.session.request("POST", url, expect=(200, 201)).text

    def delete_delegation(self, delegation_id: str) -> None:
        """Remove a slot; A-REX refuses while a job still uses it."""
        url = self._delegation_url(delegation_id, "delete")
        self.session.request("POST", url, expect=(200, 202, 204))


def _matched(chunk: Sequence[str], entries: list[Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Each id of ``chunk`` with its answer: by id when the CE named it, else by position.

    A-REX answers in request order and names each job, but a per-job error
    entry may lack the id; such an entry is taken for the id at its position
    unless it names another job (:func:`_unnamed`).
    """
    # By id first: positions are only right as long as the CE kept the order,
    # and an id match cannot attach one job's outcome to another.
    by_id = {str(e["id"]): e for e in entries if isinstance(e, dict) and e.get("id")}
    for position, job_id in enumerate(chunk):
        yield job_id, by_id.get(job_id) or _unnamed(entries, position)


def _bulk_result(job_id: str, entry: dict[str, Any]) -> BulkResult:
    """One job's bulk answer as a :class:`BulkResult`; no entry at all is status 0."""
    if not entry:
        return BulkResult(job_id, 0, "The CE did not answer for this job")
    # ``action=info`` wraps the GLUE2 activity in ``info_document``; other
    # actions have none, which leaves ``info`` empty rather than failing.
    info = entry.get("info_document")
    activity = info.get("ComputingActivity", {}) if isinstance(info, dict) else {}
    return BulkResult(
        id=job_id,
        status=_int(entry.get("status-code")),
        reason=str(entry.get("reason") or ""),
        state=entry.get("state") or None,
        info=activity if isinstance(activity, dict) else {},
        delegations=tuple(str(d) for d in as_list(entry.get("delegation_id"))),
    )


def _entry_name(child: Any, url: str) -> str:
    """A listing entry's name (``""`` for an empty one, which is skipped); unsafe ones raise.

    The whole listing fails rather than skipping the entry: skipping it
    would hand back a download that silently lacks a file the job produced.
    """
    name = (child.text or "").strip()
    if name and not is_safe_name(name):
        raise ARCError(f"The CE listed an unsafe file name {name!r}", errno.EPROTO, url=url)
    return name


def _size(child: Any) -> int | None:
    """A ``file`` entry's ``size`` attribute; ``-1`` if unreadable, ``None`` if absent."""
    # -1 and None differ on purpose: absent means "the CE did not say", and
    # unreadable means it said something wrong, which a resumed download
    # must not trust as a length.
    size = child.get("size")
    return _int(size, -1) if size is not None else None


def _choose_version(offered: Sequence[str], ce: str) -> str:
    """The highest REST version both sides speak; ``EPROTONOSUPPORT`` if there is none."""
    # Our preference order decides, not the order the server lists them in.
    chosen = next((v for v in SUPPORTED_VERSIONS if v in offered), None)
    if chosen is None:
        raise ARCError(
            f"The CE offers REST versions {', '.join(offered) or 'none'}; "
            f"this client speaks {', '.join(SUPPORTED_VERSIONS)}",
            errno.EPROTONOSUPPORT,
            url=ce,
        )
    return chosen
