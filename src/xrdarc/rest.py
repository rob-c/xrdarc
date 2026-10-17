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
"""

from __future__ import annotations

import errno
import json
import urllib.parse
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from xrdclient._xml import UnsafeXML
from xrdclient._xml import fromstring as _xml

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
]

#: The REST versions this client speaks, most preferred first.
SUPPORTED_VERSIONS = ("1.1", "1.0")

#: Ids per bulk request: A-REX reads at most 1 MiB of a bulk body.
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

_JSON = {"Accept": "application/json"}
_JSON_BODY = {"Accept": "application/json", "Content-Type": "application/json"}


def as_list(value: Any) -> list[Any]:
    """A field that may repeat, as a list: ``None`` and ``""`` are empty."""
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _decode(response: Response) -> dict[str, Any]:
    """The JSON object in ``response``; ``{}`` for the empty body old servers send."""
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
    entry = entries[position] if position < len(entries) else None
    return entry if isinstance(entry, dict) and not entry.get("id") else {}


def _session_path(path: str) -> str:
    """``path`` inside a session directory, percent-encoded; ``..`` is refused."""
    parts = [p for p in PurePosixPath(path).parts if p not in ("/", ".")]
    if ".." in parts:
        raise ARCError(f"Refusing a session path outside the job: {path!r}", errno.EINVAL)
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
        return self.status == 201 and self.id is not None


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
        if self._version is None:
            offered = self.versions()
            chosen = next((v for v in SUPPORTED_VERSIONS if v in offered), None)
            if chosen is None:
                raise ARCError(
                    f"The CE offers REST versions {', '.join(offered) or 'none'}; "
                    f"this client speaks {', '.join(SUPPORTED_VERSIONS)}",
                    errno.EPROTONOSUPPORT,
                    url=self.ce,
                )
            self._version = chosen
        return self._version

    @property
    def base(self) -> str:
        return f"{self.ce}/rest/{self.version}"

    def _url(self, path: str, **query: str | None) -> str:
        params = {k: v for k, v in query.items() if v is not None}
        suffix = f"?{urllib.parse.urlencode(params)}" if params else ""
        return f"{self.base}/{path}{suffix}"

    # -- information -------------------------------------------------------

    def info(self) -> dict[str, Any]:
        """The CE's GLUE2 document, as JSON (``GET info``)."""
        return _decode(self.session.request("GET", self._url("info"), headers=_JSON))

    def jobs(self, states: Iterable[str] = ()) -> list[tuple[str, str | None]]:
        """The ids of this user's jobs on the CE, with states when filtered by them."""
        wanted = ",".join(states) or None
        doc = _decode(self.session.request("GET", self._url("jobs", state=wanted), headers=_JSON))
        found = []
        for entry in as_list(doc.get("job")):
            if isinstance(entry, dict) and entry.get("id"):
                found.append((str(entry["id"]), entry.get("state")))
        return found

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
        if self.version != "1.0":
            extra = {
                "queue": queue,
                "delegation_id": delegation_id,
                "instances": None if instances is None else str(instances),
                "instances_min": None if instances_min is None else str(instances_min),
            }
        body = description.encode() if isinstance(description, str) else description
        response = self.session.request(
            "POST",
            self._url("jobs", action="new", **extra),
            body=body,
            headers={"Accept": "application/json", "Content-Type": "application/xml"},
            expect=(201,),
        )
        results = []
        for entry in as_list(_decode(response).get("job")):
            fields = entry if isinstance(entry, dict) else {}
            results.append(
                SubmitResult(
                    status=_int(fields.get("status-code")),
                    reason=str(fields.get("reason") or ""),
                    id=str(fields["id"]) if fields.get("id") else None,
                    state=fields.get("state") or None,
                )
            )
        return results

    def _bulk(self, action: str, ids: Sequence[str]) -> Iterator[tuple[str, dict[str, Any]]]:
        for start in range(0, len(ids), BULK_CHUNK):
            chunk = list(ids[start : start + BULK_CHUNK])
            body = json.dumps({"job": [{"id": str(i)} for i in chunk]}).encode()
            response = self.session.request(
                "POST",
                self._url("jobs", action=action),
                body=body,
                headers=_JSON_BODY,
                expect=(200, 201),
            )
            entries = as_list(_decode(response).get("job"))
            by_id = {str(e["id"]): e for e in entries if isinstance(e, dict) and e.get("id")}
            for position, job_id in enumerate(chunk):
                yield job_id, by_id.get(job_id) or _unnamed(entries, position)

    def bulk(self, action: str, ids: Sequence[str]) -> list[BulkResult]:
        """``POST jobs?action=<action>`` for ``ids``, one result per id, in order.

        An id the CE left out of its answer gets status 0 and an explanatory reason.
        """
        results = []
        for job_id, entry in self._bulk(action, ids):
            if not entry:
                results.append(BulkResult(job_id, 0, "The CE did not answer for this job"))
                continue
            info = entry.get("info_document")
            activity = info.get("ComputingActivity", {}) if isinstance(info, dict) else {}
            results.append(
                BulkResult(
                    id=job_id,
                    status=_int(entry.get("status-code")),
                    reason=str(entry.get("reason") or ""),
                    state=entry.get("state") or None,
                    info=activity if isinstance(activity, dict) else {},
                    delegations=tuple(str(d) for d in as_list(entry.get("delegation_id"))),
                )
            )
        return results

    def status(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("status", ids)

    def job_info(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("info", ids)

    def kill(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("kill", ids)

    def clean(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("clean", ids)

    def restart(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("restart", ids)

    def job_delegations(self, ids: Sequence[str]) -> list[BulkResult]:
        return self.bulk("delegations", ids)

    # -- session directory and diagnostics ------------------------------------

    def session_url(self, job_id: str, path: str = "") -> str:
        quoted = _session_path(path)
        job = urllib.parse.quote(job_id, safe="")
        return f"{self.base}/jobs/{job}/session" + (f"/{quoted}" if quoted else "")

    def listing(self, job_id: str, path: str = "") -> Listing:
        """One level of the session directory, with file sizes (asked for as XML)."""
        response = self.session.request(
            "GET", self.session_url(job_id, path) + "/", headers={"Accept": "application/xml"}
        )
        try:
            root = _xml(response.body)
        except (UnsafeXML, SyntaxError) as exc:
            raise ARCError(
                "The CE sent an unreadable directory listing", errno.EPROTO, url=response.url
            ) from exc
        files: dict[str, int | None] = {}
        dirs = []
        for child in root:
            name = (child.text or "").strip()
            if not name:
                continue
            if child.tag == "dir":
                dirs.append(name)
            elif child.tag == "file":
                size = child.get("size")
                files[name] = _int(size, -1) if size is not None else None
        return Listing(files, tuple(dirs))

    def walk(self, job_id: str, path: str = "") -> Iterator[tuple[str, int | None]]:
        """Every file under ``path`` in the session directory, depth first."""
        level = self.listing(job_id, path)
        prefix = f"{path.strip('/')}/" if path.strip("/") else ""
        for name, size in level.files.items():
            yield prefix + name, size
        for name in level.dirs:
            yield from self.walk(job_id, prefix + name)

    def get_file(self, job_id: str, path: str, target: Path) -> int:
        return self.session.download(self.session_url(job_id, path), target)

    def read_file(self, job_id: str, path: str) -> bytes:
        return self.session.request("GET", self.session_url(job_id, path)).body

    def stream_file(self, job_id: str, path: str, out: BinaryIO) -> int:
        return self.session.copy_to(self.session_url(job_id, path), out)

    def put_file(self, job_id: str, path: str, source: Path) -> int:
        if not _session_path(path):
            raise ARCError("An upload needs a file name", errno.EINVAL)
        return self.session.upload(self.session_url(job_id, path), source)

    def delete_file(self, job_id: str, path: str) -> None:
        if not _session_path(path):
            raise ARCError("Refusing to delete the whole session directory", errno.EINVAL)
        self.session.request("DELETE", self.session_url(job_id, path), expect=(200, 202, 204))

    def diagnose(self, job_id: str, item: str) -> bytes:
        """One of A-REX's per-job control files (``DIAGNOSE_ITEMS``)."""
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
            if isinstance(entry, dict) and entry.get("id"):
                found.append((str(entry["id"]), str(entry.get("type") or "x509")))
        return found

    @staticmethod
    def _delegation_id(response: Response) -> str:
        location = response.headers.get("Location") or response.headers.get("location") or ""
        found = urllib.parse.urlsplit(location).path.rstrip("/").rpartition("/")[2]
        if not found:
            raise ARCError(
                "The CE created a delegation but did not say where", errno.EPROTO, url=response.url
            )
        return found

    def new_delegation(self) -> tuple[str, str]:
        """Ask for a new X.509 delegation slot: ``(id, PEM certificate request)``."""
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
        response = self.session.request(
            "POST",
            self._url("delegations", action="new", type="jwt"),
            headers={"X-Token-Delegation": token},
            expect=(201,),
        )
        return self._delegation_id(response)

    def _delegation_url(self, delegation_id: str, action: str | None = None) -> str:
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
        url = self._delegation_url(delegation_id, "delete")
        self.session.request("POST", url, expect=(200, 202, 204))
