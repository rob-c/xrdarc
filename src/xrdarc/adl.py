"""EMI ADL job descriptions: sent as written, with the client's part done here.

A-REX parses ADL itself, so the document is forwarded unchanged unless the
CE only speaks REST 1.0, when the delegation has to be named inside it. What
the client has to do is find the input files it must upload: an
``InputFile`` with no ``Source`` (or a ``file://`` one) is pushed from the
submission directory into the session directory.
"""

from __future__ import annotations

import urllib.parse
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

from xrdcore.safexml import UnsafeXML
from xrdcore.safexml import fromstring as _xml

from .errors import DescriptionError
from .xrsl import PreparedJob, Upload

__all__ = ["ADL_NS", "NORDUGRID_NS", "is_adl", "prepare_adl"]

#: The EMI-ES ADL namespace. Elements are matched by namespace, never by
#: prefix: a document may bind it to any prefix, or make it the default.
ADL_NS = "http://www.eu-emi.eu/es/2010/12/adl"
#: NorduGrid's ADL extensions (``LoggingDirectory``, ``DelegationID``...).
NORDUGRID_NS = "http://www.nordugrid.org/es/2011/12/nordugrid-adl"

#: ElementTree's ``{namespace}`` tag prefixes, for ``find`` paths.
_A = f"{{{ADL_NS}}}"
_N = f"{{{NORDUGRID_NS}}}"


def is_adl(text: str) -> bool:
    """The description is XML (A-REX dispatches on the first character the same way)."""
    # Deliberately no parse here: an XML document that is not ADL must still
    # take the ADL path, so its error says "ADL" rather than an xRSL syntax error.
    return text.lstrip().startswith("<")


def _text(node: ET.Element | None, path: str) -> str | None:
    """The stripped text at ``path`` under ``node``; ``None`` for no node, no element, or blank."""
    found = None if node is None else node.findtext(path)
    return found.strip() if found and found.strip() else None


def _local_source(uri: str | None, name: str, base: Path) -> Path | None:
    """Where the client reads an input from, or ``None`` if the CE fetches it."""
    # No Source at all means "the file of that name next to the description",
    # which is how ``arcsub`` reads an ADL InputFile without one.
    if uri is None:
        return base / name
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme == "file":
        # A file URI's path is percent-encoded; the file system name is not.
        return Path(urllib.parse.unquote(parts.path))
    return None


def _uploads(staging: ET.Element | None, base: Path) -> tuple[list[Upload], bool, bool]:
    """Client uploads, whether the CE stages anything, and whether the document changed.

    A ``file://`` source is the client's to upload, so it is removed from the
    document: left in, A-REX would try to fetch a path on *its* disk. The
    CE stages something itself when any input has a remote source or any
    output a target, which is what makes a delegation necessary.
    """
    inputs = [] if staging is None else staging.findall(f"{_A}InputFile")
    uploads, remote, changed = [], False, False
    for item in inputs:
        upload = _input(item, base)
        if upload is None:
            remote = True
            continue
        uploads.append(upload)
        # Evaluated first, so every local input is stripped even once
        # ``changed`` is already true (``or`` would short-circuit it away).
        changed = _strip_sources(item) or changed
    targets = [] if staging is None else staging.findall(f"{_A}OutputFile/{_A}Target/{_A}URI")
    return uploads, remote or bool(targets), changed


def _input(item: ET.Element, base: Path) -> Upload | None:
    """One ``InputFile`` the client must upload, or ``None`` if the CE fetches it.

    The name becomes a path inside the session directory, so it must be
    relative and stay below it; a local source must exist now, not at
    upload time, so a typo stops the submission before the CE is contacted.
    """
    name = _text(item, f"{_A}Name")
    if name is None or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
        raise DescriptionError(f"ADL InputFile name {name!r} must be a relative path")
    source = _local_source(_text(item, f"{_A}Source/{_A}URI"), name, base)
    if source is None:
        return None
    if not source.is_file():
        raise DescriptionError(f"Input file {name} not found at {source}")
    executable = (_text(item, f"{_A}IsExecutable") or "").lower() == "true"
    return Upload(name, source.resolve(), executable)


def _strip_sources(item: ET.Element) -> bool:
    """Remove ``item``'s ``Source`` elements; whether there were any."""
    sources = item.findall(f"{_A}Source")
    for child in sources:
        item.remove(child)
    return bool(sources)


def prepare_adl(
    text: str, *, base: Path, delegation_id: str | None = None, embed_delegation: bool = False
) -> PreparedJob:
    """The ADL to POST and the files to upload after it.

    ``embed_delegation`` writes ``delegation_id`` into ``DataStaging`` (for
    REST 1.0, which has no ``delegation_id`` parameter) unless the document
    already names one. Raises ``DescriptionError`` for XML that is not an
    ``ActivityDescription``, unsafe XML, or a missing local input.
    """
    try:
        root = _xml(text)
    except (UnsafeXML, SyntaxError) as exc:
        raise DescriptionError(f"The ADL description is not valid XML: {exc}") from exc
    # Checked before anything else is read, so a stray XML file is reported
    # as the wrong document rather than as some missing field.
    if root.tag != f"{_A}ActivityDescription":
        raise DescriptionError(f"Expected an ADL ActivityDescription, found <{root.tag}>")
    uploads, remote, changed = _uploads(root.find(f"{_A}DataStaging"), base)
    if embed_delegation and delegation_id:
        changed = _embed_delegation(root, delegation_id) or changed
    application = root.find(f"{_A}Application")
    resources = root.find(f"{_A}Resources")
    wall = _text(resources, f"{_A}WallTime")
    # Serialising must keep the document's own prefixes readable: ADL as the
    # default namespace, the NorduGrid extension under its usual prefix.
    ET.register_namespace("", ADL_NS)
    ET.register_namespace("nordugrid-adl", NORDUGRID_NS)
    return PreparedJob(
        # The user's text, byte for byte, unless something had to change: a
        # re-serialised document loses comments and formatting the CE's
        # logs would otherwise show as written.
        description=ET.tostring(root, encoding="unicode") if changed else text,
        name=_text(root, f"{_A}ActivityIdentification/{_A}Name"),
        queue=_text(resources, f"{_A}QueueName"),
        stdout=_text(application, f"{_A}Output"),
        stderr=_text(application, f"{_A}Error"),
        gmlog=_text(application, f"{_N}LoggingDirectory"),
        uploads=tuple(uploads),
        runtime_environments=_runtime_environments(resources),
        # Only the plain-seconds form is understood here; anything else is
        # still sent, A-REX being the authority on ADL.
        walltime=int(wall) if wall and wall.isdigit() else None,
        # Not extracted from ADL: A-REX reads them from the document itself.
        cputime=None,
        count=None,
        memory=None,
        rerun=None,
        remote_staging=remote,
        relations=(),
    )


def _embed_delegation(root: ET.Element, delegation_id: str) -> bool:
    """Name the delegation in ``DataStaging`` (REST 1.0's only way); whether anything changed.

    A document that already names a delegation keeps it: the user chose it.
    """
    staging = root.find(f"{_A}DataStaging")
    if staging is None:
        staging = ET.SubElement(root, f"{_A}DataStaging")
    if staging.find(f"{_N}DelegationID") is not None:
        return False
    ET.SubElement(staging, f"{_N}DelegationID").text = delegation_id
    return True


def _runtime_environments(resources: ET.Element | None) -> tuple[str, ...]:
    """Each requested ``RuntimeEnvironment`` as ``Name-Version`` (or just the name), as in xRSL."""
    found = [] if resources is None else resources.findall(f"{_A}RuntimeEnvironment")
    return tuple(
        "-".join(filter(None, (_text(r, f"{_A}Name"), _text(r, f"{_A}Version")))) for r in found
    )
