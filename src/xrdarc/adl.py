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

from xrdclient._xml import UnsafeXML
from xrdclient._xml import fromstring as _xml

from .errors import DescriptionError
from .xrsl import PreparedJob, Upload

__all__ = ["ADL_NS", "NORDUGRID_NS", "is_adl", "prepare_adl"]

ADL_NS = "http://www.eu-emi.eu/es/2010/12/adl"
NORDUGRID_NS = "http://www.nordugrid.org/es/2011/12/nordugrid-adl"

_A = f"{{{ADL_NS}}}"
_N = f"{{{NORDUGRID_NS}}}"


def is_adl(text: str) -> bool:
    """The description is XML (A-REX dispatches on the first character the same way)."""
    return text.lstrip().startswith("<")


def _text(node: ET.Element | None, path: str) -> str | None:
    found = None if node is None else node.findtext(path)
    return found.strip() if found and found.strip() else None


def _local_source(uri: str | None, name: str, base: Path) -> Path | None:
    """Where the client reads an input from, or ``None`` if the CE fetches it."""
    if uri is None:
        return base / name
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme == "file":
        return Path(urllib.parse.unquote(parts.path))
    return None


def _uploads(staging: ET.Element | None, base: Path) -> tuple[list[Upload], bool, bool]:
    """Client uploads, whether the CE stages anything, and whether ``file://`` sources
    were removed (the CE must not try to fetch them itself)."""
    uploads, remote, stripped = [], False, False
    for item in [] if staging is None else staging.findall(f"{_A}InputFile"):
        name = _text(item, f"{_A}Name")
        if name is None or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            raise DescriptionError(f"ADL InputFile name {name!r} must be a relative path")
        source = _local_source(_text(item, f"{_A}Source/{_A}URI"), name, base)
        if source is None:
            remote = True
            continue
        if not source.is_file():
            raise DescriptionError(f"Input file {name} not found at {source}")
        executable = (_text(item, f"{_A}IsExecutable") or "").lower() == "true"
        uploads.append(Upload(name, source.resolve(), executable))
        for child in item.findall(f"{_A}Source"):
            item.remove(child)
            stripped = True
    targets = [] if staging is None else staging.findall(f"{_A}OutputFile/{_A}Target/{_A}URI")
    return uploads, remote or bool(targets), stripped


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
    if root.tag != f"{_A}ActivityDescription":
        raise DescriptionError(f"Expected an ADL ActivityDescription, found <{root.tag}>")
    staging = root.find(f"{_A}DataStaging")
    uploads, remote, changed = _uploads(staging, base)
    if embed_delegation and delegation_id:
        if staging is None:
            staging = ET.SubElement(root, f"{_A}DataStaging")
        if staging.find(f"{_N}DelegationID") is None:
            ET.SubElement(staging, f"{_N}DelegationID").text = delegation_id
            changed = True
    application = root.find(f"{_A}Application")
    resources = root.find(f"{_A}Resources")
    rtes = tuple(
        "-".join(filter(None, (_text(r, f"{_A}Name"), _text(r, f"{_A}Version"))))
        for r in ([] if resources is None else resources.findall(f"{_A}RuntimeEnvironment"))
    )
    wall = _text(resources, f"{_A}WallTime")
    ET.register_namespace("", ADL_NS)
    ET.register_namespace("nordugrid-adl", NORDUGRID_NS)
    return PreparedJob(
        description=ET.tostring(root, encoding="unicode") if changed else text,
        name=_text(root, f"{_A}ActivityIdentification/{_A}Name"),
        queue=_text(resources, f"{_A}QueueName"),
        stdout=_text(application, f"{_A}Output"),
        stderr=_text(application, f"{_A}Error"),
        gmlog=_text(application, f"{_N}LoggingDirectory"),
        uploads=tuple(uploads),
        runtime_environments=rtes,
        walltime=int(wall) if wall and wall.isdigit() else None,
        cputime=None,
        count=None,
        memory=None,
        rerun=None,
        remote_staging=remote,
        relations=(),
    )
