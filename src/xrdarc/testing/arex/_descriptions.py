"""What the fake A-REX reads from a job description: just enough to behave like a CE.

A-REX parses descriptions fully (``JobDescription::Parse``); the fake reads
only the attributes its behaviour depends on - the job's name, queue,
stdout/stderr, log directory, ``rerun`` count and delegation ids - with a
regular expression for xRSL and ElementTree for ADL, and splits a
submission into jobs as A-REX does: ``&`` is one xRSL job, ``+`` a multi-job
request split on its top-level parentheses, ``<`` ADL (one
``ActivityDescription`` or an ``ActivityDescriptions`` list). Anything else
is "Payload is not recognized". A description that does not parse fails
*per job*, as on A-REX, not the whole request.

Why not xrdarc's own xRSL parser: the fake is what that parser's output is
tested against, so it must not share its bugs. Reading a few attributes
with an independent, deliberately simple reader keeps the two honest.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from xrdcore import safexml

from ._model import _int, _unique
from ._render import _local

#: ``(delegationid = "...")`` in xRSL: the delegation a job will use. Found
#: anywhere in the text rather than only at the top level, so every id a job
#: mentions is collected: the fake needs them only to answer
#: ``action=delegations`` and to refuse deleting a delegation a job uses.
_DELEGATION_IDS = re.compile(r"delegationid\s*=\s*\"?([^\"\s()]+)", re.IGNORECASE)


@dataclass
class _Description:
    """One job's description as submitted, and its language."""

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
    """The first value of ``(attribute = value)``, quoted or not; ``""`` if absent.

    xRSL attribute names ignore case, hence ``IGNORECASE``. The three value
    forms are a double-quoted literal (``""`` inside is one ``"``), a
    single-quoted one (``''`` likewise) and a bare word, which ends at a
    blank, a parenthesis or a quote.
    """
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
    """The fields of an xRSL job, by regular expression (see the package docstring)."""
    return _Fields(
        name=_xrsl(text, "jobname"),
        queue=_xrsl(text, "queue"),
        stdout=_xrsl(text, "stdout"),
        stderr=_xrsl(text, "stderr"),
        # ``gmlog`` is xRSL's name for the log directory ADL calls LoggingDirectory.
        logdir=_xrsl(text, "gmlog"),
        # A ``rerun`` that is not a number means no restarts, not a refusal.
        rerun=_int(_xrsl(text, "rerun"), 0),
        delegations=_unique(_DELEGATION_IDS.findall(text)),
    )


def _adl_fields(text: str) -> _Fields | None:
    """The fields of an ADL ``ActivityDescription``, or ``None`` if it is not XML.

    A document that declares a document type counts as not XML: the fake
    reads XML through :mod:`xrdcore.safexml`, as every reader of the chain does.

    Elements are found by local name anywhere in the document, the first of
    each name winning, which is enough for the descriptions clients send.
    """
    try:
        root = safexml.fromstring(text)
    except (ET.ParseError, safexml.UnsafeXML):
        # ``None`` becomes the per-job "Failed to parse job description".
        return None
    values = _first_values(root)
    delegations = [
        (element.text or "").strip()
        for element in root.iter()
        if _local(element.tag) == "DelegationID"
    ]
    return _Fields(
        name=values.get("JobName", ""),
        queue=values.get("QueueName", ""),
        stdout=values.get("Output", ""),
        stderr=values.get("Error", ""),
        logdir=values.get("LoggingDirectory", ""),
        rerun=_int(values.get("Rerun", ""), 0),
        delegations=_unique([d for d in delegations if d]),
    )


def _first_values(root: ET.Element) -> dict[str, str]:
    """Each element's text by local name, the first in document order winning.

    The job's name is the ``Name`` *inside* ``ActivityIdentification``
    (stored as ``JobName``), since ``Name`` alone also names input files.
    """
    values: dict[str, str] = {}
    for element in root.iter():
        name = _local(element.tag)
        if name == "ActivityIdentification":
            names = ((c.text or "").strip() for c in element if _local(c.tag) == "Name")
            values["JobName"] = next(names, "")
        values.setdefault(name, (element.text or "").strip())
    return values


def _top_level_groups(text: str) -> list[str]:
    """The contents of each top-level ``( ... )`` group, honouring double quotes.

    Nested groups stay inside their job's text. Only double quotes protect a
    parenthesis: xrdarc's writer double-quotes every literal, and a
    single-quoted ``(`` in a hand-written test would need this reader to
    grow, not the fake to guess.
    """
    groups: list[str] = []
    depth = start = 0
    for index, char in _unquoted(text):
        if char == "(":
            depth += 1
            start = index + 1 if depth == 1 else start
        else:  # ")": _unquoted yields nothing else
            depth -= 1
            if depth == 0:
                groups.append(text[start:index].strip())
    return groups


def _unquoted(text: str) -> Iterator[tuple[int, str]]:
    """Each parenthesis of ``text`` outside double quotes, with its offset."""
    quoted = False
    for index, char in enumerate(text):
        if char == '"':
            quoted = not quoted
        elif not quoted and char in "()":
            yield index, char


def _split_adl(text: str) -> tuple[list[_Description], bool]:
    """One ADL job, or each child of an ``ActivityDescriptions`` list; and whether it was a list."""
    try:
        root = safexml.fromstring(text)
    except (ET.ParseError, safexml.UnsafeXML):
        return [_Description(text, "emies:adl")], False  # fails per job, as A-REX's does
    if _local(root.tag) != "ActivityDescriptions":
        return [_Description(text, "emies:adl")], False
    return [_Description(ET.tostring(c, encoding="unicode"), "emies:adl") for c in root], True


def _split_xrsl(text: str) -> tuple[list[_Description], bool]:
    """A single ``&`` xRSL job."""
    return [_Description(text, "nordugrid:xrsl")], False


def _split_multi_xrsl(text: str) -> tuple[list[_Description], bool]:
    """A ``+(&...)(&...)`` multi-job request: one job per top-level group."""
    # The ``+`` itself is dropped; each group's text (``&...``) is one job's.
    groups = _top_level_groups(text.lstrip()[1:])
    return [_Description(group, "nordugrid:xrsl") for group in groups], True


#: The first non-blank character of a submission -> how to split it into jobs.
_SPLITTERS: dict[str, Callable[[str], tuple[list[_Description], bool]]] = {
    "<": _split_adl,
    "&": _split_xrsl,
    "+": _split_multi_xrsl,
}
