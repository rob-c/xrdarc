"""Writing xRSL: :func:`unparse`, the canonical single-line form of one job.

The inverse of :func:`~._syntax.parse` for anything parse can produce:
``parse(unparse(job)) == [list(job)]``, which the property tests in
``tests/test_xrsl_properties.py`` check on generated jobs. Every literal is
double-quoted, so no value can be misread as syntax, and a ``(*`` inside a
value is split across a ``#`` concatenation so it never opens a comment.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._syntax import _SPECIAL, _WHITESPACE, OPERATORS, Relation, Value, _normalise


def _quote(text: str) -> str:
    """``text`` double-quoted; a ``(*`` is split across a ``#`` so it never reads as a comment."""
    pieces = text.split("(*")
    parts = [pieces[0]]
    for piece in pieces[1:]:
        parts[-1] += "("
        parts.append("*" + piece)
    return " # ".join('"' + part.replace('"', '""') + '"' for part in parts)


def _write_value(value: Value) -> str:
    """A value: a quoted literal, or a parenthesised sequence of values."""
    if isinstance(value, str):
        return _quote(value)
    return "(" + " ".join(_write_value(item) for item in value) + ")"


def _write_attribute(attribute: str) -> str:
    """An attribute name, bare where it can be (quoted if it would read as a comment or split).

    Only normalised names are accepted, since ``parse`` normalises: writing
    ``Run_Time`` would read back as ``runtime``, breaking the round trip.
    ``rslsubstitution`` would be *applied* on reading, not read back.
    """
    if (
        not attribute
        or attribute != _normalise(attribute)
        or _SPECIAL.intersection(attribute)
        or attribute == "rslsubstitution"
    ):
        raise ValueError(f"{attribute!r} cannot be written as a normalised xRSL attribute name")
    if attribute.startswith("*") or _WHITESPACE.intersection(attribute):
        return _quote(attribute)
    return attribute


def _write_relation(relation: Relation) -> str:
    """``(attribute op values...)``."""
    if relation.operator not in OPERATORS:
        raise ValueError(f"{relation.operator!r} is not an xRSL relation operator")
    head = f"{_write_attribute(relation.attribute)} {relation.operator}"
    if not relation.values:
        return f"({head})"
    return f"({head} {' '.join(_write_value(value) for value in relation.values)})"


def unparse(job: Sequence[Relation]) -> str:
    """One job as canonical single-line xRSL: ``&(executable = "/bin/echo")(arguments = "a")``.

    Every literal is double-quoted (an embedded ``"`` doubled), so
    ``parse(unparse(job)) == [list(job)]``. Raises ``ValueError`` for an
    empty job, an unknown operator, or an attribute name that is not in
    normalised form or could not be read back (``rslsubstitution`` included).
    """
    if not job:
        raise ValueError("an xRSL job needs at least one relation")
    return "&" + "".join(_write_relation(relation) for relation in job)
