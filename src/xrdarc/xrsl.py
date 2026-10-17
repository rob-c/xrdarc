"""xRSL, NorduGrid's job description language: parsed, written and made ready to submit.

The grammar is ARC's ``RSLParser.cpp``: ``&`` joins relations into one job,
``+`` lists several jobs, values are literals or parenthesised sequences,
``#`` (or plain adjacency) concatenates, ``$(NAME)`` reads a variable bound
by ``rsl_substitution`` and ``(* ... *)`` is a comment. Attribute names are
case-insensitive and ignore underscores; values keep their case.

People write the *user* dialect (``walltime="90"`` means ninety minutes,
``join="yes"`` merges the error stream); A-REX reads the *GRIDMANAGER*
dialect (times in seconds, no ``join``). :func:`prepare` turns one into the
other the way ``XRSLParser`` and ``JobDescription::Prepare`` do in the C++
client, and lists the local files the client must upload into the session
directory after submitting.

Everything that is wrong with a description raises
:class:`~xrdarc.errors.DescriptionError`; syntax errors give the line and
column (both counted from 1).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypeAlias
from urllib.parse import unquote, urlsplit

from .errors import DescriptionError

__all__ = [
    "PreparedJob",
    "Relation",
    "Upload",
    "Value",
    "parse",
    "parse_period",
    "prepare",
    "unparse",
]

#: A literal, or a parenthesised sequence of values.
Value: TypeAlias = str | tuple["Value", ...]

OPERATORS = ("=", "!=", "<", "<=", ">", ">=")

#: Characters that end an unquoted literal (with whitespace) and that no
#: attribute or variable name may contain, even quoted.
_SPECIAL = frozenset("+&|()=<>!\"'^#$")
_WHITESPACE = frozenset(" \t\n\v\f\r")
_UNQUOTED_END = _SPECIAL | _WHITESPACE

_DISJUNCTION = "client-side brokering with '|' is not supported; submit each alternative separately"


@dataclass(frozen=True, slots=True)
class Relation:
    """One ``(attribute operator values...)`` of a job.

    ``attribute`` is normalised as ARC does it (lower case, underscores
    removed), so ``RunTime_Environment`` and ``runtimeenvironment`` compare
    equal. ``values`` may be empty: ``(arguments=)`` is legal.
    """

    attribute: str
    operator: str
    values: tuple[Value, ...]


# --- syntax tree --------------------------------------------------------------------------------
# Parsing and evaluation are separate passes, as in ARC, so a syntax error
# anywhere is reported before a problem with a variable or a concatenation.


@dataclass(frozen=True, slots=True)
class _Literal:
    text: str
    pos: int


@dataclass(frozen=True, slots=True)
class _Variable:
    name: str
    pos: int


@dataclass(frozen=True, slots=True)
class _Concat:
    left: _Term
    right: _Term
    pos: int


@dataclass(frozen=True, slots=True)
class _Sequence:
    items: tuple[_Term, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class _Condition:
    attribute: str
    operator: str
    values: tuple[_Term, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class _Boolean:
    operator: str
    children: tuple[_Node, ...]
    pos: int


_Term: TypeAlias = _Literal | _Variable | _Concat | _Sequence
_Node: TypeAlias = _Condition | _Boolean

# How the next value in a list relates to the one before it.
_SEPARATE, _EXPLICIT, _IMPLICIT = 0, 1, 2


def _location(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    return line, pos - (text.rfind("\n", 0, pos) + 1) + 1


def _syntax_error(text: str, pos: int, what: str) -> DescriptionError:
    line, column = _location(text, pos)
    return DescriptionError(f"xRSL syntax error at line {line}, column {column}: {what}")


def _normalise(attribute: str) -> str:
    return attribute.lower().replace("_", "")


def _scan_comments(text: str) -> dict[int, int]:
    """Where each comment starts and ends, found ignoring quotes as ARC does.

    A ``(*`` inside a quoted value therefore still needs a later ``*)``, and
    the ``*)`` is searched for from the ``(`` itself, so ``(*)`` is a whole
    comment.
    """
    comments: dict[int, int] = {}
    start = text.find("(*")
    while start != -1:
        end = text.find("*)", start)
        if end == -1:
            raise _syntax_error(text, start, "comment '(*' is never closed with '*)'")
        comments[start] = end + 2
        start = text.find("(*", end + 2)
    return comments


class _Parser:
    """A recursive-descent reading of ``RSLParser``; ``pos`` walks ``text``."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.comments = _scan_comments(text)

    def fail(self, what: str, pos: int | None = None) -> DescriptionError:
        return _syntax_error(self.text, self.pos if pos is None else pos, what)

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def found(self) -> str:
        char = self.peek()
        return f"found {char!r}" if char else "but the description ended"

    def skip(self) -> None:
        """Skip whitespace and comments; a comment counts only where it starts."""
        while True:
            start = self.pos
            while self.pos < len(self.text) and self.text[self.pos] in _WHITESPACE:
                self.pos += 1
            self.pos = self.comments.get(self.pos, self.pos)
            if self.pos == start:
                return

    def expect(self, char: str) -> None:
        if self.peek() != char:
            raise self.fail(f"expected {char!r}, {self.found()}")
        self.pos += 1

    def rsl(self) -> _Node:
        self.skip()
        start, char = self.pos, self.peek()
        if char and char in "&|+":
            self.pos += 1
            return self.boolean(char, start)
        return self.condition()

    def boolean(self, operator: str, start: int) -> _Boolean:
        self.skip()
        children: list[_Node] = []
        while True:
            self.expect("(")
            children.append(self.rsl())
            self.skip()
            self.expect(")")
            self.skip()
            if self.peek() != "(":
                return _Boolean(operator, tuple(children), start)

    def condition(self) -> _Condition:
        start = self.pos
        attribute = self.string()
        if not attribute:
            raise self.fail(f"expected an attribute name or '&', '|', '+', {self.found()}", start)
        if _SPECIAL.intersection(attribute):
            raise self.fail(f"attribute name {attribute!r} contains one of {_special()}", start)
        self.skip()
        operator = self.operator()
        if operator is None:
            raise self.fail(
                f"expected a relation operator ({', '.join(OPERATORS)}), {self.found()}"
            )
        self.skip()
        return _Condition(_normalise(attribute), operator, self.values(), start)

    def operator(self) -> str | None:
        for operator in ("!=", "<=", ">=", "=", "<", ">"):
            if self.text.startswith(operator, self.pos):
                self.pos += len(operator)
                return operator
        return None

    def string(self) -> str | None:
        """A quoted or bare literal at ``pos``; None when there is none here."""
        char = self.peek()
        if char and char in "\"'":
            return self.quoted(self.pos)
        if char == "^":
            if self.pos + 1 >= len(self.text):
                raise self.fail("'^' must be followed by the delimiter character of a string")
            self.pos += 1
            return self.quoted(self.pos - 1)
        end = self.pos
        while end < len(self.text) and self.text[end] not in _UNQUOTED_END:
            end += 1
        word, self.pos = self.text[self.pos : end], end
        return word or None

    def quoted(self, start: int) -> str:
        """The string whose delimiter is at ``pos``; a doubled delimiter is literal."""
        delimiter = self.text[self.pos]
        parts: list[str] = []
        while True:
            close = self.text.find(delimiter, self.pos + 1)
            if close == -1:
                raise self.fail(f"string is never closed (no matching {delimiter!r})", start)
            parts.append(self.text[self.pos + 1 : close])
            self.pos = close + 1
            if self.peek() != delimiter:
                return delimiter.join(parts)

    def values(self) -> tuple[_Term, ...]:
        """A value list, folding ``a # b`` and ``a$(B)"c"`` into concatenations.

        Whitespace or a comment between two values keeps them separate unless
        a ``#`` joins them; adjacency joins them.
        """
        values: list[_Term] = []
        left: _Term | None = None
        mode = _SEPARATE
        while True:
            before = self.pos
            self.skip()
            if self.pos != before:
                mode = _SEPARATE
            at = self.pos
            if self.peek() == "#":
                self.pos += 1
                self.skip()
                mode = _EXPLICIT
            right, follow = self.term()
            left = self.combine(values, left, right, mode, at)
            mode = follow
            if left is None and right is None:
                return tuple(values)

    def combine(
        self, values: list[_Term], left: _Term | None, right: _Term | None, mode: int, at: int
    ) -> _Term | None:
        if mode == _EXPLICIT:
            if left is None:
                raise self.fail("'#' has nothing on its left to concatenate", at)
            if right is None:
                raise self.fail(f"'#' has nothing on its right to concatenate, {self.found()}")
            return _Concat(left, right, at)
        if mode == _IMPLICIT and left is not None:
            return left if right is None else _Concat(left, right, at)
        if left is not None:
            values.append(left)
        return right

    def term(self) -> tuple[_Term | None, int]:
        start, char = self.pos, self.peek()
        if char == "(":
            self.pos += 1
            items = self.values()
            self.skip()
            self.expect(")")
            return _Sequence(items, start), _SEPARATE
        if char == "$":
            return self.variable(start), _IMPLICIT
        text = self.string()
        if text is None:
            return None, _SEPARATE
        return _Literal(text, start), _IMPLICIT

    def variable(self, start: int) -> _Variable:
        self.pos += 1
        self.skip()
        self.expect("(")
        self.skip()
        at = self.pos
        name = self.string()
        if name is None:
            raise self.fail(f"expected a variable name after '$(', {self.found()}")
        if _SPECIAL.intersection(name):
            raise self.fail(f"variable name {name!r} contains one of {_special()}", at)
        self.skip()
        self.expect(")")
        return _Variable(name, start)


def _special() -> str:
    return "".join(sorted(_SPECIAL))


# --- evaluation ---------------------------------------------------------------------------------


def _jobs(text: str, node: _Node) -> list[list[Relation]]:
    """The jobs under a top-level node: ``+`` lists them (nesting flattens), ``&`` is one."""
    if isinstance(node, _Boolean) and node.operator == "+":
        return [job for child in node.children for job in _jobs(text, child)]
    if isinstance(node, _Boolean) and node.operator == "&":
        return [_conjunction(text, node, {})]
    if isinstance(node, _Boolean):
        raise _syntax_error(text, node.pos, _DISJUNCTION)
    raise _syntax_error(
        text, node.pos, "a job must be an '&' conjunction such as &(executable=...)(...)"
    )


def _conjunction(text: str, node: _Boolean, scope: dict[str, str]) -> list[Relation]:
    """The relations of an ``&``, with nested ``&`` flattened into it.

    Variables bound here are seen by the following siblings and everything
    inside them, never by the enclosing ``&``: each conjunction starts from
    a copy of its parent's bindings.
    """
    scope = dict(scope)
    relations: list[Relation] = []
    for child in node.children:
        if isinstance(child, _Condition):
            relation = _relation(text, child, scope)
            if relation is not None:
                relations.append(relation)
        elif child.operator == "&":
            relations.extend(_conjunction(text, child, scope))
        elif child.operator == "|":
            raise _syntax_error(text, child.pos, _DISJUNCTION)
        else:
            raise _syntax_error(text, child.pos, "'+' (several jobs) is only allowed at the top")
    return relations


def _relation(text: str, node: _Condition, scope: dict[str, str]) -> Relation | None:
    if node.attribute == "rslsubstitution":
        _substitute(text, node, scope)
        return None
    values = tuple(_value(text, term, scope) for term in node.values)
    return Relation(node.attribute, node.operator, values)


def _substitute(text: str, node: _Condition, scope: dict[str, str]) -> None:
    """Bind each ``(NAME value)`` pair in turn, so a later pair may use an earlier one."""
    for term in node.values:
        if not isinstance(term, _Sequence):
            raise _syntax_error(text, term.pos, "rsl_substitution expects (NAME value) pairs")
        if len(term.items) != 2:
            raise _syntax_error(
                text,
                term.pos,
                f"an rsl_substitution pair needs 2 elements (NAME value), not {len(term.items)}",
            )
        name = _literal(text, term.items[0], scope, "an rsl_substitution variable name")
        scope[name] = _literal(text, term.items[1], scope, "an rsl_substitution value")


def _literal(text: str, term: _Term, scope: dict[str, str], what: str) -> str:
    value = _value(text, term, scope)
    if not isinstance(value, str):
        raise _syntax_error(text, term.pos, f"{what} must be a string, not a sequence")
    return value


def _value(text: str, term: _Term, scope: dict[str, str]) -> Value:
    if isinstance(term, _Literal):
        return term.text
    if isinstance(term, _Variable):
        return scope.get(term.name, "")
    if isinstance(term, _Concat):
        left = _literal(text, term.left, scope, "the left side of a concatenation")
        return left + _literal(text, term.right, scope, "the right side of a concatenation")
    return tuple(_value(text, item, scope) for item in term.items)


def parse(text: str) -> list[list[Relation]]:
    """The jobs in an xRSL description, one list of relations per job.

    ``&(...)`` is one job; ``+(&(...))(&(...))`` is several, each an ``&``
    conjunction. ``&`` nested in ``&`` is flattened. ``rsl_substitution``
    relations are applied (and removed) and every ``$(NAME)`` is replaced by
    its value, or by ``""`` when unbound, as ARC does; concatenations are
    folded into single strings and comments dropped.

    Raises ``DescriptionError`` with the line and column for an empty
    description, a syntax error, text after the end of the description, a
    ``|`` disjunction (it needs client-side brokering), a ``+`` below the
    top level, or a concatenation or substitution involving a sequence.
    """
    parser = _Parser(text)
    parser.skip()
    if parser.pos == len(text):
        raise parser.fail("the description is empty")
    root = parser.rsl()
    parser.skip()
    if parser.pos != len(text):
        raise parser.fail(f"unexpected text after the end of the description, {parser.found()}")
    return _jobs(text, root)


# --- writing ------------------------------------------------------------------------------------


def _quote(text: str) -> str:
    """``text`` double-quoted; a ``(*`` is split across a ``#`` so it never reads as a comment."""
    pieces = text.split("(*")
    parts = [pieces[0]]
    for piece in pieces[1:]:
        parts[-1] += "("
        parts.append("*" + piece)
    return " # ".join('"' + part.replace('"', '""') + '"' for part in parts)


def _write_value(value: Value) -> str:
    if isinstance(value, str):
        return _quote(value)
    return "(" + " ".join(_write_value(item) for item in value) + ")"


def _write_attribute(attribute: str) -> str:
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


# --- time periods -------------------------------------------------------------------------------

_MINUTE, _HOUR, _DAY, _WEEK = 60, 3600, 86400, 604800
_MONTH, _YEAR = 2592000, 31536000

#: A bare number's unit, as (multiplier, divisor) applied to it.
_BASES = {"seconds": (1, 1), "minutes": (_MINUTE, 1)}

#: Free-format unit letter -> (seconds, unit of a bare number that follows it).
_FREE_UNITS = {
    letter: unit
    for key, unit in {
        "w": (_WEEK, (_DAY, 1)),
        "d": (_DAY, (_HOUR, 1)),
        "h": (_HOUR, (_MINUTE, 1)),
        "m": (_MINUTE, (1, 1)),
        "s": (1, (1, 1000)),
    }.items()
    for letter in (key, key.upper())
}
_FREE_TOKEN = re.compile(r"([0-9]+) *([^0-9 ]?)")

_ISO_UNITS = {"Y": _YEAR, "W": _WEEK, "D": _DAY, "H": _HOUR, "S": 1}
_ISO_TOKEN = re.compile(r"T|([0-9]+)(.)", re.DOTALL)


def _period_error(text: str, why: str) -> DescriptionError:
    return DescriptionError(f"Invalid time period {text!r}: {why}")


def _iso_period(text: str) -> int:
    """ARC's ISO 8601 reading: ``M`` is months until a ``T``, ``W``, ``D``, ``H`` or ``M``.

    Components may come in any order and ``T`` anywhere, as in ARC.
    """
    seconds, minutes, components, pos = 0, False, 0, 1
    while pos < len(text):
        match = _ISO_TOKEN.match(text, pos)
        if match is None:
            raise _period_error(text, f"expected a number and a unit at {text[pos:]!r}")
        pos = match.end()
        if match[0] == "T":
            minutes = True
            continue
        number, unit = int(match[1]), match[2]
        if unit == "M":
            seconds += number * (_MINUTE if minutes else _MONTH)
        elif unit in _ISO_UNITS:
            seconds += number * _ISO_UNITS[unit]
        else:
            raise _period_error(text, f"unknown ISO 8601 unit {unit!r}")
        minutes = minutes or unit in "WDHM"
        components += 1
    if not components:
        raise _period_error(text, "an ISO 8601 duration needs at least one component")
    return seconds


def _free_period(text: str, base: tuple[int, int]) -> int:
    """ARC's free format: numbers with ``w d h m s`` units, anything else after a unit ignored.

    So ``"60 minutes"`` is an hour and ``"1h30"`` ninety minutes: a final bare
    number takes the unit below the last one given, or ``base`` if none was.
    """
    seconds = 0
    tokens = list(_FREE_TOKEN.finditer(text))
    if not tokens:
        raise _period_error(text, "no number in it")
    for token in tokens:
        number, unit = int(token[1]), token[2]
        if unit in _FREE_UNITS:
            size, base = _FREE_UNITS[unit]
            seconds += number * size
        elif unit:
            raise _period_error(text, f"unknown unit {unit!r} after {token[1]}")
        elif token.end() != len(text):
            # ARC reads "5 5m" as 5 minutes and "5 5" as nothing: refuse both.
            raise _period_error(text, "two numbers separated only by spaces")
        else:
            seconds += number * base[0] // base[1]
    return seconds


def parse_period(text: str, default: str = "minutes") -> int:
    """A duration in whole seconds, read exactly as ARC's ``Period`` reads it.

    ``P...`` is ISO 8601 (``PT1H30M``; ``P1M`` is a 30-day month); anything
    else is the free format (``1h30``, ``2d 3h``, ``60 minutes``), where a
    number with no unit at all is in ``default`` (``"minutes"`` for the user
    dialect, ``"seconds"`` for the CE's). Where ARC logs an error and returns
    zero, or silently misreads digits split by spaces, this raises
    ``DescriptionError``; an unknown ``default`` is a ``ValueError``.
    """
    if default not in _BASES:
        raise ValueError(f"default must be 'seconds' or 'minutes', not {default!r}")
    if text.startswith("P"):
        return _iso_period(text)
    return _free_period(text, _BASES[default])


# --- preparing jobs for submission --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Upload:
    """A local file the client must PUT to ``<job>/session/<name>`` after submitting."""

    name: str
    source: Path
    executable: bool


@dataclass(frozen=True, slots=True)
class PreparedJob:
    """One job rewritten for the CE, with what the client must do around it.

    ``description`` is the GRIDMANAGER-dialect xRSL to POST (``unparse`` of
    ``relations``); times are in seconds and memory in MB, as the CE reads
    them. ``remote_staging`` says the CE itself will fetch or store files
    (an input with a URL source or an output with a URL target), which
    needs a delegated credential.
    """

    description: str
    name: str | None
    queue: str | None
    stdout: str | None
    stderr: str | None
    gmlog: str | None
    uploads: tuple[Upload, ...]
    runtime_environments: tuple[str, ...]
    walltime: int | None
    cputime: int | None
    count: int | None
    memory: int | None
    rerun: int | None
    remote_staging: bool
    relations: tuple[Relation, ...]


#: Attributes A-REX writes for itself; a user description must not carry them.
_INTERNAL = ("action", "hostname", "jobid", "clientxrsl", "clientsoftware", "savestate")

_NORMALISED_TIME = (
    "is normalised CPU time, which needs client-side brokering against the CE's "
    "benchmarks and is not supported; give 'cputime' or 'walltime' instead"
)
_URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_WHOLE_NUMBER = re.compile(r"[0-9]+")


class _Job:
    """The relations of one job, edited in place while it is prepared."""

    def __init__(self, relations: Sequence[Relation]) -> None:
        self.relations = list(relations)

    def all(self, attribute: str) -> list[Relation]:
        return [relation for relation in self.relations if relation.attribute == attribute]

    def single(self, attribute: str) -> str | None:
        """The one string value of ``attribute``; None when it is absent."""
        found = self.all(attribute)
        if not found:
            return None
        if len(found) > 1:
            raise DescriptionError(f"Attribute '{attribute}' is given more than once")
        values = found[0].values
        if len(values) != 1 or not isinstance(values[0], str):
            raise DescriptionError(f"Attribute '{attribute}' must have exactly one string value")
        return values[0]

    def put(self, attribute: str, values: tuple[Value, ...]) -> None:
        """Replace the first ``attribute`` (keeping its place and operator) or append one."""
        kept: list[Relation] = []
        placed = False
        for relation in self.relations:
            if relation.attribute != attribute:
                kept.append(relation)
            elif not placed:
                kept.append(replace(relation, values=values))
                placed = True
        if not placed:
            kept.append(Relation(attribute, "=", values))
        self.relations = kept

    def drop(self, attribute: str) -> None:
        self.relations = [
            relation for relation in self.relations if relation.attribute != attribute
        ]


def _refuse_unsupported(job: _Job) -> None:
    for relation in job.relations:
        if relation.attribute in _INTERNAL:
            raise DescriptionError(
                f"Attribute '{relation.attribute}' is set by the CE itself and cannot appear "
                "in a job description"
            )
        if relation.attribute in ("gridtime", "benchmarks"):
            raise DescriptionError(f"Attribute '{relation.attribute}' {_NORMALISED_TIME}")


def _convert_time(job: _Job, attribute: str) -> int | None:
    """Rewrite a user-dialect time (bare number = minutes) as seconds for the CE."""
    text = job.single(attribute)
    if text is None:
        return None
    try:
        seconds = parse_period(text, "minutes")
    except DescriptionError as exc:
        raise DescriptionError(f"Attribute '{attribute}': {exc.user_message}") from None
    job.put(attribute, (str(seconds),))
    return seconds


def _integer(job: _Job, attribute: str) -> int | None:
    text = job.single(attribute)
    if text is None:
        return None
    if not _WHOLE_NUMBER.fullmatch(text):
        raise DescriptionError(f"Attribute '{attribute}' must be a whole number, not {text!r}")
    return int(text)


def _resolve_join(job: _Job) -> tuple[str | None, str | None]:
    """Apply and remove ``join``: the CE ignores it, so stderr is pointed at stdout here."""
    stdout, stderr = job.single("stdout"), job.single("stderr")
    join = job.single("join")
    job.drop("join")
    if join is None or join.lower() not in ("yes", "true"):
        return stdout, stderr
    if not stdout:
        raise DescriptionError("Attribute 'join' needs 'stdout' to be given as well")
    if stderr and stderr != stdout:
        raise DescriptionError("Attribute 'join' cannot be used when 'stderr' names another file")
    job.put("stderr", (stdout,))
    return stdout, stdout


def _runtime_environments(job: _Job) -> tuple[str, ...]:
    """The RTE names; further values of a relation are options and stay in the description."""
    names: list[str] = []
    for relation in job.all("runtimeenvironment"):
        if not relation.values or not all(isinstance(v, str) for v in relation.values):
            raise DescriptionError("Attribute 'runtimeenvironment' needs a name and string options")
        if relation.operator != "=":
            raise DescriptionError(
                f"Runtime environment {relation.values[0]!r} is requested with "
                f"{relation.operator!r}: only '=' can be sent to the CE (version ranges need "
                "client-side brokering)"
            )
        names.append(str(relation.values[0]))
    return tuple(names)


def _only_equals(job: _Job, attribute: str) -> None:
    for relation in job.all(attribute):
        if relation.operator != "=":
            raise DescriptionError(
                f"Attribute '{attribute}' only takes '=' when sent to a CE, "
                f"not {relation.operator!r}"
            )


def _queue(job: _Job, default: str | None) -> str | None:
    _only_equals(job, "queue")
    name = job.single("queue")
    if name is None and default:
        job.put("queue", (default,))
        return default
    return name


def _delegation(job: _Job, delegation_id: str | None) -> None:
    _only_equals(job, "delegationid")
    if delegation_id and not job.all("delegationid"):
        job.put("delegationid", (delegation_id,))


def _is_local_relative(path: str) -> bool:
    """A path the client uploads: not absolute on the worker node, not an environment reference."""
    return bool(path) and not path.startswith(("/", "$"))


def _entries(job: _Job, attribute: str) -> list[tuple[str, ...]]:
    """Every ``(name location [options...])`` of ``attribute``, across all its relations."""
    entries: list[tuple[str, ...]] = []
    for relation in job.all(attribute):
        for value in relation.values:
            if (
                isinstance(value, str)
                or len(value) < 2
                or not all(isinstance(item, str) for item in value)
            ):
                raise DescriptionError(
                    f"Each '{attribute}' entry must be a sequence of strings "
                    f"(name location [options...]), not {value!r}"
                )
            entry = tuple(str(item) for item in value)
            if not entry[0]:
                raise DescriptionError(f"An '{attribute}' entry has an empty file name")
            entries.append(entry)
    return entries


def _session_name(name: str) -> str:
    if name.startswith("/") or ".." in name.split("/"):
        raise DescriptionError(
            f"Input file name {name!r} must be a relative path inside the session directory"
        )
    return name


def _is_remote(location: str) -> bool:
    match = _URL.match(location)
    return match is not None and match[1].lower() != "file"


def _local_path(name: str, source: str, base: Path) -> Path:
    """The local file behind an input whose source is empty, a path or a ``file://`` URL."""
    if _URL.match(source):
        parts = urlsplit(source)
        if parts.netloc not in ("", "localhost"):
            raise DescriptionError(f"Input file {name!r}: {source!r} names another host")
        path = Path(unquote(parts.path))
    else:
        path = base / (source or name)
    path = path.absolute()
    if not path.is_file():
        raise DescriptionError(
            f"Input file {name!r}: {str(path)!r} does not exist or is not a file"
        )
    return path


class _Inputs:
    """The job's input files: remote ones as written, local ones as uploads."""

    def __init__(self, entries: list[tuple[str, ...]], base: Path) -> None:
        self.base = base
        self.entries: list[tuple[str, ...]] = []
        self.sources: dict[str, Path] = {}
        self.remote = False
        for entry in entries:
            self.add(entry)

    def add(self, entry: tuple[str, ...]) -> None:
        name = _session_name(entry[0])
        if any(existing[0] == name for existing in self.entries):
            raise DescriptionError(f"Two input files are both named {name!r}")
        if _is_remote(entry[1]):
            self.remote = True
            self.entries.append(entry)
            return
        # The CE expects the client to upload it: the source it sees is "".
        self.sources[name] = _local_path(name, entry[1], self.base)
        self.entries.append((name, ""))

    def ensure(self, name: str) -> None:
        if not any(entry[0] == name for entry in self.entries):
            self.add((name, ""))

    def uploads(self, executables: Sequence[str]) -> tuple[Upload, ...]:
        return tuple(
            Upload(name, source, name in executables) for name, source in self.sources.items()
        )


def _executables(job: _Job, inputs: _Inputs, executable: str) -> list[str]:
    """The names to make executable, with a relative ``executable`` added to them."""
    names: list[str] = []
    for relation in job.all("executables"):
        for value in relation.values:
            if not isinstance(value, str):
                raise DescriptionError(f"Attribute 'executables' lists names, not {value!r}")
            names.append(value)
    if _is_local_relative(executable) and executable not in names:
        names.append(executable)
    known = {entry[0] for entry in inputs.entries}
    for name in names:
        if name not in known:
            raise DescriptionError(f"File {name!r} in 'executables' is not one of the input files")
    if names:
        job.put("executables", tuple(names))
    return names


def _outputs(job: _Job, wanted: Sequence[str | None], gmlog: str | None) -> bool:
    """Add stdout, stderr and the gmlog directory to the outputs; True if any output is remote."""
    entries: list[Value] = list(_entries(job, "outputfiles"))
    remote = any(_is_remote(str(entry[1])) for entry in entries)
    names = {str(entry[0]).rstrip("/") for entry in entries}
    added = [name for name in wanted if name] + ([gmlog.rstrip("/") + "/"] if gmlog else [])
    for name in added:
        if name.rstrip("/") not in names:
            names.add(name.rstrip("/"))
            entries.append((name, ""))
    if entries:
        job.put("outputfiles", tuple(entries))
    return remote


def _stage(
    job: _Job, base: Path, stdout: str | None, stderr: str | None
) -> tuple[tuple[Upload, ...], bool]:
    """Complete the data staging as ``JobDescription::Prepare`` does."""
    executable = job.single("executable")
    if not executable:
        raise DescriptionError("The job description has no 'executable'")
    had_inputs = bool(job.all("inputfiles"))
    inputs = _Inputs(_entries(job, "inputfiles"), base)
    stdin = job.single("stdin")
    for implicit in (executable, stdin):
        if implicit and _is_local_relative(implicit):
            inputs.ensure(implicit)
    executables = _executables(job, inputs, executable)
    if inputs.entries or had_inputs:
        job.put("inputfiles", tuple(inputs.entries))
    remote_outputs = _outputs(job, (stdout, stderr), job.single("gmlog"))
    return inputs.uploads(executables), inputs.remote or remote_outputs


def _prepare_job(
    relations: Sequence[Relation], base: Path, delegation_id: str | None, queue: str | None
) -> PreparedJob:
    job = _Job(relations)
    _refuse_unsupported(job)
    walltime = _convert_time(job, "walltime")
    cputime = _convert_time(job, "cputime")
    _convert_time(job, "lifetime")
    stdout, stderr = _resolve_join(job)
    runtime_environments = _runtime_environments(job)
    queue_name = _queue(job, queue)
    _delegation(job, delegation_id)
    uploads, remote = _stage(job, base, stdout, stderr)
    return PreparedJob(
        description=unparse(job.relations),
        name=job.single("jobname"),
        queue=queue_name,
        stdout=stdout,
        stderr=stderr,
        gmlog=job.single("gmlog"),
        uploads=uploads,
        runtime_environments=runtime_environments,
        walltime=walltime,
        cputime=cputime,
        count=_integer(job, "count"),
        memory=_integer(job, "memory"),
        rerun=_integer(job, "rerun"),
        remote_staging=remote,
        relations=tuple(job.relations),
    )


def prepare(
    text: str, *, base: Path, delegation_id: str | None = None, queue: str | None = None
) -> list[PreparedJob]:
    """Turn a user-dialect xRSL description into GRIDMANAGER-dialect jobs for the CE.

    Times become seconds, ``join`` is resolved, the executable, ``stdin``
    and every input with an empty, local or ``file://`` source become
    uploads from ``base`` (the source the CE sees becomes ``""``), and
    ``stdout``, ``stderr`` and ``gmlog`` are added to the outputs, as
    ``arcsub`` does. ``queue`` and ``delegation_id`` are added only where
    the description has none. Other attributes pass through unchanged.

    Raises ``DescriptionError`` for anything ``parse`` refuses, a missing
    ``executable`` or local input file, an input name outside the session
    directory, an attribute the CE sets itself, normalised-time attributes,
    and any requirement (``!=`` queues, RTE version ranges) that only a
    client-side broker could meet. With several jobs the message says
    which one failed.
    """
    jobs = parse(text)
    prepared: list[PreparedJob] = []
    for number, relations in enumerate(jobs, 1):
        try:
            prepared.append(_prepare_job(relations, base, delegation_id, queue))
        except DescriptionError as exc:
            if len(jobs) == 1:
                raise
            raise DescriptionError(f"Job {number} of {len(jobs)}: {exc.user_message}") from exc
    return prepared
