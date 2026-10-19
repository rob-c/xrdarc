"""xRSL's grammar: the syntax tree, ARC's ``RSLParser`` ported, and evaluation into relations.

Parsing and evaluation are separate passes, as in ARC, so a syntax error
anywhere is reported before a problem with a variable or a concatenation:
:class:`_Parser` builds a tree of :class:`_Condition`/:class:`_Boolean`
nodes over :class:`_Literal`/:class:`_Variable`/:class:`_Concat`/
:class:`_Sequence` terms, and :func:`_jobs` walks it with the
``rsl_substitution`` variables in scope, producing each job's
:class:`Relation` list. :func:`parse` is the entry point.

What must not break: positions. Every node keeps the offset it started at,
and :func:`_syntax_error` turns one into the line and column (from 1) the
error message names, which is what a user fixing a description reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from ..errors import DescriptionError

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
    """A string as written (quotes removed, doubled delimiters undone); ``pos`` is its start."""

    text: str
    pos: int


@dataclass(frozen=True, slots=True)
class _Variable:
    """``$(NAME)``: replaced by the value an enclosing ``rsl_substitution`` bound."""

    name: str
    pos: int


@dataclass(frozen=True, slots=True)
class _Concat:
    """Two terms joined by ``#`` or by adjacency (``a$(B)"c"``): one string once evaluated."""

    left: _Term
    right: _Term
    pos: int


@dataclass(frozen=True, slots=True)
class _Sequence:
    """A parenthesised list of values: ``("in" "gsiftp://...")`` in ``inputfiles``."""

    items: tuple[_Term, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class _Condition:
    """One ``(attribute op values...)``, the attribute already normalised."""

    attribute: str
    operator: str
    values: tuple[_Term, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class _Boolean:
    """``&``, ``|`` or ``+`` over its parenthesised children."""

    operator: str
    children: tuple[_Node, ...]
    pos: int


_Term: TypeAlias = _Literal | _Variable | _Concat | _Sequence
_Node: TypeAlias = _Condition | _Boolean

# How the next value in a list relates to the one before it.
_SEPARATE, _EXPLICIT, _IMPLICIT = 0, 1, 2


def _location(text: str, pos: int) -> tuple[int, int]:
    """Offset ``pos`` of ``text`` as (line, column), both counted from 1 as editors count."""
    line = text.count("\n", 0, pos) + 1
    return line, pos - (text.rfind("\n", 0, pos) + 1) + 1


def _syntax_error(text: str, pos: int, what: str) -> DescriptionError:
    """The error for ``what`` at ``pos``, naming the line and column a user would look at."""
    line, column = _location(text, pos)
    return DescriptionError(f"xRSL syntax error at line {line}, column {column}: {what}")


def _normalise(attribute: str) -> str:
    """ARC's attribute-name rule: case and underscores do not matter (``Run_Time``)."""
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
    """A recursive-descent reading of ``RSLParser``; ``pos`` walks ``text``.

    The grammar, as ARC's parser accepts it (``*`` = repeated)::

        rsl       := ("&" | "|" | "+") "(" rsl ")" ("(" rsl ")")*  |  condition
        condition := attribute operator value*
        value     := term (("#" | <adjacent>) term)*
        term      := "(" value* ")" | "$(" name ")" | string

    Each method parses one production and leaves ``pos`` just after it;
    whitespace and comments are skipped by the caller that knows they are
    allowed there, because adjacency (no blank between two terms) means
    concatenation and must be seen.
    """

    def __init__(self, text: str) -> None:
        """Ready to parse ``text`` from the start; the comments are located up front."""
        self.text = text
        self.pos = 0
        self.comments = _scan_comments(text)

    def fail(self, what: str, pos: int | None = None) -> DescriptionError:
        """A syntax error at ``pos`` (default: where the parser is), to ``raise``."""
        return _syntax_error(self.text, self.pos if pos is None else pos, what)

    def peek(self) -> str:
        """The next character, or ``""`` at the end."""
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def found(self) -> str:
        """What is at ``pos``, for "expected X, found Y" messages."""
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
        """Consume ``char``, or fail saying what was there instead."""
        if self.peek() != char:
            raise self.fail(f"expected {char!r}, {self.found()}")
        self.pos += 1

    def rsl(self) -> _Node:
        """One node: an ``&``/``|``/``+`` over children, or a single condition."""
        self.skip()
        start, char = self.pos, self.peek()
        if char and char in "&|+":
            self.pos += 1
            return self.boolean(char, start)
        return self.condition()

    def boolean(self, operator: str, start: int) -> _Boolean:
        """The parenthesised children after ``operator``: at least one, up to a non-``(``."""
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
        """``attribute op values...`` (the parentheses are the caller's)."""
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
        """The relation operator at ``pos``; two-character ones first (``<=``, not ``<``)."""
        for operator in ("!=", "<=", ">=", "=", "<", ">"):
            if self.text.startswith(operator, self.pos):
                self.pos += len(operator)
                return operator
        return None

    def string(self) -> str | None:
        """A quoted or bare literal at ``pos``; None when there is none here.

        Three forms, as ``RSLParser`` reads them: ``"..."`` or ``'...'``;
        ``^X...X``, where the character after the caret is the delimiter (so
        a value full of quotes needs no doubling); and a bare word, ended by
        whitespace or any character with a meaning in xRSL.
        """
        char = self.peek()
        if char and char in "\"'":
            return self.quoted(self.pos)
        if char == "^":
            return self.caret()
        end = self.pos
        while end < len(self.text) and self.text[end] not in _UNQUOTED_END:
            end += 1
        word, self.pos = self.text[self.pos : end], end
        return word or None

    def caret(self) -> str:
        """``^X...X``: the character after the caret delimits the string."""
        if self.pos + 1 >= len(self.text):
            raise self.fail("'^' must be followed by the delimiter character of a string")
        self.pos += 1
        return self.quoted(self.pos - 1)

    def quoted(self, start: int) -> str:
        """The string whose delimiter is at ``pos``; a doubled delimiter is literal."""
        delimiter = self.text[self.pos]
        parts: list[str] = []
        # ``"a""b"`` is ``a"b``: each doubled delimiter ends one part and the
        # parts are joined with the delimiter, exactly as RSLParser does it.
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
            # Anything skipped - a blank or a comment - ends adjacency.
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
            # No term here and nothing pending: the list is over (at ``)``
            # or the end); the caller checks what comes next.
            if left is None and right is None:
                return tuple(values)

    def combine(
        self, values: list[_Term], left: _Term | None, right: _Term | None, mode: int, at: int
    ) -> _Term | None:
        """Fold ``right`` into the value being built, or start a new one; the value in progress.

        ``mode`` says how ``right`` relates to ``left`` (separate, ``#``,
        adjacent). A finished value is appended to ``values``. Five
        arguments plus ``self``: it is one step of :meth:`values`' loop,
        and every one is that loop's state.
        """
        if mode == _EXPLICIT:
            return self.hashed(left, right, at)
        if mode == _IMPLICIT and left is not None:
            return left if right is None else _Concat(left, right, at)
        if left is not None:
            values.append(left)
        return right

    def hashed(self, left: _Term | None, right: _Term | None, at: int) -> _Concat:
        """``left # right``: both sides must be there."""
        if left is None:
            raise self.fail("'#' has nothing on its left to concatenate", at)
        if right is None:
            raise self.fail(f"'#' has nothing on its right to concatenate, {self.found()}")
        return _Concat(left, right, at)

    def term(self) -> tuple[_Term | None, int]:
        """One value and how the next one relates to it (a sequence is never adjacent-joined)."""
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
        """``$(NAME)``, with blanks and comments allowed inside the parentheses, as in ARC."""
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
    """The characters a name may not contain, for messages."""
    return "".join(sorted(_SPECIAL))


# --- evaluation ---------------------------------------------------------------------------------


def _jobs(text: str, node: _Node) -> list[list[Relation]]:
    """The jobs under a top-level node: ``+`` lists them (nesting flattens), ``&`` is one."""
    if not isinstance(node, _Boolean):
        raise _syntax_error(
            text, node.pos, "a job must be an '&' conjunction such as &(executable=...)(...)"
        )
    if node.operator == "+":
        return [job for child in node.children for job in _jobs(text, child)]
    if node.operator == "&":
        return [_conjunction(text, node, {})]
    raise _syntax_error(text, node.pos, _DISJUNCTION)


def _conjunction(text: str, node: _Boolean, scope: dict[str, str]) -> list[Relation]:
    """The relations of an ``&``, with nested ``&`` flattened into it.

    Variables bound here are seen by the following siblings and everything
    inside them, never by the enclosing ``&``: each conjunction starts from
    a copy of its parent's bindings.
    """
    scope = dict(scope)
    return [relation for child in node.children for relation in _child(text, child, scope)]


def _child(text: str, child: _Node, scope: dict[str, str]) -> list[Relation]:
    """The relations one child of an ``&`` contributes (none for a substitution)."""
    if isinstance(child, _Condition):
        relation = _relation(text, child, scope)
        return [] if relation is None else [relation]
    if child.operator == "&":
        return _conjunction(text, child, scope)
    if child.operator == "|":
        raise _syntax_error(text, child.pos, _DISJUNCTION)
    raise _syntax_error(text, child.pos, "'+' (several jobs) is only allowed at the top")


def _relation(text: str, node: _Condition, scope: dict[str, str]) -> Relation | None:
    """A condition evaluated in ``scope``; ``rsl_substitution`` binds (into ``scope``) instead."""
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
    """``term``'s value, which must be a string; ``what`` names it in the error otherwise."""
    value = _value(text, term, scope)
    if not isinstance(value, str):
        raise _syntax_error(text, term.pos, f"{what} must be a string, not a sequence")
    return value


def _value(text: str, term: _Term, scope: dict[str, str]) -> Value:
    """``term`` evaluated: an unbound variable is ``""`` (ARC's rule), a sequence a tuple."""
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
