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

The package is a facade over four modules, in the order a description
flows through them: :mod:`._syntax` (the grammar and :func:`parse`),
:mod:`._write` (:func:`unparse`), :mod:`._period` (:func:`parse_period`)
and :mod:`._prepare` (:func:`prepare`, :class:`PreparedJob`,
:class:`Upload`). Import from ``xrdarc.xrsl``; the private modules may be
rearranged.
"""

from __future__ import annotations

from ._period import parse_period
from ._prepare import PreparedJob, Upload, prepare
from ._syntax import OPERATORS, Relation, Value, parse
from ._write import unparse

__all__ = [
    "OPERATORS",
    "PreparedJob",
    "Relation",
    "Upload",
    "Value",
    "parse",
    "parse_period",
    "prepare",
    "unparse",
]
