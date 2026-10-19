"""Property-based tests of the xRSL parser and writer.

The example-based tests in ``test_xrsl.py`` pin ARC's grammar case by case;
these check the two contracts every caller relies on, over inputs nobody
thought to write down:

* ``parse(unparse(job)) == [job]`` for any job ``unparse`` accepts - the
  writer's quoting (doubled ``"``, ``(*`` split across ``#``) must survive
  any text, including quotes, comment markers, newlines and non-ASCII;
* arbitrary text, and text built from xRSL's own punctuation, either parses
  or raises :class:`~xrdarc.errors.DescriptionError` - never ``IndexError``,
  ``RecursionError`` or anything else a caller would not expect. The same
  holds for :func:`~xrdarc.xrsl.parse_period`.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# ``deadline=None`` throughout: these are correctness properties, and hypothesis's
# per-example wall-clock deadline only measures how busy the machine is (six
# xdist workers on a shared runner miss 200 ms routinely).
from xrdarc.errors import DescriptionError
from xrdarc.xrsl import OPERATORS, Relation, Value, parse, parse_period, unparse

#: Characters an attribute name may contain after ARC's normalisation.
_NAME_ALPHABET = st.characters(
    exclude_characters="+&|()=<>!\"'^#$_", exclude_categories=("Lu", "Lt", "Cs")
)
_ATTRIBUTE = (
    st.text(_NAME_ALPHABET, min_size=1, max_size=12)
    .filter(lambda name: name == name.lower().replace("_", ""))
    .filter(lambda name: name != "rslsubstitution")
)
#: Any character but a lone surrogate, which no text file can hold.
_CHARACTER = st.characters(exclude_categories=["Cs"])
_LITERAL = st.text(_CHARACTER, max_size=20)
_VALUE: st.SearchStrategy[Value] = st.recursive(
    _LITERAL, lambda inner: st.lists(inner, max_size=4).map(tuple), max_leaves=12
)
_RELATION = st.builds(
    Relation,
    attribute=_ATTRIBUTE,
    operator=st.sampled_from(OPERATORS),
    values=st.lists(_VALUE, max_size=4).map(tuple),
)
#: Text made mostly of xRSL's own syntax, which reaches deeper into the parser than noise.
_SYNTAX = st.text(st.sampled_from(list("&+|()=<>!\"'^#$*  \nabcXYZ019_.-/")), max_size=80)


def _writable(relation: Relation) -> bool:
    try:
        unparse([relation])
    except ValueError:
        return False
    return True


@given(st.lists(_RELATION.filter(_writable), min_size=1, max_size=6))
@settings(deadline=None, max_examples=300, suppress_health_check=[HealthCheck.filter_too_much])
def test_unparse_then_parse_round_trips(job: list[Relation]) -> None:
    assert parse(unparse(job)) == [job]


@given(
    st.lists(st.lists(_RELATION.filter(_writable), min_size=1, max_size=3), min_size=2, max_size=4)
)
@settings(deadline=None, max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
def test_several_jobs_round_trip(jobs: list[list[Relation]]) -> None:
    text = "+" + "".join(f"({unparse(job)})" for job in jobs)
    assert parse(text) == jobs


@given(st.one_of(st.text(max_size=120), _SYNTAX))
@settings(deadline=None, max_examples=500)
def test_garbage_only_raises_description_error(text: str) -> None:
    try:
        jobs = parse(text)
    except DescriptionError:
        return
    assert jobs
    assert all(isinstance(r, Relation) for job in jobs for r in job)


@given(st.one_of(st.text(max_size=30), st.from_regex(r"[0-9 PTYMWDHSwdhms]{0,12}")))
@settings(deadline=None, max_examples=300)
def test_garbage_periods_only_raise_description_error(text: str) -> None:
    try:
        seconds = parse_period(text)
    except DescriptionError:
        return
    assert isinstance(seconds, int)
    assert seconds >= 0


@pytest.mark.parametrize("depth", [50, 400])
def test_deep_nesting_is_a_description_error_or_parses(depth: int) -> None:
    text = "&(a=" + "(" * depth + '"x"' + ")" * depth + ")"
    with contextlib.suppress(DescriptionError):
        parse(text)
