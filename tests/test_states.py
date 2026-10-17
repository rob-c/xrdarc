"""Job states: the REST vocabulary, ARC's generic states and how one maps to the other."""

from __future__ import annotations

import pytest

from xrdarc.states import REST_STATES, JobState, generic_state

# ``JobStateARCREST::StateMap`` in ARC's REST job controller plugin, verbatim.
ARC_STATE_MAP = {
    "ACCEPTING": "Accepted",
    "ACCEPTED": "Accepted",
    "PREPARING": "Preparing",
    "PREPARED": "Preparing",
    "SUBMITTING": "Submitting",
    "QUEUING": "Queuing",
    "RUNNING": "Running",
    "HELD": "Hold",
    "EXITINGLRMS": "Running",
    "OTHER": "Running",
    "EXECUTED": "Running",
    "KILLING": "Running",
    "FINISHING": "Finishing",
    "FINISHED": "Finished",
    "FAILED": "Failed",
    "KILLED": "Killed",
    "WIPED": "Deleted",
}


@pytest.mark.parametrize(("rest", "generic"), sorted(ARC_STATE_MAP.items()))
def test_generic_state_follows_arcs_state_map(rest: str, generic: str) -> None:
    assert generic_state(rest).value == generic


def test_rest_states_are_exactly_arcs() -> None:
    assert frozenset(ARC_STATE_MAP) == REST_STATES


@pytest.mark.parametrize("rest", ["running", " Finished\n", "wiped"])
def test_generic_state_ignores_case_and_whitespace(rest: str) -> None:
    assert generic_state(rest) is generic_state(rest.strip().upper())


@pytest.mark.parametrize("rest", [None, ""])
def test_no_state_is_undefined(rest: str | None) -> None:
    assert generic_state(rest) is JobState.UNDEFINED


@pytest.mark.parametrize("rest", ["SOMETHINGNEW", "arcrest:RUNNING", "   "])
def test_unknown_state_is_other(rest: str) -> None:
    assert generic_state(rest) is JobState.OTHER


@pytest.mark.parametrize(
    ("state", "terminal", "retrievable"),
    [
        (JobState.FINISHED, True, True),
        (JobState.FAILED, True, True),
        (JobState.KILLED, True, True),
        (JobState.DELETED, True, False),
        (JobState.RUNNING, False, False),
        (JobState.UNDEFINED, False, False),
        (JobState.OTHER, False, False),
    ],
)
def test_terminal_and_retrievable(state: JobState, terminal: bool, retrievable: bool) -> None:
    assert (state.terminal, state.retrievable) == (terminal, retrievable)


def test_only_four_states_are_terminal() -> None:
    assert {s for s in JobState if s.terminal} == {
        JobState.FINISHED,
        JobState.KILLED,
        JobState.FAILED,
        JobState.DELETED,
    }


@pytest.mark.parametrize("state", list(JobState))
def test_parse_reads_back_what_str_writes(state: JobState) -> None:
    assert str(state) == state.value
    assert JobState.parse(str(state)) is state
    assert JobState.parse(f"  {state.value.upper()} ") is state


@pytest.mark.parametrize("text", ["", "Bogus", "ACCEPTING"])
def test_parse_unknown_is_undefined(text: str) -> None:
    assert JobState.parse(text) is JobState.UNDEFINED
