"""Job states: the CE's REST vocabulary and the generic states people read.

A-REX reports one of eighteen REST states; ARC's own client folds them into
thirteen generic states (``JobStateARCREST::StateMap``), and those are what
``arcstat`` prints and what the job list stores. Both are kept, because the
REST state says more (``EXITINGLRMS`` against plain "Running") while the
generic one is what scripts written for ARC match on.
"""

from __future__ import annotations

import enum

__all__ = ["REST_STATES", "JobState", "generic_state"]


class JobState(enum.Enum):
    """ARC's generic job state; the value is the name ``arcstat`` prints."""

    UNDEFINED = "Undefined"
    ACCEPTED = "Accepted"
    PREPARING = "Preparing"
    SUBMITTING = "Submitting"
    HOLD = "Hold"
    QUEUING = "Queuing"
    RUNNING = "Running"
    FINISHING = "Finishing"
    FINISHED = "Finished"
    KILLED = "Killed"
    FAILED = "Failed"
    DELETED = "Deleted"
    OTHER = "Other"

    @property
    def terminal(self) -> bool:
        """The job will not change again: ``JobState::IsFinished`` in ARC."""
        return self in _TERMINAL

    @property
    def retrievable(self) -> bool:
        """Finished one way or another with the session directory still there."""
        return self in _TERMINAL and self is not JobState.DELETED

    @classmethod
    def parse(cls, text: str) -> JobState:
        """The state named ``text`` (case-insensitive), as stored in a job list."""
        for state in cls:
            if state.value.lower() == text.strip().lower():
                return state
        return cls.UNDEFINED

    def __str__(self) -> str:
        return self.value


_TERMINAL = frozenset({JobState.FINISHED, JobState.KILLED, JobState.FAILED, JobState.DELETED})

#: ``JobStateARCREST::StateMap``: REST state name to generic state.
_REST_MAP = {
    "ACCEPTING": JobState.ACCEPTED,
    "ACCEPTED": JobState.ACCEPTED,
    "PREPARING": JobState.PREPARING,
    "PREPARED": JobState.PREPARING,
    "SUBMITTING": JobState.SUBMITTING,
    "QUEUING": JobState.QUEUING,
    "RUNNING": JobState.RUNNING,
    "EXITINGLRMS": JobState.RUNNING,
    "OTHER": JobState.RUNNING,
    "EXECUTED": JobState.RUNNING,
    "KILLING": JobState.RUNNING,
    "HELD": JobState.HOLD,
    "FINISHING": JobState.FINISHING,
    "FINISHED": JobState.FINISHED,
    "FAILED": JobState.FAILED,
    "KILLED": JobState.KILLED,
    "WIPED": JobState.DELETED,
}

#: Every state name A-REX's REST interface can report, ``None`` aside.
REST_STATES = frozenset(_REST_MAP)


def generic_state(rest: str | None) -> JobState:
    """The generic state for a REST state: unknown names are ``OTHER``, none (``None`` or
    empty) is ``UNDEFINED``, as in ``JobStateARCREST::StateMap``."""
    if not rest:
        return JobState.UNDEFINED
    return _REST_MAP.get(rest.strip().upper(), JobState.OTHER)
