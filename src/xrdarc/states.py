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
        """Finished one way or another with the session directory still there.

        ``FAILED`` and ``KILLED`` count: their outputs and ``gmlog`` are what
        tells the user why, which is why ``arcget`` fetches them too.
        """
        return self in _TERMINAL and self is not JobState.DELETED

    @classmethod
    def parse(cls, text: str) -> JobState:
        """The state named ``text`` (case-insensitive), as stored in a job list."""
        # Unknown text is UNDEFINED, not an error: a job list written by a
        # newer ARC with a state this version lacks must still load.
        for state in cls:
            if state.value.lower() == text.strip().lower():
                return state
        return cls.UNDEFINED

    def __str__(self) -> str:
        """The name ``arcstat`` prints (``Running``), so f-strings read as ARC's output does."""
        return self.value


#: States a job never leaves; ``wait`` stops at them. ``DELETED`` counts: the
#: CE wiped the job's files, and asking again will never bring them back.
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
    # The batch job is ending, but A-REX has not yet seen it end.
    "EXITINGLRMS": JobState.RUNNING,
    # ``OTHER`` as a reported name is Running in ARC's map; a name ARC does
    # not know at all is Other (see :func:`generic_state`).
    "OTHER": JobState.RUNNING,
    # The batch job is over but A-REX has not yet staged out: still "Running"
    # to ARC, so a script polling for Finished does not jump the gun.
    "EXECUTED": JobState.RUNNING,
    # A kill is asynchronous; until A-REX has done it the job still runs.
    "KILLING": JobState.RUNNING,
    "HELD": JobState.HOLD,
    "FINISHING": JobState.FINISHING,
    "FINISHED": JobState.FINISHED,
    "FAILED": JobState.FAILED,
    "KILLED": JobState.KILLED,
    # The session directory is gone (erase time reached, or cleaned): nothing
    # more can be retrieved, so it is terminal like Finished.
    "WIPED": JobState.DELETED,
}

#: Every state name A-REX's REST interface can report, ``None`` aside.
REST_STATES = frozenset(_REST_MAP)


def generic_state(rest: str | None) -> JobState:
    """The generic state for a REST state: unknown names are ``OTHER``, none (``None`` or
    empty) is ``UNDEFINED``, as in ``JobStateARCREST::StateMap``."""
    # Case and blanks are forgiven because the state also arrives through
    # GLUE2 text and job lists other tools wrote, not just A-REX's JSON.
    if not rest:
        return JobState.UNDEFINED
    return _REST_MAP.get(rest.strip().upper(), JobState.OTHER)
