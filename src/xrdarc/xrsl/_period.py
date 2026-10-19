"""Time periods as ARC's ``Period`` class reads them: :func:`parse_period`.

``walltime``, ``cputime`` and the command line's ``--lifetime`` all take
either ISO 8601 durations (``PT1H30M``; ``P1M`` is a 30-day month, as in
ARC) or ARC's free format (``1h30``, ``2d 3h``, ``60 minutes``), where a
bare number is in the dialect's unit: minutes for the user dialect, seconds
for the CE's. Where ARC logs an error and quietly returns zero, this raises
:class:`~xrdarc.errors.DescriptionError`, so a typo never becomes a job
with no time limit.
"""

from __future__ import annotations

import re

from ..errors import DescriptionError

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
    """The error for an unreadable period, quoting it as written."""
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
        seconds += number * _iso_unit(text, unit, minutes)
        # ARC's quirk: after a week, day or hour (or a minute), M means minutes.
        minutes = minutes or unit in "WDHM"
        components += 1
    if not components:
        raise _period_error(text, "an ISO 8601 duration needs at least one component")
    return seconds


def _iso_unit(text: str, unit: str, minutes: bool) -> int:
    """Seconds in one ISO 8601 ``unit``; ``M`` is a month or a minute, as ``minutes`` says."""
    if unit == "M":
        return _MINUTE if minutes else _MONTH
    if unit not in _ISO_UNITS:
        raise _period_error(text, f"unknown ISO 8601 unit {unit!r}")
    return _ISO_UNITS[unit]


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
