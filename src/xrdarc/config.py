"""ARC's client configuration, ``client.conf``, read the way ARC reads it.

The system file (``/etc/arc/client.conf``) is read first and the user's
(``~/.arc/client.conf``) on top, or one explicit file instead of both, as
with ``arcsub -z``. The grammar is ARC's ``IniConfig``: ``#`` comments at the
start of a line, ``[section]`` headers, ``key = value`` split at the first
``=`` with both sides trimmed, quotes *not* stripped, a repeated key adding a
value, and keys before any section belonging to ``[common]``.

Only what an ARC REST client acts on is interpreted; anything else is kept
in ``UserConfig.common`` for callers that want it.
"""

from __future__ import annotations

import errno
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ARCError

__all__ = ["Service", "UserConfig", "arc_dir", "load_config", "parse_ini"]

#: The site-wide file ARC's tools read before the user's. A module attribute
#: so a test suite can point it away from the machine's real one.
SYSTEM_CONFIG = Path("/etc/arc/client.conf")
#: ARC's own default ``timeout`` (seconds per connect and per read).
DEFAULT_TIMEOUT = 20.0


def arc_dir(environ: Mapping[str, str] | None = None) -> Path:
    """The per-user ARC directory: ``~/.arc`` (``%USERPROFILE%\\.arc`` on Windows)."""
    env = os.environ if environ is None else environ
    # ``$HOME`` first, so a test or a service that sets it is obeyed rather
    # than the password database.
    home = env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")
    return Path(home) / ".arc"


def parse_ini(text: str) -> dict[str, dict[str, list[str]]]:
    """``IniConfig``'s grammar: sections of multi-valued keys."""
    sections: dict[str, dict[str, list[str]]] = {}
    # Keys before any header belong to [common], as in ARC.
    current = sections.setdefault("common", {})
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # A repeated header reopens the same section rather than starting a
        # new one, so its keys add to what the first block set.
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
            continue
        # Split at the first "=": a value may itself contain one (a URL query).
        # A line without one is ignored, as IniConfig ignores it.
        key, sep, value = line.partition("=")
        if sep:
            current.setdefault(key.strip(), []).append(value.strip())
    return sections


@dataclass(frozen=True, slots=True)
class Service:
    """A ``[computing/<alias>]`` block: a CE the user named in their config."""

    alias: str
    #: As written: anything ``-C`` accepts, normalised only when used.
    url: str
    #: ``default = yes``: used when a command is given no ``-C`` at all.
    default: bool = False
    #: Names that select several CEs at once (``-C <group>``).
    groups: tuple[str, ...] = ()


@dataclass(slots=True)
class UserConfig:
    """The settings an ARC client reads from ``client.conf``.

    Paths are as written in the file (``~`` expanded); ``None`` means "not
    configured, discover it". ``joblist`` is always set, defaulting to
    ``~/.arc/jobs.dat`` as ARC does.
    """

    joblist: Path
    proxy_path: str | None = None
    cert_path: str | None = None
    key_path: str | None = None
    ca_dir: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    download_dir: str | None = None
    #: ``[computing/<alias>]`` blocks by alias, in file order.
    services: dict[str, Service] = field(default_factory=dict)
    #: Every ``[common]`` key, raw and multi-valued, interpreted or not.
    common: dict[str, list[str]] = field(default_factory=dict)

    def resolve(self, name: str) -> list[str]:
        """The CE URLs ``-C name`` means: an alias, a group, or ``name`` itself.

        An alias wins over a group of the same name, as in ARC; anything
        that is neither is taken to be a CE (a host name or URL), which
        :func:`~xrdarc.urls.ce_url` then checks.
        """
        if name in self.services:
            return [self.services[name].url]
        grouped = [s.url for s in self.services.values() if name in s.groups]
        return grouped or [name]

    def defaults(self) -> list[str]:
        """The CEs marked ``default = yes``, for a command given no ``-C``."""
        return [s.url for s in self.services.values() if s.default]


def _last(values: Mapping[str, list[str]], key: str) -> str | None:
    """A single-valued setting: the last value given wins (as in ARC), ``~`` expanded."""
    found = values.get(key)
    # An empty last value (``proxypath =``) means "unset", which lets a
    # user's file switch off a path the system file configured.
    return os.path.expanduser(found[-1]) if found and found[-1] else None


def _timeout(common: Mapping[str, list[str]], origin: str) -> float:
    """``timeout``, in seconds; a value that is not a positive number is an error, not ignored.

    ARC would read a typo as zero - wait forever, or not at all - so it is
    refused, naming the file it came from.
    """
    text = _last(common, "timeout")
    if text is None:
        return DEFAULT_TIMEOUT
    try:
        value = float(text)
    except ValueError:
        # Folded into the one check below, so every bad spelling gets the
        # same message naming the file.
        value = 0.0
    # ``isfinite`` as well: ``float("inf")`` and ``nan`` parse, and either would
    # reach the HTTP session as a timeout that never fires or always does.
    if not (math.isfinite(value) and value > 0):
        raise ARCError(f"{origin}: timeout = {text} is not a positive number of seconds")
    return value


def _services(sections: Mapping[str, Mapping[str, list[str]]]) -> dict[str, Service]:
    """Every ``[computing/<alias>]`` block with a ``url``, by alias; other sections are ignored."""
    found = (_service(name, values) for name, values in sections.items())
    return {service.alias: service for service in found if service is not None}


def _service(name: str, values: Mapping[str, list[str]]) -> Service | None:
    """One section as a :class:`Service`, if it is a ``computing/<alias>`` block with a URL.

    ``group`` may be repeated and each value may list several groups,
    separated by blanks, as ARC allows.
    """
    # Only ``computing/`` blocks name CEs; other kinds ARC knows (``registry/``
    # index servers) are skipped, as nothing here queries an index.
    kind, _, alias = name.partition("/")
    url = _last(values, "url")
    if kind != "computing" or not alias or url is None:
        return None
    default = (_last(values, "default") or "").lower() in ("yes", "true", "1")
    groups = tuple(g for value in values.get("group", []) for g in value.split())
    return Service(alias, url, default, groups)


def _merge(into: dict[str, dict[str, list[str]]], text: str) -> None:
    """Read ``text`` on top of ``into``: a key the later file sets replaces the earlier values."""
    # Per key, not per section: the user's file overriding ``timeout`` must
    # not wipe the system file's other ``[common]`` settings.
    for section, values in parse_ini(text).items():
        target = into.setdefault(section, {})
        target.update(values)


def load_config(
    path: str | os.PathLike[str] | None = None, environ: Mapping[str, str] | None = None
) -> UserConfig:
    """Read the configuration ARC would read; missing default files are fine.

    An explicit ``path`` that cannot be read raises ``ARCError`` (ENOENT or
    EACCES), as does a malformed ``timeout``.
    """
    user_dir = arc_dir(environ)
    files = [Path(path)] if path is not None else [SYSTEM_CONFIG, user_dir / "client.conf"]
    sections: dict[str, dict[str, list[str]]] = {}
    for candidate in files:
        _merge(sections, _read(candidate, required=path is not None))
    common = sections.get("common", {})
    # Errors name the last file read: with both defaults that is the user's,
    # the one a user can fix (and the one most likely to hold the typo).
    origin = str(files[-1])
    return UserConfig(
        joblist=Path(_last(common, "joblist") or user_dir / "jobs.dat"),
        proxy_path=_last(common, "proxypath"),
        cert_path=_last(common, "certificatepath"),
        key_path=_last(common, "keypath"),
        ca_dir=_last(common, "cacertificatesdirectory"),
        timeout=_timeout(common, origin),
        download_dir=_last(common, "jobdownloaddirectory"),
        services=_services(sections),
        common=common,
    )


def _read(candidate: Path, *, required: bool) -> str:
    """One configuration file's text; a missing default file is empty, a missing named one an error.

    Undecodable bytes are kept (``surrogateescape``) rather than failing: a
    Latin-1 comment in ``/etc/arc/client.conf`` must not stop every command.
    """
    try:
        return candidate.read_text(encoding="utf-8", errors="surrogateescape")
    except FileNotFoundError as exc:
        if required:
            raise ARCError(f"Configuration file {candidate} does not exist", errno.ENOENT) from exc
        return ""
    except OSError as exc:
        # Even a default file that exists but cannot be read is an error: it
        # was meant to apply, and silently ignoring it would change behaviour.
        # 5 is EIO, for an OSError that carries no errno.
        raise ARCError(
            f"Cannot read configuration file {candidate}: {exc.strerror}", exc.errno or 5
        ) from exc
