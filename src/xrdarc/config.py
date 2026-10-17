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

SYSTEM_CONFIG = Path("/etc/arc/client.conf")
DEFAULT_TIMEOUT = 20.0


def arc_dir(environ: Mapping[str, str] | None = None) -> Path:
    """The per-user ARC directory: ``~/.arc`` (``%USERPROFILE%\\.arc`` on Windows)."""
    env = os.environ if environ is None else environ
    home = env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")
    return Path(home) / ".arc"


def parse_ini(text: str) -> dict[str, dict[str, list[str]]]:
    """``IniConfig``'s grammar: sections of multi-valued keys."""
    sections: dict[str, dict[str, list[str]]] = {}
    current = sections.setdefault("common", {})
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
            continue
        key, sep, value = line.partition("=")
        if sep:
            current.setdefault(key.strip(), []).append(value.strip())
    return sections


@dataclass(frozen=True, slots=True)
class Service:
    """A ``[computing/<alias>]`` block: a CE the user named in their config."""

    alias: str
    url: str
    default: bool = False
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
    services: dict[str, Service] = field(default_factory=dict)
    common: dict[str, list[str]] = field(default_factory=dict)

    def resolve(self, name: str) -> list[str]:
        """The CE URLs ``-C name`` means: an alias, a group, or ``name`` itself."""
        if name in self.services:
            return [self.services[name].url]
        grouped = [s.url for s in self.services.values() if name in s.groups]
        return grouped or [name]

    def defaults(self) -> list[str]:
        """The CEs marked ``default = yes``, for a command given no ``-C``."""
        return [s.url for s in self.services.values() if s.default]


def _last(values: Mapping[str, list[str]], key: str) -> str | None:
    found = values.get(key)
    return os.path.expanduser(found[-1]) if found and found[-1] else None


def _timeout(common: Mapping[str, list[str]], origin: str) -> float:
    text = _last(common, "timeout")
    if text is None:
        return DEFAULT_TIMEOUT
    try:
        value = float(text)
    except ValueError:
        value = 0.0
    if not (math.isfinite(value) and value > 0):
        raise ARCError(f"{origin}: timeout = {text} is not a positive number of seconds")
    return value


def _services(sections: Mapping[str, Mapping[str, list[str]]]) -> dict[str, Service]:
    found: dict[str, Service] = {}
    for name, values in sections.items():
        kind, _, alias = name.partition("/")
        url = _last(values, "url")
        if kind != "computing" or not alias or url is None:
            continue
        default = (_last(values, "default") or "").lower() in ("yes", "true", "1")
        groups = tuple(g for value in values.get("group", []) for g in value.split())
        found[alias] = Service(alias, url, default, groups)
    return found


def _merge(into: dict[str, dict[str, list[str]]], text: str) -> None:
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
        try:
            _merge(sections, candidate.read_text(encoding="utf-8", errors="surrogateescape"))
        except FileNotFoundError as exc:
            if path is not None:
                raise ARCError(
                    f"Configuration file {candidate} does not exist", errno.ENOENT
                ) from exc
        except OSError as exc:
            raise ARCError(
                f"Cannot read configuration file {candidate}: {exc.strerror}", exc.errno or 5
            ) from exc
    common = sections.get("common", {})
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
