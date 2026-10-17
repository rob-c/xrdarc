"""CE and job URLs in the canonical shapes ARC's own tools read and write.

A computing element is named the way ``arcsub -C`` accepts it - ``ce.example.org``,
``ce.example.org:8443``, ``https://ce.example.org`` or a full
``https://ce.example.org:443/arex`` - and always stored canonically, with the
port explicit and the A-REX path present, because that is the form the C++
client writes into ``~/.arc/jobs.dat`` and matches ``-C`` against.

A job is named by its job URL, ``<ce>/rest/1.0/jobs/<id>``; the CE answers
on any REST version regardless of the one in the stored URL, so ``1.0`` is
kept for interoperability and the version actually spoken is negotiated.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from .errors import DescriptionError

__all__ = ["JobURL", "ce_url", "job_url", "parse_job_url"]

DEFAULT_PORT = {"https": 443, "http": 80}
DEFAULT_PATH = "/arex"

_JOB_PATH = re.compile(r"^(?P<base>.*?)/rest/(?P<version>[^/]+)/jobs/(?P<id>[^/?#]+)/?$")


def _host_port(netloc: str, scheme: str, given: str) -> tuple[str, int]:
    probe = urllib.parse.urlsplit(f"//{netloc}")
    host = probe.hostname
    if not host:
        raise DescriptionError(f"No host name in the computing element {given!r}")
    try:
        port = probe.port or DEFAULT_PORT[scheme]
    except ValueError as exc:
        raise DescriptionError(f"Bad port in the computing element {given!r}") from exc
    return host, port


def ce_url(text: str) -> str:
    """The canonical CE URL for anything ``arcsub -C`` would accept.

    Raises ``DescriptionError`` for an empty string, a scheme other than
    ``https``/``http``, or a URL with no host.
    """
    given = text.strip()
    if not given:
        raise DescriptionError("No computing element given")
    if "://" not in given:
        given = f"https://{given}"
    parts = urllib.parse.urlsplit(given)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORT:
        raise DescriptionError(
            f"Computing element {text!r} must be an https:// URL (got {scheme}://)"
        )
    host, port = _host_port(parts.netloc.rpartition("@")[2], scheme, text)
    path = parts.path.rstrip("/") or DEFAULT_PATH
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}:{port}{path}"


@dataclass(frozen=True, slots=True)
class JobURL:
    """A job URL taken apart: the CE it lives on and its id there."""

    ce: str
    id: str

    def __str__(self) -> str:
        return job_url(self.ce, self.id)


def job_url(ce: str, job_id: str) -> str:
    """The job URL ARC stores for ``job_id`` on ``ce`` (canonicalised)."""
    return f"{ce_url(ce)}/rest/1.0/jobs/{job_id}"


def parse_job_url(text: str) -> JobURL:
    """Split a job URL into its CE and id; ``DescriptionError`` if it is not one.

    Accepts any REST version in the path, and the CE part is canonicalised,
    so ``https://ce/arex/rest/1.1/jobs/abc`` and
    ``https://ce:443/arex/rest/1.0/jobs/abc`` name the same job.
    """
    stripped = text.strip()
    parts = urllib.parse.urlsplit(stripped)
    match = _JOB_PATH.match(parts.path)
    if parts.scheme.lower() not in DEFAULT_PORT or not parts.netloc or match is None:
        raise DescriptionError(f"{text!r} is not an ARC REST job URL")
    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, match["base"], "", ""))
    return JobURL(ce_url(base), match["id"])
