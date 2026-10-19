"""CE and job URLs: every form ``arcsub -C`` takes, canonicalised the way ARC stores it."""

from __future__ import annotations

import errno

import pytest

from xrdarc.errors import DescriptionError
from xrdarc.urls import JobURL, ce_url, job_url, parse_job_url

CE = "https://ce.example.org:443/arex"


@pytest.mark.parametrize(
    ("given", "canonical"),
    [
        ("ce.example.org", CE),
        ("  ce.example.org\n", CE),
        ("CE.Example.ORG", CE),
        ("ce.example.org:8443", "https://ce.example.org:8443/arex"),
        ("https://ce.example.org", CE),
        ("https://ce.example.org/", CE),
        ("HTTPS://ce.example.org", CE),
        ("https://ce.example.org:443/arex", CE),
        ("https://ce.example.org:443/arex/", CE),
        ("https://ce.example.org/custom/path/", "https://ce.example.org:443/custom/path"),
        ("http://ce.example.org", "http://ce.example.org:80/arex"),
        ("http://ce.example.org:8080/arex", "http://ce.example.org:8080/arex"),
        ("[::1]:8443", "https://[::1]:8443/arex"),
        ("https://[2001:db8::1]", "https://[2001:db8::1]:443/arex"),
        ("user@ce.example.org", CE),
        ("https://user:secret@ce.example.org:443/arex", CE),
        ("https://ce.example.org/arex?query#fragment", CE),
    ],
)
def test_ce_url_canonical_forms(given: str, canonical: str) -> None:
    assert ce_url(given) == canonical


def test_ce_url_is_idempotent() -> None:
    for given in ("ce.example.org", "[::1]:8443", "http://h:1/p"):
        assert ce_url(ce_url(given)) == ce_url(given)


@pytest.mark.parametrize("given", ["", "   \t"])
def test_ce_url_empty(given: str) -> None:
    with pytest.raises(DescriptionError, match=r"^No computing element given$") as caught:
        ce_url(given)
    assert caught.value.errno == errno.EINVAL


@pytest.mark.parametrize(("given", "scheme"), [("gsiftp://ce", "gsiftp"), ("FTP://ce", "ftp")])
def test_ce_url_bad_scheme(given: str, scheme: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        ce_url(given)
    assert str(caught.value) == (
        f"Computing element {given!r} must be an https:// URL (got {scheme}://)"
    )


@pytest.mark.parametrize("given", ["ce.example.org:http", "ce.example.org:99999", "h:-1"])
def test_ce_url_bad_port(given: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        ce_url(given)
    assert str(caught.value) == f"Bad port in the computing element {given!r}"
    assert isinstance(caught.value.__cause__, ValueError)


@pytest.mark.parametrize("given", ["https://", "https:///arex", "user@", "https://:8443/arex"])
def test_ce_url_without_host(given: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        ce_url(given)
    assert str(caught.value) == f"No host name in the computing element {given!r}"


def test_job_url_uses_rest_1_0_on_the_canonical_ce() -> None:
    assert job_url("ce.example.org", "abc") == f"{CE}/rest/1.0/jobs/abc"
    assert job_url("[::1]:8443", "x") == "https://[::1]:8443/arex/rest/1.0/jobs/x"


@pytest.mark.parametrize(
    "given",
    [
        f"{CE}/rest/1.0/jobs/abc",
        f"{CE}/rest/1.0/jobs/abc/",
        "https://ce.example.org/arex/rest/1.1/jobs/abc",
        "  https://CE.example.org:443/arex/rest/1.0/jobs/abc?x=1  ",
        "https://u@ce.example.org/arex/rest/2.0/jobs/abc#frag",
    ],
)
def test_parse_job_url_any_version(given: str) -> None:
    parsed = parse_job_url(given)
    assert parsed == JobURL(CE, "abc")
    assert str(parsed) == f"{CE}/rest/1.0/jobs/abc"


def test_parse_job_url_keeps_custom_base_and_http() -> None:
    parsed = parse_job_url("http://[::1]:8080/a/b/rest/1.1/jobs/id-1")
    assert parsed == JobURL("http://[::1]:8080/a/b", "id-1")
    assert parse_job_url(str(parsed)) == parsed


@pytest.mark.parametrize(
    "given",
    [
        "",
        "abc",
        "ce.example.org/arex/rest/1.0/jobs/abc",
        "gsiftp://ce.example.org/arex/rest/1.0/jobs/abc",
        "https:///arex/rest/1.0/jobs/abc",
        f"{CE}/rest/1.0/jobs/",
        f"{CE}/rest/1.0/jobs/abc/session",
        f"{CE}/rest/jobs/abc",
        "https://ce.example.org:2811/jobs/abc",
    ],
)
def test_parse_job_url_rejects_non_job_urls(given: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        parse_job_url(given)
    assert str(caught.value) == f"{given!r} is not an ARC REST job URL"
    assert caught.value.errno == errno.EINVAL


@pytest.mark.parametrize("attribute", ["ce", "id"])
def test_job_url_is_frozen_and_hashable(attribute: str) -> None:
    parsed = JobURL(CE, "abc")
    assert {parsed, JobURL(CE, "abc")} == {parsed}
    with pytest.raises(AttributeError):
        setattr(parsed, attribute, "other")
