"""EMI ADL: forwarded as written, with client uploads found and the delegation embedded."""

from __future__ import annotations

from pathlib import Path

import pytest
from xrdcore import safexml

from xrdarc.adl import ADL_NS, NORDUGRID_NS, is_adl, prepare_adl
from xrdarc.errors import DescriptionError
from xrdarc.xrsl import Upload

A = f"{{{ADL_NS}}}"
N = f"{{{NORDUGRID_NS}}}"


def _adl(body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<ActivityDescription xmlns="{ADL_NS}" xmlns:nordugrid-adl="{NORDUGRID_NS}">'
        f"{body}</ActivityDescription>"
    )


def _staging(*items: str) -> str:
    return _adl(f"<DataStaging>{''.join(items)}</DataStaging>")


def _input(name: str, extra: str = "") -> str:
    return f"<InputFile><Name>{name}</Name>{extra}</InputFile>"


def _source(uri: str) -> str:
    return f"<Source><URI>{uri}</URI></Source>"


FULL = _adl(
    "<ActivityIdentification><Name> my job </Name></ActivityIdentification>"
    "<Application><Executable><Path>run.sh</Path></Executable>"
    "<Output>out.txt</Output><Error>err.txt</Error>"
    "<nordugrid-adl:LoggingDirectory>gmlog</nordugrid-adl:LoggingDirectory></Application>"
    "<Resources><QueueName>grid</QueueName><WallTime>3600</WallTime>"
    "<RuntimeEnvironment><Name>APPS/HEP/ATLAS</Name><Version>21.0</Version></RuntimeEnvironment>"
    "<RuntimeEnvironment><Name>ENV/PROXY</Name></RuntimeEnvironment></Resources>"
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("<ActivityDescription/>", True), ("\n  <?xml?>", True), ('&(executable="x")', False)],
)
def test_is_adl(text: str, expected: bool) -> None:
    assert is_adl(text) is expected


def test_plain_document_is_forwarded_unchanged(tmp_path: Path) -> None:
    job = prepare_adl(FULL, base=tmp_path)
    assert job.description is FULL
    assert job.name == "my job"
    assert (job.queue, job.stdout, job.stderr, job.gmlog) == ("grid", "out.txt", "err.txt", "gmlog")
    assert job.runtime_environments == ("APPS/HEP/ATLAS-21.0", "ENV/PROXY")
    assert job.walltime == 3600
    assert job.uploads == ()
    assert job.remote_staging is False
    assert (job.cputime, job.count, job.memory, job.rerun, job.relations) == (
        None,
        None,
        None,
        None,
        (),
    )


def test_minimal_document_has_nothing_set(tmp_path: Path) -> None:
    job = prepare_adl(_adl(""), base=tmp_path)
    assert (job.name, job.queue, job.stdout, job.stderr, job.gmlog, job.walltime) == (None,) * 6
    assert job.runtime_environments == ()


@pytest.mark.parametrize("wall", ["PT1H", "", "  "])
def test_walltime_must_be_seconds(tmp_path: Path, wall: str) -> None:
    job = prepare_adl(_adl(f"<Resources><WallTime>{wall}</WallTime></Resources>"), base=tmp_path)
    assert job.walltime is None


def test_input_without_source_is_uploaded_from_base(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "in.txt").write_text("x")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    text = _staging(
        _input("data/in.txt"),
        _input("run.sh", "<IsExecutable>TRUE</IsExecutable>"),
    )
    job = prepare_adl(text, base=tmp_path)
    assert job.uploads == (
        Upload("data/in.txt", (tmp_path / "data" / "in.txt").resolve(), False),
        Upload("run.sh", (tmp_path / "run.sh").resolve(), True),
    )
    assert job.description is text
    assert job.remote_staging is False


def test_file_source_is_uploaded_and_removed(tmp_path: Path) -> None:
    local = tmp_path / "my input.dat"
    local.write_text("x")
    uri = f"file://{tmp_path.as_posix().replace(' ', '%20')}/my%20input.dat"
    job = prepare_adl(_staging(_input("in.dat", _source(uri))), base=tmp_path / "elsewhere")
    assert job.uploads == (Upload("in.dat", local.resolve(), False),)
    root = safexml.fromstring(job.description)
    (item,) = root.iter(f"{A}InputFile")
    assert item.find(f"{A}Source") is None
    assert item.findtext(f"{A}Name") == "in.dat"
    assert job.remote_staging is False


def test_rewritten_document_keeps_adl_namespaces(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("x")
    text = _adl(
        f"<Application><nordugrid-adl:LoggingDirectory>log</nordugrid-adl:LoggingDirectory>"
        f"</Application><DataStaging>{_input('f', _source(f'file://{tmp_path}/f'))}</DataStaging>"
    )
    job = prepare_adl(text, base=tmp_path)
    assert job.description != text
    assert f'xmlns="{ADL_NS}"' in job.description
    assert f'xmlns:nordugrid-adl="{NORDUGRID_NS}"' in job.description
    assert "<nordugrid-adl:LoggingDirectory>log</nordugrid-adl:LoggingDirectory>" in (
        job.description
    )
    assert job.gmlog == "log"


def test_remote_source_is_left_for_the_ce(tmp_path: Path) -> None:
    text = _staging(_input("big.root", _source("https://storage.example.org/big.root")))
    job = prepare_adl(text, base=tmp_path)
    assert job.uploads == ()
    assert job.remote_staging is True
    assert job.description is text


def test_source_without_uri_is_a_client_upload(tmp_path: Path) -> None:
    (tmp_path / "in").write_text("x")
    job = prepare_adl(_staging(_input("in", "<Source/>")), base=tmp_path)
    assert job.uploads == (Upload("in", (tmp_path / "in").resolve(), False),)
    assert safexml.fromstring(job.description).find(f".//{A}Source") is None


@pytest.mark.parametrize(
    ("output", "remote"),
    [
        ("<OutputFile><Name>out</Name></OutputFile>", False),
        ("<OutputFile><Name>o</Name><Target><URI>https://se/o</URI></Target></OutputFile>", True),
    ],
)
def test_output_targets_need_remote_staging(tmp_path: Path, output: str, remote: bool) -> None:
    assert prepare_adl(_staging(output), base=tmp_path).remote_staging is remote


@pytest.mark.parametrize("source", ["", _source("file:///no/such/file")])
def test_missing_local_input(tmp_path: Path, source: str) -> None:
    with pytest.raises(DescriptionError, match=r"^Input file in.txt not found at ") as caught:
        prepare_adl(_staging(_input("in.txt", source)), base=tmp_path)
    expected = tmp_path / "in.txt" if not source else Path("/no/such/file")
    assert str(caught.value) == f"Input file in.txt not found at {expected}"


def test_directory_is_not_an_input_file(tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    with pytest.raises(DescriptionError, match="not found"):
        prepare_adl(_staging(_input("dir")), base=tmp_path)


@pytest.mark.parametrize(
    ("item", "shown"),
    [
        ("<InputFile/>", "None"),
        ("<InputFile><Name>  </Name></InputFile>", "None"),
        (_input("/etc/passwd"), "'/etc/passwd'"),
        (_input("../escape"), "'../escape'"),
        (_input("a/../../b"), "'a/../../b'"),
    ],
)
def test_bad_input_names(tmp_path: Path, item: str, shown: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        prepare_adl(_staging(item), base=tmp_path)
    assert str(caught.value) == f"ADL InputFile name {shown} must be a relative path"


def _delegation(description: str) -> list[str | None]:
    root = safexml.fromstring(description)
    return [d.text for d in root.iter(f"{N}DelegationID")]


def test_delegation_embedded_without_data_staging(tmp_path: Path) -> None:
    job = prepare_adl(_adl(""), base=tmp_path, delegation_id="deleg-1", embed_delegation=True)
    assert _delegation(job.description) == ["deleg-1"]
    staging = safexml.fromstring(job.description).find(f"{A}DataStaging")
    assert staging is not None
    assert staging.find(f"{N}DelegationID") is not None


def test_delegation_embedded_into_existing_data_staging(tmp_path: Path) -> None:
    text = _staging("<OutputFile><Name>o</Name></OutputFile>")
    job = prepare_adl(text, base=tmp_path, delegation_id="deleg-2", embed_delegation=True)
    root = safexml.fromstring(job.description)
    assert len(root.findall(f"{A}DataStaging")) == 1
    assert _delegation(job.description) == ["deleg-2"]


def test_existing_delegation_is_kept(tmp_path: Path) -> None:
    text = _staging("<nordugrid-adl:DelegationID>mine</nordugrid-adl:DelegationID>")
    job = prepare_adl(text, base=tmp_path, delegation_id="other", embed_delegation=True)
    assert job.description is text


@pytest.mark.parametrize(
    ("delegation_id", "embed"), [("deleg", False), (None, True), ("", True), (None, False)]
)
def test_delegation_not_embedded(tmp_path: Path, delegation_id: str | None, embed: bool) -> None:
    text = _adl("")
    job = prepare_adl(text, base=tmp_path, delegation_id=delegation_id, embed_delegation=embed)
    assert job.description is text


@pytest.mark.parametrize("text", ["<ActivityDescription>", "not xml at all", ""])
def test_malformed_xml(tmp_path: Path, text: str) -> None:
    with pytest.raises(DescriptionError, match=r"^The ADL description is not valid XML: "):
        prepare_adl(text, base=tmp_path)


def test_doctype_is_refused(tmp_path: Path) -> None:
    text = (
        '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY lol "lol">]>'
        f'<ActivityDescription xmlns="{ADL_NS}">&lol;</ActivityDescription>'
    )
    with pytest.raises(DescriptionError) as caught:
        prepare_adl(text, base=tmp_path)
    assert str(caught.value) == (
        "The ADL description is not valid XML: "
        "XML document type and entity declarations are not allowed"
    )


@pytest.mark.parametrize(
    ("text", "tag"),
    [
        ("<job/>", "job"),
        ("<ActivityDescription/>", "ActivityDescription"),
        (f'<Activity xmlns="{ADL_NS}"/>', f"{A}Activity"),
    ],
)
def test_root_must_be_an_adl_activity_description(tmp_path: Path, text: str, tag: str) -> None:
    with pytest.raises(DescriptionError) as caught:
        prepare_adl(text, base=tmp_path)
    assert str(caught.value) == f"Expected an ADL ActivityDescription, found <{tag}>"
