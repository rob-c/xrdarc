"""xRSL: the RSL grammar, ARC's period parser, and preparing user xRSL for a CE."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from xrdarc.errors import DescriptionError
from xrdarc.xrsl import (
    PreparedJob,
    Relation,
    Upload,
    Value,
    parse,
    parse_period,
    prepare,
    unparse,
)


def one(text: str) -> list[Relation]:
    jobs = parse(text)
    assert len(jobs) == 1
    return jobs[0]


def values(text: str, attribute: str = "a") -> tuple[Value, ...]:
    (relation,) = [r for r in one(text) if r.attribute == attribute]
    return relation.values


def error(text: str) -> str:
    with pytest.raises(DescriptionError) as info:
        parse(text)
    return str(info.value)


# --- grammar ------------------------------------------------------------------------------------


def test_simple_job() -> None:
    assert one('&(executable="/bin/echo")(arguments="a" "b")') == [
        Relation("executable", "=", ("/bin/echo",)),
        Relation("arguments", "=", ("a", "b")),
    ]


def test_attribute_names_are_normalised_values_keep_case() -> None:
    assert one("&(Run_Time_Environment = APPS/HEP)") == [
        Relation("runtimeenvironment", "=", ("APPS/HEP",))
    ]


@pytest.mark.parametrize("operator", ["=", "!=", "<", "<=", ">", ">="])
def test_relation_operators(operator: str) -> None:
    assert one(f"&(a {operator} b)") == [Relation("a", operator, ("b",))]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"plain"', "plain"),
        ('"say ""hi"""', 'say "hi"'),
        ('""""', '"'),
        ('""', ""),
        ("'single'", "single"),
        ("'it''s'", "it's"),
        ("^!user!", "user"),
        ("^!a!!b!", "a!b"),
        ("^xa b=c\"d'x", "a b=c\"d'"),
        ("bare/path:with.dots-and*stars", "bare/path:with.dots-and*stars"),
        ('"multi\nline"', "multi\nline"),
    ],
)
def test_string_quoting(text: str, expected: str) -> None:
    assert values(f"&(a = {text})") == (expected,)


def test_empty_value_list() -> None:
    assert values("&(arguments=)", "arguments") == ()


def test_nested_sequences() -> None:
    assert values('&(a = (x ("y" (z))) () w)') == (("x", ("y", ("z",))), (), "w")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a#b", ("ab",)),
        ("a # b # c", ("abc",)),
        ('"a" #\n "b"', ("ab",)),
        ("a\"b\"'c'", ("abc",)),
        ("a b", ("a", "b")),
        ('"a" "b"', ("a", "b")),
        ("a(* split *)b", ("a", "b")),
        ("a #(* joined *)b", ("ab",)),
    ],
)
def test_concatenation(text: str, expected: tuple[str, ...]) -> None:
    assert values(f"&(a = {text})") == expected


def test_comments_anywhere_including_multiline() -> None:
    text = """(* leading
    comment *)&(* between *)(executable(* in *)=(* there *)/bin/true)
    (* a comment
       over lines *)(arguments = "x")(* trailing *)
    """
    assert one(text) == [
        Relation("executable", "=", ("/bin/true",)),
        Relation("arguments", "=", ("x",)),
    ]


def test_comment_ends_at_first_close_searched_from_open() -> None:
    # As in ARC "(*)" is a complete comment, and quotes do not hide "(*".
    assert one("&(*)(a=b)") == [Relation("a", "=", ("b",))]
    assert values('&(a = "x(*y*)z")') == ("x(*y*)z",)


def test_variables_and_substitution() -> None:
    text = """&(rsl_substitution = (TOP /opt) (BIN $(TOP)/bin))
               (executable = $(BIN)/run)
               (arguments = $(TOP)#"/x" pre$(TOP) $(UNDEFINED) $ ( "BIN" ))"""
    assert one(text) == [
        Relation("executable", "=", ("/opt/bin/run",)),
        Relation("arguments", "=", ("/opt/x", "pre/opt", "", "/opt/bin")),
    ]


def test_substitution_scoping() -> None:
    # A binding is seen by later siblings and their descendants, not earlier
    # siblings nor the enclosing conjunction.
    text = """&(a = $(X))
               (rsl_substitution = (X outer))
               (b = $(X))
               (&(rsl_substitution = (X inner)) (c = $(X)))
               (d = $(X))
               (&(rsl_substitution = (Y only-inside)))
               (e = $(Y))"""
    assert one(text) == [
        Relation("a", "=", ("",)),
        Relation("b", "=", ("outer",)),
        Relation("c", "=", ("inner",)),
        Relation("d", "=", ("outer",)),
        Relation("e", "=", ("",)),
    ]


def test_multi_job_each_starts_with_empty_bindings() -> None:
    text = """+(&(rsl_substitution=(X one))(executable=$(X)))
               (&(executable=$(X)))
               (+(&(executable=three)))"""
    assert parse(text) == [
        [Relation("executable", "=", ("one",))],
        [Relation("executable", "=", ("",))],
        [Relation("executable", "=", ("three",))],
    ]


def test_nested_conjunctions_are_flattened() -> None:
    assert one("&(a=1)(&(b=2)(&(c=3)))(d=4)") == [
        Relation("a", "=", ("1",)),
        Relation("b", "=", ("2",)),
        Relation("c", "=", ("3",)),
        Relation("d", "=", ("4",)),
    ]


def test_quoted_attribute_name() -> None:
    assert one("&('Odd_Name'=x)") == [Relation("oddname", "=", ("x",))]


@pytest.mark.parametrize(
    ("text", "where", "what"),
    [
        ("", "line 1, column 1", "the description is empty"),
        ("  \n (* only a comment *)\n", "line 3, column 1", "the description is empty"),
        ("&", "line 1, column 2", "expected '(', but the description ended"),
        ("&(a=b", "line 1, column 6", "expected ')', but the description ended"),
        ("&(a=b))", "line 1, column 7", "unexpected text after the end of the description"),
        ("&(a=b)\n  junk", "line 2, column 3", "found 'j'"),
        ("&(a=b)(* open", "line 1, column 7", "comment '(*' is never closed"),
        ('&(a = "x(*")', "line 1, column 9", "comment '(*' is never closed"),
        ('&(a="open)', "line 1, column 5", "string is never closed (no matching '\"')"),
        ("&(a='open)", "line 1, column 5", 'no matching "\'"'),
        ("&(a=^!open)", "line 1, column 5", "no matching '!'"),
        ("&(a=^", "line 1, column 5", "'^' must be followed by the delimiter"),
        ('&(""=x)', "line 1, column 3", "expected an attribute name"),
        ("&(=x)", "line 1, column 3", "expected an attribute name or '&', '|', '+', found '='"),
        ("&((a=b))", "line 1, column 3", "expected an attribute name"),
        ("&('a=b'=x)", "line 1, column 3", "attribute name 'a=b' contains one of"),
        ("&(a b)", "line 1, column 5", "expected a relation operator"),
        ("&(a ! b)", "line 1, column 5", "expected a relation operator"),
        ("&(a=(b)", "line 1, column 8", "expected ')'"),
        ("&(a=b c=d)", "line 1, column 8", "expected ')', found '='"),
        ("&(a=#b)", "line 1, column 5", "'#' has nothing on its left"),
        ("&(a=b #)", "line 1, column 8", "'#' has nothing on its right to concatenate, found ')'"),
        ("&(a=$x)", "line 1, column 6", "expected '(', found 'x'"),
        ("&(a=$())", "line 1, column 7", "expected a variable name after '$('"),
        ('&(a=$("x$"))', "line 1, column 7", "variable name 'x$' contains one of"),
        ("&(a=$(x y))", "line 1, column 9", "expected ')', found 'y'"),
        ("a=b", "line 1, column 1", "a job must be an '&' conjunction"),
        ("+(a=b)", "line 1, column 3", "a job must be an '&' conjunction"),
        ("+(&(a=b))(|(c=d))", "line 1, column 11", "client-side brokering with '|'"),
        ("|(&(a=b))(&(a=c))", "line 1, column 1", "submit each alternative separately"),
        ("&(a=b)\n(|(c=d)(c=e))", "line 2, column 2", "client-side brokering with '|'"),
        ("&(+(&(a=b)))", "line 1, column 3", "'+' (several jobs) is only allowed at the top"),
        ("&(a = b(c))", "line 1, column 8", "right side of a concatenation must be a string"),
        ("&(a = (b) # c)", "line 1, column 7", "left side of a concatenation must be a string"),
        ("&(rsl_substitution = X)", "line 1, column 22", "expects (NAME value) pairs"),
        ("&(rsl_substitution = (X))", "line 1, column 22", "needs 2 elements (NAME value), not 1"),
        ("&(rsl_substitution = ((X) y))", "line 1, column 23", "variable name must be a string"),
        ("&(rsl_substitution = (X (y)))", "line 1, column 25", "value must be a string"),
    ],
)
def test_errors_say_what_and_where(text: str, where: str, what: str) -> None:
    message = error(text)
    assert message.startswith(f"xRSL syntax error at {where}: ")
    assert what in message


def test_errors_are_description_errors() -> None:
    with pytest.raises(ValueError):
        parse("&(")
    with pytest.raises(OSError):
        parse("&(")


# --- writing ------------------------------------------------------------------------------------


def test_unparse_canonical_form() -> None:
    job = [
        Relation("executable", "=", ("/bin/echo",)),
        Relation("arguments", "=", ("a", 'say "hi"')),
        Relation("inputfiles", "=", (("in", ""), ("x", "http://h/x", "cache=no"))),
        Relation("count", ">=", ("2",)),
        Relation("environment", "=", ()),
    ]
    text = unparse(job)
    assert text == (
        '&(executable = "/bin/echo")(arguments = "a" "say ""hi""")'
        '(inputfiles = ("in" "") ("x" "http://h/x" "cache=no"))(count >= "2")(environment =)'
    )
    assert parse(text) == [job]


def test_unparse_splits_comment_openers_and_quotes_odd_attributes() -> None:
    job = [
        Relation("a", "=", ("(*", "x(*y*)", "(*(*", "*)")),
        Relation("*star", "=", ("v",)),
        Relation("two words", "=", ("v",)),
    ]
    text = unparse(job)
    assert "(*" not in text
    assert parse(text) == [job]


@pytest.mark.parametrize(
    ("job", "what"),
    [
        ([], "at least one relation"),
        ([Relation("a", "==", ("b",))], "not an xRSL relation operator"),
        ([Relation("", "=", ("b",))], "cannot be written"),
        ([Relation("Upper", "=", ("b",))], "cannot be written"),
        ([Relation("under_score", "=", ("b",))], "cannot be written"),
        ([Relation("a=b", "=", ("b",))], "cannot be written"),
        ([Relation("rslsubstitution", "=", (("X", "y"),))], "cannot be written"),
    ],
)
def test_unparse_refuses_what_cannot_be_read_back(job: list[Relation], what: str) -> None:
    with pytest.raises(ValueError) as info:
        unparse(job)
    assert what in str(info.value)


_ALPHABET = "aZ09 _-/:.=()*#$&|+!<>\"'^\n\t\\"


def _random_literal(rng: random.Random) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(0, 8)))


def _random_value(rng: random.Random, depth: int) -> Value:
    if depth > 2 or rng.random() < 0.7:
        return _random_literal(rng)
    return tuple(_random_value(rng, depth + 1) for _ in range(rng.randrange(0, 4)))


def _random_job(rng: random.Random) -> list[Relation]:
    names = ["executable", "arguments", "inputfiles", "x1", "*odd", "with space", "a.b"]
    return [
        Relation(
            rng.choice(names),
            rng.choice(["=", "!=", "<", "<=", ">", ">="]),
            tuple(_random_value(rng, 0) for _ in range(rng.randrange(0, 4))),
        )
        for _ in range(rng.randrange(1, 5))
    ]


@pytest.mark.parametrize("seed", range(300))
def test_round_trip_property(seed: int) -> None:
    job = _random_job(random.Random(seed))
    assert parse(unparse(job)) == [job]


def test_round_trip_of_parsed_text() -> None:
    text = "&(executable=run.sh)(arguments=$(X)a 'b''c')(inputfiles=(a '')(b ^|x|))"
    job = one(text)
    assert parse(unparse(job)) == [job]


# --- periods ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "default", "seconds"),
    [
        # ISO 8601, with ARC's reading of M (month until T/W/D/H/M, then minute).
        ("PT1H30M", "minutes", 5400),
        ("P1D", "minutes", 86400),
        ("P1M", "minutes", 2592000),
        ("P1Y", "minutes", 31536000),
        ("P1W", "seconds", 604800),
        ("PT45S", "minutes", 45),
        ("P1DT2H3M4S", "minutes", 93784),
        ("P1M1M", "minutes", 2592060),
        ("P1D1M", "minutes", 86460),
        ("P1H", "minutes", 3600),
        ("PT0S", "minutes", 0),
        # Free format: units w d h m s; a trailing bare number takes the next
        # smaller unit after the last one seen, else the default.
        ("1h30", "minutes", 5400),
        ("1h30", "seconds", 5400),
        ("90", "minutes", 5400),
        ("90", "seconds", 90),
        ("1w", "minutes", 604800),
        ("1w2", "minutes", 777600),
        ("1d2", "minutes", 93600),
        ("1m30", "minutes", 90),
        ("1s500", "minutes", 1),
        ("2d 3h", "minutes", 183600),
        ("60 minutes", "minutes", 3600),
        ("5 minutes", "seconds", 300),
        ("1 hour 30 minutes", "minutes", 5400),
        ("2 Days", "minutes", 172800),
        ("10 S", "minutes", 10),
        (" 7 ", "minutes", 420),
        ("0", "minutes", 0),
    ],
)
def test_parse_period(text: str, default: str, seconds: int) -> None:
    assert parse_period(text, default) == seconds


def test_parse_period_default_is_minutes() -> None:
    assert parse_period("2") == 120


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("", "no number in it"),
        ("soon", "no number in it"),
        ("5x", "unknown unit 'x' after 5"),
        ("1.5h", "unknown unit '.' after 1"),
        ("5\tm", "unknown unit '\\t' after 5"),
        ("5 5m", "two numbers separated only by spaces"),
        ("5 5", "two numbers separated only by spaces"),
        ("P", "needs at least one component"),
        ("PT", "needs at least one component"),
        ("P1", "expected a number and a unit at '1'"),
        ("PX", "expected a number and a unit at 'X'"),
        ("PT1.5H", "unknown ISO 8601 unit '.'"),
        ("P1Q", "unknown ISO 8601 unit 'Q'"),
    ],
)
def test_parse_period_refuses_what_arc_would_read_as_zero(text: str, why: str) -> None:
    with pytest.raises(DescriptionError) as info:
        parse_period(text)
    message = str(info.value)
    assert message.startswith(f"Invalid time period {text!r}: ")
    assert why in message


def test_parse_period_unknown_default() -> None:
    with pytest.raises(ValueError, match="'seconds' or 'minutes'"):
        parse_period("5", "hours")


# --- prepare ------------------------------------------------------------------------------------


@pytest.fixture
def base(tmp_path: Path) -> Path:
    for name in ("upload.sh", "in.bin", "proxy.sh", "data.txt", "stdin.txt"):
        (tmp_path / name).write_text(name)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.txt").write_text("nested")
    return tmp_path


def _upload(name: str, source: Path, executable: bool) -> Upload:
    """The upload ``prepare`` makes of ``source``: with its size, which the CE is told too."""
    return Upload(name, source, executable, source.stat().st_size)


def prepared(text: str, base: Path, **kwargs: str) -> PreparedJob:
    jobs = prepare(text, base=base, **kwargs)
    assert len(jobs) == 1
    assert jobs[0].description == unparse(jobs[0].relations)
    assert jobs[0].description.startswith("&")
    return jobs[0]


def refused(text: str, base: Path, **kwargs: str) -> str:
    with pytest.raises(DescriptionError) as info:
        prepare(text, base=base, **kwargs)
    return str(info.value)


def test_prepare_hello(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/sh")(arguments="-c" "hostname; echo PWD=`pwd`")'
        '(stdout="out.txt")(stderr="err.txt")(jobname="t1-hello")(queue="main")',
        base,
    )
    assert job.name == "t1-hello"
    assert job.queue == "main"
    assert (job.stdout, job.stderr, job.gmlog) == ("out.txt", "err.txt", None)
    assert job.uploads == ()
    assert job.remote_staging is False
    assert job.description == (
        '&(executable = "/bin/sh")(arguments = "-c" "hostname; echo PWD=`pwd`")'
        '(stdout = "out.txt")(stderr = "err.txt")(jobname = "t1-hello")(queue = "main")'
        '(outputfiles = ("out.txt" "") ("err.txt" ""))'
    )


def test_prepare_upload_job(base: Path) -> None:
    job = prepared(
        '&(executable="upload.sh")(inputfiles=("upload.sh" "")("in.bin" ""))'
        '(outputfiles=("sum.txt" "")("copy.bin" ""))(stdout="out.txt")(jobname="t2-upload")',
        base,
    )
    assert job.uploads == (
        _upload("upload.sh", base / "upload.sh", True),
        _upload("in.bin", base / "in.bin", False),
    )
    assert job.description == (
        '&(executable = "upload.sh")(inputfiles = ("upload.sh" "9") ("in.bin" "6"))'
        '(outputfiles = ("sum.txt" "") ("copy.bin" "") ("out.txt" ""))(stdout = "out.txt")'
        '(jobname = "t2-upload")(executables = "upload.sh")'
    )


def test_prepare_remote_staging(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/sh")(arguments="-c" "sha256sum data.bin")'
        '(inputfiles=("data.bin" "http://arc-ce.arctest.local:8080/data.bin" "cache=no"))'
        '(stdout="out.txt")(jobname="t3-httpstage")',
        base,
    )
    assert job.remote_staging is True
    assert job.uploads == ()
    assert (
        Relation(
            "inputfiles",
            "=",
            (("data.bin", "http://arc-ce.arctest.local:8080/data.bin", "cache=no"),),
        )
        in job.relations
    )


def test_prepare_remote_output(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/true")(outputfiles=("r" "gsiftp://se/r")("l" "file:///tmp/l"))', base
    )
    assert job.remote_staging is True
    job = prepared('&(executable="/bin/true")(outputfiles=("l" "file:///tmp/l")("k" ""))', base)
    assert job.remote_staging is False


def test_prepare_executable_listed_input_with_rte(base: Path) -> None:
    job = prepared(
        '&(executable="proxy.sh")(inputfiles=("proxy.sh" ""))(runtimeenvironment="ENV/PROXY")'
        '(runtimeenvironment="APPS/HEP/ATLAS-1.0" "opt1")'
        '(stdout="out.txt")(stderr="err.txt")(jobname="t4-envproxy")',
        base,
    )
    assert job.runtime_environments == ("ENV/PROXY", "APPS/HEP/ATLAS-1.0")
    assert Relation("runtimeenvironment", "=", ("APPS/HEP/ATLAS-1.0", "opt1")) in job.relations
    assert job.uploads == (_upload("proxy.sh", base / "proxy.sh", True),)


def test_prepare_multicore_and_times(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/sh")(count="2")(countpernode="2")(walltime="5 minutes")'
        '(cputime="90")(lifetime="P1D")(memory="2000")(rerun="3")(queue="short")',
        base,
    )
    assert (job.count, job.memory, job.rerun) == (2, 2000, 3)
    assert (job.walltime, job.cputime) == (300, 5400)
    assert job.description == (
        '&(executable = "/bin/sh")(count = "2")(countpernode = "2")(walltime = "300")'
        '(cputime = "5400")(lifetime = "86400")(memory = "2000")(rerun = "3")(queue = "short")'
    )


def test_prepare_minimal_has_no_optional_fields(base: Path) -> None:
    job = prepared('&(executable="/bin/sleep")(arguments="600")', base)
    assert job.relations == (
        Relation("executable", "=", ("/bin/sleep",)),
        Relation("arguments", "=", ("600",)),
    )
    assert (job.name, job.queue, job.stdout, job.stderr, job.gmlog) == (None,) * 5
    assert (job.walltime, job.cputime, job.count, job.memory, job.rerun) == (None,) * 5
    assert job.runtime_environments == ()


def test_prepare_multi_job_in_order(base: Path) -> None:
    jobs = prepare(
        '+(&(executable="/bin/true")(jobname=one))(&(executable="upload.sh")(jobname=two))',
        base=base,
    )
    assert [job.name for job in jobs] == ["one", "two"]
    assert jobs[1].uploads == (_upload("upload.sh", base / "upload.sh", True),)


def test_prepare_multi_job_error_names_the_job(base: Path) -> None:
    message = refused('+(&(executable="/bin/true"))(&(executable="missing.sh"))', base)
    assert message.startswith("Job 2 of 2: Input file 'missing.sh': ")


def test_join(base: Path) -> None:
    job = prepared('&(executable="/bin/true")(stdout="log")(join="yes")', base)
    assert (job.stdout, job.stderr) == ("log", "log")
    assert job.description == (
        '&(executable = "/bin/true")(stdout = "log")(stderr = "log")(outputfiles = ("log" ""))'
    )
    job = prepared('&(executable="/bin/true")(stdout="log")(stderr="log")(join="TRUE")', base)
    assert (job.stdout, job.stderr) == ("log", "log")
    job = prepared('&(executable="/bin/true")(stdout="o")(stderr="e")(join="no")', base)
    assert (job.stdout, job.stderr) == ("o", "e")
    assert all(relation.attribute != "join" for relation in job.relations)


@pytest.mark.parametrize(
    ("relations", "what"),
    [
        ('(join="yes")', "'join' needs 'stdout'"),
        ('(stdout="o")(stderr="e")(join="yes")', "'stderr' names another file"),
    ],
)
def test_join_refused(base: Path, relations: str, what: str) -> None:
    assert what in refused(f'&(executable="/bin/true"){relations}', base)


def test_gmlog_and_existing_outputs(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/true")(gmlog="log")(stdout="o")(outputfiles=("o" "")("x" ""))', base
    )
    assert job.gmlog == "log"
    assert Relation("outputfiles", "=", (("o", ""), ("x", ""), ("log/", ""))) in job.relations
    job = prepared('&(executable="/bin/true")(gmlog="log/")(outputfiles=("log" ""))', base)
    assert Relation("outputfiles", "=", (("log", ""),)) in job.relations


def test_local_sources_become_uploads(base: Path) -> None:
    job = prepared(
        f'&(executable="/bin/true")(inputfiles=("a" "data.txt" "cache=no")'
        f'("b" "{base}/in.bin")("c" "file://{base}/sub/nested.txt")'
        f'("d" "file://localhost{base}/data.txt")("sub/nested.txt" ""))',
        base,
    )
    assert job.uploads == (
        _upload("a", base / "data.txt", False),
        _upload("b", base / "in.bin", False),
        _upload("c", base / "sub" / "nested.txt", False),
        _upload("d", base / "data.txt", False),
        _upload("sub/nested.txt", base / "sub" / "nested.txt", False),
    )
    assert Relation(
        "inputfiles",
        "=",
        (("a", "8"), ("b", "6"), ("c", "6"), ("d", "8"), ("sub/nested.txt", "6")),
    ) in (job.relations)
    assert job.remote_staging is False


def test_relative_base_gives_absolute_sources(base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(base.parent)
    job = prepared('&(executable="upload.sh")', Path(base.name))
    assert job.uploads == (_upload("upload.sh", base / "upload.sh", True),)
    assert job.uploads[0].source.is_absolute()


def test_stdin_is_uploaded(base: Path) -> None:
    job = prepared('&(executable="/bin/cat")(stdin="stdin.txt")', base)
    assert job.uploads == (_upload("stdin.txt", base / "stdin.txt", False),)
    assert Relation("inputfiles", "=", (("stdin.txt", "9"),)) in job.relations
    job = prepared('&(executable="/bin/cat")(stdin="/dev/null")', base)
    assert job.uploads == ()


def test_environment_executable_is_not_uploaded(base: Path) -> None:
    job = prepared("&(executable='$HOME/bin/run')", base)
    assert job.uploads == ()
    assert all(relation.attribute != "executables" for relation in job.relations)


def test_executables_attribute(base: Path) -> None:
    job = prepared(
        '&(executable="upload.sh")(inputfiles=("in.bin" "")("proxy.sh" ""))'
        '(executables="proxy.sh")',
        base,
    )
    assert job.uploads == (
        _upload("in.bin", base / "in.bin", False),
        _upload("proxy.sh", base / "proxy.sh", True),
        _upload("upload.sh", base / "upload.sh", True),
    )
    assert Relation("executables", "=", ("proxy.sh", "upload.sh")) in job.relations
    job = prepared('&(executable="upload.sh")(executables="upload.sh")', base)
    assert Relation("executables", "=", ("upload.sh",)) in job.relations


def test_remote_executable_is_marked_executable(base: Path) -> None:
    job = prepared('&(executable="run")(inputfiles=("run" "https://h/run"))', base)
    assert job.uploads == ()
    assert job.remote_staging is True
    assert Relation("executables", "=", ("run",)) in job.relations


def test_several_inputfiles_relations_merge(base: Path) -> None:
    job = prepared(
        '&(inputfiles=("in.bin" ""))(executable="/bin/true")(inputfiles=("data.txt" ""))', base
    )
    assert job.relations[0] == Relation("inputfiles", "=", (("in.bin", "6"), ("data.txt", "8")))
    assert [r.attribute for r in job.relations] == ["inputfiles", "executable"]


def test_empty_inputfiles_kept(base: Path) -> None:
    job = prepared('&(executable="/bin/true")(inputfiles=)', base)
    assert Relation("inputfiles", "=", ()) in job.relations


def test_queue_and_delegation_parameters(base: Path) -> None:
    job = prepared('&(executable="/bin/true")', base, queue="grid", delegation_id="D1")
    assert job.queue == "grid"
    assert job.relations[-2:] == (
        Relation("queue", "=", ("grid",)),
        Relation("delegationid", "=", ("D1",)),
    )
    job = prepared(
        '&(executable="/bin/true")(queue="mine")(delegationid="D0")',
        base,
        queue="grid",
        delegation_id="D1",
    )
    assert job.queue == "mine"
    assert Relation("delegationid", "=", ("D0",)) in job.relations
    assert Relation("queue", "=", ("grid",)) not in job.relations


def test_unknown_attributes_pass_through(base: Path) -> None:
    job = prepared(
        '&(executable="/bin/true")(notify="be me@example.org")(priority=50)(somethingnew=(a b))',
        base,
    )
    assert job.relations[1:] == (
        Relation("notify", "=", ("be me@example.org",)),
        Relation("priority", "=", ("50",)),
        Relation("somethingnew", "=", (("a", "b"),)),
    )


@pytest.mark.parametrize(
    ("relations", "what"),
    [
        ("", "has no 'executable'"),
        ('(executable="")', "has no 'executable'"),
        ('(executable="missing.sh")', "Input file 'missing.sh': "),
        ('(executable="sub")', "does not exist or is not a file"),
        (
            '(executable="/bin/true")(executable="/bin/false")',
            "'executable' is given more than once",
        ),
        ('(executable="/bin/a" "/bin/b")', "'executable' must have exactly one string value"),
        ("(executable=(/bin/a))", "'executable' must have exactly one string value"),
        ('(executable="/bin/true")(action="request")', "'action' is set by the CE itself"),
        ('(executable="/bin/true")(jobid="x")', "'jobid' is set by the CE itself"),
        ('(executable="/bin/true")(gridtime="60")', "'gridtime' is normalised CPU time"),
        ('(executable="/bin/true")(benchmarks=(a b c))', "'benchmarks' is normalised CPU time"),
        ('(executable="/bin/true")(walltime="5x")', "Attribute 'walltime': Invalid time period"),
        ('(executable="/bin/true")(count="two")', "'count' must be a whole number, not 'two'"),
        ('(executable="/bin/true")(memory="-1")', "'memory' must be a whole number"),
        ('(executable="/bin/true")(runtimeenvironment=)', "needs a name and string options"),
        ('(executable="/bin/true")(runtimeenvironment=(A))', "needs a name and string options"),
        (
            '(executable="/bin/true")(runtimeenvironment>="APPS/X-1")',
            "Runtime environment 'APPS/X-1' is requested with '>=': only '=' can be sent to the CE",
        ),
        ('(executable="/bin/true")(queue!="slow")', "'queue' only takes '='"),
        ('(executable="/bin/true")(delegationid<"x")', "'delegationid' only takes '='"),
        ('(executable="/bin/true")(inputfiles="a")', "must be a sequence of strings"),
        ('(executable="/bin/true")(inputfiles=("a"))', "must be a sequence of strings"),
        ('(executable="/bin/true")(inputfiles=("a" ("b")))', "must be a sequence of strings"),
        ('(executable="/bin/true")(inputfiles=("" "http://h/x"))', "has an empty file name"),
        ('(executable="/bin/true")(outputfiles=("o"))', "'outputfiles' entry must be a sequence"),
        ('(executable="/bin/true")(inputfiles=("/abs" "http://h/x"))', "must be a relative path"),
        ('(executable="/bin/true")(inputfiles=("a/../../b" "http://h/x"))', "relative path"),
        ('(executable="../up.sh")', "Input file name '../up.sh' must be a relative path"),
        (
            '(executable="/bin/true")(inputfiles=("a" "http://h/a")("a" "http://h/b"))',
            "Two input files are both named 'a'",
        ),
        ('(executable="/bin/true")(inputfiles=("a" "missing"))', "'a': "),
        ('(executable="/bin/true")(inputfiles=("a" "file://host/x"))', "names another host"),
        ('(executable="/bin/true")(executables=(x))', "'executables' lists names"),
        ('(executable="/bin/true")(executables="nope")', "'nope' in 'executables' is not one"),
    ],
)
def test_prepare_refusals(base: Path, relations: str, what: str) -> None:
    assert what in refused(f"&(jobname=x){relations}", base)


def test_prepare_passes_syntax_errors_through(base: Path) -> None:
    assert refused("&(executable=", base).startswith("xRSL syntax error at line 1, column 14")


def test_prepared_description_is_gridmanager_round_trippable(base: Path) -> None:
    job = prepared(
        "&(executable=upload.sh)(arguments='a b' \"c\"\"d\")(walltime='1h30')(stdout=o)(join=yes)"
        "(inputfiles=(in.bin '')(remote 'srm://se/x' 'location=gsiftp://a/b'))",
        base,
    )
    assert parse(job.description) == [list(job.relations)]
    assert Relation("walltime", "=", ("5400",)) in job.relations
