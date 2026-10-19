"""Making a parsed xRSL job ready to submit: :func:`prepare`.

People write the *user* dialect (``walltime="90"`` is ninety minutes,
``join="yes"`` merges stderr into stdout); A-REX reads the *GRIDMANAGER*
dialect (times in seconds, no ``join``). :func:`prepare` rewrites one into
the other as ``XRSLParser`` and ``JobDescription::Prepare`` do in ARC's C++
client, refuses what this client does not support (client-side brokering,
attributes A-REX sets itself), and works out the local files the client
must upload into the session directory after the CE accepts the job - the
executable and every ``inputfiles`` entry without a URL - with their sizes,
which go into the description so A-REX can tell a complete upload.

:class:`_Job` is the job's relations, edited in place; each ``_``-prefixed
function below handles one attribute family and is applied by
:func:`_prepare_job` in ARC's order (the order matters: ``join`` must be
resolved before ``stdout``/``stderr`` are read as outputs).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..errors import DescriptionError
from ._period import parse_period
from ._syntax import Relation, Value, parse
from ._write import unparse


@dataclass(frozen=True, slots=True)
class Upload:
    """A local file the client must PUT to ``<job>/session/<name>`` after submitting.

    ``size`` is the file's size when the description was prepared, which is
    also what the description told the CE to expect; ``None`` when unknown
    (an ADL upload). A file whose size has changed by upload time is not
    sent, since A-REX would reject it or wait forever for the rest.
    """

    name: str
    source: Path
    executable: bool
    size: int | None = None


@dataclass(frozen=True, slots=True)
class PreparedJob:
    """One job rewritten for the CE, with what the client must do around it.

    ``description`` is the GRIDMANAGER-dialect xRSL to POST (``unparse`` of
    ``relations``); times are in seconds and memory in MB, as the CE reads
    them. ``remote_staging`` says the CE itself will fetch or store files
    (an input with a URL source or an output with a URL target), which
    needs a delegated credential.
    """

    description: str
    name: str | None
    queue: str | None
    stdout: str | None
    stderr: str | None
    gmlog: str | None
    uploads: tuple[Upload, ...]
    runtime_environments: tuple[str, ...]
    walltime: int | None
    cputime: int | None
    count: int | None
    memory: int | None
    rerun: int | None
    remote_staging: bool
    relations: tuple[Relation, ...]


#: Attributes A-REX writes for itself; a user description must not carry them.
#: (``XRSLParser`` refuses them too: a forged ``jobid`` or ``hostname`` would
#: confuse the CE's bookkeeping.)
_INTERNAL = ("action", "hostname", "jobid", "clientxrsl", "clientsoftware", "savestate")

#: The refusal for ``gridtime``/``benchmarks``: those are scaled to a CE's
#: published benchmark values, which ``arcsub`` does while brokering; A-REX
#: never sees them, so passing them through would silently drop the limit.
_NORMALISED_TIME = (
    "is normalised CPU time, which needs client-side brokering against the CE's "
    "benchmarks and is not supported; give 'cputime' or 'walltime' instead"
)
#: A URL scheme at the start of a location (RFC 3986's ``scheme ":" "//"``).
_URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
#: What ``count``, ``memory`` and ``rerun`` must be: digits, no sign, no unit.
#: Checked here, before anything reaches the CE, so a unit typo
#: (``memory="2GB"``) is a local error naming the attribute.
_WHOLE_NUMBER = re.compile(r"[0-9]+")


class _Job:
    """The relations of one job, edited in place while it is prepared."""

    def __init__(self, relations: Sequence[Relation]) -> None:
        """A working copy: the parsed job itself is never changed."""
        # A copy, so relations a caller parsed itself are still the user's own
        # after preparing (the rewrite edits this list freely).
        self.relations = list(relations)

    def all(self, attribute: str) -> list[Relation]:
        """Every relation of ``attribute``, in order (a repeated attribute is legal xRSL)."""
        return [relation for relation in self.relations if relation.attribute == attribute]

    def single(self, attribute: str) -> str | None:
        """The one string value of ``attribute``; None when it is absent."""
        found = self.all(attribute)
        if not found:
            return None
        # A repeated single-valued attribute is ambiguous: refusing it makes
        # the user say which one was meant, instead of a guess going to the CE.
        if len(found) > 1:
            raise DescriptionError(f"Attribute '{attribute}' is given more than once")
        values = found[0].values
        if len(values) != 1 or not isinstance(values[0], str):
            raise DescriptionError(f"Attribute '{attribute}' must have exactly one string value")
        return values[0]

    def put(self, attribute: str, values: tuple[Value, ...]) -> None:
        """Replace the first ``attribute`` (keeping its place and operator) or append one."""
        kept: list[Relation] = []
        placed = False
        # Keeping the first one's place makes the description sent read like
        # the one written, which is what a user comparing them expects.
        for relation in self.relations:
            if relation.attribute != attribute:
                kept.append(relation)
            elif not placed:
                kept.append(replace(relation, values=values))
                placed = True
        if not placed:
            kept.append(Relation(attribute, "=", values))
        self.relations = kept

    def drop(self, attribute: str) -> None:
        """Remove every relation of ``attribute``."""
        self.relations = [
            relation for relation in self.relations if relation.attribute != attribute
        ]


def _refuse_unsupported(job: _Job) -> None:
    """Refuse attributes A-REX sets itself, and the normalised-time ones that need brokering."""
    for relation in job.relations:
        if relation.attribute in _INTERNAL:
            raise DescriptionError(
                f"Attribute '{relation.attribute}' is set by the CE itself and cannot appear "
                "in a job description"
            )
        if relation.attribute in ("gridtime", "benchmarks"):
            raise DescriptionError(f"Attribute '{relation.attribute}' {_NORMALISED_TIME}")


def _convert_time(job: _Job, attribute: str) -> int | None:
    """Rewrite a user-dialect time (bare number = minutes) as seconds for the CE."""
    text = job.single(attribute)
    if text is None:
        return None
    try:
        # The user dialect's bare number is minutes ("walltime=90").
        seconds = parse_period(text, "minutes")
    except DescriptionError as exc:
        raise DescriptionError(f"Attribute '{attribute}': {exc.user_message}") from None
    # The GRIDMANAGER dialect's bare number is seconds; written plainly, no unit.
    job.put(attribute, (str(seconds),))
    return seconds


def _integer(job: _Job, attribute: str) -> int | None:
    """A whole-number attribute (``count``, ``memory``, ``rerun``), read for the summary."""
    text = job.single(attribute)
    if text is None:
        return None
    if not _WHOLE_NUMBER.fullmatch(text):
        raise DescriptionError(f"Attribute '{attribute}' must be a whole number, not {text!r}")
    return int(text)


def _resolve_join(job: _Job) -> tuple[str | None, str | None]:
    """Apply and remove ``join``: the CE ignores it, so stderr is pointed at stdout here."""
    stdout, stderr = job.single("stdout"), job.single("stderr")
    join = job.single("join")
    # Dropped whatever its value: A-REX would reject the unknown attribute.
    job.drop("join")
    if join is None or join.lower() not in ("yes", "true"):
        return stdout, stderr
    if not stdout:
        raise DescriptionError("Attribute 'join' needs 'stdout' to be given as well")
    if stderr and stderr != stdout:
        raise DescriptionError("Attribute 'join' cannot be used when 'stderr' names another file")
    job.put("stderr", (stdout,))
    return stdout, stdout


def _runtime_environments(job: _Job) -> tuple[str, ...]:
    """The RTE names; further values of a relation are options and stay in the description."""
    return tuple(_runtime_environment(relation) for relation in job.all("runtimeenvironment"))


def _runtime_environment(relation: Relation) -> str:
    """One ``runtimeenvironment`` relation's name, if the CE can be sent it as it is.

    ARC's broker resolves ``>=``/``<=`` against what each CE publishes;
    A-REX itself only matches a name exactly, so anything but ``=`` would
    silently mean something else once submitted, and is refused.
    """
    if not relation.values or not all(isinstance(v, str) for v in relation.values):
        raise DescriptionError("Attribute 'runtimeenvironment' needs a name and string options")
    if relation.operator != "=":
        raise DescriptionError(
            f"Runtime environment {relation.values[0]!r} is requested with "
            f"{relation.operator!r}: only '=' can be sent to the CE (version ranges need "
            "client-side brokering)"
        )
    return str(relation.values[0])


def _only_equals(job: _Job, attribute: str) -> None:
    """Refuse ``!=`` and friends on ``attribute``: a CE takes only a value, not a constraint."""
    for relation in job.all(attribute):
        if relation.operator != "=":
            raise DescriptionError(
                f"Attribute '{attribute}' only takes '=' when sent to a CE, "
                f"not {relation.operator!r}"
            )


def _queue(job: _Job, default: str | None) -> str | None:
    """The job's queue: its own, else ``default`` (``-q``), which is then written into it."""
    _only_equals(job, "queue")
    name = job.single("queue")
    if name is None and default:
        job.put("queue", (default,))
        return default
    return name


def _delegation(job: _Job, delegation_id: str | None) -> None:
    """Name ``delegation_id`` in the job unless it names its own (REST 1.0 needs it there)."""
    _only_equals(job, "delegationid")
    if delegation_id and not job.all("delegationid"):
        job.put("delegationid", (delegation_id,))


def _is_local_relative(path: str) -> bool:
    """A path the client uploads: not absolute on the worker node, not an environment reference."""
    return bool(path) and not path.startswith(("/", "$"))


def _entries(job: _Job, attribute: str) -> list[tuple[str, ...]]:
    """Every ``(name location [options...])`` of ``attribute``, across all its relations."""
    return [
        _entry(attribute, value) for relation in job.all(attribute) for value in relation.values
    ]


def _entry(attribute: str, value: Value) -> tuple[str, ...]:
    """One staging entry, checked: a sequence of at least two strings, the name not empty."""
    if isinstance(value, str) or len(value) < 2 or not all(isinstance(i, str) for i in value):
        raise DescriptionError(
            f"Each '{attribute}' entry must be a sequence of strings "
            f"(name location [options...]), not {value!r}"
        )
    entry = tuple(str(item) for item in value)
    if not entry[0]:
        raise DescriptionError(f"An '{attribute}' entry has an empty file name")
    return entry


def _session_name(name: str) -> str:
    """An input's name, which must stay inside the session directory (it is a path there)."""
    if name.startswith("/") or ".." in name.split("/"):
        raise DescriptionError(
            f"Input file name {name!r} must be a relative path inside the session directory"
        )
    return name


def _is_remote(location: str) -> bool:
    """A URL the CE fetches or stores itself; ``file://`` is the client's own disk."""
    match = _URL.match(location)
    return match is not None and match[1].lower() != "file"


def _local_path(name: str, source: str, base: Path) -> Path:
    """The local file behind an input whose source is empty, a path or a ``file://`` URL."""
    if _URL.match(source):
        parts = urlsplit(source)
        # ``file://host/path`` names a file on another machine, which the
        # client cannot read; only the local host's form is the client's own.
        if parts.netloc not in ("", "localhost"):
            raise DescriptionError(f"Input file {name!r}: {source!r} names another host")
        path = Path(unquote(parts.path))
    else:
        path = base / (source or name)
    # Checked now, not at upload: a missing input must stop the submission
    # before a job exists that would wait for it.
    path = path.absolute()
    if not path.is_file():
        raise DescriptionError(
            f"Input file {name!r}: {str(path)!r} does not exist or is not a file"
        )
    return path


class _Inputs:
    """The job's input files: remote ones as written, local ones as uploads.

    A local input is written for the CE as ``(name "<size>")``, the
    GRIDMANAGER form ``XRSLParser`` unparses for a file the client uploads
    (``JobDescription::Prepare`` fills the size in from ``stat``). A-REX
    then holds the job until that many bytes have arrived and fails it if
    more do, so a truncated or swapped upload cannot run. ARC also appends
    ``.<checksum>`` for small files, but A-REX's REST interface tracks
    uploads itself and never computes it, so no checksum is sent.
    """

    def __init__(self, entries: list[tuple[str, ...]], base: Path) -> None:
        """Take every ``inputfiles`` entry; local sources are found from ``base``."""
        self.base = base
        self.entries: list[tuple[str, ...]] = []
        self.sources: dict[str, Path] = {}
        self.sizes: dict[str, int] = {}
        self.remote = False
        for entry in entries:
            self.add(entry)

    def add(self, entry: tuple[str, ...]) -> None:
        """One input: a remote one kept as written, a local one checked and sized now."""
        name = _session_name(entry[0])
        if any(existing[0] == name for existing in self.entries):
            raise DescriptionError(f"Two input files are both named {name!r}")
        if _is_remote(entry[1]):
            self.remote = True
            self.entries.append(entry)
            return
        # The CE expects the client to upload it: what it sees is the size.
        path = _local_path(name, entry[1], self.base)
        self.sources[name] = path
        self.sizes[name] = path.stat().st_size
        self.entries.append((name, str(self.sizes[name])))

    def ensure(self, name: str) -> None:
        """Make ``name`` an input unless it is one (the executable, ``stdin``), as ARC does."""
        if not any(entry[0] == name for entry in self.entries):
            self.add((name, ""))

    def uploads(self, executables: Sequence[str]) -> tuple[Upload, ...]:
        """The local inputs to PUT after submission, marked executable as the job says."""
        return tuple(
            Upload(name, source, name in executables, self.sizes[name])
            for name, source in self.sources.items()
        )


def _executables(job: _Job, inputs: _Inputs, executable: str) -> list[str]:
    """The names to make executable, with a relative ``executable`` added to them."""
    names = [_name(value) for relation in job.all("executables") for value in relation.values]
    if _is_local_relative(executable) and executable not in names:
        names.append(executable)
    known = {entry[0] for entry in inputs.entries}
    unknown = next((name for name in names if name not in known), None)
    if unknown is not None:
        raise DescriptionError(f"File {unknown!r} in 'executables' is not one of the input files")
    if names:
        job.put("executables", tuple(names))
    return names


def _name(value: Value) -> str:
    """An ``executables`` entry: a name, never a sequence."""
    if not isinstance(value, str):
        raise DescriptionError(f"Attribute 'executables' lists names, not {value!r}")
    return value


def _outputs(job: _Job, wanted: Sequence[str | None], gmlog: str | None) -> bool:
    """Add stdout, stderr and the gmlog directory to the outputs; True if any output is remote."""
    entries: list[Value] = list(_entries(job, "outputfiles"))
    remote = any(_is_remote(str(entry[1])) for entry in entries)
    names = {str(entry[0]).rstrip("/") for entry in entries}
    for name in _implicit_outputs(wanted, gmlog):
        if name.rstrip("/") not in names:
            names.add(name.rstrip("/"))
            entries.append((name, ""))
    if entries:
        job.put("outputfiles", tuple(entries))
    return remote


def _implicit_outputs(wanted: Sequence[str | None], gmlog: str | None) -> list[str]:
    """The outputs a job has without naming them: stdout, stderr, and the gmlog directory.

    A directory output ends in ``/`` (A-REX then keeps the whole tree), so
    the gmlog name gets one.
    """
    return [name for name in wanted if name] + ([gmlog.rstrip("/") + "/"] if gmlog else [])


def _stage(
    job: _Job, base: Path, stdout: str | None, stderr: str | None
) -> tuple[tuple[Upload, ...], bool]:
    """Complete the data staging as ``JobDescription::Prepare`` does."""
    executable = job.single("executable")
    if not executable:
        raise DescriptionError("The job description has no 'executable'")
    had_inputs = bool(job.all("inputfiles"))
    inputs = _Inputs(_entries(job, "inputfiles"), base)
    # The executable and stdin are inputs too when they are local files.
    for implicit in (executable, job.single("stdin")):
        if implicit and _is_local_relative(implicit):
            inputs.ensure(implicit)
    executables = _executables(job, inputs, executable)
    if inputs.entries or had_inputs:
        job.put("inputfiles", tuple(inputs.entries))
    remote_outputs = _outputs(job, (stdout, stderr), job.single("gmlog"))
    return inputs.uploads(executables), inputs.remote or remote_outputs


def _prepare_job(
    relations: Sequence[Relation], base: Path, delegation_id: str | None, queue: str | None
) -> PreparedJob:
    """One job, user dialect in, GRIDMANAGER dialect out, in ``XRSLParser``'s order.

    The order matters: ``join`` is resolved before staging reads
    ``stdout``/``stderr`` as outputs, and the times are converted before
    the summary fields are read back.
    """
    job = _Job(relations)
    _refuse_unsupported(job)
    walltime = _convert_time(job, "walltime")
    cputime = _convert_time(job, "cputime")
    _convert_time(job, "lifetime")
    stdout, stderr = _resolve_join(job)
    runtime_environments = _runtime_environments(job)
    queue_name = _queue(job, queue)
    _delegation(job, delegation_id)
    uploads, remote = _stage(job, base, stdout, stderr)
    return PreparedJob(
        description=unparse(job.relations),
        name=job.single("jobname"),
        queue=queue_name,
        stdout=stdout,
        stderr=stderr,
        gmlog=job.single("gmlog"),
        uploads=uploads,
        runtime_environments=runtime_environments,
        walltime=walltime,
        cputime=cputime,
        count=_integer(job, "count"),
        memory=_integer(job, "memory"),
        rerun=_integer(job, "rerun"),
        remote_staging=remote,
        relations=tuple(job.relations),
    )


def prepare(
    text: str, *, base: Path, delegation_id: str | None = None, queue: str | None = None
) -> list[PreparedJob]:
    """Turn a user-dialect xRSL description into GRIDMANAGER-dialect jobs for the CE.

    Times become seconds, ``join`` is resolved, the executable, ``stdin``
    and every input with an empty, local or ``file://`` source become
    uploads from ``base`` (what the CE sees instead of the source is the
    file's size, which A-REX checks the upload against), and
    ``stdout``, ``stderr`` and ``gmlog`` are added to the outputs, as
    ``arcsub`` does. ``queue`` and ``delegation_id`` are added only where
    the description has none. Other attributes pass through unchanged.

    Raises ``DescriptionError`` for anything ``parse`` refuses, a missing
    ``executable`` or local input file, an input name outside the session
    directory, an attribute the CE sets itself, normalised-time attributes,
    and any requirement (``!=`` queues, RTE version ranges) that only a
    client-side broker could meet. With several jobs the message says
    which one failed.
    """
    jobs = parse(text)
    prepared: list[PreparedJob] = []
    for number, relations in enumerate(jobs, 1):
        try:
            prepared.append(_prepare_job(relations, base, delegation_id, queue))
        except DescriptionError as exc:
            if len(jobs) == 1:
                raise
            raise DescriptionError(f"Job {number} of {len(jobs)}: {exc.user_message}") from exc
    return prepared
