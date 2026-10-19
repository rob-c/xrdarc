# Developing

## Setup

xrdarc is developed against sibling checkouts of the libraries it is built
on, installed editable into one environment. It needs no storage client:

```console
$ python3 -m venv .venv
$ .venv/bin/pip install -e ../xrdcore -e ../xrdsec -e ../xrdhttp -e '.[dev,docs]'
```

A sibling checkout of [xrd-devtools](https://github.com/rob-c/xrd-devtools)
belongs there too: it holds the chain's gates (the take-over scorecard that
`tests/test_scorecard.py` loads as a pytest plugin, `xrddevtools
conformance`, `xrddevtools dupes`, the release pre-flight). It is not on PyPI
and cannot be a dependency (PyPI refuses direct-URL requirements); pytest's
`pythonpath` finds `../xrd-devtools` or CI's `.dependencies/xrd-devtools`,
and anywhere else `pip install -e` it or put its `src` on `PYTHONPATH`.
Without it the scorecard test skips, saying why (as it does without radon
and complexipy); CI loads the plugin with `-p` and sets
`XRD_DEVTOOLS_REQUIRED=1`, so there it cannot skip. CI is xrd-devtools'
reusable workflows and candidates action, so it needs `rob-c/xrd-devtools`
to exist; nothing of xrdclient is checked out any more.

## The local gate

Everything here must pass before a change is done:

```console
$ pytest -n auto --cov --cov-report=term-missing   # 100% line and branch, enforced
$ ruff check src tests
$ ruff format --check src tests
$ mypy                                              # strict, over src and tests
$ complexipy --quiet                                # cognitive complexity <= 15
$ xrddevtools conformance --repo .                  # the chain's one configuration standard
$ python -m build && twine check --strict dist/*
$ mkdocs build --strict
```

The same standard applies to old code and new, as in every repository of
the family. Nothing is grandfathered:

* ruff selects `E F W I UP B C4 SIM RUF` and the high-confidence `S`
  checks, with no ignored rules and no per-file ignores, plus `TID251`: the
  APIs the libraries own (`http.client`, hand-built TLS contexts,
  `ThreadPoolExecutor`, XML parsers, ...) are banned in src and tests alike,
  each with the library replacement in its message - CONTRIBUTING.md,
  *Banned APIs*, lists them;
* there are no suppression comments: no `# noqa`, `# type: ignore`,
  `# pragma: no cover`, `# fmt: skip` or complexipy markers - the code is
  fixed instead (a test reaches the branch, the types say what is meant);
* mypy is strict over the tests too;
* complexipy checks src and tests against the limit itself, with no
  snapshot of existing over-limit functions;
* coverage excludes only the shared `exclude_also` patterns, and omits
  nothing;
* pytest turns every warning into an error (`filterwarnings = ["error"]`);
  a test that expects a warning asserts it with `pytest.warns`;
* the only skips are environmental, and their reasons say which
  environment: the interop marker, POSIX file modes as a non-root user, a
  platform without `time.tzset`, a missing xrdclient checkout for the
  scorecard.

The suite is hermetic. xrdsec's pytest plugin (`xrdsec.testing.fixtures`,
loaded by `tests/conftest.py`, whose `pytest_xrdsec_hermetic` hook adds
xrdarc's own variables and `client.conf`) has an autouse fixture that
clears every credential variable, points `HOME` at a temporary directory,
points
`xrdsec.credentials.TMP_DIR` (the `/tmp` of `/tmp/x509up_u<uid>` and
`/tmp/bt_u<uid>`) at an empty one and `xrdsec.credentials.GRID_SECURITY_DIRS`
(where `grid-security/certificates`, `vomsdir` and `vomses` are looked
for) at a directory of the test's own (the `grid_security` fixture), so
nothing from the developer's grid setup leaks in and "no CA directory"
means the same on every machine - through the libraries' documented
inputs, not by patching their internals. Tests that need credentials use the in-process PKI
(`pki`, `grid_env` fixtures, from the same plugin); VOMS tests run a
real `xrdsec.testing.voms.FakeVOMSServer`.

## The fake A-REX

`xrdarc.testing.arex.FakeARex` is an in-process, threaded, TLS fake of A-REX's
REST interface, written from `rest.cpp`, on xrdsec's generic
`FakeHTTPSServer` (TLS, keep-alive, faults, the request log). It ships in the package so other
projects can test against it. It reproduces the quirks a client has to
survive:

* HTML unless `Accept` names JSON or XML;
* all JSON values are strings, with forced arrays per endpoint;
* bulk answers are HTTP 201 with per-job codes, including 505;
* explanations come in the reason phrase;
* delegation requests carry an empty subject;
* session `PUT` does not truncate.

It also has controls for state progression, faults (status, delay,
dropped connections), legacy ARC 6 JSON and denied operations. See its
module docstring.

## Interop: a real CE

`tests/test_interop.py` runs real jobs, with the caller's real credentials,
and is skipped unless asked for:

```console
$ export XRDARC_INTEROP=1
$ export XRDARC_INTEROP_CE=ce.example.org          # or https://ce.example.org:443/arex
$ export XRDARC_INTEROP_QUEUE=grid                 # optional
$ export XRDARC_INTEROP_RTE=ENV/PROXY              # optional: checks the delegated proxy on the WN
$ pytest -m interop -v -o addopts=
```

The tests cover:

* `info`;
* a hello-world round trip with `gmlog`;
* a 3 MiB input upload, returned and checked by checksum;
* a failing job's exit code and diagnostics;
* kill;
* delegation renewal;
* with an RTE that exports `X509_USER_PROXY`, `openssl verify` of the
  delegated chain on the worker node.

The job list is a temporary file, and every job is cleaned at the end.

For the docker ARC CE and SLURM cluster in `ARC-test/cluster`, one command
brings the cluster up, makes a proxy with `xrdarc proxy` from the test user's
certificate, and runs the suite from a clean Linux container on the cluster
network:

```console
$ tools/interop-docker.sh /path/to/ARC-test/cluster
```

A WLCG site CE needs a VOMS proxy for the VO the CE supports:

```console
$ xrdarc proxy -S atlas                  # or voms-proxy-init, arcproxy
$ xrdarc info -C ce.example.org -l       # queues and VO shares
$ XRDARC_INTEROP=1 XRDARC_INTEROP_CE=ce.example.org XRDARC_INTEROP_QUEUE=... pytest -m interop -v -o addopts=
```

## Debugging a job

```console
$ xrdarc stat -l JOB              # REST state, errors, exit code, nodes, times
$ xrdarc cat -l JOB               # A-REX's log of the job (stage-in, LRMS submission, ...)
$ xrdarc diagnose JOB             # every control file: failed, errors, diag, local, description ...
$ xrdarc ls JOB                   # what is in the session directory now
$ xrdarc cat -f some/file JOB     # any file, also while the job runs
$ xrdarc -d DEBUG stat JOB        # every HTTP request
$ xrdarc stat --json JOB          # everything, machine-readable
```

## Releasing

xrdarc is released on GitHub and PyPI, after xrdcore, xrdsec and xrdhttp are on PyPI (step
5 of xrdclient's `docs/releasing.md`, *Releasing the 0.4.0 chain*). Date the
version's `CHANGELOG.md` heading, wait for CI, then push an annotated
`v<version>` tag. `.github/workflows/publish.yml` builds with xrd-devtools'
shared `publish` action, the release build of every package of the chain: it
builds the sdist and wheel and runs `twine check --strict`, then runs
xrd-devtools' `chain_preflight.py pypi` on the wheel, so xrdcore, xrdsec and xrdhttp at
their lower bounds must be on PyPI as wheels. It installs the wheel from PyPI alone and checks the tag,
version and changelog, then runs this suite against the installed wheel.
Last, it creates the GitHub release with both files attached and the
changelog section as its notes, and uploads the same files to PyPI with
trusted publishing (owner `rob-c`, repository `xrdarc`, workflow
`publish.yml`, environment `pypi`).
