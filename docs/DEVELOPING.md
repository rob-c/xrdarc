# Developing

## Setup

xrdarc is developed against the sibling checkouts of xrdclient and
xgfalclient, installed editable into one environment:

```console
$ python3 -m venv .venv
$ .venv/bin/pip install -e ../xrdclient -e ../xgfalclient -e '.[dev,docs]'
```

## The local gate

Everything here must pass before a change is done:

```console
$ pytest -n auto --cov --cov-report=term-missing   # 100% line and branch, enforced
$ ruff check src tests
$ ruff format --check src tests
$ mypy
$ complexipy --quiet                                # cognitive complexity <= 15
$ python -m build && twine check --strict dist/*
$ mkdocs build --strict
```

The suite is hermetic. An autouse fixture clears every credential variable,
points `HOME` at a temporary directory and makes `/tmp/x509up_u<uid>`
unfindable, so nothing from the developer's grid setup leaks in. Tests that
need credentials use the in-process PKI (`pki`, `grid_env` fixtures, from
`xgfalclient.testing.pki`).

## The fake A-REX

`xrdarc.testing.arex.FakeARex` is an in-process, threaded, TLS fake of A-REX's
REST interface, written from `rest.cpp`. It ships in the package so other
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
