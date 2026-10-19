# Changelog

All notable changes to xrdarc are recorded here.

## [0.4.0] - Unreleased

Released with the 0.4.0 storage clients and libraries. Reliability and
safety fixes to the job lifecycle and the command line, and xrdarc is now
built on the grid libraries `xrdcore` and `xrdsec` instead of on the
storage clients: it no longer depends on xrdclient or xgfalclient at all.

### Changed: built on xrdcore and xrdsec

What moved where (xrdarc keeps only what is ARC's):

- Credential discovery (`xrdarc.creds`) is `xrdsec.discovery.ARC` and
  `xrdsec.credentials` (was `xgfalclient.creds`/`Options`); TLS contexts are
  `xrdsec.tls.client_context(..., x509_strict=False)` (was
  `xgfalclient.creds.TLSContexts`). This fixes: an insecure token file
  raising an uncaught gfal2 `GError`; a gfal2 configuration file overriding
  `$BEARER_TOKEN`, or breaking xrdarc when malformed; a blank
  `X509_CERT_DIR` used as the CA path. Contexts are now rebuilt when a
  proxy is renewed or the CA directory changes, and ARC's
  `X509_CERT_POLICY` (`any`: grid and system store; `system`: system store
  only) is honoured (`Credentials.system_ca`).
- Proxies (`xrdarc.proxy`, 472 lines before) are `xrdsec.proxies` under its
  `"arc"` profile: `load_signer` (was `Signer.load`), `sign_request`,
  `create_proxy` (now returns an `xrdsec.x509.ProxyCredential`; `voms_acs=`
  takes the ACs), `write_proxy`, `proxy_info` (now `xrdsec.proxies.ProxyInfo`,
  with `voms-proxy-info`'s type wording). `Signer` is an alias of
  `ProxyCredential`. Removed: `openssl_name`, `verify_chain_link`,
  `VOMSAttributes`, `sign_request(copy_voms=)`, `create_proxy(now=)`.
- Proxy lifetime checks are `xrdsec.lifetime`'s: `ARCClient.check_lifetime`
  classifies the signer's remaining life with `xrdsec.lifetime.assess`
  (expired, under `min_lifetime`, under `LOW_LIFETIME`), and the
  expired-signer refusal before signing uses `xrdsec.lifetime.chain_expiry`.
  Messages, errno and behaviour are unchanged; the private
  `client._base._require_lifetime` is `_refuse_short_lived`.
- VOMS (`xrdarc.voms`, removed) is `xrdsec.voms_client` (`find_vomses`,
  `servers_for`, `fetch_ac`). `xrdarc proxy -S` asks the VOMS servers with
  the user certificate and key held in memory, so it no longer writes a
  ten-minute proxy with its private key to `$TMPDIR`; the AC is checked
  against the local `vomsdir` (a warning, logged, if it does not verify).
- Safe XML parsing is `xrdcore.safexml` (was `xrdclient._xml`); the CLI
  report is `xrdcore.report` (was `xrdclient.cli._output`).
- The transport takes its backoff from `xrdcore.retry` (full jitter,
  capped at `transport.BACKOFF_CAP`), honours `Retry-After` on 429/503
  (429 is now retried for idempotent requests), redacts its log records
  with `xrdcore.log`, and `Session.download(cancel=)` (`xrdcore.cancel`)
  stops a download mid-file, waking a read blocked on a stalled CE; `get`
  passes its stop event, so Ctrl-C no longer waits for the current file.
  `Session(pool=)` is gone.
- `xrdarc.errors.CredentialError` is also an `xrdcore.errors.CredentialError`
  (joined, as the libraries ask); `errors.credential_error` turns library
  errors into xrdarc's at the boundary.
- `xrdarc.testing.arex` is a package built on
  `xrdsec.testing.https.FakeHTTPSServer` (TLS, keep-alive, faults, request
  log) and xrdhttp's reply helpers (`xrdhttp.testing.ranged_reply`,
  `propfind_reply`, `dav_entries`), with A-REX's quirks kept; the
  facade is unchanged except that `Fault` is xrdsec's (`pattern=` rather
  than `path_pattern=`; `FakeARex.fault(...)` is unchanged).
- The test suite uses `xrdsec.testing.pki` and `xrdsec.testing.voms`
  (`FakeVOMSServer`) and stays hermetic through `xrdsec.credentials.TMP_DIR`
  and `xrdsec.credentials.GRID_SECURITY_DIRS` instead of patching client
  internals, so it no longer depends on the machine having no
  `/etc/grid-security/certificates`.
- `xrdarc proxy -S` reaches VOMS servers with Python 3.13's RFC 5280 strict
  mode off (`xrdsec.voms_client.fetch_ac(..., x509_strict=False)`), as it
  reaches CEs and as `arcproxy` does.
- `xrdarc.client` and `xrdarc.xrsl` are packages (one module per concern)
  behind unchanged public names.
- The exit-code table's shared codes (0, 1, 2, 70, 130, 141) are
  `xrdcore.cli.ExitCode`'s (`cli._common.ExitCode` restates them and adds
  3-7, checked by `xrdcore.cli.extends`); Ctrl-C and the quiet broken pipe
  are `xrdcore.cli.run` (private `cli._common.silence_stdout` removed: it is
  `xrdcore.cli.silence_stdout`). `get`'s download pool is
  `xrdcore.fanout.run_all`: on Ctrl-C it now waits for the running
  downloads, which stop mid-file, before the interrupt propagates, instead
  of abandoning them (the interpreter joined them at exit anyway).
- The HTTPS transport (`xrdarc.transport`) is `xrdhttp.session.Session`,
  the pooled session the storage clients share, under A-REX's policy (which
  statuses and failures are retried, the `HTTPError`/`ARCError` wording);
  urllib3 is no longer used or a dependency (`transport.py` 391 -> 379
  lines). Same retries, backoff, `Retry-After`, errors, streaming and
  cancellation, except: a timed-out request is no longer repeated (a CE
  that did not answer in the time allowed would only be given it again);
  `Session.open` returns an `xrdhttp.session.Response` (`read`,
  `readinto`, `close`, `shutdown`) instead of a urllib3 response; a stream
  body is re-sent from where it stood, not from offset 0; downloads read
  large buffers straight off the socket. `--insecure` warns with
  `xrdhttp.session.UnverifiedTLSWarning` (was urllib3's
  `InsecureRequestWarning`) on every new connection.

- The end of a command is `xrdcore.cli.Fatal` (was `cli._fatal`): the same
  one line and exit code, now redacted like a log line. The exit-code rules
  are one ordered table, `cli._common.EXIT_CODES`, which `exit_code_for`
  reads through `xrdcore.cli.exit_code`. `-v`/`-d` logging is
  `xrdcore.log.configure` (was `cli._common`'s own `_Handler`/`_Stderr`);
  the handler now also redacts what it writes. Output is unchanged.

### Code health

- Banned APIs (ruff `TID251`, `[tool.ruff.lint.flake8-tidy-imports.banned-api]`): src and
  tests may not use `http.client`, urllib3/requests/httpx/`urllib.request`, `gssapi`/`krb5`,
  hand-built TLS contexts (`ssl.create_default_context`, `ssl.PROTOCOL_TLS*`),
  `ThreadPoolExecutor`, the stdlib XML parsers, botocore/boto3, or xrdclient, xgfalclient and
  xrdwms; each message names the library replacement (CONTRIBUTING.md, *Banned APIs*). To get
  there the fake A-REX (`xrdarc.testing.arex`) reads XML through `xrdcore.safexml`, so a
  description or request body that declares a document type is now "not XML" to it, and the
  tests drive it through `xrdhttp.connection`, build TLS contexts with the test PKI and
  `xrdsec.tls`, and run the proxy handshake check on `xrdcore.fanout.run_all`.
- New public `xrdarc.testing.fixtures`, a pytest plugin (loaded with `pytest_plugins`, never
  automatically) for suites that drive xrdarc against the fake CE: the `make_ce`/`ce`,
  `credentials` and `make_arc` fixtures, `make_credentials`, `quiet_session` (the default
  `arc_session_factory`, overridable) and `gate_interop` for a suite's interop opt-in. xrdarc's
  own tests and xrdwms's load it instead of each keeping a copy (`tests/_arex.py` keeps only
  the recording-session fixtures; the two `make_arc` copies in `test_client.py` and
  `test_reliability.py` are gone).
- `tests/conftest.py` loads xrdsec's `xrdsec.testing.fixtures` plugin
  (the hermetic environment and the `home`, `tmp_dir`, `grid_security`,
  `pki` and `grid_env` fixtures) instead of its own copy; its
  `pytest_xrdsec_hermetic` hook clears xrdarc's own variables and hides the
  system `client.conf`, and interop tests are marked `ambient`.
- Nothing is grandfathered: ruff runs with no ignored rules (C4 added),
  mypy is strict over the tests as well as `src`, every warning fails the
  suite, and there are no `# noqa`, `# type: ignore`, `# pragma: no cover`
  or `# fmt: skip` comments left. The job list's SQL text is built by one
  helper that only splices in plain column names (docs/DEVELOPING.md).
- The chain's tooling is the new
  [xrd-devtools](https://github.com/rob-c/xrd-devtools) repository, used
  from a checkout (not on PyPI, so never a dependency):
  `tests/test_scorecard.py` is a few lines loading its scorecard plugin
  (found through pytest's `pythonpath`: `../xrd-devtools/src` or CI's
  `.dependencies/xrd-devtools/src`) instead of reading xrdclient's
  `tools/scorecard.py` from an `XRDCLIENT_CHECKOUT`; it skips, saying so,
  without one, and is required in CI. Nothing of xrdclient is checked out
  any more.
- CI calls xrd-devtools' reusable workflows (`static.yml`: ruff, mypy,
  complexipy, the scorecard and `xrddevtools conformance`; `tests.yml`;
  `chain.yml`: the duplicate and conformance gates over all seven
  repositories), with the libraries from its candidates action (now xrdhttp
  too); the build, twine, mkdocs and no-storage-client checks stay a job of
  their own. `publish.yml` runs xrd-devtools' `chain_preflight.py pypi`. CI
  therefore needs `rob-c/xrd-devtools` to exist.
- Release metadata is xrd-devtools' release gate:
  `tests/test_release_metadata.py` is `release_gate(__file__)` from
  `xrddevtools.pytest_plugin` - one version source (`_version.py`, read by
  hatch), a CHANGELOG led by exactly that version's well-formed section,
  project metadata and README that name this repository, and a release
  workflow built through the shared publish action.
- `publish.yml`'s build job is xrd-devtools' shared `publish`
  composite action (build, `twine check --strict`, the artifact or
  pre-flight checks, a clean install whose tag, runtime version and dated
  changelog section agree, the artifact upload) and the suite run against the installed
  wheel; the GitHub release job is unchanged.
- The standard's settings in `pyproject.toml` (ruff rules, the banned-API
  table, mypy's strictness and allowed overrides, complexipy, coverage,
  pytest's warnings filter) and CONTRIBUTING's *The code standard*, *Banned
  APIs* table and *xrd-devtools* sections are managed blocks, written by
  `xrddevtools sync` from the standard kept once in xrd-devtools;
  `xrddevtools conformance` fails a hand edit between the markers. The
  repository's own keys and notes sit beside the blocks.
- Banned-API messages for importing a package of the chain built on this
  one now say so ("sits below ... dependency direction"), generated from the
  declared layering.

### Changed: behaviour

- A proxy, key or token file that others can read is refused (it was only
  warned about), as ARC refuses it.
- `xrdarc proxy` finds the user certificate in ARC's order (`~/.arc` before
  `~/.globus`, and `certificatepath`/`keypath` from `client.conf`), and
  reads `vomses` as `voms-proxy-init` does (every standard location that
  exists, merged). `--insecure` no longer applies to VOMS servers.
- `xrdarc proxy`'s workflow is `xrdsec.proxytool`'s, shared with xrdclient's
  `xrd-proxy` (user certificate search as `proxytool.ARCPROXY`, VOMS
  requests, ACs before the proxy, the proxy file's path and link rule, the
  file read back); `cli/proxy.py` keeps `arcproxy`'s options and `-I` text,
  and `xrdarc.proxy` gains `make_proxy` (that workflow with xrdarc's
  errors). Behaviour now shared with `xrd-proxy`: a symbolic link at the
  default `/tmp/x509up_u<uid>` is refused (followed only at `--proxy` or
  `$X509_USER_PROXY`); `proxy_info` and `-I` read the file under the
  private-file rules (a proxy others can read is refused with the `chmod`
  that fixes it; a file without a certificate is `EACCES`, was `EINVAL`);
  an expired user certificate is refused before any VOMS server is asked;
  `--key` without `--cert` is honoured; `-S :/fqan` is a usage error; the
  "no user certificate" and "no proxy" messages are xrdsec's.
  `proxy.write_proxy` and `proxy.proxy_info` take `follow_symlinks=`
  (default `True`), `proxy_info` also `now=`.

### Fixed

- Submitted jobs can no longer be lost from the job list. The job list is
  opened and write-locked (`JobList.check`) before anything is sent, so an
  old XML `jobs.dat`, an unwritable `~/.arc` or a held lock stops `sub`
  before a job exists. Jobs are recorded the moment the CE accepts them,
  before their inputs upload. Anything that interrupts the uploads (Ctrl-C
  included) kills and cleans every accepted job still waiting for inputs;
  a job the CE will not remove stays in the list with the reason. A job
  list that fails after the check is warned about, naming the jobs and
  `xrdarc sync`.
- `sub` prints each job id, and appends it to `-o`, as soon as the job is
  submitted, not after every description; `-o` is opened before anything
  is submitted.
- Path traversal in `get`: a job name (`-J`), a job id from `sub`/`sync`,
  or a session listing entry that is not one safe file name is refused
  (`rest.is_safe_name`); every local path is checked to resolve inside the
  target before any directory is created (a hostile `../../x` listing used
  to create directories outside it). `get -f` now overwrites the job's
  files as `arcget -f` does, instead of deleting the existing directory.
- `wait` no longer gives up on a job after one transient error: CE
  unreachable, HTTP 5xx/408/429 or a job missing from the answer keep it
  pending (`Outcome.transient`), with a capped, jittered backoff
  (`xrdcore.retry`) between troubled polls. The read-only `info`, `status`
  and `delegations` bulk queries are retried by the transport like GETs
  (`Session.request(idempotent=...)`).
- Ctrl-C during `get` stops at once: jobs are handed to the download pool
  only as workers free up, running downloads stop before their next file,
  and the pool is not waited for.
- `Credentials` no longer shows the bearer token in its `repr`.
- A `BrokenPipeError` (`xrdarc cat JOB | head`) or a plain `OSError` no
  longer prints a traceback; neither does any unexpected exception (one
  line, `internal error: ...`; `-d DEBUG` logs the traceback).

### Changed

- Exit codes come from a fixed table (`xrdarc.cli._common.ExitCode`,
  documented in docs/compatibility.md) instead of the fatal error's errno:
  0 ok, 1 some jobs failed (or a job is not in the list), 2 usage, 3
  credentials, 4 job description, 5 CE, 6 local, 7 `wait` timeout, 70
  internal error, 130 interrupted, 141 broken pipe.
- Several descriptions in one `sub` are all-or-nothing: every one is
  prepared before any is submitted, and they share one delegation (as
  docs/compatibility.md always said). A failed submission POST deletes a
  delegation no accepted job uses.
- Local inputs are sent to the CE with their sizes (`("in.dat" "1024")`,
  ARC's GRIDMANAGER form), so A-REX can tell a complete upload from a
  truncated one; `Upload.size` records it and a file that changed size
  before upload is not sent.
- `sub` refuses an expired proxy before contacting the CE, warns when less
  than an hour is left, and `--min-lifetime PERIOD` refuses a proxy with
  less (`ARCClient.check_lifetime`, `ARCClient.min_lifetime`).
- The usage errors (no jobs, no CE, no description, a bad duration) raise
  `UsageError` and exit 2.

### Added

- `ARCClient.submit_all` (several descriptions, one delegation, a `report`
  callback per job), `ARCClient.check_lifetime`, `JobList.check`,
  `rest.is_safe_name`, `Outcome.transient`.
- `--token-file PATH` and `--token -` (standard input); a literal `--token`
  is warned about once.
- Property-based tests (hypothesis) of the xRSL parser: `unparse` round
  trips through `parse`, and arbitrary text only ever raises
  `DescriptionError`.
- `docs/architecture.md`, and `tests/test_scorecard.py`: the family's
  take-over scorecard, every measurement better than the median of 39 widely
  used Python libraries.
- Dependencies: `xrdcore>=0.4.0,<0.5`, `xrdsec>=0.4.0,<0.5`,
  `xrdhttp>=0.4.0,<0.5` (without its `s3` extra, so no botocore) and
  `cryptography`; xrdclient, xgfalclient and urllib3 are no longer
  dependencies. The optional `testing` extra (pytest) is for the
  `testing.fixtures` pytest plugin only.
- `.github/workflows/publish.yml` (renamed from `release.yml`, the name
  every package of the chain releases with): a `v*` tag builds the sdist and wheel,
  runs `twine check --strict` and xrdclient's `chain_preflight.py pypi`, so
  xrdcore, xrdsec and xrdhttp must already be on PyPI. It then installs the wheel
  from PyPI alone, runs the suite against it, attaches both files to a
  GitHub release and uploads them to PyPI with trusted publishing
  (docs/DEVELOPING.md, *Releasing*).

## [0.1.0] - Unreleased

### Added

- An ARC REST client (`xrdarc.ARCClient`, `xrdarc.RESTClient`) covering every A-REX REST 1.0/1.1 endpoint: info, job listing, bulk submission, status/info/kill/clean/restart, session directory access, diagnostics, and X.509 and token delegations.
- The `xrdarc` command with ARC-compatible subcommands: `proxy`, `info`, `sub`, `stat`, `wait`, `get`, `cat`, `ls`, `diagnose`, `kill`, `clean`, `resume`, `renew` and `sync`, all with `--json`/`--xml` reports.
- An xRSL parser following ARC's RSL grammar, with user-to-CE dialect conversion and implicit inputs and outputs; ADL pass-through.
- RFC 3820 proxy creation, with VOMS attribute certificates fetched over VOMS REST, and delegation signing that copies the VOMS AC.
- The job list in ARC's SQLite `jobs.dat` format, and `client.conf` support.
- `xrdarc.testing.arex.FakeARex`, an in-process fake A-REX for tests.
- An opt-in interop suite, and a script running it against the docker ARC CE + SLURM cluster.
