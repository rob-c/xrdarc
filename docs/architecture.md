# Architecture

This page is for whoever maintains xrdarc next: what the pieces are, how a
command flows through them, and the few rules that must not be broken.

## Where xrdarc sits

xrdarc is a client of the grid libraries, not of the storage clients:

```text
xrdcore        safe XML, the report contract, backoff, cancellation, log redaction, errors,
               thread fan-out, the shared exit codes
   ^
xrdsec         credentials, discovery (ARC's search order), TLS, proxies, VOMS, test PKI
   ^
xrdarc         client.conf, xRSL/ADL, the A-REX REST protocol, the job list, the CLI
```

It imports `xrdcore`, `xrdsec` and `xrdhttp` and nothing from `xrdclient`
or `xgfalclient` (CI checks that neither is importable). A-REX needs a
pooled, retrying HTTPS session: that is `xrdhttp.session`, the session the
storage clients share, configured by `transport` with A-REX's policy
(statuses, retries, errors); `botocore` stays out, since it is only
`xrdhttp`'s `s3` extra. If the libraries need to change for xrdarc, they change there,
with tests; xrdarc never carries a fork of library code.

## The layers, bottom up

| module | what it does | built on |
|---|---|---|
| `errors` | every error is an `OSError` with an errno; `CredentialError` is also `xrdcore.errors.CredentialError` | xrdcore.errors |
| `config` | `client.conf` read as ARC's `IniConfig` reads it | - |
| `creds` | which credential to present and what to trust (`Credentials`), in ARC's order; the TLS context | xrdsec.discovery, credentials, tls |
| `proxy` | the ARC delegation profile; load, sign, make, describe proxies (`make_proxy` is `arcproxy`'s workflow, shared with `xrd-proxy`) | xrdsec.proxies, xrdsec.proxytool |
| `transport` | A-REX's policy over the shared session: which statuses and failures are retried, A-REX's errors, streamed uploads, cancellable downloads | xrdhttp.session, xrdcore.cancel |
| `rest` | one method per A-REX endpoint; the wire quirks absorbed; CE-chosen names checked | xrdcore.safexml |
| `info`, `states`, `urls` | GLUE2 documents, state vocabularies, CE and job URLs | - |
| `xrsl` (package) | ARC's xRSL grammar, the user-to-GRIDMANAGER dialect, implicit inputs and outputs | - |
| `adl` | ADL forwarded as written; the client's uploads found | xrdcore.safexml |
| `joblist` | `~/.arc/jobs.dat` in ARC's SQLite format, shared safely with ARC's tools | sqlite3 |
| `client` (package) | `ARCClient`: each user operation as the right sequence of REST calls; `get`'s download pool | everything above, xrdcore.fanout |
| `cli` (package) | `xrdarc <command>`: ARC's options, text and `--json`/`--xml` reports, the exit-code table | xrdcore.report, xrdcore.cli |
| `testing.arex` (package) | `FakeARex`, an in-process A-REX for tests | xrdsec.testing.https |
| `testing.fixtures` | pytest plugin: the fake-CE, credentials and `make_arc` fixtures and the interop gate, shared with xrdwms's suite | testing.arex, xrdsec.testing.pki |

Where to start reading: `client/__init__.py` (the reliability invariant),
then `client/_submit.py` (the most consequential sequence of calls), then
`rest.py` (what A-REX actually expects on the wire).

## How `xrdarc sub` flows

1. `cli/submit.py` reads every description file and opens `-o` (if given)
   before anything else, so an unreadable file or an unwritable id file
   costs nothing.
2. `ARCClient.submit_all` (`client/_submit.py`) prepares every description
   (`xrsl.prepare` or `adl.prepare_adl`), opens and write-locks the job list
   (`JobList.check`), checks the proxy's remaining life, and only then
   contacts the CE.
3. One delegation (`ARCClient.delegate`): `POST delegations?action=new`
   returns a CSR; `proxy.sign_request` answers it under xrdsec's `"arc"`
   profile; the chain is `PUT` back. A failure deletes the empty slot.
4. Each description is `POST`ed (`rest.RESTClient.submit`; never retried, a
   repeat would submit twice). The jobs the CE accepted are recorded in the
   job list *at once*, before their inputs go up.
5. Each job's local inputs are uploaded (`Session.upload`, with the size the
   description announced). A job whose uploads fail - or are interrupted -
   is killed and cleaned; one the CE will not remove stays in the list with
   the reason.

The invariant behind steps 2-5: between the CE accepting a job and the
command returning, the job is either in the job list, or killed and
cleaned, or named in a warning - never silently lost.

## Credentials

`creds.discover` asks xrdsec, with ARC's settings merged in first (the
environment outranks `client.conf`, as in ARC):

* X.509: `xrdsec.discovery.ARC` - named proxy (missing = error), the
  default proxy, the `$TMPDIR` one, a certificate and key, `~/.arc`,
  `~/.globus`;
* tokens: WLCG Bearer Token Discovery (`xrdsec.credentials.find_bearer_token`);
* trust: `xrdsec.discovery.discover_ca_dir`, with ARC's `X509_CERT_POLICY`
  deciding whether the system store is trusted too.

`Credentials.ssl_context` hands all of it to `xrdsec.tls.client_context`,
which reads keys through the private-file checks, pipes them to OpenSSL,
and caches the context until a file changes. Every library failure is
turned into an xrdarc `CredentialError` at this boundary
(`errors.credential_error`), so the CLI's exit codes and the report's
`code` stay meaningful.

## Concurrency

* `Session` is thread-safe; one per `ARCClient`, shared by `get`'s download
  pool. Its TLS context is shared and never modified.
* `get` feeds its pool one job at a time, so Ctrl-C has nothing queued to
  wait for; the download in progress is stopped mid-file by the transport's
  cancel hook (`xrdcore.cancel.watching` shuts the connection down).
* The job list is opened per operation; SQLite's lock serialises writers,
  ARC's tools included.

## Errors and exit codes

Library code raises; the CLI decides. `cli/_common.EXIT_CODES`, an ordered
table of exception classes, maps an exception to the fixed table in
`docs/compatibility.md` (usage 2, credentials 3, description 4, CE 5,
local 6, timeout 7, bug 70); `exit_code_for` reads it. An `ARCError` with a
URL is the CE's; without one it is local. 0, 1, 2, 70, 130 and 141 are
`xrdcore.cli.ExitCode`'s, shared with every tool on the stack
(`xrdcore.cli.extends` checks the table keeps them), and `xrdcore.cli.run`
turns Ctrl-C into 130 and a closed pipe into a quiet 141; everything else
goes to `xrdcore.cli.Fatal`, which prints the one line, records the error
and logs a bug's traceback at `-d DEBUG`. `-v`/`-d` logging is
`xrdcore.log.configure` on the `xrdarc` logger and the libraries' (`xrdcore`,
`xrdhttp`, `xrdsec`), so `-d DEBUG` shows every request the transport sends
with its status, and xrdhttp's retries and redirects.

## Tests

* The suite is hermetic (see `docs/DEVELOPING.md`) and holds every line and
  branch, against the in-process `FakeARex`, the PKI of `xrdsec.testing.pki`
  and xrdsec's `FakeVOMSServer`.
* `FakeARex` is a package: `_server` (lifecycle, controls, the router),
  `_jobs`/`_session`/`_info`/`_delegations` (the endpoints), `_base` (shared
  state and the job state machine), `_model`, `_render`, `_wire`,
  `_descriptions`. It ports `rest.cpp`'s quirks deliberately; changing one
  needs a reason from A-REX's own source.
* `tests/test_scorecard.py` holds the code to the family's take-over
  scorecard (xrd-devtools' pytest plugin): every one of its twelve
  measurements better than the median of 39 widely used Python libraries.
* `tests/test_interop.py` runs against a real CE, opt-in.

## What must not break

* The reliability invariant above, and its order: prepare and check
  everything, then delegate, then POST, record, upload.
* Names chosen by a CE (job ids, listing entries, log directories) are
  checked to be single safe path components where they arrive, and local
  paths to resolve inside the target, before anything is written.
* A POST is never retried; read-only bulk actions may be.
* Every failure leaving `creds`/`proxy` is an xrdarc `CredentialError`, but for
  `proxy.make_proxy`'s local ones: a `vomses` configuration that is missing or
  names no server for the VO (`ARCError`, `ENOENT`) and a malformed FQAN
  (`ValueError`, which the command line reports as a usage error).
* The job list's columns, spelling and escaping are ARC's.
