# xrdarc

A pure Python 3 client for NorduGrid ARC computing elements. It submits,
monitors, retrieves and manages jobs over A-REX's REST interface, with the
grid's X.509/VOMS proxies or WLCG bearer tokens. It needs no ARC C++
libraries, no Globus and no compiler.

```console
$ xrdarc proxy -S atlas                         # arcproxy -S atlas
$ xrdarc sub -C ce.example.org job.xrsl         # arcsub
Job submitted with jobid: https://ce.example.org:443/arex/rest/1.0/jobs/7855c3ea9869
$ xrdarc stat -a                                # arcstat -a
$ xrdarc get -a -D results                      # arcget
```

```python
import xrdarc

with xrdarc.ARCClient() as arc:
    [sub] = arc.submit("ce.example.org", '&(executable="/bin/hostname")(stdout="out.txt")')
    [done] = arc.wait([sub.job], interval=30)
    print(done.job.state, done.job.exit_code)
    arc.get([done.job], "results")
```

It is built on the grid libraries shared with the storage clients
([xrdclient](https://github.com/rob-c/xrdclient),
[xgfalclient](https://github.com/rob-c/xgfalclient)), and on no client:
[xrdsec](https://github.com/rob-c/xrdsec) finds the credentials (ARC's own
search order), builds the TLS context, issues proxies and fetches VOMS
attributes; [xrdcore](https://github.com/rob-c/xrdcore) supplies safe XML
parsing, the versioned JSON/XML report format, backoff, cancellation and
log redaction. How the pieces fit is in
[docs/architecture.md](https://github.com/rob-c/xrdarc/blob/main/docs/architecture.md).

## Install

```console
$ pip install xrdarc
```

Requires Python 3.11+. Runtime dependencies are `xrdcore`, `xrdsec`
(with `asn1crypto`), `xrdhttp` (without its `s3` extra) and `cryptography`, all of which install
from wheels on Linux (glibc and musl) and macOS. Windows is not supported
yet (see
[docs/platforms.md](https://github.com/rob-c/xrdarc/blob/main/docs/platforms.md)).

## Commands

One program, `xrdarc`, whose subcommands are ARC's client tools with ARC's
option spellings. They are not installed under ARC's own names, so both can
be on one machine; `alias arcstat='xrdarc stat'` works for most uses.

| xrdarc | ARC | does |
|---|---|---|
| `xrdarc proxy [-S vo[:fqan]] [-I] [-r]` | `arcproxy` | make an RFC 3820 proxy, with VOMS attributes; inspect or remove one |
| `xrdarc info -C ce [-l]` | `arcinfo` | endpoints, queues (and VO shares), runtime environments |
| `xrdarc sub -C ce file... [-e text] [-q queue] [-o idfile] [--dry-run]` | `arcsub` | delegate, submit, upload local inputs, record the jobs |
| `xrdarc stat [jobs\|-a] [-s state] [-l]` | `arcstat` | job states, exit codes, errors, usage |
| `xrdarc wait [jobs\|-a]` | | poll until every job has finished |
| `xrdarc get [jobs\|-a] [-D dir] [-k] [-J] [--diagnose]` | `arcget` | download results (and `gmlog`), then clean |
| `xrdarc cat [-o\|-e\|-l\|-f path] jobs` | `arccat` | stdout, stderr, A-REX's job log, or any file, even while running |
| `xrdarc ls job [dir]` | | list the session directory with sizes |
| `xrdarc diagnose job [item...]` | | A-REX's per-job control files: `failed`, `errors`, `diag`, `local`, ... |
| `xrdarc kill`, `clean`, `resume`, `renew` | `arckill` ... | the bulk job actions |
| `xrdarc sync -C ce [-T]` | `arcsync` | add the CE's jobs to the job list |

Every subcommand takes `--json` or `--xml` and then emits one versioned
report document (the `storage-client-report` schema shared with xrdclient
and xgfalclient), with one record per job and numeric error codes.

Exit codes come from one fixed table: 0 success, 1 some jobs failed, 2 a
usage error, 3-7 fatal credential, description, CE, local and timeout
errors, 130 interrupted, 141 a closed pipe (see
[docs/compatibility.md](https://github.com/rob-c/xrdarc/blob/main/docs/compatibility.md)).
Bearer tokens are best given with `--token-file PATH` or `--token -`
(standard input), which keep them out of the process list.

## Compatible with ARC's own tools

* **The job list is ARC's.** Jobs go into `~/.arc/jobs.dat` in ARC's
  SQLite format, so `arcstat` shows jobs submitted here and `xrdarc stat`
  shows jobs submitted with `arcsub`. Both directions have been checked
  against ARC 7.
* **Configuration is ARC's.** `~/.arc/client.conf` (and `-z`) supplies
  `[computing/<alias>]` services, default CEs, the proxy and CA paths, the
  timeout and the download directory.
* **Credentials are found where ARC finds them.** `X509_USER_PROXY`, then
  `proxypath`, then `/tmp/x509up_u<uid>` (and under `$TMPDIR`), then the
  user certificate from the environment, `client.conf`, `~/.arc` or
  `~/.globus`. Tokens are found by WLCG bearer-token discovery. Trust
  anchors come from `X509_CERT_DIR`, `cacertificatesdirectory`,
  `~/.arc/certificates`, `~/.globus/certificates` or
  `/etc/grid-security/certificates`; `X509_CERT_POLICY=any` adds the
  system store, as in ARC.
* **Job descriptions** are xRSL (`&`, and `+` for several jobs) or ADL.
  xRSL is parsed client side with ARC's grammar: quoting, `(* comments *)`,
  `rsl_substitution`/`$(VAR)`, and user-dialect times in minutes. It is
  converted to the dialect A-REX expects, and implicit inputs and outputs
  (the executable, stdin, stdout, stderr, gmlog) are added as `arcsub`
  adds them.

Where xrdarc deliberately differs from ARC is listed in
[docs/compatibility.md](https://github.com/rob-c/xrdarc/blob/main/docs/compatibility.md).

## Status

Tested end to end against ARC 7 A-REX with a SLURM back end:

* proxy creation;
* delegation, checked with `openssl verify` on the worker node;
* input upload and output download, checked by checksum;
* failing, killed and resumed jobs;
* renewal, `cat`, `ls`, `diagnose`, `sync`;
* job list interchange with `arcstat`/`arcsub`.

The hermetic suite runs against an in-process fake A-REX (`xrdarc.testing.arex`)
and holds the package at 100% line and branch coverage. See
[docs/DEVELOPING.md](https://github.com/rob-c/xrdarc/blob/main/docs/DEVELOPING.md) for running the interop suite against
a CE of your own.

## Licence

LGPL-3.0-or-later.
