# Where xrdarc differs from ARC's client

xrdarc follows ARC's behaviour unless there is a reason not to. These are the
deliberate differences.

## Commands and output

* **One program.** The commands are `xrdarc sub`, `xrdarc stat` and so on.
  `arcsub` and friends are not installed, so both clients can live on one
  machine.
* **Machine-readable output** is the versioned `storage-client-report`
  JSON/XML shared with xrdclient and xgfalclient (`--json`, `--xml`), not
  `arcstat -J`'s format.
* **Exit status** comes from one fixed table, the same on every platform.
  ARC's tools exit 0 or 1; xrdarc keeps those meanings and gives fatal
  errors their own codes instead of an errno (errno values differ between
  Linux and macOS, and ENOENT and EPERM would read as 2 and 1):

  | code | meaning |
  |---|---|
  | 0 | everything worked |
  | 1 | some jobs (or CEs) failed, or a named job is not in the job list |
  | 2 | usage error: an unknown option, no jobs, no CE, no description, a bad duration |
  | 3 | credentials: no proxy, certificate or token, an expired or too-short proxy, or the CE refused it (HTTP 401/403) |
  | 4 | a job description that cannot be parsed or submitted |
  | 5 | the CE could not be reached, failed the request, or answered nonsense |
  | 6 | a local problem: the job list, a file to read or write |
  | 7 | `wait --max-wait` ran out with jobs still running |
  | 70 | an internal error (a bug), reported in one line; `-d DEBUG` logs the traceback |
  | 130 | interrupted (Ctrl-C) |
  | 141 | the reader of standard output went away (`xrdarc cat JOB \| head`); nothing is printed |
* **`xrdarc stat` never writes the job list.** Neither does `arcstat`.
  `get` and `clean` remove what they cleaned.
* **Bearer tokens** can be read from a file (`--token-file PATH`) or
  standard input (`--token -`). A literal `--token TOKEN` still works but is
  warned about, once: it is visible to other users in the process list.
* **New commands:**
  * `xrdarc wait` polls until jobs finish. A poll that fails transiently
    (the CE unreachable, HTTP 5xx, 408 or 429, a job missing from the
    answer) keeps the job pending, and the next pause grows by a jittered,
    doubling extra capped at ten minutes; only a definite answer (no such
    job, a 4xx refusal) settles a job. The `info` and `status` bulk queries
    are retried like any GET, since they change nothing;
  * `xrdarc ls` lists a session directory;
  * `xrdarc diagnose` prints A-REX's per-job control files.

## Submission

* **REST only.** The EMI-ES and GridFTP job interfaces were removed in ARC 7,
  and there is no client-side brokering: `-C` names the CE, and
  `|` disjunctions in xRSL are refused.
* **xRSL is forwarded as xRSL** (converted to the dialect A-REX parses)
  rather than translated to ADL as `arcsub` does. ADL is forwarded as
  written. Attributes xrdarc does not know pass through to the CE unchanged
  rather than being dropped.
* **`gridtime` and `benchmarks` are refused.** They need client-side
  benchmark normalisation.
* **Period strings** that ARC silently reads as 0 (`"5 5"`, `"PT"`) are
  refused rather than submitted with no limit.
* **Everything is checked before the CE is contacted**, as `arcsub` parses
  every description first: all descriptions must prepare (a missing input
  file in the last one submits nothing), the job list must be writable and
  not locked (`arcsub` only finds out after submitting, and then asks you
  to run `arcsync`), `-o` must be writable, and the proxy must not have
  expired (`--min-lifetime` refuses one with less left; under an hour is
  warned about).
* **Jobs are recorded as soon as the CE accepts them**, before their input
  files are uploaded, and each job's id is printed (and appended to `-o`)
  as soon as its inputs are up. `arcsub` writes the job list and the `-o`
  file once, at the end, so an interrupted `arcsub` can leave running jobs
  nobody knows about. If the job list fails after all, the warning names
  the jobs and says to run `xrdarc sync`.
* **A job whose input uploads fail, or are interrupted, is killed and
  cleaned.** `arcsub` logs the failure and leaves the job waiting ten
  minutes for the files. A job the CE will not kill or clean stays in the
  job list, with the reason as its error, and is named in a warning.
* **Local inputs are sent with their sizes** (`("in.dat" "1024")`, the
  GRIDMANAGER form `XRSLParser` writes), so A-REX holds the job until every
  byte has arrived and fails it if more arrive. A file whose size changed
  between preparing and uploading is not uploaded (the job is abandoned).
  No checksum is sent: A-REX's REST interface tracks uploads itself and
  never computes one.
* **One delegation per CE per `sub`**, the same as `arcsub`, shared by
  every description. The 1.1 `delegation_id` parameter is used, and the id
  is also named in the xRSL, so 1.0-only CEs work. If the submission POST
  fails, a delegation no accepted job uses is deleted again.

## Delegation and proxies

* **The delegated proxy carries the VOMS AC** in its own extension, as well
  as in the chain, as `voms-proxy-init` and XRootD place it. Some storage
  elements read VOMS attributes only from the end-entity side of the chain.
* **`xrdarc proxy` speaks VOMS' REST interface** (`/generate-ac`) only. The
  legacy GSI socket protocol is not implemented. VOMS servers and INDIGO IAM
  VOMS-AA serve REST. The `vomses` files are those of `voms-proxy-init`:
  `$X509_VOMSES` (or `$VOMS_USERCONF`, `$X509_VOMS_FILE`) when set, else
  every one of `~/.voms/vomses`, `~/.glite/vomses`, `~/.arc/vomses`,
  `/etc/vomses` and `grid-security/vomses` that exists, merged. The AC is
  checked against the local `vomsdir`; one that does not verify is still
  used, with a warning, as `voms-proxy-init` does.
* **`xrdarc proxy -I` names proxy types as `voms-proxy-info` does**
  (`RFC3820 compliant impersonation proxy`, `full legacy globus proxy`,
  `end entity credential`), the family's shared wording.
* **A user certificate is found in ARC's order** for `xrdarc proxy`:
  `--cert`/`--key`, then `X509_USER_CERT`/`X509_USER_KEY` (or
  `certificatepath`/`keypath`), then `~/.arc`, then `~/.globus`.
* **Key, proxy and token files must be private** (a regular file, the
  user's own, mode 0600 or tighter); one others can read is refused, not
  used with a warning.
* **New proxies go to `/tmp/x509up_u<uid>`** (where `voms-proxy-init`,
  gfal2 and XRootD look), not `$TMPDIR`. `$TMPDIR` is still searched when
  reading.
* **Token delegation renewal** is not implemented by A-REX itself: its
  `renew` always returns an X.509 request. `xrdarc renew` renews X.509
  delegations.

## Retrieval

* **Names from the CE are checked.** A job name (`get -J`), a job id (from
  `sub` or `sync`) or a session directory entry that is not a single safe
  file name (`..`, `/`, `\`, NUL, a drive letter) is refused: the job is
  not downloaded, or the id is not recorded. `arcget -J` uses the name as
  given. Every local path is checked to resolve inside the target before
  anything is created, so a symlink already in a `-f` target cannot lead a
  download out either.
* **`get -f` overwrites files, as `arcget -f` does**: it downloads into the
  existing directory, replacing the files the job has and leaving others.
* **Ctrl-C during `get` stops at once**: nothing more is started, running
  downloads stop before their next file, and nothing is cleaned.

* **`gmlog`**: A-REX's REST interface never puts the log directory in the
  session directory. `xrdarc get` writes the `diagnose` items into
  `<job>/<gmlog>/`, which is what `arcget` does. `--diagnose` saves them for
  any job.
* **Downloads** are written to `<file>.part` and renamed into place when
  complete, so an interrupted `get` leaves no truncated outputs.
