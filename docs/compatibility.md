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
* **Exit status** is 0 when everything worked, 1 when some jobs failed, 2
  for usage errors, and otherwise the errno of the fatal error.
* **`xrdarc stat` never writes the job list.** Neither does `arcstat`.
  `get` and `clean` remove what they cleaned.
* **New commands:**
  * `xrdarc wait` polls until jobs finish;
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
* **A job whose input uploads fail is killed and cleaned.** `arcsub` logs
  the failure and leaves the job waiting ten minutes for the files.
* **One delegation per CE per `sub`**, the same as `arcsub`. The 1.1
  `delegation_id` parameter is used, and the id is also named in the xRSL,
  so 1.0-only CEs work.

## Delegation and proxies

* **The delegated proxy carries the VOMS AC** in its own extension, as well
  as in the chain, as `voms-proxy-init` and XRootD place it. Some storage
  elements read VOMS attributes only from the end-entity side of the chain.
* **`xrdarc proxy` speaks VOMS' REST interface** (`/generate-ac`) only. The
  legacy GSI socket protocol is not implemented. VOMS servers and INDIGO IAM
  VOMS-AA serve REST.
* **New proxies go to `/tmp/x509up_u<uid>`** (where `voms-proxy-init`,
  gfal2 and XRootD look), not `$TMPDIR`. `$TMPDIR` is still searched when
  reading.
* **Token delegation renewal** is not implemented by A-REX itself: its
  `renew` always returns an X.509 request. `xrdarc renew` renews X.509
  delegations.

## Retrieval

* **`gmlog`**: A-REX's REST interface never puts the log directory in the
  session directory. `xrdarc get` writes the `diagnose` items into
  `<job>/<gmlog>/`, which is what `arcget` does. `--diagnose` saves them for
  any job.
* **Downloads** are written to `<file>.part` and renamed into place when
  complete, so an interrupted `get` leaves no truncated outputs.
