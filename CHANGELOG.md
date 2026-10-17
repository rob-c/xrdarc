# Changelog

All notable changes to xrdarc are recorded here.

## [0.1.0] - Unreleased

### Added

- An ARC REST client (`xrdarc.ARCClient`, `xrdarc.RESTClient`) covering every A-REX REST 1.0/1.1 endpoint: info, job listing, bulk submission, status/info/kill/clean/restart, session directory access, diagnostics, and X.509 and token delegations.
- The `xrdarc` command with ARC-compatible subcommands: `proxy`, `info`, `sub`, `stat`, `wait`, `get`, `cat`, `ls`, `diagnose`, `kill`, `clean`, `resume`, `renew` and `sync`, all with `--json`/`--xml` reports.
- An xRSL parser following ARC's RSL grammar, with user-to-CE dialect conversion and implicit inputs and outputs; ADL pass-through.
- RFC 3820 proxy creation, with VOMS attribute certificates fetched over VOMS REST, and delegation signing that copies the VOMS AC.
- The job list in ARC's SQLite `jobs.dat` format, and `client.conf` support.
- `xrdarc.testing.arex.FakeARex`, an in-process fake A-REX for tests.
- An opt-in interop suite, and a script running it against the docker ARC CE + SLURM cluster.
