# Platforms

xrdarc is pure Python (3.11 to 3.14). Its dependencies are pure Python
(xrdclient, xgfalclient, urllib3) or ship wheels for every mainstream
platform (cryptography).

| Platform | Status |
|---|---|
| Linux (glibc, musl), x86-64 and ARM64 | tested; end-to-end against ARC 7 from a `python:3.12-slim` container |
| macOS (Intel, Apple Silicon) | tested; hermetic suite |
| Windows | not yet working; see below |

## Windows

xrdarc does not run on Windows yet, because xrdclient (0.3.2, and the 0.4.0
candidate) calls `os.register_at_fork` unconditionally when it is imported,
and Windows has no `fork`. CI runs the Windows jobs but does not fail on
them until that is fixed upstream. The Windows-specific behaviour already in
xrdarc is:

* The default proxy is `%TEMP%\x509up_u<login>`, since there is no uid.
  `X509_USER_PROXY` takes precedence everywhere.
* `~/.arc` is `%USERPROFILE%\.arc`.
* The permission warning for key files readable by others is POSIX-only.
* There is no `/etc/grid-security/certificates`. Set `X509_CERT_DIR`, or use
  the system trust store for CEs with public certificates.
