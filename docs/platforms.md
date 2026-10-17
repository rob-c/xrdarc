# Platforms

xrdarc is pure Python (3.11 to 3.14). Its dependencies are pure Python
(xrdclient, xgfalclient, urllib3) or ship wheels for every mainstream
platform (cryptography).

| Platform | Status |
|---|---|
| Linux (glibc, musl), x86-64 and ARM64 | tested; end-to-end against ARC 7 from a `python:3.12-slim` container |
| macOS (Intel, Apple Silicon) | tested; hermetic suite |
| Windows | expected to work, not yet exercised; see below |

## Windows

* The default proxy is `%TEMP%\x509up_u<login>`, since there is no uid.
  `X509_USER_PROXY` takes precedence everywhere.
* `~/.arc` is `%USERPROFILE%\.arc`.
* The permission warning for key files readable by others is POSIX-only.
* There is no `/etc/grid-security/certificates`. Set `X509_CERT_DIR`, or use
  the system trust store for CEs with public certificates.
