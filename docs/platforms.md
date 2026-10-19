# Platforms

xrdarc is pure Python (3.11 to 3.14). Its dependencies are pure Python
(xrdcore, xrdsec, xrdhttp, asn1crypto) or ship wheels for every mainstream
platform (cryptography).

| Platform | Status |
|---|---|
| Linux (glibc, musl), x86-64 and ARM64 | tested; end-to-end against ARC 7 from a `python:3.12-slim` container |
| macOS (Intel, Apple Silicon) | tested; hermetic suite |
| Windows | not supported; see below |

## Windows

xrdarc no longer imports a storage client, so the old blocker (xrdclient
calling `os.register_at_fork` on import) is gone, but Windows is still not
supported: xrdsec, which reads and presents the credentials, is built and
tested for Linux and macOS (it checks key files by POSIX owner and mode,
and hands keys to OpenSSL through `/dev/fd`). CI does not run Windows.
What xrdarc itself does differently there:

* `~/.arc` is `%USERPROFILE%\.arc`.
* There is no `/etc/grid-security/certificates`. Set `X509_CERT_DIR`, or use
  the system trust store for CEs with public certificates.
