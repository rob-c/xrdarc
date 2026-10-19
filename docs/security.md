# Security

* **Server verification is on by default.** The CE's certificate is checked
  against the grid CA directory (or the system store), with the hostname,
  by xrdsec's shared TLS builder (`xrdsec.tls.client_context`), which also
  rebuilds the context when the proxy is renewed or the CA directory
  changes. Python 3.13's RFC 5280 strict mode is relaxed, as ARC and gfal2
  never apply it and IGTF CAs predate it - for VOMS servers (`xrdarc proxy
  -S`) as for CEs. `--insecure` exists for test CEs only; it never applies
  to VOMS servers.
* **Revocation lists are not consulted.** ARC's TLS layer checks a CRL when
  the CA directory has one and forgives a missing one, from an OpenSSL
  verify callback; Python's `ssl` module offers no such callback, and its
  all-or-nothing CRL checking would refuse every CE whose CA has no CRL
  installed. xrdsec documents why it offers no "when present" mode
  (`xrdsec.tls.client_context`); until one exists, a revoked CE
  certificate is caught only by its CA's expiry or removal.
* **Credential files must be private.** A proxy or key that is not a
  regular file owned by the user with mode 0600 (or tighter) is refused,
  not just warned about, and so is a token file others could read: the
  bytes checked are the bytes used (xrdsec reads the file once, through
  the open descriptor). Proxies are written atomically with mode 0600.
* **No private key is written to make a VOMS proxy.** `xrdarc proxy -S`
  presents the user certificate and key to the VOMS server from memory
  (through pipes to OpenSSL); the only file with a key in it is the proxy
  itself.
* **Delegation signs only what the CE asked for.** The request's signature
  is checked against its key before signing. The result can never outlive
  the signer, and a limited signer always issues limited proxies.
* **Every XML parse** (session listings, ADL, VOMS answers) goes through
  `xrdcore.safexml`, the declaration-rejecting parser the whole family
  uses. DOCTYPE and entities are refused.
* **No token goes to a host the user did not name.** A-REX never redirects,
  and the transport does not follow redirects.
* **Session paths** with `..` are refused, and deleting the whole session
  directory is refused.
* **A CE cannot choose where results are written.** Job ids, job names and
  session listing entries must each be one safe file name (no `..`, `/`,
  `\`, NUL or drive letter), checked where they arrive (`rest.is_safe_name`);
  every local path must resolve inside the result directory, checked
  before any directory is created, so a pre-existing symlink cannot be
  followed out; `get -f` overwrites files instead of deleting directories.
* **Tokens stay out of sight.** `Credentials` leaves the token out of its
  `repr`, so it never reaches a log or a traceback, and every log record
  passes xrdcore's redaction filter (`Bearer ...`, `access_token=`, JWTs).
  `--token-file` and `--token -` keep it out of the process list; a
  literal `--token` is warned about.
