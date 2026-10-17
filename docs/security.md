# Security

* **Server verification is on by default.** The CE's certificate is checked
  against the grid CA directory (or the system store), with the hostname.
  Python 3.13's RFC 5280 strict mode is relaxed, as in xgfalclient, because
  IGTF CAs predate it. `--insecure` exists for test CEs only.
* **Proxies are written atomically with mode 0600.** A key file that others
  can read is warned about.
* **Delegation signs only what the CE asked for.** The request's signature
  is checked against its key before signing. The result can never outlive
  the signer, and a limited signer always issues limited proxies.
* **Every XML parse** (session listings, ADL, VOMS answers) goes through
  xrdclient's declaration-rejecting parser. DOCTYPE and entities are refused.
* **No token goes to a host the user did not name.** A-REX never redirects,
  and the transport does not follow redirects.
* **Session paths** with `..` are refused, and deleting the whole session
  directory is refused.
