"""A fake ARC 7 A-REX REST service, in process, for tests.

:class:`FakeARex` is a threaded HTTP(S) server that answers the A-REX REST
interface (``<base>/rest``, ``<base>/rest/<version>/{info,jobs,delegations}``)
the way ``services/a-rex/rest/rest.cpp`` does, down to its quirks::

    with FakeARex(tmp_path, tls=pki.server_context()) as ce:
        ce.url                                   # https://127.0.0.1:<port>/arex
        ...                                      # drive a client against it
        ce.set_state(job_id, "FINISHED", exit_code=0)
        ce.requests[-1].path                     # what the client sent

What it reproduces:

* ``Accept`` negotiation (JSON, XML, else an HTML table) and A-REX's
  XML-to-JSON rendering: the root element dropped, every value a string,
  per-endpoint forced arrays, attributes of leaf elements dropped;
  ``legacy_json=True`` renders like an ARC 6 server instead (no forced
  arrays, an empty list as an empty body);
* errors as A-REX reports them, in the HTTP reason phrase with an empty body;
* bulk job actions (``POST jobs?action=...``) with the exact
  ``Content-Type`` rule and per-job status codes, job submission of ADL,
  single and multi xRSL (with the 1.1 ``queue``, ``delegation_id`` and
  ``instances`` parameters), job states that tests drive or that progress
  on each poll, asynchronous kill, clean and restart;
* the session directory (listing, ranged GET, ranged PUT with upload
  completion tracking, DELETE, PROPFIND) and the diagnose files;
* X.509 delegation (a CSR with an empty subject, the signed chain checked
  on upload) and 1.1 token delegation;
* authentication by client certificate (the end-entity subject of a proxy
  chain) or by bearer token, and fault injection (:meth:`FakeARex.fault`, a
  :class:`~xrdsec.testing.https.Fault`).

Every request is recorded in :attr:`FakeARex.requests`.

How it is built: the generic HTTP(S) server - TLS per connection, keep-alive,
the request log, fault injection - is
:class:`xrdsec.testing.https.FakeHTTPSServer`, shared with every other fake
on the stack; this package is what A-REX *says*. Where to start reading:

* :mod:`._server` - :class:`FakeARex`: lifecycle, test controls, the router;
* :mod:`._jobs`, :mod:`._session`, :mod:`._info`, :mod:`._delegations` -
  the endpoints, one module per part of the REST tree;
* :mod:`._base` - the state every endpoint reads, and the job state machine;
* :mod:`._model` - states and the records tests read (:class:`FakeJob`...);
* :mod:`._render`, :mod:`._wire`, :mod:`._descriptions` - A-REX's renderings,
  its request quirks, and what is read from a job description.

This module is the facade: import from ``xrdarc.testing.arex``, never from
the private modules, which may be rearranged.

Where it knowingly differs from A-REX:

* descriptions are not really parsed: a few xRSL attributes are read with a
  regular expression and ADL with ElementTree, a ``+`` multi-job request is
  split on its top-level parentheses, and anything starting with ``&`` is a
  valid xRSL job;
* malformed client JSON yields no job ids at all (A-REX keeps what it
  parsed before the error); non-string scalars do lose their first
  character, as on A-REX;
* the ``status`` and ``info`` actions see a state change at once (A-REX's
  infoprovider can lag a cycle); kill and clean are applied when the job is
  next polled or the next request arrives, respectively;
* every request needs a credential, ``GET /rest`` and ``/info`` included;
* all delegations share one key; a job's delegations are the ids its
  description names (else the 1.1 ``delegation_id``), whether or not they exist.
"""

from __future__ import annotations

from xrdsec.testing.https import Fault

from ._model import (
    CANCEL_CAUSE,
    DEFAULT_PROGRESSION,
    DIAGNOSE_ITEMS,
    GLUE2_NS,
    OPERATIONS,
    REST_STATES,
    TERMINAL_STATES,
    CEInfo,
    FakeDelegation,
    FakeJob,
    FakeQueue,
    Request,
)
from ._server import FakeARex

__all__ = [
    "CANCEL_CAUSE",
    "DEFAULT_PROGRESSION",
    "DIAGNOSE_ITEMS",
    "GLUE2_NS",
    "OPERATIONS",
    "REST_STATES",
    "TERMINAL_STATES",
    "CEInfo",
    "FakeARex",
    "FakeDelegation",
    "FakeJob",
    "FakeQueue",
    "Fault",
    "Request",
]
