"""The ARC client: submit, monitor, retrieve and manage jobs across CEs.

``ARCClient`` is what the command-line tools are built on and what a script
should use. It owns one HTTPS session (and so one credential), the job list,
and a ``RESTClient`` per CE, and turns each user-level operation into the
right sequence of REST calls:

* **submit**: prepare every description (all must be valid before anything
  is sent), check that the job list can be written and that the proxy has
  life left, delegate once, POST each description, record every job the CE
  accepted *at once*, then upload each job's local inputs. A job whose
  uploads fail - or are interrupted, Ctrl-C included - is killed and cleaned
  rather than left waiting ten minutes for files that will never arrive; one
  the CE will not remove stays in the job list with the reason;
* **status**: one ``action=info`` per CE for any number of jobs; **wait**
  repeats it, riding out transient trouble with a capped, jittered backoff;
* **retrieve**: walk the session directory, download it, then clean. Every
  name the CE supplies must be one safe path component, and every local
  path is checked to resolve inside the target before anything is created;
* **kill / clean / resume / renew**: the bulk actions, per CE.

Operations on many jobs never stop at the first failure: they return one
``Outcome`` per job, so a report can say which ones failed and why.

The invariant a maintainer must keep: between the CE accepting a job and
this module returning, the job is either in the job list, or killed and
cleaned, or named in a warning - never silently lost.
"""

from __future__ import annotations

from ._model import LOW_LIFETIME, POLL_BACKOFF_CAP, Outcome, Progress, Report, Submission
from ._retrieve import _Retrieving
from ._submit import _Submitting

__all__ = [
    "LOW_LIFETIME",
    "POLL_BACKOFF_CAP",
    "ARCClient",
    "Outcome",
    "Progress",
    "Report",
    "Submission",
]


class ARCClient(_Retrieving, _Submitting):
    """Jobs on ARC CEs, through the REST interface.

    Everything is optional: ``config`` defaults to ``client.conf``,
    ``credentials`` to ARC's discovery, the job list to ``config.joblist``
    (``joblist=None`` keeps no list at all). ``password`` is called if a
    user key must be decrypted to sign a delegation. Close it, or use
    ``with``, to release connections.

    ``min_lifetime`` (seconds, default 0) is the least life the delegating
    proxy must have left for ``submit`` to go ahead; an expired one is
    always refused, as ``arcsub`` refuses it.
    """
