"""Finding jobs and asking about them: selection, status, ``wait``, and the bulk actions.

Every operation on many jobs groups them by CE and makes one bulk request
per CE (``action=info|kill|clean|restart``), so a hundred jobs on one CE
cost one round trip. A CE that fails the whole request fails every job in
it, without touching the other CEs' answers, and such a failure is
*transient* when it is worth asking again (a network error, 5xx, 408, 429)
- which is what lets :meth:`_Monitoring.wait` ride out an outage with a
capped, jittered backoff (:mod:`xrdcore.retry`) instead of giving up.
"""

from __future__ import annotations

import errno
import math
import time
from collections.abc import Callable, Sequence

from xrdcore import retry as _retry

from ..errors import ARCError, HTTPError, JobNotFoundError
from ..info import parse_activity
from ..joblist import Job
from ..proxy import Signer, sign_request
from ..rest import BulkResult, RESTClient
from ..urls import ce_url
from ._base import _ClientBase
from ._model import _TRANSIENT_ERRNOS, POLL_BACKOFF_CAP, Outcome, _group


class _Monitoring(_ClientBase):
    """Selecting jobs, refreshing their state, waiting, and acting on them in bulk."""

    # -- selecting and refreshing jobs --------------------------------------------

    def known(self) -> list[Job]:
        """Every job in the job list."""
        return [] if self.joblist is None else self.joblist.jobs()

    def select(
        self,
        names: Sequence[str] = (),
        *,
        everything: bool = False,
        ces: Sequence[str] = (),
        states: Sequence[str] = (),
    ) -> list[Job]:
        """The jobs ``arcstat`` and friends would act on.

        ``names`` are job URLs or job names; a URL not in the job list is
        still accepted. ``ces`` keeps only jobs on those CEs; ``states`` is
        applied by the caller once fresh states are known (``filter_states``).
        A name that matches nothing raises ``JobNotFoundError``.
        """
        known = self.known()
        # ``-c CE`` or ``-s STATE`` alone means "every job, then filter", as in ARC.
        whole = everything or (not names and bool(ces or states))
        chosen = list(known) if whole else _named(known, names)
        if ces:
            chosen = self._on_ces(chosen, ces)
        return chosen

    def _on_ces(self, jobs: list[Job], ces: Sequence[str]) -> list[Job]:
        """``jobs`` on one of ``ces`` (aliases and groups resolved, URLs canonical)."""
        wanted = {ce_url(url) for ce in ces for url in self.config.resolve(ce)}
        return [job for job in jobs if job.ce in wanted]

    def status(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Ask each CE about its jobs (``action=info``); ``Outcome.job`` holds the news.

        A job the CE no longer knows comes back with ``ok=False`` and the
        CE's reason; transport failures for one CE do not affect the others
        and are marked ``transient``.
        """
        outcomes: dict[str, Outcome] = {}
        for ce, group in _group(jobs).items():
            outcomes.update(self._per_ce(ce, "info", group, _refreshed))
        return [outcomes[job.url] for job in jobs]

    def _per_ce(
        self,
        ce: str,
        action: str,
        group: Sequence[Job],
        outcome: Callable[[Job, BulkResult], Outcome],
    ) -> dict[str, Outcome]:
        """One bulk ``action`` on one CE; a CE that fails the request fails every job.

        Such a failure keeps ``status`` 0 even for an HTTP error: a 404 for
        the whole request (a wrong path) must not read as "no such job",
        which would make ``clean`` forget every job.
        """
        try:
            results = self.rest(ce).bulk(action, [j.id for j in group])
        except ARCError as exc:
            transient = _is_transient(exc)
            return {
                job.url: Outcome(job, False, exc.user_message, transient=transient) for job in group
            }
        return {job.url: outcome(job, r) for job, r in zip(group, results, strict=True)}

    def wait(
        self,
        jobs: Sequence[Job],
        *,
        interval: float = 60.0,
        timeout: float | None = None,
        callback: Callable[[Sequence[Outcome]], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> list[Outcome]:
        """Poll until every job is in a terminal state (or unknown to its CE).

        ``callback`` sees each round's outcomes. A job whose poll failed
        transiently (``Outcome.transient``: the CE unreachable or answering
        5xx) stays pending; only a definite answer settles it. After such a
        round the next pause grows by a jittered, doubling extra (capped at
        ``POLL_BACKOFF_CAP``, see ``xrdcore.retry``), so a CE coming back
        from an outage is not met by every waiting client at once.
        ``timeout`` raises ``ARCError`` (ETIMEDOUT) with jobs still running;
        no pause runs past it.
        """
        # No timeout is a deadline that never comes: one code path for both.
        deadline = math.inf if timeout is None else clock() + timeout
        pending = list(jobs)
        done: dict[str, Outcome] = {}
        troubled = 0
        while True:
            outcomes = self.status(pending)
            if callback is not None:
                callback(outcomes)
            pending = _settle(outcomes, done)
            if not pending:
                return [done[job.url] for job in jobs]
            troubled = _troubled(outcomes, troubled)
            pause = _next_pause(interval, troubled, deadline - clock())
            if pause is None:
                raise ARCError(f"{len(pending)} jobs still not finished", errno.ETIMEDOUT)
            sleep(pause)

    # -- bulk management --------------------------------------------------------

    def _bulk(
        self, action: str, jobs: Sequence[Job], accept: Callable[[Job], str | None] | None = None
    ) -> list[Outcome]:
        """``action`` on ``jobs``, one request per CE, outcomes in ``jobs``' order.

        ``accept`` may refuse a job before anything is sent (``kill`` refuses
        one that has already finished); its reason becomes the outcome.
        """
        outcomes: dict[str, Outcome] = {}
        for job in jobs:
            refusal = accept(job) if accept else None
            if refusal:
                outcomes[job.url] = Outcome(job, False, refusal)
        eligible = [job for job in jobs if job.url not in outcomes]
        for ce, group in _group(eligible).items():
            outcomes.update(self._per_ce(ce, action, group, _acted))
        return [outcomes[job.url] for job in jobs]

    def kill(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Ask the CEs to cancel the jobs; asynchronous, like A-REX itself."""
        return self._bulk("kill", jobs, _refuse_finished)

    def clean(self, jobs: Sequence[Job], *, forget: bool = True) -> list[Outcome]:
        """Remove finished jobs from their CEs and (``forget``) from the job list.

        A job its CE no longer knows (404) is forgotten too, as ``arcclean -f`` does.
        """
        outcomes = self._bulk("clean", jobs)
        if forget:
            self._forget([o.job for o in outcomes if o.ok or o.status == 404])
        return outcomes

    def resume(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Restart failed jobs from where they failed (needs ``rerun`` in the description)."""
        return self._bulk("restart", jobs)

    def renew(self, jobs: Sequence[Job]) -> list[Outcome]:
        """Refresh the delegated proxies of running jobs with the current credential."""
        signer = self.signer()
        # Jobs share delegations (one per ``sub``): each is renewed once, and
        # every job using it gets that one result.
        renewed: dict[tuple[str, str], str | None] = {}
        outcomes = []
        for job in jobs:
            failure = self._renew_job(job, signer, renewed)
            outcomes.append(Outcome(job, failure is None, failure or ""))
        return outcomes

    def _renew_job(
        self, job: Job, signer: Signer, renewed: dict[tuple[str, str], str | None]
    ) -> str | None:
        """Renew every delegation ``job`` uses; the first failure, or ``None``.

        The job list knows the delegations of jobs submitted here; for others
        (``sync``ed ones) the CE is asked.
        """
        ids, failure = (job.delegations, None) if job.delegations else self._delegations_of(job)
        for delegation_id in ids:
            key = (job.ce, delegation_id)
            if key not in renewed:
                renewed[key] = self._renew_one(job.ce, delegation_id, signer)
            failure = failure or renewed[key]
        if not ids and failure is None:
            failure = "The CE knows of no delegation for this job"
        return failure

    def _delegations_of(self, job: Job) -> tuple[tuple[str, ...], str | None]:
        """The job's delegation ids as its CE lists them, or why the CE could not say."""
        try:
            result = self.rest(job.ce).job_delegations([job.id])[0]
        except ARCError as exc:
            return (), exc.user_message
        if not result.ok:
            return (), result.reason or f"HTTP {result.status}"
        return result.delegations, None

    def _renew_one(self, ce: str, delegation_id: str, signer: Signer) -> str | None:
        """Renew one delegation: a fresh CSR from the CE, signed and put back; why not, if not."""
        client = self.rest(ce)
        try:
            request = client.renew_delegation(delegation_id)
            client.put_delegation(
                delegation_id, sign_request(request, signer, lifetime=self.delegation_lifetime)
            )
        except HTTPError as exc:
            return exc.reason or exc.user_message
        except ARCError as exc:
            return exc.user_message
        return None

    def sync(self, ce: str, *, replace_all: bool = False) -> list[Job]:
        """``arcsync``: add the CE's jobs for this user to the job list; returns the new ones.

        Job ids that are not a single safe name are skipped (``RESTClient.jobs``).
        """
        found = _listed_jobs(self.rest(ce))
        if self.joblist is not None and replace_all:
            self.joblist.clear()
        known = {job.url for job in self.known()}
        new = [job for job in found if job.url not in known]
        self._record(new)
        return new


def _named(known: Sequence[Job], names: Sequence[str]) -> list[Job]:
    """The jobs ``names`` mean, in order, each once (a job name may match several jobs)."""
    chosen: list[Job] = []
    for name in names:
        chosen.extend(m for m in _matching(known, name) if m not in chosen)
    return chosen


def _listed_jobs(client: RESTClient) -> list[Job]:
    """This user's jobs on the CE, with the delegations each uses (so ``renew`` can find them)."""
    ids = [job_id for job_id, _ in client.jobs()]
    delegations = {r.id: r.delegations for r in client.job_delegations(ids)} if ids else {}
    return [Job(ce=client.ce, id=job_id, delegations=delegations.get(job_id, ())) for job_id in ids]


def _matching(known: Sequence[Job], name: str) -> list[Job]:
    """The listed jobs ``name`` means (URL, id or job name); a job URL stands for itself."""
    matches = [j for j in known if name in (j.url, j.id, j.name)]
    if matches:
        return matches
    if "://" in name:
        return [Job.from_url(name)]
    raise JobNotFoundError(f"Job {name!r} is not in the job list")


def _is_transient(exc: ARCError) -> bool:
    """Whether a failed request is worth repeating: 5xx, 408, 429, or a network failure."""
    if isinstance(exc, HTTPError):
        return exc.status >= 500 or exc.status in (408, 429)
    return exc.code in _TRANSIENT_ERRNOS


def _backoff(troubled: int, interval: float) -> float:
    """The extra pause after ``troubled`` polls in a row hit transient trouble.

    Full jitter over a window that starts at the interval (at least one
    second) and doubles each troubled round, up to ``POLL_BACKOFF_CAP`` or
    the interval, whichever is larger.
    """
    if troubled == 0:
        return 0.0
    return _retry.delay(troubled, max(interval, 1.0), max(interval, POLL_BACKOFF_CAP))


def _troubled(outcomes: Sequence[Outcome], before: int) -> int:
    """Polls in a row that hit transient trouble, counting this one's ``outcomes``."""
    return before + 1 if any(outcome.transient for outcome in outcomes) else 0


def _next_pause(interval: float, troubled: int, left: float) -> float | None:
    """How long ``wait`` sleeps before its next poll; ``None`` when time is up.

    ``left`` is what remains of the deadline (infinite without one). Less
    than one ``interval`` left means another poll could not be waited for,
    so the wait ends now rather than after a pointless shortened sleep; a
    backoff never runs past the deadline either.
    """
    if left < interval:
        return None
    return min(interval + _backoff(troubled, interval), left)


def _settle(outcomes: Sequence[Outcome], done: dict[str, Outcome]) -> list[Job]:
    """File the outcomes that are final under ``done``; the jobs still to wait for.

    Final means a terminal state or a definite failure; a transient failure
    leaves the job pending, to be asked about again.
    """
    pending = []
    for outcome in outcomes:
        if outcome.transient or (outcome.ok and not outcome.job.state.terminal):
            pending.append(outcome.job)
        else:
            done[outcome.job.url] = outcome
    return pending


def _acted(job: Job, result: BulkResult) -> Outcome:
    """A bulk action's answer for one job as its outcome (the per-job status kept)."""
    return Outcome(job, result.ok, result.reason, status=result.status)


def _refreshed(job: Job, result: BulkResult) -> Outcome:
    """A job updated from its ``action=info`` answer; a per-job 5xx or no answer is transient."""
    if not result.ok:
        transient = result.status == 0 or result.status >= 500
        reason = result.reason or f"HTTP {result.status}"
        return Outcome(job, False, reason, status=result.status, transient=transient)
    return Outcome(job.update(parse_activity(result.info, result.state)), True)


def _refuse_finished(job: Job) -> str | None:
    """``kill``'s refusal of a job that has already ended (A-REX would answer 505 for it)."""
    if job.state.terminal:
        return f"The job is already {job.state.value.lower()}"
    return None
