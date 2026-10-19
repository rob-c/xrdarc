"""Submission: prepare every description, delegate once, POST, record, upload.

The order is the reliability contract of ``xrdarc sub`` (see the
``xrdarc.client`` docstring): nothing reaches the CE until every
description has prepared and the job list is open and locked; a job is
recorded the moment the CE accepts it, before its inputs upload; a job
whose inputs cannot all arrive is killed and cleaned (:meth:`_abandon`);
and a failed POST deletes a delegation no accepted job uses. Each step is
one method or function below, in the order :meth:`_Submitting._submit_all`
calls them.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path

from .. import joblist as _joblist
from ..adl import is_adl, prepare_adl
from ..errors import ARCError, DescriptionError
from ..joblist import Job
from ..rest import BulkResult, RESTClient, SubmitResult
from ..states import JobState
from ..xrsl import PreparedJob, Upload, prepare
from ._base import _ClientBase, _drop_delegation
from ._model import Progress, Report, Submission, _Batch, _log, _SubmitPlan


class _Submitting(_ClientBase):
    """``submit`` and ``submit_all``, and the steps between them and the CE."""

    # -- submission ------------------------------------------------------------

    def prepare(
        self,
        text: str,
        *,
        base: Path,
        delegation_id: str | None = None,
        queue: str | None = None,
        version: str = "1.1",
    ) -> list[PreparedJob]:
        """Turn a description (xRSL or ADL) into what is POSTed, and the uploads it needs.

        ``version`` is the REST version the POST will use; it only matters
        for ADL, whose delegation must be written into the document on 1.0.
        """
        if is_adl(text):
            return [
                prepare_adl(
                    text,
                    base=base,
                    delegation_id=delegation_id,
                    embed_delegation=version == "1.0",
                )
            ]
        return prepare(text, base=base, delegation_id=delegation_id, queue=queue)

    def submit(
        self,
        ce: str,
        description: str,
        *,
        base: str | os.PathLike[str] | None = None,
        queue: str | None = None,
        delegate: bool = True,
        progress: Progress | None = None,
    ) -> list[Submission]:
        """Submit a description (several jobs, for ``+`` xRSL) to ``ce``.

        ``base`` is where relative input files are read from (default: the
        current directory). Raises for what stops every job - an unreadable
        description, a job list that cannot be written, no or an expired
        credential, a CE that cannot be reached; per-job refusals come back
        as unsuccessful ``Submission``s. See ``submit_all`` for the order of
        events and what happens to jobs on failure.
        """
        plan = _SubmitPlan(queue, delegate, progress, None)
        return self._submit_all(ce, [(description, base)], plan)[0]

    def submit_all(
        self,
        ce: str,
        descriptions: Sequence[tuple[str, str | os.PathLike[str] | None]],
        *,
        queue: str | None = None,
        delegate: bool = True,
        report: Report | None = None,
    ) -> list[list[Submission]]:
        """Submit several descriptions, each with its ``base`` directory, as ``arcsub`` does.

        All or nothing up front: every description is prepared (so a
        missing input file or a syntax error stops everything) and the job
        list is opened and write-locked once *before* the CE is contacted;
        then one delegation is made and shared by every job. Each
        description is POSTed in turn; the jobs the CE accepts are recorded
        in the job list at once, before their inputs go up. ``report`` is
        told each job's final ``Submission`` as soon as it is known, so a
        caller can print job ids even if a later description fails.

        A POST that fails raises (earlier descriptions stay submitted and
        recorded), deleting the delegation if no accepted job uses it yet.
        A job whose uploads fail is killed and cleaned; if anything else
        interrupts the uploads (Ctrl-C), every accepted job still waiting
        for inputs is killed and cleaned before the exception propagates.
        """
        return self._submit_all(ce, descriptions, _SubmitPlan(queue, delegate, None, report))

    def _submit_all(
        self,
        ce: str,
        descriptions: Sequence[tuple[str, str | os.PathLike[str] | None]],
        plan: _SubmitPlan,
    ) -> list[list[Submission]]:
        """The body of ``submit`` and ``submit_all``: check everything, delegate, POST, stage."""
        client = self.rest(ce)
        # The base directory is fixed now: a description's relative inputs
        # must resolve the same in the check and the real preparation.
        texts = [
            (text, Path(base) if base is not None else Path.cwd()) for text, base in descriptions
        ]
        self._check_all(texts, plan)
        delegation_id = self._delegation_for(ce, plan)
        batch = _Batch(client, delegation_id, plan)
        results: list[list[Submission]] = []
        # Whether an accepted job uses the delegation yet: until one does, a
        # failed POST deletes it rather than leave a live proxy on the CE.
        used = False
        for index, (text, base) in enumerate(texts):
            # Prepared again, now with the delegation id to embed (REST 1.0
            # names it inside the description; 1.1 takes a parameter).
            prepared = self.prepare(
                text,
                base=base,
                delegation_id=delegation_id,
                queue=plan.queue,
                version=client.version,
            )
            answers = _post(batch, prepared, keep_delegation=used)
            used = used or any(answer.ok for answer in answers)
            results.append(self._stage(batch, index, prepared, answers))
        return results

    def _check_all(self, texts: Sequence[tuple[str, Path]], plan: _SubmitPlan) -> None:
        """Everything that must hold before the CE is contacted, or the reason it does not.

        Nothing reaches the CE until every description has prepared cleanly
        (a bad third file must not leave the first two submitted), and the
        job list must be writable before a job exists that would need
        recording.
        """
        # ``_bundle`` too, not just ``prepare``: whatever would stop the POST
        # body being built fails here, before any delegation is made.
        for text, base in texts:
            _bundle(self.prepare(text, base=base, queue=plan.queue))
        if self.joblist is not None:
            self.joblist.check()

    def _delegation_for(self, ce: str, plan: _SubmitPlan) -> str | None:
        """The one delegation every job of this submission shares (after a lifetime check)."""
        if not plan.delegate:
            return None
        # Checked before delegating: a proxy about to expire would be
        # delegated and the jobs accepted, only to fail at stage-out.
        self.check_lifetime()
        return self.delegate(ce)

    def _stage(
        self,
        batch: _Batch,
        index: int,
        prepared: Sequence[PreparedJob],
        answers: Sequence[SubmitResult],
    ) -> list[Submission]:
        """Record what the CE accepted, then upload each job's inputs and report it.

        Recording comes first so that a job is in the list for as long as
        it exists on the CE. A failure inside ``_finish`` belongs to its job;
        anything that escapes it (Ctrl-C, a failing ``report``) abandons
        every job not yet finished that still needed inputs. A job with no
        inputs is complete the moment it is accepted, so it is kept.
        """
        pairs = [
            (job, answer, _accepted(batch, job, answer))
            for job, answer in _paired(prepared, answers)
        ]
        self._record_safely([job for _, _, job in pairs if job is not None])
        submissions: list[Submission] = []
        try:
            for job_prepared, answer, job in pairs:
                submission = self._finish(batch, job_prepared, answer, job)
                submissions.append(submission)
                if batch.plan.report is not None:
                    batch.plan.report(index, submission)
        except BaseException:
            # Everything after the last finished job is in doubt: jobs still
            # waiting for inputs would sit on the CE until they time out.
            for job_prepared, _answer, job in pairs[len(submissions) :]:
                if job is not None and job_prepared.uploads:
                    self._abandon(batch.client, job, "The submission was interrupted")
            raise
        return submissions

    def _finish(
        self,
        batch: _Batch,
        prepared: PreparedJob,
        answer: SubmitResult,
        job: Job | None,
    ) -> Submission:
        """Upload one accepted job's inputs; a failure abandons the job and is its ``reason``."""
        if job is None:
            return Submission(prepared, None, answer.status, answer.reason or "Not submitted")
        try:
            for upload in prepared.uploads:
                _check_size(upload)
                sent = batch.client.put_file(job.id, upload.name, upload.source)
                if batch.plan.progress is not None:
                    batch.plan.progress(upload.name, sent)
        except (ARCError, OSError) as exc:
            # OSError: the local file went away or could not be read mid-upload.
            # ``user_message`` is ARCError's text without the traceback detail;
            # an OSError has only ``str``.
            reason = getattr(exc, "user_message", None) or str(exc)
            why = f"Uploading input files failed: {reason}"
            self._abandon(batch.client, job, why)
            return Submission(prepared, None, 0, why)
        return Submission(prepared, job, answer.status, answer.reason)

    def _abandon(self, client: RESTClient, job: Job, why: str) -> None:
        """Kill and clean a job whose inputs will never all arrive, and forget it.

        A job the CE would not kill or clean is kept in the job list with
        ``why`` and the CE's answers as its error, and named in a warning,
        so the user can find and remove it later instead of it running
        unseen. A job the CE no longer knows (404) counts as removed.
        """
        # Both steps are tried even if the kill fails: a job that already ended
        # cannot be killed but can still be cleaned, and a clean marks a
        # running job for removal once it stops.
        attempts = (_removal(name, action, job) for name, action in _removals(client))
        problems = [problem for problem in attempts if problem]
        if not problems:
            self._forget_safely([job])
            return
        note = f"{why}; the job could not be removed from the CE ({'; '.join(problems)})"
        _log.warning("%s: %s. Remove it with 'xrdarc kill' and 'xrdarc clean'", job.url, note)
        self._record_safely([replace(job, errors=(note,))])


def _post(
    batch: _Batch, prepared: Sequence[PreparedJob], *, keep_delegation: bool
) -> list[SubmitResult]:
    """POST one description's jobs (``action=new``).

    If the POST fails in any way the delegation is deleted, unless jobs
    accepted earlier in the same submission use it (``keep_delegation``):
    otherwise every failed ``sub`` would leave a live proxy on the CE.
    """
    try:
        return batch.client.submit(
            _bundle(prepared), queue=batch.plan.queue, delegation_id=batch.delegation_id
        )
    except BaseException:
        if batch.delegation_id is not None and not keep_delegation:
            _drop_delegation(batch.client, batch.delegation_id)
        raise


def _accepted(batch: _Batch, prepared: PreparedJob, answer: SubmitResult) -> Job | None:
    """The job the CE created for ``prepared``, as it is recorded; ``None`` if it refused."""
    if not answer.ok or answer.id is None:
        return None
    return Job(
        ce=batch.client.ce,
        id=answer.id,
        name=prepared.name,
        description=prepared.description,
        submitted=_joblist.now(),
        delegations=(batch.delegation_id,) if batch.delegation_id else (),
        # Accepted, whatever the REST state says: the job list's state is the
        # generic one, and ``stat`` replaces it with the CE's on the next poll.
        state=JobState.ACCEPTED,
        rest_state=answer.state,
        queue=prepared.queue,
        stdout=prepared.stdout,
        stderr=prepared.stderr,
        log_dir=prepared.gmlog,
    )


def _check_size(upload: Upload) -> None:
    """Refuse to upload a file whose size is not what the description told the CE.

    A-REX would wait for the missing bytes of a file that shrank and fail
    a job whose file grew; better that the job is abandoned now, saying so.
    """
    # No recorded size (an ADL input declares none): nothing to compare with.
    if upload.size is None:
        return
    size = upload.source.stat().st_size
    if size != upload.size:
        raise ARCError(
            f"{upload.source} changed size since the job was described "
            f"({upload.size} bytes, now {size})",
            errno.EIO,
        )


def _bundle(prepared: Sequence[PreparedJob]) -> str:
    """One request body for several descriptions: ``+`` xRSL or ``ActivityDescriptions``."""
    # One description goes as written, ADL included: only a multi-job body
    # needs the ``+`` wrapper, and only xRSL has one.
    if len(prepared) == 1:
        return prepared[0].description
    texts = [p.description for p in prepared]
    if not all(_is_xrsl_job(text) for text in texts):
        raise DescriptionError("Several descriptions can only be submitted together as xRSL")
    return "+" + "".join(f"({t})" for t in texts)


def _is_xrsl_job(text: str) -> bool:
    """One ``&`` xRSL job, which a ``+`` multi-job request can hold."""
    return text.lstrip().startswith("&")


def _removals(
    client: RESTClient,
) -> tuple[tuple[str, Callable[[list[str]], list[BulkResult]]], ...]:
    """The two steps that remove a job from a CE, in order: kill it, then clean it.

    Kill first: A-REX defers a clean of a running job until it has finished,
    so cleaning first would leave it running (and charged) until then.
    """
    return (("kill", client.kill), ("clean", client.clean))


def _removal(name: str, action: Callable[[list[str]], list[BulkResult]], job: Job) -> str:
    """One removal step for ``job``; ``""`` if it worked (or the CE no longer knows the job)."""
    try:
        # One id in, so one result out: ``bulk`` pads a missing answer.
        [result] = action([job.id])
    except ARCError as exc:
        return f"{name}: {exc.user_message}"
    if result.ok or result.status == 404:
        return ""
    return f"{name}: {result.reason or f'HTTP {result.status}'}"


def _paired(
    prepared: Sequence[PreparedJob], results: Sequence[SubmitResult]
) -> Iterator[tuple[PreparedJob, SubmitResult]]:
    """Each prepared job with the CE's answer for it; a missing answer is a refusal.

    A-REX answers in request order, one entry per job; an answer shorter
    than the request (a broken CE) must not leave a job unaccounted for.
    """
    for index, job in enumerate(prepared):
        if index < len(results):
            yield job, results[index]
        else:
            yield job, SubmitResult(0, "The CE did not answer for this description", None, None)
