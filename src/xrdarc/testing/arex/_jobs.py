"""``/rest/<version>/jobs``: listing, submission and the bulk job actions.

Submission is where the fake is most like A-REX and most deliberately
not: the payload is split into jobs exactly as A-REX splits it (and the
1.1 ``instances``, ``queue`` and ``delegation_id`` parameters are honoured),
but descriptions are only read for the handful of fields the fake's
behaviour needs (:mod:`._descriptions`). Each job gets a real session
directory.

The bulk actions (``POST jobs?action=info|status|kill|clean|restart|
delegations``) take a list of job ids in JSON or XML - with A-REX's exact
``Content-Type`` rule (:func:`~._render._job_ids`) - and answer one entry
per id. ``kill`` and ``clean`` are asynchronous, as on A-REX, which is what
lets a client's "kill, then poll until KILLED" logic be tested.

Two levels of failure are kept apart throughout, because clients must
handle both: a request-level refusal is an HTTP status on the whole answer,
while a per-job failure is a ``status-code`` inside a ``201`` that otherwise
succeeded. A client that only checks the HTTP status will miss the second
kind, and the tests make sure xrdarc does not.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from xrdsec.testing.https import Response

from ._descriptions import _SPLITTERS, _adl_fields, _Description, _Fields, _xrsl_fields
from ._model import _RESTART_STATE, CEInfo, FakeJob, _int, _iso, _new_id
from ._render import _job_ids, _Node
from ._session import _SessionEndpoints
from ._wire import _Ctx, _fault, _Submit

#: A bulk action's per-job handler.
_Bulk = Callable[["_JobEndpoints", FakeJob, _Node], None]


class _JobEndpoints(_SessionEndpoints):
    """``/jobs`` and everything under it (one job's resources are :class:`_SessionEndpoints`')."""

    def _jobs(self, ctx: _Ctx) -> Response:
        """``/jobs``: list (``GET``), submit (``action=new``), a bulk action, or one job."""
        job_id = ctx.token()
        # ``jobs/<id>/...`` is one job's resources; ``jobs`` itself is the collection.
        if job_id:
            return self._job(ctx, job_id)
        if ctx.method in ("GET", "HEAD"):
            return self._list_jobs(ctx)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        action = ctx.query.get("action", "")
        if action == "new":
            return self._submit(ctx)
        if action not in self._BULK:
            return _fault(501, "Action not implemented")
        return self._bulk(ctx, action)

    def _list_jobs(self, ctx: _Ctx) -> Response:
        """The caller's jobs, filtered by ``state=`` on the fast REST state when one is given."""
        denied = self._denied("JobInfo")
        if denied is not None:
            return denied
        # ``state=`` takes a comma-separated list and matches the *fast* state,
        # so ``state=RUNNING`` also finds queuing and held jobs, as on A-REX.
        states = [state for state in ctx.query.get("state", "").split(",") if state]
        root = _Node("jobs")
        for job in self.jobs.values():
            if job.owner == ctx.identity and (not states or job.fast_state in states):
                _listed(root, job, with_state=bool(states))
        return self._render(ctx, root, ("job",))

    # -- action=new ----------------------------------------------------------------------

    def _submit(self, ctx: _Ctx) -> Response:
        """``action=new``: split the payload into jobs and make each, or say why not, per job.

        Request-level refusals (``maxjobs``, an empty or unrecognised payload,
        bad instance counts) are HTTP faults; a description that fails is a
        per-job ``500`` inside a ``201`` answer, as on A-REX.
        """
        # The checks run in A-REX's order: the first refusal is the one a client sees.
        refused = self._denied("JobCreate") or self._payload_refusal(ctx)
        if refused is not None:
            return refused
        # Undecodable bytes are replaced, not refused: a description in the
        # wrong encoding fails (or not) per job, where A-REX parses it.
        text = ctx.body.decode("utf-8", "replace")
        params = self._submit_params(ctx)
        if isinstance(params, Response):
            return params
        split = _split(text, params)
        if isinstance(split, Response):
            return split
        descriptions, multi = split
        root = _Node("jobs")
        if multi or params.maximum <= 1:
            self._submit_each(ctx, descriptions, params, root)
        else:
            self._submit_instances(ctx, descriptions[0], params, root)
        return self._render(ctx, root, ("job",), status=201)

    def _payload_refusal(self, ctx: _Ctx) -> Response | None:
        """A submission refused before its payload is read: the CE full, or nothing sent.

        A full CE is reported before an empty payload, so a client probing
        with an empty body still learns the CE is full; whitespace alone
        counts as empty, with its own reason.
        """
        if self.maxjobs is not None and len(self.jobs) >= self.maxjobs:
            return _fault(500, "No more jobs allowed")
        if not ctx.body:
            return _fault(500, "Missing payload")
        if not ctx.body.decode("utf-8", "replace").lstrip(" \t\r\n"):
            return _fault(500, "Payload is empty")
        return None

    def _submit_params(self, ctx: _Ctx) -> _Submit | Response:
        """The 1.1 ``instances[_min]``, ``queue`` and ``delegation_id`` parameters, checked."""
        # Through 1.0 ``ctx.param`` reads "", so both are 1: one job per description.
        minimum = _int(ctx.param("instances_min"), 1)
        maximum = _int(ctx.param("instances"), 1)
        if maximum < 1 or minimum > maximum:
            return _fault(500, "Wrong number of instances specified")
        if self.maxjobs is not None:
            if len(self.jobs) + minimum > self.maxjobs:
                return _fault(403, "Number of requested instances exceeds allowed limit")
            # Fewer than asked for, but at least the minimum, is a success: the
            # client learns how many it got from the number of entries.
            maximum = min(maximum, self.maxjobs - len(self.jobs))
        return _Submit(ctx.param("queue"), ctx.param("delegation_id"), minimum, maximum)

    def _submit_each(
        self, ctx: _Ctx, descriptions: list[_Description], params: _Submit, root: _Node
    ) -> None:
        """One job per description, each refused on its own (``maxjobs`` reached mid-way)."""
        for description in descriptions:
            node = root.add("job")
            # Checked per job: the earlier jobs of this same request may have
            # filled the CE, and only the ones past the limit fail.
            if self.maxjobs is not None and len(self.jobs) >= self.maxjobs:
                node.add("status-code", "500")
                node.add("reason", "No more jobs allowed")
                continue
            failure = self._rejection(description.text)
            job = self._build(ctx.identity, description, params, ctx.version, failure)
            self._created(node, job)

    def _submit_instances(
        self, ctx: _Ctx, description: _Description, params: _Submit, root: _Node
    ) -> None:
        """REST 1.1 ``instances``: up to ``params.maximum`` copies of one description.

        The test's rejection is taken once for the request, not per copy:
        the copies are one description, so they share one verdict.
        """
        failure = self._rejection(description.text)
        for _ in range(params.maximum):
            job = self._build(ctx.identity, description, params, ctx.version, failure)
            self._created(root.add("job"), job)
            if isinstance(job, str):
                return  # one failure answers for every instance

    def _rejection(self, text: str) -> str:
        """Why the next job fails: a :meth:`reject_next` reason, else :attr:`policy`'s.

        Queued reasons are used first, oldest first, so a test can script
        "fail the first submission, accept the retry" without a policy.
        """
        if self._rejections:
            return self._rejections.pop(0)
        return (self.policy(text) or "") if self.policy is not None else ""

    @staticmethod
    def _created(node: _Node, job: FakeJob | str) -> None:
        """One job's entry in a submission answer: ``201`` and its id, or ``500`` and why."""
        if isinstance(job, str):
            node.add("status-code", "500")
            node.add("reason", job)
            return
        node.add("status-code", "201")
        node.add("reason", "Created")
        node.add("id", job.id)
        # The state at creation, whatever ``add_job`` or a test does next.
        node.add("state", "ACCEPTING")

    def _queue_for(self, wanted: str) -> str | None:
        """The queue a job lands in: the one asked for, else the first; ``None``: no such queue.

        A CE with raw XML ``info`` publishes no queues the fake can read, so
        any name (or none) is accepted there.
        """
        queues = self._queue_names()
        queue = wanted or (queues[0] if queues else "")
        return None if queues and queue not in queues else queue

    def _queue_names(self) -> list[str]:
        """The queues the information document publishes (none for raw XML ``info``)."""
        return [queue.name for queue in self.info.queues] if isinstance(self.info, CEInfo) else []

    def _build(
        self,
        owner: str,
        description: _Description,
        params: _Submit,
        version: str = "1.0",
        failure: str = "",
    ) -> FakeJob | str:
        """Make a job, or say why A-REX would not (the text becomes the per-job reason).

        ``failure`` is a refusal decided by the test (:meth:`reject_next`,
        :attr:`policy`); it is applied after parsing, as A-REX parses before
        it authorises.
        """
        fields = _fields(description)
        if fields is None:
            return "Failed to parse job description"
        if failure:
            return failure
        wanted = fields.queue or params.queue
        queue = self._queue_for(wanted)
        if queue is None:
            return f"Requested queue {wanted} does not match any of available queues"
        job_id = _new_id(self.jobs)
        # Delegations named in the description win over the 1.1 parameter,
        # which only applies to a job that names none.
        delegations = fields.delegations or ([params.delegation] if params.delegation else [])
        job = FakeJob(
            id=job_id,
            owner=owner,
            description=description.text,
            language=description.language,
            session=self.session_dir(job_id),
            name=fields.name,
            queue=queue,
            stdout=fields.stdout,
            stderr=fields.stderr,
            logdir=fields.logdir,
            rerun=fields.rerun,
            delegations=delegations,
            version=version,
        )
        # A real directory: tests put files in it, and uploads land in it.
        # No ``exist_ok``: a fresh id names a fresh directory, and finding one
        # already there means two fakes share a root - better loud than mixed.
        job.session.mkdir(mode=0o700)
        job.log.append(f"{_iso(job.submitted)} Job state change UNDEFINED -> ACCEPTED   Reason: ")
        self.jobs[job_id] = job
        return job

    # -- bulk actions ------------------------------------------------------------------------

    def _bulk(self, ctx: _Ctx, action: str) -> Response:
        """A bulk ``action`` on the jobs the body names; a job not the caller's is a per-job 404."""
        operation, handler, missing = self._BULK[action]
        denied = self._denied(operation)
        if denied is not None:
            return denied
        root = _Node("jobs")
        # One entry per id read, in the order sent, repeats included: nothing
        # is merged, so a client must pair answers with its ids by ``id``.
        for job_id in _job_ids(ctx.header("Content-Type"), ctx.body):
            node = root.add("job")
            job = self._lookup(job_id, ctx.identity)
            # Somebody else's job is indistinguishable from no job at all:
            # A-REX never confirms that another user's id exists.
            if job is None:
                node.add("status-code", "404")
                node.add("reason", "Job not found")
                node.add("id", job_id)
                # Some actions add an empty field even for a missing job
                # (``state: None`` from ``status``), which clients must survive.
                if missing is not None:
                    node.add(*missing)
                continue
            handler(self, job, node)
        # 201 whatever happened: the real outcome is each entry's status-code.
        return self._render(ctx, root, ("job",), status=201)

    @staticmethod
    def _ok(node: _Node, job: FakeJob, code: str = "200", reason: str = "OK") -> None:
        """A per-job result: status code, reason and id."""
        node.add("status-code", code)
        node.add("reason", reason)
        node.add("id", job.id)

    def _bulk_info(self, job: FakeJob, node: _Node) -> None:
        """``action=info``: the GLUE2 activity (after one poll's progress)."""
        self._observe(job)
        self._ok(node, job)
        node.add("info_document").children.append(self._activity(job))

    def _bulk_status(self, job: FakeJob, node: _Node) -> None:
        """``action=status``: the REST state (after one poll's progress).

        Progress happens here and in ``info``, not on a timer, so the
        client's own polling is what moves a job (see ``_observe``).
        """
        self._observe(job)
        self._ok(node, job)
        node.add("state", job.state)

    def _bulk_kill(self, job: FakeJob, node: _Node) -> None:
        """``action=kill``: asynchronous - the job becomes ``KILLED`` when next polled."""
        if "kill" in job.refuse:
            self._ok(node, job, "505", job.refuse["kill"])
            return
        # Killing a finished job is accepted and does nothing, as on A-REX;
        # the client is the one that refuses to ask (``kill`` on a terminal job).
        job.kill_requested = not job.terminal
        self._ok(node, job, "202", "Queued for killing")

    def _bulk_clean(self, job: FakeJob, node: _Node) -> None:
        """``action=clean``: marked; it goes with the first request after it is terminal."""
        if "clean" in job.refuse:
            self._ok(node, job, "505", job.refuse["clean"])
            return
        job.clean_requested = True
        self._ok(node, job, "202", "Queued for cleaning")

    def _bulk_restart(self, job: FakeJob, node: _Node) -> None:
        """``action=restart``: a failed job with restarts left goes back to ``PREPARING``."""
        if job.state != "FAILED":
            self._ok(node, job, "505", "Job has not failed")
        elif job.rerun <= 0:
            self._ok(node, job, "505", "No more restarts allowed")
        else:
            # Each restart spends one ``rerun``; the failure is forgotten, and
            # the job goes back to where A-REX restarts it from.
            job.rerun -= 1
            job.restarts += 1
            job.failure, job.exit_code = "", None
            self._transition(job, _RESTART_STATE, reason="Restarted by user")
            self._ok(node, job, "202", "Queued for restarting")

    def _bulk_delegations(self, job: FakeJob, node: _Node) -> None:
        """``action=delegations``: the job's delegation ids that exist and are the owner's."""
        self._ok(node, job)
        # Only delegations that exist and are the owner's: a job may name an
        # id that was never created, or that has since been deleted.
        for delegation_id in job.delegations:
            found = self.delegations.get(delegation_id)
            if found is not None and found.owner == job.owner:
                node.add("delegation_id", delegation_id)

    # action -> (operation class, per-job handler, what a missing job's entry adds).
    # The operation classes are A-REX's: ``restart`` creates work (JobCreate),
    # ``clean`` removes the job (JobDelete), and every read is JobInfo.
    _BULK: ClassVar[dict[str, tuple[str, _Bulk, tuple[str, str] | None]]] = {
        "info": ("JobInfo", _bulk_info, ("info_document", "")),
        "status": ("JobInfo", _bulk_status, ("state", "None")),
        "kill": ("JobCancel", _bulk_kill, None),
        "clean": ("JobDelete", _bulk_clean, None),
        "restart": ("JobCreate", _bulk_restart, None),
        "delegations": ("JobInfo", _bulk_delegations, None),
    }


def _listed(root: _Node, job: FakeJob, *, with_state: bool) -> None:
    """One ``GET jobs`` entry: the id, and the fast state when the listing was filtered by state.

    An unfiltered listing carries ids only, so a client that wants states
    must ask for them (``action=status``) rather than read them from here.
    """
    node = root.add("job")
    node.add("id", job.id)
    if with_state:
        node.add("state", job.fast_state)


def _fields(description: _Description) -> _Fields | None:
    """What the fake reads from a description, by its language; ``None`` if it does not parse."""
    if description.language == "emies:adl":
        return _adl_fields(description.text)
    return _xrsl_fields(description.text)


def _split(text: str, params: _Submit) -> tuple[list[_Description], bool] | Response:
    """The payload as jobs, by its first character, or A-REX's refusal of it.

    Several descriptions and several instances of one cannot be combined;
    a ``+`` request with no job in it is a parse failure.
    """
    # The first non-blank character decides the language; only these four
    # blanks are skipped, so a payload led by any other character is refused.
    start = text.lstrip(" \t\r\n")[:1]
    splitter = _SPLITTERS.get(start)
    if splitter is None:
        return _fault(500, "Payload is not recognized")
    descriptions, multi = splitter(text)
    if multi and params.maximum > 1:
        return _fault(403, "No multiple descriptions and multiple instances simultaneously")
    if start == "+" and not descriptions:
        return _fault(500, "Failed to parse job description")
    return descriptions, multi
