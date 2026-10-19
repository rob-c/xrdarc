"""``GET /rest`` and ``GET /rest/<version>/info``: what the fake CE says about itself.

The information document is GLUE2 as A-REX's infoprovider writes it - an
``InfoRoot`` with one ``AdminDomain``, a ``ComputingService`` holding the
REST ``ComputingEndpoint``, a ``ComputingShare`` per queue (and one more per
VO a queue serves, named ``<queue>_<vo>``, with a ``MappingPolicy``) and a
``ComputingManager`` listing the runtime environments - built from
:class:`~xrdarc.testing.arex.CEInfo`. ``xrdarc.info`` parses it; that parser
is tested against this, and against documents captured from real CEs
(:attr:`FakeARex.info` may hold raw XML).

The forced-array list is the part of rest.cpp's ``/info`` rendering that a
JSON client sees: its main containers are kept in :data:`_INFO_ARRAYS`.

Start reading at :meth:`_InfoEndpoints._info`; :meth:`_glue2` and the
``_glue2_*`` helpers build the tree top-down. The document is rebuilt on
every request from :attr:`FakeARex.jobs` and :attr:`FakeARex.info`, so a
test that changes either sees the next ``/info`` reflect it - nothing here
is cached. What a maintainer must not break: the ``ID`` formats (clients are
told not to parse them, and the tests check they do not), the element names
``xrdarc.info`` reads, and the per-VO share shape (see :meth:`_glue2_share`).
"""

from __future__ import annotations

import time

from xrdsec.testing.https import Response

from ._base import _ARexBase
from ._model import GLUE2_NS, REST_STATES, CEInfo, FakeJob, FakeQueue, _iso
from ._render import _Node, _parse_xml
from ._wire import _Ctx, _fault

# Paths below the rendered root (``InfoRoot`` is dropped by the renderer).
_CS = "Domains/AdminDomain/Services/ComputingService"
_CE = _CS + "/ComputingEndpoint"
_CA = _CE + "/ComputingActivities/ComputingActivity"
_SHARE = _CS + "/ComputingShare"
_MANAGER = _CS + "/ComputingManager"
#: The main containers of rest.cpp's ~190 forced-array paths for ``/info``:
#: each is a JSON list even with one member, on an ARC 7 server. The rest of
#: rest.cpp's list is leaves no client reads; ``legacy_json=True`` drops them
#: all, as an ARC 6 server did, which is what makes ``xrdarc.info``'s
#: "object or list" tolerance testable.
_INFO_ARRAYS = (
    "Domains/AdminDomain",
    "Domains/AdminDomain/Services/Service",
    "Domains/AdminDomain/Services/StorageService",
    "Domains/AdminDomain/Services/Contact",
    "Domains/AdminDomain/Services/OtherInfo",
    "Domains/UserDomain",
    _CS,
    _CS + "/Capability",
    _CS + "/StatusInfo",
    _CS + "/Contact",
    _CS + "/OtherInfo",
    _CS + "/Extensions/Extension",
    _CS + "/Associations/ServiceID",
    _CE,
    _CE + "/Capability",
    _CE + "/InterfaceVersion",
    _CE + "/InterfaceExtension",
    _CE + "/JobDescription",
    _CE + "/Semantics",
    _CE + "/SupportedProfile",
    _CE + "/TrustedCA",
    _CE + "/OtherInfo",
    _CE + "/AccessPolicy",
    _CE + "/AccessPolicy/Rule",
    _CE + "/Associations/ComputingShareID",
    _CA,
    _CA + "/State",
    _CA + "/RestartState",
    _CA + "/Error",
    _CA + "/ExecutionNode",
    _CA + "/OtherMessages",
    _CA + "/RequestedApplicationEnvironment",
    _SHARE,
    _SHARE + "/MappingPolicy",
    _SHARE + "/MappingPolicy/Rule",
    _SHARE + "/OtherInfo",
    _SHARE + "/Tag",
    _SHARE + "/Associations/ComputingEndpointID",
    _SHARE + "/Associations/ExecutionEnvironmentID",
    _MANAGER,
    _MANAGER + "/OtherInfo",
    _MANAGER + "/Benchmark",
    _MANAGER + "/ApplicationEnvironments/ApplicationEnvironment",
    _MANAGER + "/ApplicationEnvironments/ApplicationEnvironment/OtherInfo",
    _MANAGER + "/ExecutionEnvironments/ExecutionEnvironment",
    _MANAGER + "/ExecutionEnvironments/ExecutionEnvironment/Benchmark",
)


class _InfoEndpoints(_ARexBase):
    """``/rest`` and ``/info``; the GLUE2 document is built afresh on every request."""

    def _versions(self, ctx: _Ctx) -> Response:
        """``GET /rest``: the REST versions this CE speaks (:attr:`versions`).

        A client negotiates from this list (the highest version both speak),
        so a test narrows :attr:`versions` to see a client fall back to 1.0.
        """
        # A method the endpoint does not serve is 501 throughout the fake, never
        # 405: A-REX dispatches on the method inside each handler and sends no
        # ``Allow`` list, so a client must not expect one.
        if ctx.method not in ("GET", "HEAD"):
            return _fault(501, "Not Implemented")
        root = _Node("versions")
        for version in self.versions:
            root.add("version", version)
        return self._render(ctx, root, ("version",))

    def _info(self, ctx: _Ctx) -> Response:
        """``GET /rest/<v>/info``: the GLUE2 document; only ``schema=glue2`` is implemented."""
        if ctx.rest:
            return _fault(404, "Not Found")
        if ctx.method not in ("GET", "HEAD"):
            return _fault(501, "Not Implemented")
        # Any other schema is refused rather than answered with GLUE2 under the
        # wrong name, so a client asking for one learns the CE cannot give it.
        if ctx.query.get("schema", "") not in ("", "glue2"):
            return _fault(501, "Schema not implemented")
        # ``show_empty=False``: a forced-array container with no members is left
        # out of ``/info`` rather than written as ``[]``, so ``xrdarc.info`` has
        # to read a missing container (a CE with no queues, no RTEs) as empty.
        return self._render(ctx, self._glue2(), _INFO_ARRAYS, show_empty=False)

    def _glue2(self) -> _Node:
        """The ``InfoRoot`` tree from :attr:`info` (a :class:`CEInfo`, or raw XML used as given)."""
        if isinstance(self.info, str):
            # A document that does not parse is served as an empty root rather
            # than failing the request: the test is of the client's parser
            # meeting a broken CE, not of the fake answering 500.
            return _parse_xml(self.info) or _Node("InfoRoot")
        info, now = self.info, _iso(time.time())
        # Every GLUE2 entity carries when it was made and for how long it is
        # good; three hours, as the job activities in ``_base`` say too.
        stamp = {"CreationTime": now, "Validity": "10800"}
        root = _Node("InfoRoot")
        domains = root.add("Domains")
        domains.xmlns = GLUE2_NS
        domain = domains.add("AdminDomain", attrs={"BaseType": "Domain", **stamp})
        # A-REX publishes the domain with placeholder values unless configured.
        domain.add("ID", "urn:ad:UNDEFINEDVALUE")
        domain.add("Name", "UNDEFINEDVALUE")
        service = domain.add("Services").add(
            "ComputingService", attrs={"BaseType": "Service", **stamp}
        )
        self._glue2_service(service, info, stamp)
        return root

    def _glue2_service(self, service: _Node, info: CEInfo, stamp: dict[str, str]) -> None:
        """The ``ComputingService``'s own fields, then its endpoint, shares and manager.

        The shares are built first because the endpoint lists their ids,
        but are added after it, in the order the infoprovider writes them.
        """
        service.add("ID", f"urn:ogf:ComputingService:{self.host}:arex")
        service.add("Name", info.name)
        for capability in ("executionmanagement.jobexecution", "executionmanagement.jobmanager"):
            service.add("Capability", capability)
        service.add("Type", "org.nordugrid.arex")
        service.add("QualityLevel", info.quality_level)
        self._glue2_totals(service, list(self.jobs.values()))
        shares = [share for queue in info.queues for share in self._glue2_shares(queue, stamp)]
        self._glue2_endpoint(service, stamp, [share.children[0].text for share in shares])
        service.children.extend(shares)
        self._glue2_manager(service, stamp)

    @staticmethod
    def _glue2_totals(node: _Node, jobs: list[FakeJob]) -> None:
        """The job counters A-REX publishes on the service and the endpoint, by REST state.

        Counted from the store on each request, so they move as a test adds
        or advances jobs. Every in-LRMS state (held, exiting, ...) counts as
        running and only ``QUEUING`` as waiting, which is the split a broker
        ranking CEs by free slots has to cope with.
        """
        groups = {
            "TotalJobs": REST_STATES,
            "RunningJobs": ("RUNNING", "HELD", "EXITINGLRMS", "OTHER", "EXECUTED"),
            "WaitingJobs": ("QUEUING",),
            "StagingJobs": ("PREPARING", "PREPARED", "FINISHING"),
            "PreLRMSWaitingJobs": ("ACCEPTING", "ACCEPTED", "SUBMITTING"),
        }
        for name, states in groups.items():
            node.add(name, str(sum(job.state in states for job in jobs)))

    def _glue2_endpoint(self, service: _Node, stamp: dict[str, str], share_ids: list[str]) -> None:
        """The REST ``ComputingEndpoint``: its URL, interface versions, health and serving state."""
        info = self.info
        assert isinstance(info, CEInfo)  # raw XML ``info`` never gets here (see _glue2)
        endpoint = service.add("ComputingEndpoint", attrs={"BaseType": "Endpoint", **stamp})
        # The ID embeds the URL, as A-REX's does; clients must not parse it.
        endpoint.add("ID", f"urn:ogf:ComputingEndpoint:{self.host}:rest:{self.url}")
        endpoint.add("Name", "ARC REST")
        endpoint.add("URL", self.url)
        for capability in (
            "executionmanagement.jobcreation",
            "executionmanagement.jobdescription",
            "executionmanagement.jobmanagement",
            "information.discovery.resource",
            "information.lookup.job",
            "security.delegation",
        ):
            endpoint.add("Capability", capability)
        endpoint.add("Technology", "rest")
        endpoint.add("InterfaceName", "org.nordugrid.arcrest")
        # One element per version served, so the information document and
        # ``GET /rest`` never disagree about what the CE speaks.
        for version in self.versions:
            endpoint.add("InterfaceVersion", version)
        endpoint.add("Semantics", "https://www.nordugrid.org/arc/arc7/tech/rest/rest.html")
        endpoint.add("Implementor", "NorduGrid")
        endpoint.add("ImplementationName", "nordugrid-arc")
        # An ARC 7 version, matching the forced-array JSON this fake renders by
        # default; ``legacy_json`` changes the rendering but not this claim.
        endpoint.add("ImplementationVersion", "7.1.1")
        endpoint.add("QualityLevel", info.quality_level)
        endpoint.add("HealthState", info.health_state)
        endpoint.add("ServingState", info.serving_state)
        endpoint.add("Staging", "staginginout")
        for language in ("nordugrid:xrsl", "emies:adl"):
            endpoint.add("JobDescription", language)
        self._glue2_totals(endpoint, list(self.jobs.values()))
        associations = endpoint.add("Associations")
        for share_id in share_ids:
            associations.add("ComputingShareID", share_id)

    def _glue2_shares(self, queue: FakeQueue, stamp: dict[str, str]) -> list[_Node]:
        """A queue's ``ComputingShare`` elements: its own, then one per VO it serves.

        Every share of a queue carries the same limits and job counts: the
        fake does not record which VO a job ran for, so the per-VO shares are
        copies of the queue's numbers. ``extra`` comes last so a test can
        override any published value, counts included.
        """
        mine = [job for job in self.jobs.values() if job.queue == queue.name]
        values = _limits(queue)
        values["ServingState"] = queue.serving_state
        values["RunningJobs"] = str(sum(job.state == "RUNNING" for job in mine))
        values["WaitingJobs"] = str(sum(job.state == "QUEUING" for job in mine))
        values.update(queue.extra)
        return [self._glue2_share(queue.name, vo, values, stamp) for vo in ("", *queue.vos)]

    def _glue2_share(
        self, queue: str, vo: str, values: dict[str, str], stamp: dict[str, str]
    ) -> _Node:
        """The queue's own share (``vo=""``) or its share for one VO, as A-REX names them."""
        name = f"{queue}_{vo}" if vo else queue
        share = _Node("ComputingShare", attrs={"BaseType": "Share", **stamp})
        # ``MappingQueue`` is what a job names in ``queue=``; a VO share's
        # ``Name`` is not a queue at all, which is what clients get wrong.
        share.add("ID", f"urn:ogf:ComputingShare:{self.host}:{name}")
        share.add("Name", name)
        share.add("MappingQueue", queue)
        for key, value in values.items():
            share.add(key, value)
        if vo:
            # The MappingPolicy is what marks a share as per-VO (``Queue.vo_share``).
            policy = share.add("MappingPolicy", attrs={"BaseType": "Policy", **stamp})
            policy.add("ID", f"urn:ogf:MappingPolicy:{self.host}:basic:{vo}")
            policy.add("Scheme", "basic")
            policy.add("Rule", f"vo:{vo}")
        return share

    def _glue2_manager(self, service: _Node, stamp: dict[str, str]) -> None:
        """The ``ComputingManager``: the batch system, CPU count and runtime environments."""
        info = self.info
        assert isinstance(info, CEInfo)
        manager = service.add("ComputingManager", attrs={"BaseType": "Manager", **stamp})
        manager.add("ID", f"urn:ogf:ComputingManager:{self.host}:{info.lrms.lower()}")
        manager.add("ProductName", info.lrms)
        manager.add("TotalLogicalCPUs", str(info.total_cpus))
        environments = manager.add("ApplicationEnvironments")
        for index, rte in enumerate(info.rtes):
            environment = environments.add("ApplicationEnvironment")
            environment.add("ID", f"urn:ogf:ApplicationEnvironment:{self.host}:rte:{index}")
            name, version = _name_version(rte)
            environment.add("AppName", name)
            if version:
                environment.add("AppVersion", version)
            environment.add("State", "installednotverified")


def _limits(queue: FakeQueue) -> dict[str, str]:
    """The queue's published limits, GLUE2 names to text; a limit not set is not published.

    Absent rather than ``0``: on a real CE an unpublished limit means "no
    limit", and a client that read a missing ``MaxWallTime`` as zero would
    refuse every job. Leaving it out is what tests that behaviour.
    """
    limits = {
        "MaxWallTime": queue.max_wall_time,
        "MaxCPUTime": queue.max_cpu_time,
        "MinWallTime": queue.min_wall_time,
        "DefaultWallTime": queue.default_wall_time,
        "MaxTotalJobs": queue.max_total_jobs,
        "MaxRunningJobs": queue.max_running_jobs,
        "MaxWaitingJobs": queue.max_waiting_jobs,
    }
    return {key: str(value) for key, value in limits.items() if value is not None}


def _name_version(rte: str) -> tuple[str, str]:
    """``APPS/HEP/ATLAS-21.0.1`` as (name, version): the part after the last ``-`` if a version.

    A name with a hyphen but no version after it (``ENV/PROXY-X``) is all name.
    Only a leading digit makes the tail a version; ``xrdarc.info`` joins the
    two back as ``AppName-AppVersion``, so the round trip is what is tested.
    """
    name, _, version = rte.rpartition("-")
    if not (name and version[:1].isdigit()):
        return rte, ""
    return name, version
