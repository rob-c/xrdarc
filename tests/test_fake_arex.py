"""The fake A-REX, driven with raw ``http.client`` and ``ssl``: no xrdarc client code."""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from xgfalclient.crypto.proxy import sign_request
from xgfalclient.testing.pki import PKI, create_pki

from xrdarc.testing import arex
from xrdarc.testing.arex import (
    CANCEL_CAUSE,
    DEFAULT_PROGRESSION,
    DIAGNOSE_ITEMS,
    GLUE2_NS,
    CEInfo,
    FakeARex,
    FakeQueue,
)

ALICE = "/CN=alice"
BOB = "/CN=bob"
TOKENS = {"alice-token": ALICE, "bob-token": BOB}
USER_DN = "/DC=org/DC=xgfal/OU=People/CN=Test User"
XRSL = '&(executable="/bin/echo")(jobname = "hello")(stdout = "out.txt")(stderr="err.txt")'
ADL = (
    '<ActivityDescription xmlns="http://www.eu-emi.eu/es/2010/12/adl" '
    'xmlns:nordugrid-adl="http://www.nordugrid.org/es/2011/12/nordugrid-adl">'
    "<ActivityIdentification><Name>adljob</Name></ActivityIdentification>"
    "<Application><Executable><Path>run.sh</Path></Executable><Output>o</Output>"
    "<Error>e</Error><nordugrid-adl:LoggingDirectory>gmlog</nordugrid-adl:LoggingDirectory>"
    "<nordugrid-adl:Rerun>1</nordugrid-adl:Rerun></Application>"
    "<Resources><QueueName>main</QueueName></Resources>"
    "<DataStaging><InputFile><Name>in</Name><Source><URI>https://h/d</URI>"
    "<DelegationID>d1</DelegationID></Source></InputFile>"
    "<nordugrid-adl:DelegationID>d1</nordugrid-adl:DelegationID></DataStaging>"
    "</ActivityDescription>"
)


# ---------------------------------------------------------------------------
# Fixtures and a small raw client
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(("X509_", "BEARER_")):
            monkeypatch.delenv(name)


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    return create_pki(tmp_path_factory.mktemp("pki"))


@dataclass
class Reply:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def jobs(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = self.json()["job"]
        return found


class Client:
    """``http.client`` with A-REX conventions: a token, ``Accept``, ``/arex/rest/<v>/``."""

    def __init__(
        self,
        ce: FakeARex,
        *,
        token: str | None = "alice-token",
        context: ssl.SSLContext | None = None,
    ) -> None:
        self.ce, self.token, self.context = ce, token, context
        self.connection = self.connect()

    def connect(self) -> http.client.HTTPConnection:
        if self.context is not None:
            return http.client.HTTPSConnection(
                self.ce.host, self.ce.port, context=self.context, timeout=10
            )
        return http.client.HTTPConnection(self.ce.host, self.ce.port, timeout=10)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | str | None = None,
        headers: dict[str, str] | None = None,
        *,
        accept: str | None = "application/json",
        version: str = "1.1",
    ) -> Reply:
        target = path if path.startswith("/") else f"/arex/rest/{version}/{path}"
        sent: dict[str, str] = {}
        if self.token:
            sent["Authorization"] = f"Bearer {self.token}"
        if accept:
            sent["Accept"] = accept
        sent.update(headers or {})
        self.connection.request(method, target, body=body, headers=sent)
        response = self.connection.getresponse()
        data = response.read()
        lowered = {key.lower(): value for key, value in response.getheaders()}
        return Reply(response.status, response.reason, lowered, data)

    def submit(self, text: str, query: str = "", **kwargs: Any) -> Reply:
        return self.request("POST", f"jobs?action=new{query}", text.encode(), **kwargs)

    def submit_one(self, text: str = XRSL, query: str = "", version: str = "1.1") -> str:
        reply = self.submit(text, query, version=version)
        assert reply.status == 201, reply
        job_id: str = reply.jobs[0]["id"]
        return job_id

    def action(self, action: str, *ids: str, **kwargs: Any) -> Reply:
        body = json.dumps({"job": [{"id": job_id} for job_id in ids]})
        headers = {"Content-Type": "application/json"}
        return self.request("POST", f"jobs?action={action}", body, headers, **kwargs)

    def state(self, job_id: str) -> str:
        found: str = self.action("status", job_id).jobs[0]["state"]
        return found

    def close(self) -> None:
        self.connection.close()


@pytest.fixture
def ce(tmp_path: Path) -> Iterator[FakeARex]:
    with FakeARex(tmp_path / "ce", tokens=TOKENS) as server:
        yield server


@pytest.fixture
def client(ce: FakeARex) -> Iterator[Client]:
    found = Client(ce)
    yield found
    found.close()


@pytest.fixture
def bob(ce: FakeARex) -> Iterator[Client]:
    found = Client(ce, token="bob-token")
    yield found
    found.close()


def _key(slot: int) -> rsa.RSAPrivateKey:
    return arex._delegation_key(slot)


def _proxy_for(pki: PKI, csr_pem: bytes, *, signer: rsa.RSAPrivateKey | None = None) -> bytes:
    """Sign a delegation CSR with the user certificate, as a client does (cryptography)."""
    csr = x509.load_pem_x509_csr(csr_pem)
    user = x509.load_pem_x509_certificate(pki.user_cert_path.read_bytes())
    user_key = serialization.load_pem_private_key(pki.user_key_path.read_bytes(), None)
    assert isinstance(user_key, rsa.RSAPrivateKey)
    serial = x509.random_serial_number()
    common = x509.NameAttribute(NameOID.COMMON_NAME, str(serial))
    subject = x509.Name([*user.subject.rdns, x509.RelativeDistinguishedName([common])])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(user.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .sign(signer or user_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return certificate.public_bytes(pem) + user.public_bytes(pem)


def _delegate(client: Client, version: str = "1.1") -> tuple[str, bytes]:
    reply = client.request("POST", "delegations?action=new", version=version)
    assert reply.status == 201, reply
    return reply.headers["location"].rsplit("/", 1)[1], reply.body


# ---------------------------------------------------------------------------
# Versions, routing, negotiation
# ---------------------------------------------------------------------------


def test_versions_in_every_format(client: Client) -> None:
    reply = client.request("GET", "/arex/rest")
    assert (reply.status, reply.reason) == (200, "OK")
    assert reply.json() == {"version": ["1.0", "1.1"]}
    assert reply.headers["content-type"] == "application/json"
    xml = client.request("GET", "/arex/rest/", accept="text/xml")
    assert xml.body == b"<versions><version>1.0</version><version>1.1</version></versions>"
    assert xml.headers["content-type"] == "application/xml"
    assert client.request("GET", "/arex/rest", accept="application/xml;q=1").body == xml.body
    html = client.request("GET", "/arex/rest", accept="image/png, text/html;q=0.9")
    assert html.headers["content-type"] == "text/html"
    assert html.body.startswith(b'<HTML><HEAD>versions</HEAD><BODY><table border="1">')
    bare = client.request("GET", "/arex/rest", accept=None)
    assert bare.body == html.body
    assert "content-type" not in bare.headers  # A-REX does not say what it sent
    head = client.request("HEAD", "/arex/rest")
    assert head.body == b"" and head.headers["content-length"] == str(len(reply.body))
    assert client.request("POST", "/arex/rest").reason == "Not Implemented"


def test_accept_header_repeated_takes_the_first_recognised(ce: FakeARex) -> None:
    connection = http.client.HTTPConnection(ce.host, ce.port, timeout=10)
    connection.putrequest("GET", "/arex/rest")
    connection.putheader("Authorization", "Bearer alice-token")
    connection.putheader("Accept", "image/png")
    connection.putheader("Accept", "application/xml, application/json")
    connection.endheaders()
    response = connection.getresponse()
    assert response.read().startswith(b"<versions>")
    connection.close()


def test_configured_versions_and_legacy_scalars(tmp_path: Path) -> None:
    with FakeARex(tmp_path, tokens=TOKENS, versions=("1.0",), legacy_json=True) as ce:
        client = Client(ce)
        assert client.request("GET", "/arex/rest").json() == {"version": "1.0"}
        assert client.request("GET", "jobs", version="1.1").reason == "Version Not Supported"
        # An ARC 6 server: an empty list is an empty body, one job is not a list.
        assert client.request("GET", "jobs", version="1.0").body == b""
        reply = client.submit(XRSL, version="1.0")
        job_id = reply.json()["job"]["id"]
        assert client.request("GET", "jobs", version="1.0").json() == {"job": {"id": job_id}}
        client.close()


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/elsewhere", "Not Found"),
        ("/arex", "Not Found"),
        ("/arex/emies", "Not Found"),
        ("/arex/rest/2.0/jobs", "Version Not Supported"),
        ("/arex/rest/1.1", "Not Found"),
        ("/arex/rest/1.1/", "Not Found"),
        ("/arex/rest/1.1/foo", "Functionality Not Supported"),
        ("/arex/rest/1.1/jobs/abc", "Missing job sub-resource"),
        ("/arex/rest/1.1/jobs/abc/foo", "Wrong job sub-resource requested"),
        ("/arex/rest/1.1/info/extra", "Not Found"),
        ("/arex/rest/1.1/delegations/abc/extra", "Not Found"),
    ],
)
def test_routing_errors(client: Client, path: str, reason: str) -> None:
    reply = client.request("GET", path)
    assert (reply.status, reply.reason, reply.body) == (404, reason, b"")


@pytest.mark.parametrize(
    ("method", "path", "reason"),
    [
        ("PUT", "jobs", "Not Implemented"),
        ("POST", "jobs?action=frobnicate", "Action not implemented"),
        ("POST", "jobs", "Action not implemented"),
        ("POST", "info", "Not Implemented"),
        ("GET", "info?schema=glue1", "Schema not implemented"),
        ("PUT", "delegations", "Not Implemented"),
        ("POST", "delegations?action=get", "Action not implemented"),
        ("GET", "delegations/abc", "Not Implemented"),
        ("DELETE", "delegations/abc", "Not Implemented"),
        ("POST", "delegations/abc?action=frobnicate", "Action not implemented"),
        ("PATCH", "jobs/abc/diagnose/errors", "Not Implemented"),
    ],
)
def test_not_implemented(client: Client, method: str, path: str, reason: str) -> None:
    reply = client.request(method, path)
    assert (reply.status, reply.reason) == (501, reason)


def test_query_parsing_rules() -> None:
    assert arex._split_target("/a%20b?x=1&x=2&y=%41") == ("/a b", {"x": "1", "y": "A"})
    assert arex._split_target("/info;schema=glue2") == ("/info", {"schema": "glue2"})
    assert arex._split_target("/plain") == ("/plain", {"": ""})


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_no_credential_and_bad_token_are_refused(ce: FakeARex) -> None:
    anonymous = Client(ce, token=None)
    reply = anonymous.request("GET", "/arex/rest")
    assert (reply.status, reply.reason) == (403, "User can't be assigned configuration")
    stranger = Client(ce, token="who")
    reply = stranger.request("GET", "/arex/rest")
    assert (reply.status, reply.reason) == (403, "Not authorized: token is not valid")
    assert ce.requests[-1].identity == ""
    anonymous.close()
    stranger.close()


def test_anonymous_identity(tmp_path: Path) -> None:
    with FakeARex(tmp_path, anonymous="/CN=guest") as ce:
        client = Client(ce, token=None)
        job_id = client.submit_one()
        assert ce.jobs[job_id].owner == "/CN=guest"
        assert ce.url == f"http://127.0.0.1:{ce.port}/arex"
        client.close()


def test_tls_identity_is_the_end_entity_subject(tmp_path: Path, pki: PKI) -> None:
    with FakeARex(tmp_path, tls=pki.server_context()) as ce:
        assert ce.url == f"https://127.0.0.1:{ce.port}/arex"
        first = pki.proxy("rfc", path=tmp_path / "rfc")
        second = pki.proxy("rfc", path=tmp_path / "second", issuer=pki.credential(first))
        limited = pki.proxy("limited", path=tmp_path / "limited")
        for proxy in (first, second, limited):
            client = Client(ce, token=None, context=pki.client_context(proxy=proxy))
            assert client.submit(XRSL).status == 201
            assert ce.requests[-1].identity == USER_DN
            client.close()
        eec = ssl.create_default_context(cafile=str(pki.ca_file))
        eec.load_cert_chain(str(pki.user_cert_path), str(pki.user_key_path))
        client = Client(ce, token=None, context=eec)
        assert len(client.request("GET", "jobs").jobs) == 3
        # A token wins over the certificate.
        ce.tokens["tok"] = ALICE
        client.token = "tok"
        assert client.request("GET", "jobs").jobs == []
        client.close()


def test_tls_without_client_certificate_needs_a_token(tmp_path: Path, pki: PKI) -> None:
    server = pki.server_context(require_client=False)
    with FakeARex(tmp_path, tls=server, tokens=TOKENS) as ce:
        context = ssl.create_default_context(cafile=str(pki.ca_file))
        client = Client(ce, token=None, context=context)
        assert client.request("GET", "/arex/rest").status == 403
        client.token = "alice-token"
        assert client.request("GET", "/arex/rest").status == 200
        client.close()


def test_broken_handshake_does_not_stop_the_server(tmp_path: Path, pki: PKI) -> None:
    with FakeARex(tmp_path, tls=pki.server_context()) as ce:
        raw = socket.create_connection((ce.host, ce.port), timeout=5)
        raw.sendall(b"GET / HTTP/1.1\r\n\r\n")  # not TLS
        with contextlib.suppress(OSError):
            raw.recv(100)
        raw.close()
        client = Client(ce, token=None, context=pki.client_context())
        assert client.request("GET", "/arex/rest").status == 200
        client.close()
    assert ce.connections == 1


# ---------------------------------------------------------------------------
# GET /info
# ---------------------------------------------------------------------------


def _service(document: dict[str, Any]) -> dict[str, Any]:
    domain = document["Domains"]["AdminDomain"][0]
    found: dict[str, Any] = domain["Services"]["ComputingService"][0]
    return found


def test_info_json(ce: FakeARex, client: Client) -> None:
    client.submit_one()
    reply = client.request("GET", "info?schema=glue2")
    assert reply.status == 200
    document = reply.json()
    assert "_attributes" in document["Domains"]["AdminDomain"][0]
    service = _service(document)
    assert service["Name"] == "fake-arex" and service["TotalJobs"] == "1"
    assert "Contact" not in service  # /info shows no empty forced arrays
    endpoint = service["ComputingEndpoint"][0]
    assert endpoint["URL"] == ce.url
    assert endpoint["InterfaceName"] == "org.nordugrid.arcrest"
    assert endpoint["InterfaceVersion"] == ["1.0", "1.1"]
    assert endpoint["JobDescription"] == ["nordugrid:xrsl", "emies:adl"]
    assert endpoint["PreLRMSWaitingJobs"] == "1"
    shares = {share["Name"]: share for share in service["ComputingShare"]}
    assert set(shares) == {"main", "main_atlas"}
    assert "MappingPolicy" not in shares["main"]
    assert shares["main"]["MaxWallTime"] == "259200"
    assert shares["main_atlas"]["MappingQueue"] == "main"
    assert shares["main_atlas"]["MappingPolicy"][0]["Rule"] == ["vo:atlas"]
    manager = service["ComputingManager"][0]
    environments = manager["ApplicationEnvironments"]["ApplicationEnvironment"]
    assert [(e["AppName"], e.get("AppVersion")) for e in environments] == [
        ("ENV/PROXY", None),
        ("APPS/HEP/ATLAS", "21.0.1"),
    ]


def test_info_xml_and_options(tmp_path: Path) -> None:
    info = CEInfo(
        name="ce1",
        queues=[FakeQueue("short", max_wall_time=None, max_cpu_time=60, extra={"Tag": "x"})],
        rtes=["A-b"],
    )
    with FakeARex(tmp_path, tokens=TOKENS, info=info) as ce:
        client = Client(ce)
        reply = client.request("GET", "/arex/rest/1.0/info;schema=glue2", accept="text/xml")
        root = ET.fromstring(reply.body)
        assert root.tag == "InfoRoot"
        service = root.find(f"{{{GLUE2_NS}}}Domains/*/*/{{{GLUE2_NS}}}ComputingService")
        assert service is not None
        assert service.findtext(f"{{{GLUE2_NS}}}Name") == "ce1"
        share = service.find(f"{{{GLUE2_NS}}}ComputingShare")
        assert share is not None and share.findtext(f"{{{GLUE2_NS}}}MaxCPUTime") == "60"
        assert share.find(f"{{{GLUE2_NS}}}MaxWallTime") is None
        assert share.findtext(f"{{{GLUE2_NS}}}Tag") == "x"
        assert b"<AppName>A-b</AppName>" in reply.body
        assert client.request("HEAD", "info").body == b""
        client.close()


def test_info_raw_document(tmp_path: Path) -> None:
    raw = (
        '<InfoRoot><Domains xmlns="http://schemas.ogf.org/glue/2009/03/spec_2.0_r1">'
        '<AdminDomain BaseType="Domain"><Services><ComputingService><Name>raw</Name>'
        "</ComputingService></Services></AdminDomain></Domains></InfoRoot>"
    )
    with FakeARex(tmp_path, tokens=TOKENS, info=raw) as ce:
        client = Client(ce)
        document = client.request("GET", "info").json()
        assert _service(document) == {"Name": "raw"}
        assert document["Domains"]["AdminDomain"][0]["_attributes"] == {"BaseType": "Domain"}
        xml = client.request("GET", "info", accept="application/xml").body
        assert xml.startswith(b'<InfoRoot><Domains xmlns="http://schemas.ogf.org')
        # No queues are known, so any queue is taken.
        assert client.submit('&(executable=a)(queue="anything")').jobs[0]["status-code"] == "201"
        ce.info = "<not xml"
        assert client.request("GET", "info").body == b""
        client.close()


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------


def test_submit_single_xrsl(ce: FakeARex, client: Client) -> None:
    reply = client.submit(XRSL + '(gmlog=gmlog)(rerun="2")(delegationid="d9")')
    assert (reply.status, reply.reason) == (201, "Created")
    (entry,) = reply.jobs
    assert entry["status-code"] == "201" and entry["reason"] == "Created"
    assert entry["state"] == "ACCEPTING"
    job = ce.jobs[entry["id"]]
    assert len(job.id) == 12 and int(job.id, 16) >= 0 and job.id == job.id.lower()
    assert (job.owner, job.name, job.stdout, job.stderr) == (ALICE, "hello", "out.txt", "err.txt")
    assert (job.logdir, job.rerun, job.delegations, job.queue) == ("gmlog", 2, ["d9"], "main")
    assert (job.language, job.version, job.gm_state) == ("nordugrid:xrsl", "1.1", "ACCEPTED")
    assert job.session == ce.session_dir(job.id) and job.session.is_dir()


def test_xrsl_value_forms() -> None:
    fields = arex._xrsl_fields("&(jobname='it''s')(stdout=bare)(stderr=\"a\"\"b\")")
    assert (fields.name, fields.stdout, fields.stderr, fields.queue) == ("it's", "bare", 'a"b', "")


def test_submit_adl_single_and_multi(ce: FakeARex, client: Client) -> None:
    job = ce.jobs[client.submit_one(ADL)]
    assert (job.name, job.stdout, job.stderr, job.logdir) == ("adljob", "o", "e", "gmlog")
    assert (job.rerun, job.delegations, job.language) == (1, ["d1"], "emies:adl")
    assert job.description == ADL
    nameless = "<ActivityDescription><ActivityIdentification/></ActivityDescription>"
    multi = f"<?xml version='1.0'?>\n<ActivityDescriptions>{ADL}{nameless}</ActivityDescriptions>"
    entries = client.submit(multi).jobs
    assert [entry["status-code"] for entry in entries] == ["201", "201"]
    assert ce.jobs[entries[1]["id"]].name == ""
    broken = client.submit("<ActivityDescription><unclosed>").jobs
    assert broken == [{"status-code": "500", "reason": "Failed to parse job description"}]


def test_submit_multi_xrsl(ce: FakeARex, client: Client) -> None:
    text = '+(&(executable="a(b)")(jobname="j1"))\n(&(executable=b)(jobname=j2))'
    entries = client.submit(text).jobs
    assert [ce.jobs[entry["id"]].name for entry in entries] == ["j1", "j2"]
    assert ce.jobs[entries[0]["id"]].description == '&(executable="a(b)")(jobname="j1")'
    reply = client.submit("+ nothing")
    assert (reply.status, reply.reason) == (500, "Failed to parse job description")


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("", "Missing payload"),
        ("  \r\n\t", "Payload is empty"),
        ("(executable=a)", "Payload is not recognized"),
        ("executable=a", "Payload is not recognized"),
    ],
)
def test_submit_payload_errors(client: Client, body: str, reason: str) -> None:
    reply = client.submit(body)
    assert (reply.status, reply.reason, reply.body) == (500, reason, b"")


def test_submit_queue_and_delegation_parameters(ce: FakeARex, client: Client) -> None:
    ce.info = CEInfo(queues=[FakeQueue("main"), FakeQueue("long")])
    bad = client.submit('&(executable=a)(queue="nope")').jobs
    reason = "Requested queue nope does not match any of available queues"
    assert bad == [{"status-code": "500", "reason": reason}]
    job_id = client.submit_one("&(executable=a)", "&queue=long&delegation_id=dd")
    assert (ce.jobs[job_id].queue, ce.jobs[job_id].delegations) == ("long", ["dd"])
    # 1.0 ignores the parameters.
    reply = client.submit("&(executable=a)", "&queue=long&delegation_id=dd", version="1.0")
    job = ce.jobs[reply.jobs[0]["id"]]
    assert (job.queue, job.delegations, job.version) == ("main", [], "1.0")


def test_submit_instances(ce: FakeARex, client: Client) -> None:
    entries = client.submit(XRSL, "&instances=3&instances_min=2").jobs
    assert len(entries) == 3 and len({entry["id"] for entry in entries}) == 3
    assert len(client.submit(XRSL, "&instances=abc").jobs) == 1
    assert len(client.submit(XRSL, "&instances=3", version="1.0").jobs) == 1
    for query in ("&instances=0", "&instances=2&instances_min=3"):
        reply = client.submit(XRSL, query)
        assert (reply.status, reply.reason) == (500, "Wrong number of instances specified")
    multi = client.submit("+(&(executable=a))(&(executable=b))", "&instances=2")
    reason = "No multiple descriptions and multiple instances simultaneously"
    assert (multi.status, multi.reason) == (403, reason)
    ce.reject_next("Runtime environments have not been resolved.")
    failed = client.submit(XRSL, "&instances=4").jobs
    assert failed == [
        {"status-code": "500", "reason": "Runtime environments have not been resolved."}
    ]


def test_maxjobs(tmp_path: Path) -> None:
    with FakeARex(tmp_path, tokens=TOKENS, maxjobs=3) as ce:
        client = Client(ce)
        client.submit_one()
        too_many = client.submit(XRSL, "&instances=5&instances_min=3")
        assert (too_many.status, too_many.reason) == (
            403,
            "Number of requested instances exceeds allowed limit",
        )
        assert len(client.submit(XRSL, "&instances=5").jobs) == 2  # capped to what fits
        ce.jobs.popitem()
        entries = client.submit("+(&(executable=a))(&(executable=b))").jobs
        assert entries[1] == {"status-code": "500", "reason": "No more jobs allowed"}
        reply = client.submit(XRSL)
        assert (reply.status, reply.reason) == (500, "No more jobs allowed")
        client.close()


def test_rejections_and_policy(ce: FakeARex, client: Client) -> None:
    ce.reject_next("New job submission is not allowed", times=2)
    text = "+(&(executable=a))(&(executable=b))(&(executable=c))"
    entries = client.submit(text).jobs
    assert [entry["status-code"] for entry in entries] == ["500", "500", "201"]
    assert "id" not in entries[0] and entries[0]["reason"] == "New job submission is not allowed"
    ce.policy = lambda description: "bad" if "fail" in description else None
    entries = client.submit("+(&(executable=fail))(&(executable=ok))").jobs
    assert [entry["status-code"] for entry in entries] == ["500", "201"]


def test_job_ids_never_collide(ce: FakeARex, monkeypatch: pytest.MonkeyPatch) -> None:
    values = iter(["aaaaaaaaaaaa", "aaaaaaaaaaaa", "bbbbbbbbbbbb"])
    monkeypatch.setattr(arex.secrets, "token_hex", lambda size: next(values))
    assert ce.add_job(ALICE).id == "aaaaaaaaaaaa"
    assert ce.add_job(ALICE).id == "bbbbbbbbbbbb"


# ---------------------------------------------------------------------------
# GET /jobs and the bulk actions
# ---------------------------------------------------------------------------


def test_list_jobs_is_per_user_with_fast_state_filter(
    ce: FakeARex, client: Client, bob: Client
) -> None:
    running, failed, killed, cancelled = (client.submit_one() for _ in range(4))
    bob.submit_one()
    ce.set_state(running, "QUEUING")
    ce.fail_job(failed)
    ce.set_state(killed, "KILLED")
    ce.set_state(cancelled, "FAILED", failure=CANCEL_CAUSE)
    assert len(client.request("GET", "jobs").jobs) == 4
    assert [job["id"] for job in bob.request("GET", "jobs").jobs] != []
    reply = client.request("GET", "jobs?state=RUNNING,FAILED")
    assert reply.jobs == [{"id": running, "state": "RUNNING"}, {"id": failed, "state": "FAILED"}]
    assert client.request("GET", "jobs?state=QUEUING").jobs == []  # never in the fast mapping
    killed_ids = {job["id"] for job in client.request("GET", "jobs?state=KILLED").jobs}
    assert killed_ids == {killed, cancelled}
    xml = client.request("GET", "jobs?state=FAILED", accept="text/xml").body
    assert xml == f"<jobs><job><id>{failed}</id><state>FAILED</state></job></jobs>".encode()


def test_bulk_content_type_rule(ce: FakeARex, client: Client) -> None:
    job_id = client.submit_one()
    xml = f"<jobs><job><id>{job_id}</id></job><other/><job/><job><id></id></job></jobs>"
    for content_type in ("application/xml", None):
        headers = {"Content-Type": content_type} if content_type else {}
        reply = client.request("POST", "jobs?action=status", xml, headers)
        assert [job["id"] for job in reply.jobs] == [job_id]
    for content_type in ("text/xml", "application/json; charset=utf-8"):
        body = json.dumps({"job": {"id": job_id}})
        reply = client.request("POST", "jobs?action=status", body, {"Content-Type": content_type})
        assert (reply.status, reply.json()) == (201, {"job": []})
    assert client.request("POST", "jobs?action=status", "<broken").json() == {"job": []}


@pytest.mark.parametrize(
    ("body", "ids"),
    [
        ('{"job":{"id":"abc"}}', ["abc"]),
        ('{"job":[{"id":"abc"},{"id":"def"}]}', ["abc", "def"]),
        ('{"job":{"id":123}}', ["23"]),
        ('{"job":{"id":true}}', ["rue"]),
        ('{"whatever":{"job":{"id":"x"}},"job":{"id":"y"}}', ["y"]),
        ('[{"id":"abc"}]', []),
        ("{not json", []),
    ],
)
def test_bulk_json_parsing(client: Client, body: str, ids: list[str]) -> None:
    reply = client.request("POST", "jobs?action=kill", body, {"Content-Type": "application/json"})
    assert [job["id"] for job in reply.jobs] == ids


def test_bulk_missing_jobs(client: Client, bob: Client) -> None:
    job_id = bob.submit_one()  # somebody else's is as good as missing
    found = {
        action: client.action(action, job_id).jobs[0]
        for action in ("info", "status", "kill", "clean", "restart", "delegations")
    }
    base = {"status-code": "404", "reason": "Job not found", "id": job_id}
    assert found["info"] == {**base, "info_document": ""}
    assert found["status"] == {**base, "state": "None"}
    assert all(found[action] == base for action in ("kill", "clean", "restart", "delegations"))
    xml = client.action("status", job_id, accept="application/xml").body.decode()
    assert xml == (
        "<jobs><job><status-code>404</status-code><reason>Job not found</reason>"
        f"<id>{job_id}</id><state>None</state></job></jobs>"
    )


def test_info_action_document(ce: FakeARex, client: Client) -> None:
    job_id = client.submit_one(XRSL + "(gmlog=gmlog)")
    ce.set_state(job_id, "RUNNING")
    ce.fail_job(job_id, "Job failed\nLRMS error: (-1) exit", exit_code=3)
    reply = client.action("info", job_id)
    (entry,) = reply.jobs
    assert (entry["status-code"], entry["reason"], entry["id"]) == ("200", "OK", job_id)
    activity = entry["info_document"]["ComputingActivity"]
    assert activity["ID"] == f"urn:caid:127.0.0.1:org.nordugrid.arcrest:{job_id}"
    assert activity["IDFromEndpoint"] == f"urn:idfe:{job_id}"
    assert activity["State"] == ["nordugrid:FAILED", "arcrest:FAILED"]
    assert activity["RestartState"] == "arcrest:RUNNING"
    assert activity["Error"] == ["Job failed", "LRMS error: (-1) exit"]
    assert (activity["ExitCode"], activity["Owner"], activity["Queue"]) == ("3", ALICE, "main")
    assert (activity["StdOut"], activity["StdErr"], activity["LogDir"]) == (
        "out.txt",
        "err.txt",
        "gmlog",
    )
    for name in ("SubmissionTime", "StartTime", "EndTime", "WorkingAreaEraseTime"):
        assert time.strptime(activity[name], "%Y-%m-%dT%H:%M:%SZ")
    assert activity["_attributes"]["BaseType"] == "Activity"
    xml = client.action("info", job_id, accept="text/xml").body.decode()
    assert f'<ComputingActivity xmlns="{GLUE2_NS}" BaseType="Activity"' in xml


def test_progression(tmp_path: Path) -> None:
    with FakeARex(tmp_path, tokens=TOKENS, progression=DEFAULT_PROGRESSION) as ce:
        client = Client(ce)
        job_id = client.submit_one()
        seen = [client.state(job_id) for _ in range(7)]
        assert seen == [*DEFAULT_PROGRESSION[1:], "FINISHED"]
        job = ce.jobs[job_id]
        assert job.exit_code == 0 and job.started is not None and job.ended is not None
        assert "Job state change INLRMS -> FINISHING" in "".join(job.log)
        client.close()


def test_kill_is_asynchronous(ce: FakeARex, client: Client) -> None:
    job_id = client.submit_one()
    ce.set_state(job_id, "RUNNING")
    reply = client.action("kill", job_id)
    assert reply.jobs == [{"status-code": "202", "reason": "Queued for killing", "id": job_id}]
    assert ce.jobs[job_id].state == "RUNNING"
    assert client.state(job_id) == "KILLED"
    assert ce.jobs[job_id].failure == CANCEL_CAUSE
    assert client.action("kill", job_id).jobs[0]["status-code"] == "202"
    assert client.state(job_id) == "KILLED"


def test_clean_waits_for_a_terminal_state(ce: FakeARex, client: Client) -> None:
    running, done = client.submit_one(), client.submit_one()
    ce.set_state(running, "RUNNING")
    ce.set_state(done, "FINISHED")
    reply = client.action("clean", running, done)
    assert [entry["reason"] for entry in reply.jobs] == ["Queued for cleaning"] * 2
    assert client.state(running) == "RUNNING"
    assert client.action("status", done).jobs[0]["state"] == "None"
    assert done not in ce.jobs and not ce.session_dir(done).exists()
    ce.set_state(running, "FINISHED")
    assert running in ce.jobs
    assert client.request("GET", "jobs").jobs == []


def test_restart(ce: FakeARex, client: Client) -> None:
    once, never = client.submit_one(XRSL + "(rerun=1)"), client.submit_one()
    assert client.action("restart", once).jobs[0]["reason"] == "Job has not failed"
    ce.fail_job(once)
    ce.fail_job(never)
    reply = client.action("restart", once, never)
    assert [(e["status-code"], e["reason"]) for e in reply.jobs] == [
        ("202", "Queued for restarting"),
        ("505", "No more restarts allowed"),
    ]
    job = ce.jobs[once]
    assert (job.state, job.rerun, job.restarts, job.failure, job.exit_code) == (
        "PREPARING",
        0,
        1,
        "",
        None,
    )
    ce.fail_job(once)
    assert client.action("restart", once).jobs[0]["reason"] == "No more restarts allowed"


def test_refused_kill_and_clean(ce: FakeARex, client: Client) -> None:
    job_id = client.submit_one()
    ce.jobs[job_id].refuse.update(
        kill="Job could not be canceled", clean="Job could not be cleaned"
    )
    assert client.action("kill", job_id).jobs[0] == {
        "status-code": "505",
        "reason": "Job could not be canceled",
        "id": job_id,
    }
    assert client.action("clean", job_id).jobs[0]["reason"] == "Job could not be cleaned"


def test_job_delegations(ce: FakeARex, client: Client, bob: Client) -> None:
    mine, _ = _delegate(client)
    other, _ = _delegate(bob)
    job_id = client.submit_one(f'&(executable=a)(delegationid="{mine}")')
    ce.jobs[job_id].delegations += [other, "unknown"]
    assert client.action("delegations", job_id).jobs == [
        {"status-code": "200", "reason": "OK", "id": job_id, "delegation_id": mine}
    ]
    ce.jobs[job_id].delegations = []
    assert "delegation_id" not in client.action("delegations", job_id).jobs[0]


# ---------------------------------------------------------------------------
# State controls
# ---------------------------------------------------------------------------


def test_state_controls(ce: FakeARex) -> None:
    job = ce.add_job(ALICE, ADL, state="FINISHED", files={"out/x.txt": b"x"})
    assert (job.language, job.exit_code, (job.session / "out/x.txt").read_bytes()) == (
        "emies:adl",
        0,
        b"x",
    )
    ce.set_state(job.id, "FINISHED", exit_code=5)
    assert job.exit_code == 5
    ce.fail_job(job.id)  # failing a finished job: there is no state to restart from
    assert (job.state, job.failed_state, job.fast_state) == ("FAILED", "", "FAILED")
    ce.set_state(job.id, "KILLED")
    assert job.failure == "Job failed" and job.fast_state == "FAILED"
    killed = ce.add_job(BOB, state="KILLED")
    assert (killed.failure, killed.fast_state) == (CANCEL_CAUSE, "KILLED")
    assert ce.add_job(ALICE, failure="x").failure == "x"
    assert ce.add_job(ALICE, exit_code=4).exit_code == 4
    with pytest.raises(ValueError, match="not a REST state"):
        ce.set_state(job.id, "SLEEPING")
    with pytest.raises(KeyError):
        ce.set_state("nope", "FINISHED")
    with pytest.raises(ValueError, match="does not match"):
        ce.add_job(ALICE, '&(executable=a)(queue="nope")')
    assert ce.add_job(ALICE).gm_state == "ACCEPTED" and not ce.add_job(ALICE).terminal


# ---------------------------------------------------------------------------
# Session directory
# ---------------------------------------------------------------------------


def test_session_listing(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE, files={"out.txt": b"12345", "gmlog/errors": b"", "err.txt": b""})
    (job.session / "link").symlink_to(job.session / "out.txt")
    listing = client.request("GET", f"jobs/{job.id}/session")
    assert listing.json() == {"file": ["err.txt", "out.txt"], "dir": ["gmlog"]}
    xml = client.request("GET", f"jobs/{job.id}/session/", accept="text/xml").body
    assert xml == (
        b'<list><file size="0">err.txt</file><dir>gmlog</dir><file size="5">out.txt</file></list>'
    )
    assert client.request("GET", f"jobs/{job.id}/session/gmlog").json() == {
        "file": ["errors"],
        "dir": [],
    }
    (job.session / "empty").mkdir()
    assert client.request("GET", f"jobs/{job.id}/session/empty").json() == {"file": [], "dir": []}


def test_session_files_and_ranges(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE, files={"data": b"0123456789", "empty": b""})
    path = f"jobs/{job.id}/session/data"
    whole = client.request("GET", path)
    assert (whole.status, whole.body, whole.headers["content-type"]) == (
        200,
        b"0123456789",
        "application/octet-stream",
    )
    part = client.request("GET", path, headers={"Range": "bytes=2-4"})
    assert (part.status, part.reason, part.body) == (206, "Partial content", b"234")
    assert part.headers["content-range"] == "bytes 2-4/10"
    tail = client.request("GET", path, headers={"Range": "bytes=7-"})
    assert (tail.status, tail.body, tail.headers["content-range"]) == (206, b"789", "bytes 7-9/10")
    assert client.request("GET", path, headers={"Range": "bytes=-3"}).status == 200
    assert client.request("GET", path, headers={"Range": "bytes=0-99"}).status == 200
    beyond = client.request("GET", path, headers={"Range": "bytes=10-"})
    assert (beyond.status, beyond.headers["content-range"]) == (416, "bytes */10")
    head = client.request("HEAD", path, headers={"Range": "bytes=2-4"})
    assert (head.status, head.headers["content-length"]) == (200, "10")
    assert client.request("GET", f"jobs/{job.id}/session/empty").body == b""
    missing = client.request("GET", f"jobs/{job.id}/session/nope")
    assert (missing.status, missing.reason) == (404, "Not found")


def test_session_paths_and_owners(ce: FakeARex, client: Client, bob: Client) -> None:
    job = ce.add_job(ALICE, files={"a/b": b"b"})
    assert client.request("GET", f"jobs/{job.id}/session/a/./../a/b").body == b"b"
    escape = client.request("GET", f"jobs/{job.id}/session/a/../../x")
    assert (escape.status, escape.reason) == (404, "Wrong path")
    # A-REX gives no failure text for a job it cannot find, so the reason is "OK".
    for who in (bob, client):
        other = who.request("GET", f"jobs/{'f' * 12 if who is client else job.id}/session")
        assert (other.status, other.reason) == (404, "OK")
    post = client.request("POST", f"jobs/{job.id}/session/a/b")
    assert (post.status, post.reason) == (501, "Not Implemented")


def test_session_upload_tracking(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE)
    base = f"jobs/{job.id}/session"
    reply = client.request("PUT", f"{base}/in/whole.txt", b"hello world")
    assert (reply.status, reply.reason, reply.body) == (200, "OK", b"")
    assert (job.session / "in/whole.txt").read_bytes() == b"hello world"
    client.request("PUT", f"{base}/in/whole.txt", b"HEY")  # no truncation
    assert (job.session / "in/whole.txt").read_bytes() == b"HEYlo world"
    second = client.request("PUT", f"{base}/part", b"56789", {"Content-Range": "bytes 5-9/10"})
    assert second.status == 200 and "/part" not in job.uploads
    client.request("PUT", f"{base}/part", b"01234", {"Content-Range": "bytes 0-4/10"})
    client.request("PUT", f"{base}/zero", b"")
    client.request("PUT", f"{base}/star", b"ab", {"Content-Range": "bytes 0-1/*"})
    assert job.uploads == ["/in/whole.txt", "/part", "/zero", "/star"]
    assert (job.session / "part").read_bytes() == b"0123456789"
    diagnose = client.request("GET", f"jobs/{job.id}/diagnose/input_status").body
    assert diagnose == b"/in/whole.txt\n/part\n/zero\n/star\n"
    for target in ("part/below", ""):
        failed = client.request("PUT", f"{base}/{target}", b"x")
        assert (failed.status, failed.reason) == (500, "Error creating file")


def test_session_delete(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE, files={"f": b"1", "d/e/g": b"2"})
    base = f"jobs/{job.id}/session"
    assert client.request("DELETE", f"{base}/f").status == 202
    deleted = client.request("DELETE", f"{base}/d")
    assert (deleted.status, deleted.reason) == (202, "Accepted")
    assert sorted(os.listdir(job.session)) == []
    missing = client.request("DELETE", f"{base}/f")
    assert (missing.status, missing.reason) == (500, "Failed to delete")
    assert client.request("DELETE", base).status == 202  # the whole session directory
    assert not job.session.exists()
    assert client.request("GET", base).reason == "Not found"


def test_propfind(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE, files={"out.txt": b"abc", "sub/inner": b"zz"})
    os.mkfifo(job.session / "fifo")
    base = f"/arex/rest/1.0/jobs/{job.id}/session"
    prefix = f"http://127.0.0.1:{ce.port}{base}"
    dav = "{DAV:}"

    def propfind(path: str, depth: str | None) -> list[ET.Element]:
        headers = {"Depth": depth} if depth is not None else {}
        reply = client.request("PROPFIND", path, headers=headers, accept=None)
        assert (reply.status, reply.headers["content-type"]) == (200, "application/xml")
        assert reply.body.startswith(b'<?xml version="1.0"?>\n<d:multistatus xmlns:d="DAV:">')
        return ET.fromstring(reply.body).findall(f"{dav}response")

    (root,) = propfind(base, "0")
    assert root.findtext(f"{dav}href") == prefix + "/"
    prop = f"{dav}propstat/{dav}prop/"
    assert root.findtext(f"{prop}{dav}displayname") == job.id
    assert root.find(f"{prop}{dav}resourcetype/{dav}collection") is not None
    hrefs = [entry.findtext(f"{dav}href") for entry in propfind(base + "/", "1")]
    assert hrefs == [prefix + "/", prefix + "/fifo", prefix + "/out.txt", prefix + "/sub/"]
    fifo = propfind(base + "/fifo", "0")[0]
    assert fifo.findtext(f"{dav}status") == "HTTP/1.1 404 Not Found"
    everything = propfind(base, "infinity")
    assert everything[-1].findtext(f"{dav}href") == prefix + "/sub/inner"
    assert everything[-1].findtext(f"{prop}{dav}getcontentlength") == "2"
    assert len(propfind(base, None)) == 5
    (missing,) = propfind(base + "/nope", "1")
    assert missing.findtext(f"{dav}status") == "HTTP/1.1 404 Not Found"


# ---------------------------------------------------------------------------
# Diagnose files
# ---------------------------------------------------------------------------


def test_diagnose(ce: FakeARex, client: Client, bob: Client) -> None:
    job_id = client.submit_one(XRSL)
    base = f"jobs/{job_id}/diagnose"
    description = client.request("GET", f"{base}/description")
    assert (description.body, description.headers["content-type"]) == (XRSL.encode(), "text/plain")
    assert client.request("GET", f"{base}/status").body == b"ACCEPTED"
    assert b"Job state change UNDEFINED -> ACCEPTED" in client.request("GET", f"{base}/errors").body
    assert f"subject={ALICE}\n".encode() in client.request("GET", f"{base}/local").body
    xml = client.request("GET", f"{base}/xml")
    assert xml.headers["content-type"] == "application/xml"
    assert ET.fromstring(xml.body).tag == f"{{{GLUE2_NS}}}ComputingActivity"
    for name in ("failed", "diag", "comment", "input_status"):
        absent = client.request("GET", f"{base}/{name}")
        assert (absent.status, absent.reason) == (404, "Not found")
    ce.fail_job(job_id, "boom", exit_code=2)
    ce.jobs[job_id].diagnose["comment"] = "from the LRMS"
    assert client.request("GET", f"{base}/failed").body == b"boom"
    assert client.request("GET", f"{base}/diag").body == b"exitcode=2\n"
    assert client.request("GET", f"{base}/comment").body == b"from the LRMS"
    assert client.request("GET", f"{base}/status", headers={"Range": "bytes=0-3"}).body == b"FINI"
    assert client.request("HEAD", f"{base}/failed").headers["content-length"] == "4"
    unknown = client.request("GET", f"{base}/gmlog")
    assert (unknown.status, unknown.reason) == (404, "Diagnostic item not found")
    assert client.request("GET", f"{base}/errors/").reason == "Diagnostic item not found"
    assert bob.request("GET", f"{base}/errors").reason == "OK"
    assert len(DIAGNOSE_ITEMS) == 14


# ---------------------------------------------------------------------------
# Delegations
# ---------------------------------------------------------------------------


def test_x509_delegation(ce: FakeARex, client: Client, pki: PKI) -> None:
    reply = client.request("POST", "delegations?action=new")
    assert (reply.status, reply.reason) == (201, "Created")
    assert reply.headers["content-type"] == "application/x-pem-file"
    location = reply.headers["location"]
    delegation_id = location.rsplit("/", 1)[1]
    assert location == f"/arex/rest/1.1/delegations/{delegation_id}" and len(delegation_id) == 12
    csr = x509.load_pem_x509_csr(reply.body)
    assert csr.subject == x509.Name([]) and csr.is_signature_valid
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA256)
    delegation = ce.delegations[delegation_id]
    assert (delegation.owner, delegation.type, delegation.csr) == (ALICE, "x509", reply.body)
    assert delegation.certificate is None
    chain = _proxy_for(pki, reply.body)
    put = client.request("PUT", f"delegations/{delegation_id}", chain)
    assert (put.status, put.reason, put.body) == (200, "OK", b"")
    assert delegation.uploads == 1 and delegation.chain_pem == chain
    assert delegation.certificate is not None and len(delegation.chain) == 2
    got = client.request("POST", f"delegations/{delegation_id}?action=get")
    assert (got.status, got.body, got.headers["content-type"]) == (
        200,
        chain,
        "application/x-pem-file",
    )


def test_delegation_signed_with_a_real_proxy(ce: FakeARex, client: Client, pki: PKI) -> None:
    delegation_id, csr = _delegate(client, version="1.0")
    proxy = pki.credential()
    der = sign_request(x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER), proxy)
    pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    body = pem + b"".join(link.pem() for link in proxy.chain)
    assert client.request("PUT", f"delegations/{delegation_id}", body).status == 200
    assert len(ce.delegations[delegation_id].chain) == len(proxy.chain) + 1


def test_delegation_upload_failures(ce: FakeARex, client: Client, bob: Client, pki: PKI) -> None:
    delegation_id, csr = _delegate(client)
    path = f"delegations/{delegation_id}"
    proxy = _proxy_for(pki, csr)
    single = proxy.split(b"-----END CERTIFICATE-----\n")[0] + b"-----END CERTIFICATE-----\n"
    wrong_key = pki.user_cert_path.read_bytes()
    forged = _proxy_for(pki, csr, signer=_key(7))
    for body in (b"garbage", wrong_key, forged):
        failed = client.request("PUT", path, body)
        assert (failed.status, failed.reason) == (500, "Failed accepting delegation")
    assert bob.request("PUT", path, proxy).reason == "Failed accepting delegation"
    assert client.request("PUT", "delegations/unknown", proxy).status == 500
    empty = client.request("PUT", path, b"")
    assert (empty.status, empty.reason) == (500, "Missing payload")
    assert client.request("PUT", path, single).status == 200  # nothing to check it against
    jwt = client.request(
        "POST", "delegations?action=new&type=jwt", headers={"X-Token-Delegation": "t"}
    )
    jwt_id = jwt.headers["location"].rsplit("/", 1)[1]
    assert client.request("PUT", f"delegations/{jwt_id}", proxy).status == 500


def test_token_delegation(ce: FakeARex, client: Client) -> None:
    headers = {"x-token-delegation": "Bearer abc"}
    reply = client.request("POST", "delegations?action=new&type=jwt", headers=headers)
    assert (reply.status, reply.body, "content-type" in reply.headers) == (201, b"", False)
    delegation_id = reply.headers["location"].rsplit("/", 1)[1]
    assert (ce.delegations[delegation_id].type, ce.delegations[delegation_id].token) == (
        "jwt",
        "Bearer abc",
    )
    got = client.request("POST", f"delegations/{delegation_id}?action=get")
    assert got.body == b"Bearer abc"
    missing = client.request("POST", "delegations?action=new&type=jwt")
    assert (missing.status, missing.reason) == (
        501,
        "Missing X-Token-Delegation header in delegation request",
    )
    unknown = client.request("POST", "delegations?action=new&type=voms")
    assert (unknown.status, unknown.reason) == (501, "Unknown delegation type specified")
    # 1.0 has no types: always an X.509 request.
    old = client.request("POST", "delegations?action=new&type=jwt", version="1.0")
    assert old.body.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
    explicit = client.request("POST", "delegations?action=new&type=x509")
    assert explicit.headers["content-type"] == "application/x-pem-file"


def test_delegation_listing(ce: FakeARex, client: Client, bob: Client) -> None:
    x509_id, _ = _delegate(client)
    headers = {"X-Token-Delegation": "tok"}
    reply = client.request("POST", "delegations?action=new&type=jwt", headers=headers)
    jwt_id = reply.headers["location"].rsplit("/", 1)[1]
    assert client.request("GET", "delegations").json() == {
        "delegation": [{"id": x509_id, "type": "x509"}, {"id": jwt_id, "type": "jwt"}]
    }
    assert client.request("GET", "delegations?type=jwt").json() == {
        "delegation": [{"id": jwt_id, "type": "jwt"}]
    }
    assert (
        len(client.request("GET", "delegations?type=jwt", version="1.0").json()["delegation"]) == 2
    )
    assert bob.request("GET", "delegations").json() == {"delegation": []}


def test_delegation_renew_and_delete(ce: FakeARex, client: Client, bob: Client) -> None:
    delegation_id, first = _delegate(client)
    renewed = client.request("POST", f"delegations/{delegation_id}?action=renew")
    assert (renewed.status, renewed.reason, "location" in renewed.headers) == (
        201,
        "Created",
        False,
    )
    assert renewed.headers["content-type"] == "application/x-pem-file"
    key = x509.load_pem_x509_csr(renewed.body).public_key()
    assert key == x509.load_pem_x509_csr(first).public_key()  # the same key
    assert ce.delegations[delegation_id].renewals == 1
    created = client.request("POST", "delegations/abcdef012345?action=renew")
    assert created.status == 201 and ce.delegations["abcdef012345"].owner == ALICE
    stolen = bob.request("POST", f"delegations/{delegation_id}?action=renew")
    assert (stolen.status, stolen.reason) == (500, "Failed generating delegation request")
    for who in (bob, client):
        missing = who.request(
            "POST", f"delegations/{'0' * 12 if who is client else delegation_id}?action=get"
        )
        assert (missing.status, missing.reason) == (404, "No delegation found")
    job_id = client.submit_one(f"&(executable=a)(delegationid={delegation_id})")
    locked = client.request("POST", f"delegations/{delegation_id}?action=delete")
    assert (locked.status, locked.reason) == (500, "Failed deleting delegation")
    ce.set_state(job_id, "FINISHED")
    client.action("clean", job_id)
    deleted = client.request("POST", f"delegations/{delegation_id}?action=delete")
    assert (deleted.status, deleted.reason) == (202, "Accepted")
    assert delegation_id not in ce.delegations
    gone = client.request("POST", f"delegations/{delegation_id}?action=delete")
    assert (gone.status, gone.reason) == (404, "No such delegation")


# ---------------------------------------------------------------------------
# Per-operation authorisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("operation", "method", "path"),
    [
        ("JobInfo", "GET", "jobs"),
        ("JobInfo", "POST", "jobs?action=status"),
        ("JobCreate", "POST", "jobs?action=new"),
        ("JobCancel", "POST", "jobs?action=kill"),
        ("JobDelete", "POST", "jobs?action=clean"),
        ("JobInfo", "GET", "jobs/{job}/diagnose/errors"),
        ("DataInfo", "GET", "jobs/{job}/session"),
        ("DataRead", "GET", "jobs/{job}/session/f"),
        ("DataWrite", "PUT", "jobs/{job}/session/f"),
        ("DataWrite", "DELETE", "jobs/{job}/session/f"),
        ("DataInfo", "PROPFIND", "jobs/{job}/session"),
        ("JobInfo", "GET", "delegations"),
        ("JobCreate", "POST", "delegations?action=new"),
        ("JobCreate", "PUT", "delegations/{deleg}"),
        ("JobInfo", "POST", "delegations/{deleg}?action=get"),
        ("JobDelete", "POST", "delegations/{deleg}?action=delete"),
    ],
)
def test_denied_operations(
    ce: FakeARex, client: Client, operation: str, method: str, path: str
) -> None:
    job = ce.add_job(ALICE, files={"f": b"x"})
    delegation_id, _ = _delegate(client)
    ce.denied = {operation}
    target = path.format(job=job.id, deleg=delegation_id)
    reply = client.request(method, target, b"x" if method in ("PUT", "POST") else None)
    assert (reply.status, reply.reason) == (403, "Operation is not allowed")
    assert reply.headers["content-type"] == "text/plain"
    assert reply.body == f"{operation} operation is not allowed for this user".encode()
    assert set(arex.OPERATIONS) >= ce.denied


# ---------------------------------------------------------------------------
# HTTP plumbing, faults and recording
# ---------------------------------------------------------------------------


def test_faults(ce: FakeARex, client: Client) -> None:
    ce.fault("GET", r"/jobs$", status=503, times=2)
    ce.fault("POST", "action=status", status=500, reason="Oops", body=b"b", headers={"X-A": "1"})
    assert client.request("GET", "info").status == 200  # does not match
    for _ in range(2):
        reply = client.request("GET", "jobs")
        assert (reply.status, reply.reason) == (503, "Service Unavailable")
    assert client.request("GET", "jobs").status == 200
    reply = client.action("status", "x")
    assert (reply.status, reply.reason, reply.body, reply.headers["x-a"]) == (
        500,
        "Oops",
        b"b",
        "1",
    )
    ce.fault(status=599)
    assert client.request("GET", "jobs").status == 599
    ce.fault(path_pattern="jobs", status=None, delay=0.05)
    started = time.monotonic()
    assert client.request("GET", "jobs").status == 200
    assert time.monotonic() - started >= 0.05
    assert ce.faults == []


def test_dropped_connection_then_retry(ce: FakeARex, client: Client) -> None:
    ce.fault("POST", "action=status", drop=True)
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        client.action("status", "x")
    client.connection.close()
    assert client.action("status", "x").status == 201
    assert [request.query.get("action") for request in ce.requests] == ["status", "status"]


def test_recording(ce: FakeARex, client: Client) -> None:
    client.request("POST", "/arex/rest/1.1/jobs?action=status&x=%2F", b"<jobs/>", {"X-Y": "z"})
    (request,) = ce.requests
    assert (request.method, request.path, request.query) == (
        "POST",
        "/arex/rest/1.1/jobs",
        {"action": "status", "x": "/"},
    )
    assert (request.body, request.identity, request.target) == (
        b"<jobs/>",
        ALICE,
        "/arex/rest/1.1/jobs?action=status&x=%2F",
    )
    assert request.header("x-y") == "z" and request.header("nope") is None
    ce.clear()
    assert ce.requests == []


def test_chunked_request_body(ce: FakeARex, client: Client) -> None:
    job = ce.add_job(ALICE)
    chunks = iter([b"abc", b"defg"])
    client.connection.request(
        "PUT",
        f"/arex/rest/1.1/jobs/{job.id}/session/c",
        body=chunks,
        headers={"Authorization": "Bearer alice-token", "Transfer-Encoding": "chunked"},
        encode_chunked=True,
    )
    response = client.connection.getresponse()
    response.read()
    assert response.status == 200
    assert (job.session / "c").read_bytes() == b"abcdefg"
    assert client.request("GET", "jobs").status == 200  # the connection is still in step


def test_expect_continue(ce: FakeARex) -> None:
    job = ce.add_job(ALICE)
    raw = socket.create_connection((ce.host, ce.port), timeout=5)
    raw.sendall(
        f"PUT /arex/rest/1.1/jobs/{job.id}/session/e HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Bearer alice-token\r\nContent-Length: 2\r\n"
        "Expect: 100-continue\r\n\r\n".encode()
    )
    assert raw.recv(100).startswith(b"HTTP/1.1 100 Continue")
    raw.sendall(b"ok")
    assert raw.recv(1000).startswith(b"HTTP/1.1 200 OK")
    raw.close()
    assert (job.session / "e").read_bytes() == b"ok"


def test_malformed_request_closes_the_connection(ce: FakeARex) -> None:
    raw = socket.create_connection((ce.host, ce.port), timeout=5)
    raw.sendall(b"GET /arex/rest HTTP/1.1\r\nHost: x\r\nContent-Length: many\r\n\r\n")
    assert raw.recv(100) == b""
    raw.close()
    assert ce.requests == []


def test_stop_hangs_up_on_open_connections(tmp_path: Path) -> None:
    ce = FakeARex(tmp_path, tokens=TOKENS).start()
    client = Client(ce)
    assert client.request("GET", "/arex/rest").status == 200
    stopper = threading.Thread(target=ce.stop)
    stopper.start()
    stopper.join(10)
    assert not stopper.is_alive()
    client.close()


def test_rendering_rules() -> None:
    node = arex._Node("root")
    assert arex._render_json(node, (), True) == ""
    assert arex._render_json(node, ("a",), True) == '{"a":[]}'
    assert arex._render_json(node, ("a",), False) == "{}"
    leaf = node.add("leaf", "v", {"dropped": "1"})
    node.add("leaf", "w")
    assert arex._render_json(node, (), True) == '{"leaf":["v","w"]}'
    assert arex._render_json(leaf, (), True) == '"v"'
    assert arex._render_xml(node) == '<root><leaf dropped="1">v</leaf><leaf>w</leaf></root>'
    assert (
        arex._render_html(arex._Node("x", "<y>"))
        == "<HTML><HEAD>x</HEAD><BODY>&lt;y&gt;</BODY></HTML>"
    )
    assert arex._merge([(5, 7), (0, 2), (1, 4)]) == [(0, 4), (5, 7)]
    assert arex._content_range("bytes 3-4/*", 2) == (3, 5)
    assert arex._top_level_groups('(a "(" b)(c)') == ['a "(" b', "c"]
