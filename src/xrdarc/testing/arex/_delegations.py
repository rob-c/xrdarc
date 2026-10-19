"""``/rest/<version>/delegations``: X.509 and token delegation, as A-REX takes them.

X.509 delegation is the one place a client signs something for the CE:
``POST delegations?action=new`` hands back a PKCS#10 request with an empty
subject for a key the CE holds, and the client ``PUT``\\ s back a proxy
certificate for that key followed by the chain that proves it. The fake
checks what A-REX checks - the certificate is for *its* key and is signed by
the next certificate up - without making a trust decision; a test that
needs more reads :attr:`FakeDelegation.chain`. All delegations share one key
(:attr:`FakeARex.delegation_key`, a frozen test key so no key is generated
per test).

Token delegation (REST 1.1, ``type=jwt``) stores the ``X-Token-Delegation``
header verbatim.

Ownership is the rule everything else follows: a delegation is visible only
to the identity that created it, and somebody else's id behaves exactly
like an id that was never issued (404, or the same 500 a bad upload gets),
so no response reveals that another user's delegation exists. A delegation
that a job names cannot be deleted while the job exists - the lock A-REX
keeps - which is what a client's "clean the job, then the delegation" order
is tested against. Start reading at :meth:`_delegations_endpoint`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from xrdsec.testing.https import Response

from ._base import _ARexBase
from ._model import FakeDelegation, _new_id
from ._render import _Node
from ._wire import _Ctx, _fault

#: A delegation action's handler: (context, the caller's delegation or ``None``, the id).
_Action = Callable[["_DelegationEndpoints", _Ctx, FakeDelegation | None, str], Response]


class _DelegationEndpoints(_ARexBase):
    """``/delegations`` and ``/delegations/<id>``."""

    def _delegations_endpoint(self, ctx: _Ctx) -> Response:
        """``/delegations``: list, or ``action=new`` - an X.509 slot (a CSR back) or a 1.1 token."""
        delegation_id = ctx.token()
        if delegation_id:
            return self._delegation(ctx, delegation_id)
        if ctx.method in ("GET", "HEAD"):
            return self._list_delegations(ctx)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        if ctx.query.get("action", "") != "new":
            return _fault(501, "Action not implemented")
        # Making a delegation is part of submitting, so it needs the right to
        # create jobs; it is checked after the request is known to be well formed.
        denied = self._denied("JobCreate")
        if denied is not None:
            return denied
        # ``ctx.param`` is "" through REST 1.0, which has no ``type``: a 1.0
        # client always gets an X.509 slot, whatever it sent.
        kind = ctx.param("type")
        if kind in ("", "x509"):
            return self._new_x509(ctx)
        if kind != "jwt":
            return _fault(501, "Unknown delegation type specified")
        return self._new_token(ctx)

    def _new_x509(self, ctx: _Ctx) -> Response:
        """A new X.509 slot: 201, its URL in ``Location`` and a CSR for the CE's key."""
        delegation = self._new_delegation(ctx.identity, "x509")
        # ``Location`` is where the signed chain is ``PUT``; clients take the
        # delegation id from its last segment, so it is the request path plus
        # the id, never an absolute URL that a proxy in front could rewrite.
        headers = {
            "Content-Type": "application/x-pem-file",
            "Location": f"{ctx.path}/{delegation.id}",
        }
        return Response(201, self._csr(delegation), headers, "Created")

    def _new_token(self, ctx: _Ctx) -> Response:
        """A new token delegation (1.1): the ``X-Token-Delegation`` header, kept verbatim."""
        token = ctx.header("X-Token-Delegation")
        if token is None:
            return _fault(501, "Missing X-Token-Delegation header in delegation request")
        delegation = self._new_delegation(ctx.identity, "jwt")
        # Kept verbatim: the fake does not look inside it.
        delegation.token = token
        return Response(201, b"", {"Location": f"{ctx.path}/{delegation.id}"}, "Created")

    def _new_delegation(self, owner: str, kind: str, delegation_id: str = "") -> FakeDelegation:
        """A new slot for ``owner``; a fresh id unless one is given (renewing an unknown id).

        Ids are unique among all users' delegations, not per user: the
        ``Location`` URL names a slot without naming its owner, so one id
        must mean one slot whoever asks.
        """
        delegation = FakeDelegation(delegation_id or _new_id(self.delegations), owner, kind)
        self.delegations[delegation.id] = delegation
        return delegation

    def _csr(self, delegation: FakeDelegation) -> bytes:
        """A PKCS#10 request with an empty subject, SHA-256, for the delegation key.

        The empty subject is A-REX's: a client must not build the proxy's
        name from the request (RFC 3820 names it after the issuer). Kept on
        the slot, so a test can check which request a chain answers.
        """
        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(self.delegation_key, hashes.SHA256())
        )
        delegation.csr = request.public_bytes(serialization.Encoding.PEM)
        return delegation.csr

    def _list_delegations(self, ctx: _Ctx) -> Response:
        """The caller's delegations, optionally of one ``type`` (1.1).

        Only the caller's: the listing is one more place another user's
        delegations must not show through. Through 1.0 ``type`` reads as ""
        and every delegation is listed.
        """
        denied = self._denied("JobInfo")
        if denied is not None:
            return denied
        wanted = ctx.param("type")
        root = _Node("delegations")
        for delegation in self.delegations.values():
            if delegation.owner == ctx.identity and wanted in ("", delegation.type):
                node = root.add("delegation")
                node.add("id", delegation.id)
                node.add("type", delegation.type)
        return self._render(ctx, root, ("delegation",))

    def _delegation(self, ctx: _Ctx, delegation_id: str) -> Response:
        """``delegations/<id>``: ``PUT`` a signed chain, or ``POST`` ``action=get|renew|delete``."""
        if ctx.rest:
            return _fault(404, "Not Found")
        found = self.delegations.get(delegation_id)
        delegation = found if found is not None and found.owner == ctx.identity else None
        if ctx.method == "PUT":
            return self._delegation_put(ctx, delegation)
        if ctx.method != "POST":
            return _fault(501, "Not Implemented")
        action = self._DELEGATION_ACTIONS.get(ctx.query.get("action", ""))
        if action is None:
            return _fault(501, "Action not implemented")
        operation, handler = action
        denied = self._denied(operation)
        if denied is not None:
            return denied
        # Somebody else's delegation cannot be had - not even renewed under its id.
        mine = delegation_id if delegation is not None or found is None else ""
        return handler(self, ctx, delegation, mine)

    def _delegation_put(self, ctx: _Ctx, delegation: FakeDelegation | None) -> Response:
        """Accept the uploaded chain if it certifies the delegation key (see :meth:`_accept`).

        A later upload replaces the chain - that is how a client renews a
        proxy behind running jobs - and :attr:`FakeDelegation.uploads`
        counts them, so a test can tell a renewal from a no-op.
        """
        denied = self._denied("JobCreate")
        if denied is not None:
            return denied
        if not ctx.body:
            return _fault(500, "Missing payload")
        # A slot that is not the caller's fails exactly like a bad chain, so
        # a PUT reveals nothing about other users' delegations.
        chain = self._accept(delegation, ctx.body)
        if delegation is None or chain is None:
            return _fault(500, "Failed accepting delegation")
        delegation.chain, delegation.chain_pem = chain, ctx.body
        delegation.uploads += 1
        return Response(200, reason="OK")

    def _accept(
        self, delegation: FakeDelegation | None, body: bytes
    ) -> list[x509.Certificate] | None:
        """The uploaded chain if A-REX would take it: our key, signed by the next one."""
        # A token slot never takes a certificate chain: the types do not mix.
        if delegation is None or delegation.type != "x509":
            return None
        # Garbage, or PEM with no certificate in it, is refused like a bad chain.
        try:
            chain = x509.load_pem_x509_certificates(body)
        except ValueError:
            return None
        return chain if self._certifies_key(chain) and _linked(chain) else None

    def _certifies_key(self, chain: list[x509.Certificate]) -> bool:
        """The first certificate is for the delegation key: the one the CSR was made with.

        The whole SubjectPublicKeyInfo is compared, not a modulus: a chain
        for any other key - a client that signed its own key, or an old CSR's
        - would leave the CE holding a certificate it has no key for.
        """
        spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        mine = self.delegation_key.public_key().public_bytes(*spki)
        return chain[0].public_key().public_bytes(*spki) == mine

    def _delegation_get(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> Response:
        """``action=get``: the chain as uploaded, or the token.

        Labelled ``application/x-pem-file`` for a token too, as the one type
        this endpoint answers with; a client must not decide what it got
        from the ``Content-Type``.
        """
        if delegation is None:
            return _fault(404, "No delegation found")
        # The chain as uploaded, never the key (the CE keeps that to itself).
        body = delegation.token.encode() if delegation.type == "jwt" else delegation.chain_pem
        return Response(200, body, {"Content-Type": "application/x-pem-file"}, "OK")

    def _delegation_renew(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> Response:
        """``action=renew``: a fresh CSR for the slot."""
        if not delegation_id:
            return _fault(500, "Failed generating delegation request")
        if delegation is None:
            # A-REX makes a slot for an id it does not know: renewing is how
            # a client re-creates a delegation that expired and was purged.
            delegation = self._new_delegation(ctx.identity, "x509", delegation_id)
        delegation.renewals += 1
        pem = {"Content-Type": "application/x-pem-file"}
        return Response(201, self._csr(delegation), pem, "Created")

    def _delegation_delete(
        self, ctx: _Ctx, delegation: FakeDelegation | None, delegation_id: str
    ) -> Response:
        """``action=delete``: refused while a job uses the delegation, as A-REX locks it."""
        if delegation is None:
            return _fault(404, "No such delegation")
        if any(delegation.id in job.delegations for job in self.jobs.values()):
            return _fault(500, "Failed deleting delegation")  # locked by a job
        del self.delegations[delegation.id]
        return Response(202, reason="Accepted")

    #: ``action`` -> (operation class it needs, handler).
    _DELEGATION_ACTIONS: ClassVar[dict[str, tuple[str, _Action]]] = {
        "get": ("JobInfo", _delegation_get),
        "renew": ("JobCreate", _delegation_renew),
        "delete": ("JobDelete", _delegation_delete),
    }


def _linked(chain: list[x509.Certificate]) -> bool:
    """The delegated certificate is signed by the next one up (no trust decision beyond that).

    Only the first link is checked: it is the one the client made, and the
    rest of the chain is its existing proxy, which the CE judges when a job
    uses it, not here.
    """
    # A lone certificate has no issuer here to check against; whether it is
    # trusted is the same later judgement.
    if len(chain) < 2:
        return True
    try:
        chain[0].verify_directly_issued_by(chain[1])
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True
