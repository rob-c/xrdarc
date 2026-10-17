"""Minting VOMS attribute certificates for the tests, ported from xrdclient's tests.

A VOMS AC is an RFC 5755 attribute certificate whose attributes carry FQANs
under ``policyAuthority`` ``<vo>://<host>:<port>``. ``xrdarc.proxy`` only
*decodes* them (through ``xrdclient.crypto.inspect_voms``), so the signature
here is real but nothing checks it against a VOMS server certificate.
"""

from __future__ import annotations

import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
VOMS_FQAN = "1.3.6.1.4.1.8005.100.100.4"
VOMS_CERTS = "1.3.6.1.4.1.8005.100.100.10"
NO_REV_AVAIL = "2.5.29.56"


def _length(count: int) -> bytes:
    if count < 0x80:
        return bytes([count])
    body = count.to_bytes((count.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    """One DER tag-length-value."""
    return bytes([tag]) + _length(len(value)) + value


def integer(value: int) -> bytes:
    width = (value.bit_length() + 8) // 8 or 1
    return tlv(0x02, value.to_bytes(width, "big", signed=True))


def oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def sequence(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def setof(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(parts))


def bitstring(data: bytes) -> bytes:
    return tlv(0x03, b"\x00" + data)


def gentime(when: float) -> bytes:
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def _extension(key: str, value: bytes) -> bytes:
    return sequence(oid(key), tlv(0x04, value))


def _general_names(name_der: bytes) -> bytes:
    return sequence(tlv(0xA4, name_der))


def _der_name(name: x509.Name) -> bytes:
    return name.public_bytes()


def make_ac(
    holder: x509.Certificate,
    voms_cert: x509.Certificate,
    voms_key: rsa.RSAPrivateKey,
    *,
    vo: str = "atlas",
    uri: str = "voms.example:15000",
    fqans: tuple[str, ...] = ("/atlas/Role=production/Capability=NULL",),
    lifetime: float = 3600.0,
) -> bytes:
    """A DER VOMS AC for ``holder`` (its issuer and serial), signed by ``voms_key``."""
    now = time.time()
    algorithm = sequence(oid(SHA256_WITH_RSA), tlv(0x05, b""))
    values = sequence(*(tlv(0x04, f.encode()) for f in fqans))
    syntax = sequence(tlv(0xA0, tlv(0x86, f"{vo}://{uri}".encode())), values)
    voms_der = voms_cert.public_bytes(serialization.Encoding.DER)
    extensions = sequence(
        _extension(VOMS_CERTS, sequence(sequence(voms_der))),
        _extension(NO_REV_AVAIL, tlv(0x05, b"")),
    )
    tbs = sequence(
        integer(1),
        sequence(
            tlv(0xA0, _general_names(_der_name(holder.issuer)) + integer(holder.serial_number))
        ),
        tlv(0xA0, _general_names(_der_name(voms_cert.subject))),
        algorithm,
        integer(55),
        sequence(gentime(now - 300), gentime(now + lifetime)),
        sequence(sequence(oid(VOMS_FQAN), setof(syntax))),
        extensions,
    )
    signature = voms_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    return sequence(tbs, algorithm, bitstring(signature))
