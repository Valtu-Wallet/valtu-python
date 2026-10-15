"""Verify that Valtu's signing enclave runs the published image, without trusting Valtu.

``GET /v1/attestation?nonce=<your random hex>`` returns attestation documents: COSE_Sign1
(ES384) signed by a certificate that chains up to the hardware vendor's root. Each carries
the image measurements (PCR0/1/2), your nonce (so it was made just now, for you) and the
enclave's statement of the public keys it holds. Compare PCR0 with the published release
measurements, and the keys with the published anchors (https://valtu.io/docs/security).

    nonce = secrets.token_hex(32)
    docs = valtu.attestation(nonce)["attestations"]
    result = verify_attestation(docs[0]["document"], nonce=nonce, expected_pcr0=PUBLISHED_PCR0)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .errors import AttestationError

#: SHA-256 fingerprint of the hardware vendor's enclave root certificate (AWS Nitro Enclaves G1),
#: as published at https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
ENCLAVE_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"


@dataclass
class VerifiedAttestation:
    module_id: str
    #: Milliseconds since the epoch, as stamped by the hypervisor.
    timestamp: int
    #: PCR index → hex. 0: the enclave image, 1: kernel and boot, 2: application.
    pcrs: Dict[int, str]
    #: The enclave's statement: ``{"v", "service", "role", "keys": {...}}``, or None.
    statement: Optional[Dict[str, Any]]


def verify_attestation(
    document: str,
    *,
    nonce: str,
    expected_pcr0: Optional[str] = None,
    at: Optional[datetime] = None,
    root_sha256: str = ENCLAVE_ROOT_SHA256,
) -> VerifiedAttestation:
    """Verify one attestation document (base64 or hex). Raises AttestationError when anything doesn't hold.

    ``nonce`` is the hex nonce you sent: without it a captured document could be replayed.
    """
    try:
        raw = bytes.fromhex(document) if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", document) else base64.b64decode(document)
    except (ValueError, binascii.Error):
        raise AttestationError("the document is neither hex nor base64") from None
    cose = _decode(raw)
    if isinstance(cose, _Tagged):
        cose = cose.value
    if not isinstance(cose, list) or len(cose) != 4:
        raise AttestationError("not a COSE_Sign1 document")
    protected, _unprotected, payload, signature = cose
    if not all(isinstance(x, bytes) for x in (protected, payload, signature)):
        raise AttestationError("malformed COSE_Sign1")
    header = _decode(protected)
    if not isinstance(header, dict) or header.get(1) != -35:
        raise AttestationError("unexpected signature algorithm (want ES384)")

    doc = _decode(payload)
    if not isinstance(doc, dict):
        raise AttestationError("malformed attestation payload")

    # Certificate chain: cabundle[0] is the root, then intermediates, then the document's certificate.
    bundle, leaf = doc.get("cabundle"), doc.get("certificate")
    if not isinstance(bundle, list) or not bundle or not isinstance(leaf, bytes):
        raise AttestationError("missing certificates")
    if hashlib.sha256(bundle[0]).hexdigest() != root_sha256.lower():
        raise AttestationError("the chain doesn't start at the published enclave root")
    try:
        chain = [x509.load_der_x509_certificate(der) for der in [*bundle, leaf]]
    except ValueError:
        raise AttestationError("a certificate in the chain can't be parsed") from None
    when = at or datetime.now(timezone.utc)
    for i, cert in enumerate(chain):
        not_before, not_after = _validity(cert)
        if not_before > when or not_after < when:
            raise AttestationError(f"certificate {i} is not valid at {when.isoformat()}")
        issuer = cert if i == 0 else chain[i - 1]
        try:
            pub = issuer.public_key()
            if not isinstance(pub, ec.EllipticCurvePublicKey) or cert.signature_hash_algorithm is None:
                raise AttestationError(f"certificate {i} doesn't use an ECDSA signature")
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        except InvalidSignature:
            raise AttestationError(f"certificate {i} isn't signed by its issuer") from None

    # The document's signature: COSE Sig_structure ["Signature1", protected, external_aad, payload], raw r||s.
    if len(signature) != 96:
        raise AttestationError("signature invalid")
    r, s = int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
    leaf_key = chain[-1].public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey):
        raise AttestationError("the document certificate isn't an ECDSA key")
    try:
        leaf_key.verify(encode_dss_signature(r, s), _sig_structure(protected, payload), ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise AttestationError("signature invalid") from None

    got_nonce = doc.get("nonce")
    want = nonce[2:] if nonce.lower().startswith("0x") else nonce
    if not isinstance(got_nonce, bytes) or got_nonce.hex() != want.lower():
        raise AttestationError("nonce doesn't match: not made for this request")

    pcrs = {int(k): bytes(v).hex() for k, v in (doc.get("pcrs") or {}).items()}
    if expected_pcr0 and pcrs.get(0) != expected_pcr0.lower():
        raise AttestationError(f"PCR0 {pcrs.get(0)} isn't the expected release")

    statement = None
    user_data = doc.get("user_data")
    if isinstance(user_data, bytes):
        try:
            statement = json.loads(user_data.decode())
        except ValueError:
            raise AttestationError("user_data is not the enclave's statement") from None
    return VerifiedAttestation(module_id=str(doc.get("module_id")), timestamp=int(doc.get("timestamp") or 0), pcrs=pcrs, statement=statement)


def _validity(cert: x509.Certificate) -> Tuple[datetime, datetime]:
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    return cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)


# ───── minimal CBOR (RFC 8949): what attestation documents use ─────


class _Tagged:
    def __init__(self, tag: int, value: Any) -> None:
        self.tag, self.value = tag, value


def _decode(buf: bytes) -> Any:
    pos = 0

    def length(info: int) -> int:
        nonlocal pos
        if info < 24:
            return info
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in sizes:
            raise AttestationError("unsupported CBOR length")
        n = sizes[info]
        if pos + n > len(buf):
            raise AttestationError("truncated CBOR")
        v = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
        return v

    def item() -> Any:
        nonlocal pos
        if pos >= len(buf):
            raise AttestationError("truncated CBOR")
        b = buf[pos]
        pos += 1
        major, info = b >> 5, b & 31
        if info == 31 and 2 <= major <= 5:
            # Indefinite length (the attestation payload is an indefinite-length map): items until 0xff.
            items: List[Any] = []
            while True:
                if pos >= len(buf):
                    raise AttestationError("truncated CBOR")
                if buf[pos] == 0xFF:
                    pos += 1
                    break
                items.append(item())
            if major == 2:
                return b"".join(items)
            if major == 3:
                return "".join(items)
            if major == 4:
                return items
            return {items[k]: items[k + 1] for k in range(0, len(items) - 1, 2)}
        if major == 0:
            return length(info)
        if major == 1:
            return -1 - length(info)
        if major in (2, 3):
            n = length(info)
            if pos + n > len(buf):
                raise AttestationError("truncated CBOR")
            v = buf[pos : pos + n]
            pos += n
            return bytes(v) if major == 2 else v.decode()
        if major == 4:
            return [item() for _ in range(length(info))]
        if major == 5:
            out: Dict[Any, Any] = {}
            for _ in range(length(info)):
                key = item()
                out[key] = item()
            return out
        if major == 6:
            tag = length(info)
            return _Tagged(tag, item())
        if major == 7:
            simple = {20: False, 21: True, 22: None}
            if info in simple:
                return simple[info]
            raise AttestationError("unsupported CBOR simple value")
        raise AttestationError("bad CBOR")

    value = item()
    if pos != len(buf):
        raise AttestationError("trailing bytes after CBOR")
    return value


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    return bytes([(major << 5) | 26]) + struct.pack(">I", n)


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    text = b"Signature1"
    return b"".join([_head(4, 4), _head(3, len(text)), text, _head(2, len(protected)), protected, _head(2, 0), _head(2, len(payload)), payload])
