"""Request signing. Every call carries an ECDSA P-256 signature over

    METHOD \\n path?query \\n timestamp_ms \\n nonce \\n hex(sha256(body))

sent as X-Stamp, with X-Valtu-Timestamp and a single-use X-Valtu-Nonce. Valtu stores only
your public key, so it can't forge requests, and nobody in between can change or replay them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_request(method: str, path_and_query: str, timestamp_ms: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([method.upper(), path_and_query, timestamp_ms, nonce, hashlib.sha256(body).hexdigest()]).encode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _compressed(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()


class RequestSigner:
    """Signs requests with an API private key (32 bytes, hex)."""

    def __init__(self, private_key_hex: str) -> None:
        hex_key = private_key_hex.strip()
        if hex_key.lower().startswith("0x"):
            hex_key = hex_key[2:]
        try:
            raw = bytes.fromhex(hex_key)
        except ValueError:
            raise ValueError("the API private key must be hex") from None
        if len(raw) != 32:
            raise ValueError("the API private key must be 32 bytes (64 hex characters)")
        self._key = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
        #: Compressed public key (hex), as shown next to the key in the dashboard.
        self.public_key = _compressed(self._key.public_key())

    def headers(self, method: str, path_and_query: str, body: bytes) -> Dict[str, str]:
        """Headers for one request. Call once per attempt: nonces are single-use."""
        timestamp = str(int(time.time() * 1000))
        nonce = _b64url(os.urandom(18))
        signature = self._key.sign(canonical_request(method, path_and_query, timestamp, nonce, body), ec.ECDSA(hashes.SHA256())).hex()
        stamp = _b64url(json.dumps({"publicKey": self.public_key, "scheme": "SIGNATURE_SCHEME_P256", "signature": signature}, separators=(",", ":")).encode())
        return {"x-valtu-timestamp": timestamp, "x-valtu-nonce": nonce, "x-stamp": stamp}


def generate_api_key() -> Tuple[str, str]:
    """A new API key pair ``(private_key_hex, public_key_hex)``. Register the public key in the
    dashboard; keep the private key in your secret manager."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_numbers().private_value.to_bytes(32, "big").hex(), _compressed(key.public_key())
