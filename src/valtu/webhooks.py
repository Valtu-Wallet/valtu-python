"""Webhook verification. Each delivery is signed twice over ``"<t>.<raw body>"``:

    X-Valtu-Signature:         t=<unix s>,v1=<hex HMAC-SHA256(endpoint secret)>
    X-Valtu-Signature-Ed25519: t=<unix s>,v1=<base64url Ed25519 signature>

Check either one. The Ed25519 public key (dashboard → Webhooks) is not a secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections import OrderedDict
from typing import Any, Dict, Mapping, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import WebhookVerificationError

SIGNATURE_HEADER = "x-valtu-signature"
ED25519_SIGNATURE_HEADER = "x-valtu-signature-ed25519"


def _parse(header: Optional[str]) -> Optional[Dict[str, str]]:
    parts: Dict[str, str] = {}
    for p in (header or "").split(","):
        k, _, v = p.partition("=")
        parts[k.strip()] = v.strip()
    return parts if parts.get("t") and parts.get("v1") else None


def _fresh(t: str, tolerance: int) -> bool:
    try:
        return abs(time.time() - float(t)) <= tolerance
    except ValueError:
        return False


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_webhook(raw_body: Union[str, bytes], signature_header: Optional[str], secret: str, tolerance_sec: int = 300) -> bool:
    """HMAC check of X-Valtu-Signature. Returns False rather than raising."""
    parts = _parse(signature_header)
    if not parts or not _fresh(parts["t"], tolerance_sec):
        return False
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    expected = hmac.new(secret.encode(), parts["t"].encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])


def verify_webhook_ed25519(raw_body: Union[str, bytes], signature_header: Optional[str], public_key: str, tolerance_sec: int = 300) -> bool:
    """Ed25519 check of X-Valtu-Signature-Ed25519. Returns False rather than raising."""
    parts = _parse(signature_header)
    if not parts or not _fresh(parts["t"], tolerance_sec):
        return False
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    try:
        if "BEGIN" in public_key:
            key = serialization.load_pem_public_key(public_key.encode())
            if not isinstance(key, Ed25519PublicKey):
                return False
        else:
            key = Ed25519PublicKey.from_public_bytes(_b64url_decode(public_key.strip()))
        key.verify(_b64url_decode(parts["v1"]), parts["t"].encode() + b"." + body)
        return True
    except (InvalidSignature, ValueError):
        return False


def _header(headers: Mapping[str, Any], name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == name:
            return v[0] if isinstance(v, (list, tuple)) else v
    return None


def construct_event(
    raw_body: Union[str, bytes],
    headers: Mapping[str, Any],
    *,
    public_key: Optional[str] = None,
    secret: Optional[str] = None,
    tolerance_sec: int = 300,
) -> Dict[str, Any]:
    """Verify a delivery and return the parsed event. Pass the raw body exactly as received
    (before any JSON parsing). Raises WebhookVerificationError.

        event = construct_event(request.get_data(), request.headers, public_key=os.environ["VALTU_WEBHOOK_PUBLIC_KEY"])
    """
    if not public_key and not secret:
        raise ValueError("give the webhook public_key or the endpoint secret")
    ok = (public_key is not None and verify_webhook_ed25519(raw_body, _header(headers, ED25519_SIGNATURE_HEADER), public_key, tolerance_sec)) or (
        secret is not None and verify_webhook(raw_body, _header(headers, SIGNATURE_HEADER), secret, tolerance_sec)
    )
    if not ok:
        raise WebhookVerificationError("webhook signature is missing, wrong or too old")
    try:
        event = json.loads(raw_body)
    except ValueError:
        raise WebhookVerificationError("webhook body is not JSON") from None
    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("type"), str):
        raise WebhookVerificationError("webhook body is not an event")
    return event


class EventDeduper:
    """Remembers event ids it has seen (in memory, bounded) so a redelivery is skipped. For more
    than one server process, de-duplicate in your database instead (a unique index on the id)."""

    def __init__(self, max_ids: int = 10_000) -> None:
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._max = max_ids

    def first(self, event_id: str) -> bool:
        """True the first time an id is seen."""
        if event_id in self._seen:
            return False
        self._seen[event_id] = None
        if len(self._seen) > self._max:
            self._seen.popitem(last=False)
        return True
