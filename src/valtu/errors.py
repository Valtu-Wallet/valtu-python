"""Errors raised by the Valtu SDK."""

from __future__ import annotations

from typing import Optional


class ValtuError(Exception):
    """A non-2xx answer from the API. ``code`` is stable; the message is for people."""

    def __init__(self, status: int, code: str, message: str, request_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        #: The API's request id (x-request-id), useful when contacting support.
        self.request_id = request_id

    def __repr__(self) -> str:
        return f"ValtuError(status={self.status}, code={self.code!r}, message={self.message!r})"


class WebhookVerificationError(Exception):
    """The webhook's signature, age or body didn't check out: answer 400 and drop it."""


class AttestationError(Exception):
    """An attestation document failed verification."""
