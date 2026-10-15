import base64
import hashlib
import hmac
import json
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from valtu import EventDeduper, WebhookVerificationError, construct_event, verify_webhook, verify_webhook_ed25519

SECRET = "whsec_test"
BODY = json.dumps({"id": "evt_1", "type": "deposit.confirmed", "workspaceId": "ws_1", "data": {"note": "naïve ✓"}}, ensure_ascii=False).encode()


def hmac_header(body: bytes, t: int) -> str:
    return f"t={t},v1=" + hmac.new(SECRET.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()


class WebhooksTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def ed_header(self, body: bytes, t: int) -> str:
        sig = self.key.sign(f"{t}.".encode() + body)
        return f"t={t},v1=" + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def test_hmac(self):
        t = int(time.time())
        self.assertTrue(verify_webhook(BODY, hmac_header(BODY, t), SECRET))
        self.assertTrue(verify_webhook(BODY.decode(), hmac_header(BODY, t), SECRET))
        self.assertFalse(verify_webhook(BODY + b" ", hmac_header(BODY, t), SECRET))
        self.assertFalse(verify_webhook(BODY, hmac_header(BODY, t), "other"))
        self.assertFalse(verify_webhook(BODY, hmac_header(BODY, t - 301), SECRET))
        self.assertFalse(verify_webhook(BODY, None, SECRET))
        self.assertFalse(verify_webhook(BODY, "garbage", SECRET))

    def test_ed25519(self):
        t = int(time.time())
        self.assertTrue(verify_webhook_ed25519(BODY, self.ed_header(BODY, t), self.pub))
        self.assertTrue(verify_webhook_ed25519(BODY, self.ed_header(BODY, t), self.pem))
        self.assertFalse(verify_webhook_ed25519(BODY.replace(b"evt_1", b"evt_2"), self.ed_header(BODY, t), self.pub))
        self.assertFalse(verify_webhook_ed25519(BODY, self.ed_header(BODY, t + 400), self.pub))
        self.assertFalse(verify_webhook_ed25519(BODY, self.ed_header(BODY, t), "not-a-key"))

    def test_construct_event(self):
        t = int(time.time())
        ev = construct_event(BODY, {"X-Valtu-Signature-Ed25519": self.ed_header(BODY, t)}, public_key=self.pub)
        self.assertEqual(ev["data"]["note"], "naïve ✓")
        ev = construct_event(BODY, {"x-valtu-signature": hmac_header(BODY, t)}, secret=SECRET)
        self.assertEqual(ev["id"], "evt_1")
        with self.assertRaises(WebhookVerificationError):
            construct_event(BODY, {"x-valtu-signature": hmac_header(BODY, t)}, public_key=self.pub)
        with self.assertRaises(WebhookVerificationError):
            construct_event(b"{}", {"x-valtu-signature": hmac_header(b"{}", t)}, secret=SECRET)

    def test_deduper(self):
        d = EventDeduper(max_ids=2)
        self.assertTrue(d.first("a"))
        self.assertFalse(d.first("a"))
        d.first("b")
        d.first("c")
        self.assertTrue(d.first("a"))


if __name__ == "__main__":
    unittest.main()
