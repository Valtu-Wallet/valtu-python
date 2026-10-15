import base64
import json
import os
import unittest
from datetime import datetime, timezone

from valtu import AttestationError, verify_attestation

FIXTURE = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "attestation.json")))


class AttestationTest(unittest.TestCase):
    """A real document from production. Its certificates expire within hours, so checks run at the
    moment the document was made."""

    def doc(self, **kw):
        kw.setdefault("nonce", FIXTURE["nonce"])
        kw.setdefault("at", MADE_AT)
        return verify_attestation(kw.pop("document", FIXTURE["document"]), **kw)

    def test_verifies(self):
        r = self.doc(expected_pcr0=FIXTURE["pcr0"])
        self.assertEqual(r.pcrs[0], FIXTURE["pcr0"])
        self.assertEqual(r.statement["service"], "valtu-enclave")
        self.assertEqual(set(r.statement["keys"]), {"notary", "policy", "quorum", "signer"})
        hexdoc = base64.b64decode(FIXTURE["document"]).hex()
        self.assertEqual(self.doc(document=hexdoc).pcrs, r.pcrs)

    def test_rejects(self):
        with self.assertRaisesRegex(AttestationError, "nonce"):
            self.doc(nonce="00" * 32)
        with self.assertRaisesRegex(AttestationError, "PCR0"):
            self.doc(expected_pcr0="11" * 48)
        with self.assertRaisesRegex(AttestationError, "root"):
            self.doc(root_sha256="22" * 32)
        with self.assertRaisesRegex(AttestationError, "not valid"):
            self.doc(at=datetime(2020, 1, 1, tzinfo=timezone.utc))
        raw = bytearray(base64.b64decode(FIXTURE["document"]))
        raw[-10] ^= 1
        with self.assertRaises(AttestationError):
            self.doc(document=base64.b64encode(bytes(raw)).decode())
        with self.assertRaises(AttestationError):
            self.doc(document="!!not a document!!")


def _made_at() -> datetime:
    """The hypervisor's timestamp inside the document (COSE_Sign1 payload, CBOR)."""
    from valtu.attestation import _decode

    cose = _decode(base64.b64decode(FIXTURE["document"]))
    cose = getattr(cose, "value", cose)
    return datetime.fromtimestamp(_decode(cose[2])["timestamp"] / 1000, timezone.utc)


MADE_AT = _made_at()


if __name__ == "__main__":
    unittest.main()
