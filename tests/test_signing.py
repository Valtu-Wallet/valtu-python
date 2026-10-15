import base64
import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from valtu import RequestSigner, canonical_request, generate_api_key


def decode_stamp(stamp: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(stamp + "=" * (-len(stamp) % 4)))


class SigningTest(unittest.TestCase):
    def test_canonical_request(self):
        self.assertEqual(
            canonical_request("get", "/v1/wallets?limit=5", "1700000000000", "abc", b""),
            b"GET\n/v1/wallets?limit=5\n1700000000000\nabc\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_headers_verify(self):
        priv, pub = generate_api_key()
        signer = RequestSigner("0x" + priv.upper())
        self.assertEqual(signer.public_key, pub)
        body = b'{"amount":"1"}'
        h = signer.headers("POST", "/v1/transfers", body)
        self.assertRegex(h["x-valtu-nonce"], r"^[A-Za-z0-9_-]{16,64}$")
        self.assertRegex(h["x-valtu-timestamp"], r"^\d{13}$")
        stamp = decode_stamp(h["x-stamp"])
        self.assertEqual(stamp["scheme"], "SIGNATURE_SCHEME_P256")
        self.assertEqual(stamp["publicKey"], pub)
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub))
        msg = canonical_request("POST", "/v1/transfers", h["x-valtu-timestamp"], h["x-valtu-nonce"], body)
        key.verify(bytes.fromhex(stamp["signature"]), msg, ec.ECDSA(hashes.SHA256()))
        self.assertNotEqual(h["x-valtu-nonce"], signer.headers("POST", "/v1/transfers", body)["x-valtu-nonce"])

    def test_known_public_key(self):
        # Private key 1 → the curve's generator point.
        self.assertEqual(RequestSigner("00" * 31 + "01").public_key, "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")

    def test_bad_keys(self):
        for bad in ["", "zz" * 32, "ab" * 31]:
            with self.assertRaises(ValueError):
                RequestSigner(bad)


if __name__ == "__main__":
    unittest.main()
