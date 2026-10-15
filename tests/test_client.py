import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from valtu import Valtu, ValtuError, canonical_request, deposit_address, generate_api_key


class FakeApi(BaseHTTPRequestHandler):
    """Checks every request's signature the way the API does, then answers from ``routes``."""

    routes: dict = {}
    calls: list = []

    def log_message(self, *a):
        pass

    def _handle(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        stamp = json.loads(base64.urlsafe_b64decode(self.headers["x-stamp"] + "=="))
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(stamp["publicKey"]))
        msg = canonical_request(self.command, self.path, self.headers["x-valtu-timestamp"], self.headers["x-valtu-nonce"], raw)
        key.verify(bytes.fromhex(stamp["signature"]), msg, ec.ECDSA(hashes.SHA256()))
        self.calls.append((self.command, self.path, json.loads(raw) if raw else None, self.headers["x-valtu-nonce"]))
        answers = self.routes[(self.command, self.path.split("?")[0])]
        status, body, headers = answers.pop(0) if len(answers) > 1 else answers[0]
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    do_GET = do_POST = _handle


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeApi.calls.clear()
        FakeApi.routes = {}
        self.valtu = Valtu(generate_api_key()[0], base_url=self.base + "/v1/", max_retries=2)

    def test_snake_case_in_camel_case_out(self):
        FakeApi.routes[("POST", "/v1/transfers")] = [(200, {"transfer": {"id": "t_1", "status": "QUEUED"}}, {})]
        t = self.valtu.transfers.create(wallet_id="w_1", asset="USDT-TRC20", amount=25500000, to="T1", external_id="p-1", fee_level="fast")
        self.assertEqual(t["id"], "t_1")
        self.assertEqual(FakeApi.calls[0][2], {"walletId": "w_1", "asset": "USDT-TRC20", "amount": "25500000", "to": "T1", "externalId": "p-1", "feeLevel": "fast"})

    def test_query_and_pagination(self):
        FakeApi.routes[("GET", "/v1/wallets")] = [
            (200, {"wallets": [{"id": "a"}, {"id": "b"}], "nextCursor": "c2"}, {}),
            (200, {"wallets": [{"id": "c"}], "nextCursor": None}, {}),
        ]
        ids = [w["id"] for w in self.valtu.wallets.iterate(external_id="cus 42/ü", limit=2)]
        self.assertEqual(ids, ["a", "b", "c"])
        self.assertEqual(FakeApi.calls[0][1], "/v1/wallets?externalId=cus+42%2F%C3%BC&limit=2")
        self.assertEqual(FakeApi.calls[1][1], "/v1/wallets?externalId=cus+42%2F%C3%BC&limit=2&cursor=c2")

    def test_retries_reads_and_idempotent_writes(self):
        FakeApi.routes[("GET", "/v1/workspace")] = [(503, {}, {"retry-after": "0"}), (429, {}, {"retry-after": "0"}), (200, {"workspace": {"id": "ws"}}, {})]
        self.assertEqual(self.valtu.workspace(), {"id": "ws"})
        self.assertEqual(len(FakeApi.calls), 3)
        self.assertEqual(len({c[3] for c in FakeApi.calls}), 3, "each attempt has a fresh nonce")

    def test_no_retry_without_external_id(self):
        FakeApi.routes[("POST", "/v1/transfers")] = [(503, {"code": "UNAVAILABLE", "message": "busy"}, {"retry-after": "0"}), (200, {"transfer": {}}, {})]
        with self.assertRaises(ValtuError) as e:
            self.valtu.transfers.create(wallet_id="w", asset="BTC", amount="1", to="bc1")
        self.assertEqual((e.exception.status, e.exception.code), (503, "UNAVAILABLE"))
        self.assertEqual(len(FakeApi.calls), 1)

    def test_errors(self):
        FakeApi.routes[("GET", "/v1/transfers/t%2F1")] = [(404, {"code": "NOT_FOUND", "message": "no such transfer"}, {"x-request-id": "req_1"})]
        with self.assertRaises(ValtuError) as e:
            self.valtu.transfers.get("t/1")
        self.assertEqual((e.exception.status, e.exception.code, e.exception.message, e.exception.request_id), (404, "NOT_FOUND", "no such transfer", "req_1"))

    def test_network_error(self):
        v = Valtu(generate_api_key()[0], base_url="http://127.0.0.1:9", max_retries=0)
        with self.assertRaises(ValtuError) as e:
            v.networks()
        self.assertEqual(e.exception.code, "NETWORK_ERROR")

    def test_batch_needs_external_ids(self):
        with self.assertRaises(ValueError):
            self.valtu.transfers.create_batch([{"wallet_id": "w", "asset": "BTC", "amount": "1", "to": "x"}])

    def test_from_env(self):
        priv, pub = generate_api_key()
        v = Valtu.from_env({"VALTU_PRIVATE_KEY": priv, "VALTU_BASE_URL": self.base})
        self.assertEqual((v.public_key, v.base_url), (pub, self.base))
        with self.assertRaises(ValueError):
            Valtu.from_env({})

    def test_deposit_address(self):
        w = {"addresses": [{"address": "0xabc", "networks": ["ethereum", "bsc"]}, {"address": "T1", "networks": ["tron"]}]}
        self.assertEqual(deposit_address(w, "bsc"), "0xabc")
        self.assertEqual(deposit_address(w, "tron"), "T1")
        self.assertIsNone(deposit_address(w, "bitcoin"))


if __name__ == "__main__":
    unittest.main()
