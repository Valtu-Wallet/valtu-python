"""The Valtu API client. Every call is signed with your API key; reads and idempotent writes
(those with an ``external_id``) are retried safely on network errors and 429/502/503/504.

    from valtu import Valtu, deposit_address

    valtu = Valtu.from_env()                              # VALTU_PRIVATE_KEY or VALTU_KEY_FILE
    wallet = valtu.wallets.for_customer("cus_42")
    print(deposit_address(wallet, "tron"))

Responses are the API's JSON objects as dicts, with the API's field names (``walletId``,
``externalId``…). Keyword arguments are snake_case and sent in the API's camelCase.
"""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional

from .amounts import from_base_units, to_base_units
from .errors import ValtuError
from .signing import RequestSigner

__version__ = "0.1.0"
DEFAULT_BASE_URL = "https://valtu.io"
FINAL_TRANSFER_STATUSES = ("CONFIRMED", "FAILED", "REJECTED", "CANCELLED", "NEEDS_REVIEW")
_TRANSIENT = {429, 502, 503, 504}

JSON = Dict[str, Any]


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w[:1].upper() + w[1:] for w in rest)


def _body(fields: Mapping[str, Any]) -> JSON:
    """snake_case keyword arguments → the API's camelCase JSON (top level), dropping None."""
    return {_camel(k): v for k, v in fields.items() if v is not None}


def _query(q: Mapping[str, Any]) -> str:
    pairs = []
    for k, v in q.items():
        if v is None or v == "":
            continue
        if isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        elif isinstance(v, bool):
            v = "true" if v else "false"
        pairs.append((_camel(k), str(v)))
    s = urllib.parse.urlencode(pairs)
    return f"?{s}" if s else ""


class Valtu:
    """A client for one workspace's API key."""

    def __init__(self, private_key: str, *, base_url: Optional[str] = None, timeout: float = 30.0, max_retries: int = 2) -> None:
        if not private_key:
            raise ValueError("Valtu: private_key is required")
        base = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.base_url = base[:-3] if base.endswith("/v1") else base
        self._signer = RequestSigner(private_key)
        #: This key's public key (compressed, hex), as the dashboard shows it.
        self.public_key = self._signer.public_key
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self.wallets = _Wallets(self)
        self.transfers = _Transfers(self)
        self.deposits = _Deposits(self)
        self.assets = _Assets(self)
        self.checkouts = _Checkouts(self)
        self.webhooks = _Webhooks(self)
        self.contracts = _Contracts(self)
        self.messages = _Messages(self)
        self.events = _Events(self)

    @classmethod
    def from_key_file(cls, path: str, **opts: Any) -> "Valtu":
        """From the key file the dashboard downloaded (``valtu-<name>.json``)."""
        with open(path, encoding="utf-8") as f:
            key = json.load(f).get("privateKey")
        if not key:
            raise ValueError(f"{path} has no privateKey")
        return cls(key, **opts)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **opts: Any) -> "Valtu":
        """``VALTU_PRIVATE_KEY`` (or ``VALTU_KEY_FILE``) and optional ``VALTU_BASE_URL``."""
        env = os.environ if env is None else env
        opts.setdefault("base_url", env.get("VALTU_BASE_URL") or None)
        if env.get("VALTU_PRIVATE_KEY"):
            return cls(env["VALTU_PRIVATE_KEY"], **opts)
        if env.get("VALTU_KEY_FILE"):
            return cls.from_key_file(env["VALTU_KEY_FILE"], **opts)
        raise ValueError("set VALTU_PRIVATE_KEY or VALTU_KEY_FILE")

    # ───── top-level calls ─────

    def workspace(self) -> JSON:
        """The workspace this key belongs to (environment test or live, status)."""
        return self.request("GET", "/v1/workspace")["workspace"]

    def balances(self) -> List[JSON]:
        """Workspace totals per coin."""
        return self.request("GET", "/v1/balances")["balances"]

    def networks(self) -> List[JSON]:
        return self.request("GET", "/v1/networks")["networks"]

    def attestation(self, nonce: str) -> JSON:
        """Attestation documents made for ``nonce`` (8-64 random bytes, hex). Check them with
        ``verify_attestation``; don't take the statement on trust."""
        return self.request("GET", "/v1/attestation", query={"nonce": nonce})

    # ───── the signed request ─────

    def request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None, *, query: Optional[Mapping[str, Any]] = None, retry: bool = False) -> Any:
        """A signed call to any /v1 path. ``retry`` marks a POST as safe to repeat (GETs always are).
        Each attempt gets a fresh timestamp and nonce."""
        method = method.upper()
        path_and_query = path + _query(query or {})
        raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        retryable = method == "GET" or retry
        attempt = 0
        while True:
            headers = {**self._signer.headers(method, path_and_query, raw), "accept": "application/json", "user-agent": f"valtu-python/{__version__}"}
            if body is not None:
                headers["content-type"] = "application/json"
            req = urllib.request.Request(self.base_url + path_and_query, data=raw if body is not None else None, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as res:
                    text = res.read().decode()
                    return json.loads(text) if text else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                try:
                    data = json.loads(text) if text else {}
                except ValueError:
                    data = {}
                if e.code in _TRANSIENT and retryable and attempt < self._max_retries:
                    after = e.headers.get("retry-after")
                    time.sleep(min(float(after), 30.0) if after and after.replace(".", "", 1).isdigit() else _backoff(attempt))
                    attempt += 1
                    continue
                raise ValtuError(e.code, data.get("code", "HTTP_ERROR"), data.get("message", f"HTTP {e.code}"), e.headers.get("x-request-id")) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if retryable and attempt < self._max_retries:
                    time.sleep(_backoff(attempt))
                    attempt += 1
                    continue
                raise ValtuError(0, "NETWORK_ERROR", f"could not reach Valtu: {getattr(e, 'reason', e)}") from None


def _backoff(attempt: int) -> float:
    return min(8.0, 0.3 * 2**attempt) * (0.75 + random.random() * 0.5)


def _page(r: JSON, key: str) -> JSON:
    """One page as ``{"items": [...], "nextCursor": str | None}``, as wallet-kit returns it."""
    return {"items": r[key], "nextCursor": r.get("nextCursor")}


def _paginate(page: Callable[[Optional[str]], JSON]) -> Iterator[JSON]:
    cursor: Optional[str] = None
    while True:
        p = page(cursor)
        yield from p["items"]
        cursor = p.get("nextCursor")
        if not cursor:
            return


def deposit_address(wallet: Mapping[str, Any], chain: str) -> Optional[str]:
    """A wallet's address on one network ("tron", "ethereum", "bsc", "bitcoin"…). EVM networks
    share one address. None if the wallet has none."""
    for a in wallet.get("addresses", []):
        if chain in a.get("networks", []):
            return a["address"]
    return None


def _id(value: str) -> str:
    return urllib.parse.quote(value, safe="")


class _Wallets:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def create(self, *, name: str, type: str = "user", external_id: Optional[str] = None, **fields: Any) -> JSON:
        """Create a wallet. With ``external_id`` it's idempotent: the same id returns the existing wallet."""
        body = _body({"name": name, "type": type, "external_id": external_id, **fields})
        return self._c.request("POST", "/v1/wallets", body, retry=external_id is not None)["wallet"]

    def for_customer(self, customer_id: str, name: Optional[str] = None) -> JSON:
        """The ``user`` wallet for one of your customers, created on first use."""
        return self.create(name=name or f"Customer {customer_id}", type="user", external_id=customer_id)

    def get(self, wallet_id: str) -> JSON:
        return self._c.request("GET", f"/v1/wallets/{_id(wallet_id)}")["wallet"]

    def find_by_external_id(self, external_id: str) -> Optional[JSON]:
        items = self.list(external_id=external_id, limit=1)["items"]
        return items[0] if items else None

    def balances(self, wallet_id: str) -> JSON:
        """Live balances of every coin on every network the wallet has an address for (cached ~30 s)."""
        return self._c.request("GET", f"/v1/wallets/{_id(wallet_id)}/balances")

    def list(self, **query: Any) -> JSON:
        """One page: ``{"items": [...], "nextCursor": ...}``. Filters: type, external_id, cursor, limit…"""
        return _page(self._c.request("GET", "/v1/wallets", query=query), "wallets")

    def iterate(self, **query: Any) -> Iterator[JSON]:
        """Every wallet matching the query, page by page."""
        return _paginate(lambda cursor: self.list(**query, cursor=cursor))


class _Transfers:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def create(self, *, wallet_id: str, asset: str, amount: str, to: Optional[str] = None, external_id: Optional[str] = None, **fields: Any) -> JSON:
        """Ask for a payout. Your policies decide whether it needs approvals (PENDING_APPROVAL) or goes
        straight to signing (QUEUED). With ``external_id`` a retry returns the same transfer and never sends twice.
        ``amount`` is in base units: use ``valtu.assets.to_base_units(asset, "25.50")``."""
        body = _body({"wallet_id": wallet_id, "asset": asset, "amount": str(amount), "to": to, "external_id": external_id, **fields})
        return self._c.request("POST", "/v1/transfers", body, retry=external_id is not None)["transfer"]

    def preview(self, *, wallet_id: str, asset: str, amount: str, to: Optional[str] = None, **fields: Any) -> JSON:
        """What a payout would do, without creating it: network fee, USD value, policy outcome."""
        body = _body({"wallet_id": wallet_id, "asset": asset, "amount": str(amount), "to": to, **fields})
        return self._c.request("POST", "/v1/transfers/preview", body, retry=True)["preview"]

    def create_batch(self, transfers: List[Mapping[str, Any]]) -> JSON:
        """Up to 100 payouts in one call, each a dict of create()'s arguments with its own ``external_id``.
        Not atomic: check each result. Re-sending the same batch is safe."""
        if any(not t.get("external_id") for t in transfers):
            raise ValueError("every transfer in a batch needs an external_id")
        items = [_body({**t, "amount": str(t["amount"])}) for t in transfers]
        return self._c.request("POST", "/v1/transfers/batch", {"transfers": items}, retry=True)

    def get(self, transfer_id: str) -> JSON:
        return self._c.request("GET", f"/v1/transfers/{_id(transfer_id)}")["transfer"]

    def find_by_external_id(self, external_id: str) -> Optional[JSON]:
        items = self.list(external_id=external_id, limit=1)["items"]
        return items[0] if items else None

    def cancel(self, transfer_id: str) -> JSON:
        """Cancel before signing."""
        return self._c.request("POST", f"/v1/transfers/{_id(transfer_id)}/cancel", {})["transfer"]

    def list(self, **query: Any) -> JSON:
        return _page(self._c.request("GET", "/v1/transfers", query=query), "transfers")

    def iterate(self, **query: Any) -> Iterator[JSON]:
        return _paginate(lambda cursor: self.list(**query, cursor=cursor))

    def wait(self, transfer_id: str, *, until: tuple = FINAL_TRANSFER_STATUSES, timeout: float = 600.0, interval: float = 5.0) -> JSON:
        """Poll until the transfer reaches one of ``until`` (default: a final status). Webhooks are
        the better way in production; this suits scripts and tests."""
        deadline = time.monotonic() + timeout
        while True:
            t = self.get(transfer_id)
            if t["status"] in until:
                return t
            if time.monotonic() > deadline:
                raise ValtuError(0, "TIMEOUT", f"transfer {transfer_id} is still {t['status']}")
            time.sleep(interval)


class _Deposits:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def get(self, deposit_id: str) -> JSON:
        return self._c.request("GET", f"/v1/deposits/{_id(deposit_id)}")["deposit"]

    def find_by_tx_hash(self, tx_hash: str) -> List[JSON]:
        return self.list(tx_hash=tx_hash, limit=50)["items"]

    def lookup(self, chain: str, tx_hash: str) -> JSON:
        """"I sent it, where is it?" The deposits if recorded; otherwise asks the network and, if
        needed, re-reads the transaction's block."""
        return self._c.request("POST", "/v1/deposits/lookup", {"chain": chain, "txHash": tx_hash}, retry=True)

    def list(self, **query: Any) -> JSON:
        """One page. Filters: status, wallet_id, asset, tx_hash, after, before, cursor, limit."""
        return _page(self._c.request("GET", "/v1/deposits", query=query), "deposits")

    def iterate(self, **query: Any) -> Iterator[JSON]:
        return _paginate(lambda cursor: self.list(**query, cursor=cursor))


class _Assets:
    def __init__(self, c: Valtu) -> None:
        self._c = c
        self._cache: Optional[tuple] = None

    def list(self, *, fresh: bool = False) -> List[JSON]:
        """Coins your workspace can use. Cached for 5 minutes."""
        if not fresh and self._cache and time.monotonic() - self._cache[0] < 300:
            return self._cache[1]
        assets = self._c.request("GET", "/v1/assets")["assets"]
        self._cache = (time.monotonic(), assets)
        return assets

    def get(self, asset: str) -> JSON:
        for a in self.list() + self.list(fresh=True):
            if a["asset"] == asset:
                return a
        raise ValtuError(404, "UNSUPPORTED", f"{asset} is not available in this workspace")

    def to_base_units(self, asset: str, value: Any) -> str:
        """``"25.5"`` USDT-TRC20 → ``"25500000"``, using the asset's decimals."""
        return to_base_units(value, self.get(asset)["decimals"])

    def from_base_units(self, asset: str, amount: Any) -> str:
        return from_base_units(amount, self.get(asset)["decimals"])


class _Checkouts:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def create(self, *, amount: Any, external_id: Optional[str] = None, **fields: Any) -> JSON:
        """A payment link for a USD amount ("25.00"). Send your customer to ``checkout["url"]``."""
        body = _body({"amount": str(amount), "external_id": external_id, **fields})
        return self._c.request("POST", "/v1/checkouts", body, retry=external_id is not None)["checkout"]

    def get(self, checkout_id: str) -> JSON:
        return self._c.request("GET", f"/v1/checkouts/{_id(checkout_id)}")["checkout"]

    def list(self, **query: Any) -> JSON:
        return _page(self._c.request("GET", "/v1/checkouts", query=query), "checkouts")

    def iterate(self, **query: Any) -> Iterator[JSON]:
        return _paginate(lambda cursor: self.list(**query, cursor=cursor))

    def cancel(self, checkout_id: str) -> JSON:
        return self._c.request("POST", f"/v1/checkouts/{_id(checkout_id)}/cancel", {})["checkout"]


class _Webhooks:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def list(self) -> List[JSON]:
        return self._c.request("GET", "/v1/webhooks")["webhooks"]

    def public_key(self) -> JSON:
        """The workspace's Ed25519 key for verifying deliveries: pass ``["publicKey"]`` to construct_event."""
        return self._c.request("GET", "/v1/webhooks/public-key")

    def test(self, endpoint_id: str) -> None:
        self._c.request("POST", f"/v1/webhooks/{_id(endpoint_id)}/test", {})


class _Contracts:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def list(self) -> List[JSON]:
        """Contracts on your allowlist (managed in the dashboard, with approval)."""
        return self._c.request("GET", "/v1/contracts")["contracts"]

    def get(self, contract_id: str) -> JSON:
        return self._c.request("GET", f"/v1/contracts/{_id(contract_id)}")["contract"]

    def call(self, *, wallet_id: str, contract_id: str, external_id: Optional[str] = None, **fields: Any) -> JSON:
        """Call an allowed function (``function`` + ``args``, or raw ``data``). The result is a transfer
        of kind CALL that goes through your policies and approvals like a payout."""
        body = _body({"wallet_id": wallet_id, "contract_id": contract_id, "external_id": external_id, **fields})
        return self._c.request("POST", "/v1/contract-calls", body, retry=external_id is not None)["transfer"]


class _Messages:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def create(self, *, wallet_id: str, type: str, message: Any, external_id: Optional[str] = None, **fields: Any) -> JSON:
        """Ask for a message signature (eip191, eip712, tip191, solana). Team signing workspaces only:
        your team approves it in the dashboard, then it's signed (``message.signed`` webhook)."""
        body = _body({"wallet_id": wallet_id, "type": type, "message": message, "external_id": external_id, **fields})
        return self._c.request("POST", "/v1/messages", body, retry=external_id is not None)["message"]

    def get(self, message_id: str) -> JSON:
        return self._c.request("GET", f"/v1/messages/{_id(message_id)}")["message"]

    def list(self, *, status: Optional[str] = None) -> List[JSON]:
        """The 100 most recent requests."""
        return self._c.request("GET", "/v1/messages", query={"status": status})["messages"]


class _Events:
    def __init__(self, c: Valtu) -> None:
        self._c = c

    def list(self, **query: Any) -> JSON:
        """Workspace events oldest first (the same objects webhooks deliver), to catch up after missed deliveries."""
        return self._c.request("GET", "/v1/events", query=query)
