# valtu: the Valtu Wallet SDK for Python

The official Python SDK for [Valtu](https://valtu.io), self-custody wallet infrastructure for stablecoin payments.
It gives you a signed API client, webhook verification and enclave attestation checks.

- Python 3.9+
- One dependency (`cryptography`)
- Typed
- MIT

```bash
pip install valtu
```

## Quick start

```python
from valtu import Valtu, deposit_address

valtu = Valtu.from_env()          # VALTU_PRIVATE_KEY, or VALTU_KEY_FILE=valtu-server.json

# One deposit wallet per customer. It's idempotent, so call it every time.
wallet = valtu.wallets.for_customer("cus_42")
print(deposit_address(wallet, "tron"))

# A payout. The same external_id never pays twice, even if you retry.
amount = valtu.assets.to_base_units("USDT-TRC20", "25.50")      # "25500000"
transfer = valtu.transfers.create(
    wallet_id=HOT_WALLET_ID, asset="USDT-TRC20", amount=amount,
    to="TQ...", external_id="payout-123",
)
print(transfer["status"])          # QUEUED, or PENDING_APPROVAL if a policy asks for approvals
```

Keyword arguments are snake_case. The SDK sends them in the API's camelCase. Responses are the API's
JSON objects as dicts, with the API's field names (`walletId`, `externalId`…).

## Webhooks

Verify the **raw** request body, before you parse it.

```python
from valtu import construct_event, EventDeduper, WebhookVerificationError

dedupe = EventDeduper()

@app.post("/webhooks/valtu")                      # Flask
def valtu_webhook():
    try:
        event = construct_event(request.get_data(), request.headers, public_key=WEBHOOK_PUBLIC_KEY)
    except WebhookVerificationError:
        return "", 400
    if dedupe.first(event["id"]):
        handle(event)                             # e.g. "deposit.confirmed", "transfer.confirmed"
    return "", 200
```

Get `WEBHOOK_PUBLIC_KEY` (Ed25519, not a secret) from Dashboard → Webhooks, or from
`valtu.webhooks.public_key()["publicKey"]`. You can pass `secret=` instead to check the HMAC signature.

## Check the enclave yourself

Signing keys live in a hardware enclave. Don't take our word for what runs there: check it.

```python
import secrets
from valtu import verify_attestation

nonce = secrets.token_hex(32)
for doc in valtu.attestation(nonce)["attestations"]:
    result = verify_attestation(doc["document"], nonce=nonce, expected_pcr0=PUBLISHED_PCR0)
    print(result.module_id, result.statement["keys"])
```

`verify_attestation` checks the following, and raises `AttestationError` if any check fails:

- the certificate chain up to the hardware vendor's root;
- the document's signature;
- your nonce;
- the image measurement.

The published measurements and key anchors are at https://valtu.io/docs/security.

## What's in the client

| | |
|---|---|
| `valtu.wallets` | `create`, `for_customer`, `get`, `find_by_external_id`, `balances`, `list`, `iterate` |
| `valtu.transfers` | `create`, `preview`, `create_batch`, `get`, `find_by_external_id`, `cancel`, `list`, `iterate`, `wait` |
| `valtu.deposits` | `get`, `find_by_tx_hash`, `lookup`, `list`, `iterate` |
| `valtu.assets` | `list`, `get`, `to_base_units`, `from_base_units` |
| `valtu.checkouts` | `create`, `get`, `list`, `iterate`, `cancel` |
| `valtu.contracts` | `list`, `get`, `call` |
| `valtu.messages` | `create`, `get`, `list` |
| `valtu.webhooks` / `valtu.events` | `list`, `public_key`, `test` / `list` |
| `valtu` | `workspace()`, `balances()`, `networks()`, `attestation(nonce)`, `request(method, path, body)` |

## How it behaves

- **Every request is signed** with your API key, using ECDSA P-256 over the method, path, timestamp, a single-use nonce and the body hash.
  - Valtu stores only the public key.
  - Nobody in between can change or replay a request.
- **Retries:** GETs, and writes with an `external_id`, are retried on network errors and 429/502/503/504. The SDK honours `Retry-After`.
- **Errors:** `ValtuError` carries `status`, a stable `code`, `message` and `request_id`. Quote the `request_id` to support.
- **Amounts** are integer strings in base units. `to_base_units` and `from_base_units` convert exactly, and refuse floats.

## Links

- API guide: https://valtu.io/docs/api
- TypeScript SDK: https://github.com/Valtu-Wallet/wallet-kit (`npm i @valtu/wallet-kit`)
- Examples: https://github.com/Valtu-Wallet/examples
- Security: https://valtu.io/docs/security · report issues to security@valtu.io
