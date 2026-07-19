# auths-receipts-client

Typed Python client for the auths **receipts-api** — the enterprise
dispute-evidence surface: build retainer-grade evidence bundles, verify them
offline over HTTP, find them by `disputeRef`, export exhibits, determine
reversals, and read usage.

```python
from auths_receipts_client import Client

api = Client(base_url="https://receipts.auths.dev", api_key="ark_live_…")

bundle = api.build_bundle(payment_ref="0x…", dispute_ref="chargeback-8842",
                          idempotency_key="cb-8842-v1")

v = api.verify(bundle.bundle)
assert v.ok and v.tx == disputed_tx   # S4 — bind the verdict to YOUR payment ref

hits = api.find_by_dispute_ref("chargeback-8842")
pdf = api.export(bundle.id, format="pdf")
used = api.usage(from_="2026-07-01", to="2026-07-31")
```

Every verdict the API returns is re-derived from signed evidence and is
**anchored** ("authorized *as of* head H") — never a bare claim. Re-check any
bundle yourself, offline, with `@auths-dev/verifier` or `auths.evidence` — the
API is never a trust root.
