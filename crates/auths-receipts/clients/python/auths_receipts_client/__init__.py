"""Typed client for the auths receipts-api.

The enterprise dispute-evidence surface: build retainer-grade bundles, verify
them offline over HTTP, find them by disputeRef, export exhibits, determine
reversals, and read usage — with Bearer key auth and 429-aware retries.

Usage:
    from auths_receipts_client import Client
    api = Client(base_url="https://receipts.auths.dev", api_key="ark_live_...")
    bundle = api.build_bundle(payment_ref="0x...", dispute_ref="chargeback-8842",
                              idempotency_key="cb-8842-v1")
    v = api.verify(bundle.bundle)
    assert v.tx == disputed_tx  # S4 — bind the verdict to YOUR payment ref
"""

from .client import AuthsApiError, Client, OfflineVerdict, StoredBundle, UsageReport

__all__ = [
    "AuthsApiError",
    "Client",
    "OfflineVerdict",
    "StoredBundle",
    "UsageReport",
]
