"""The one class — methods map 1:1 to the receipts-api endpoints."""

from __future__ import annotations

import time
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field


class AuthsApiError(Exception):
    """A typed API failure: the stable machine code plus the human message."""

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


class StoredBundle(BaseModel):
    """The POST /v1/bundles response."""

    id: str
    disputeRef: Optional[str] = None
    verdicts: dict[str, Any]
    asOf: dict[str, Any]
    createdAt: str
    bundle: dict[str, Any]


class OfflineVerdict(BaseModel):
    """The POST /v1/verify response — always assert the S4 binding fields
    (subject / tx / callIndex) match the transaction YOU are adjudicating."""

    ok: bool
    reason: Optional[str] = None
    detail: Optional[str] = None
    verdicts: Optional[dict[str, Any]] = None
    subject: dict[str, Any]
    tx: str
    callIndex: int
    root: Optional[str] = None


class UsageReport(BaseModel):
    """The GET /v1/usage response."""

    byKind: dict[str, Any]
    includedBundles: Optional[int] = None
    usedBundles: Optional[int] = None
    overageBundles: Optional[int] = None
    projectedOverageCents: Optional[int] = None
    totalCents: Optional[int] = None


class Client:
    """The receipts-api client.

    Args:
        base_url: the API origin, e.g. ``https://receipts.auths.dev``.
        api_key: the ``ark_...`` key (shown once at issue).
        timeout: per-request timeout in seconds.
        max_retries: attempts for 429s (honoring ``Retry-After``).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        self._max_retries = max_retries

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            response = self._client.request(method, path, **kwargs)
            if response.status_code == 429 and attempt < self._max_retries:
                delay = float(response.headers.get("Retry-After", "1") or "1")
                time.sleep(min(delay, 30.0))
                continue
            if response.status_code >= 400:
                try:
                    err = response.json()["error"]
                    raise AuthsApiError(err["code"], err["message"], response.status_code)
                except (KeyError, ValueError):
                    raise AuthsApiError(
                        "http_error", response.text[:200], response.status_code
                    ) from None
            return response
        raise AuthsApiError("rate_limited", "retries exhausted", 429)

    def build_bundle(
        self,
        payment_ref: str,
        registry_url: Optional[str] = None,
        dispute_ref: Optional[str] = None,
        counterparty: Optional[str] = None,
        escrow_record: Optional[dict[str, Any]] = None,
        compliance_receipt: Optional[dict[str, Any]] = None,
        head_max_age_secs: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> StoredBundle:
        """Build (and store) a dispute-evidence bundle for a payment."""
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        body = {
            "paymentRef": payment_ref,
            "registryUrl": registry_url,
            "disputeRef": dispute_ref,
            "counterparty": counterparty,
            "escrowRecord": escrow_record,
            "complianceReceipt": compliance_receipt,
            "headMaxAgeSecs": head_max_age_secs,
        }
        response = self._request("POST", "/v1/bundles", json=body, headers=headers)
        return StoredBundle.model_validate(response.json())

    def verify(self, bundle: dict[str, Any]) -> OfflineVerdict:
        """Re-check a bundle offline; assert the echoed tx matches YOUR dispute."""
        response = self._request("POST", "/v1/verify", json={"bundle": bundle})
        return OfflineVerdict.model_validate(response.json())

    def get_bundle(self, bundle_id: str) -> dict[str, Any]:
        """Fetch one stored bundle (tenant-scoped)."""
        return self._request("GET", f"/v1/bundles/{bundle_id}").json()

    def find_by_dispute_ref(
        self, dispute_ref: str, cursor: Optional[int] = None, limit: int = 20
    ) -> dict[str, Any]:
        """The 'find the evidence for this disputed payment' query."""
        params: dict[str, Any] = {"disputeRef": dispute_ref, "limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        return self._request("GET", "/v1/bundles", params=params).json()

    def export(self, bundle_id: str, format: str = "pdf") -> bytes:
        """Export the exhibit (application/pdf for format='pdf')."""
        response = self._request(
            "GET", f"/v1/bundles/{bundle_id}/export", params={"format": format}
        )
        return response.content

    def determine_reversal(
        self,
        bundle_id: Optional[str] = None,
        bundle: Optional[dict[str, Any]] = None,
        dispute_ref: Optional[str] = None,
        hold: str = "none",
        payee_org: Optional[str] = None,
        payee_settlement_account: Optional[str] = None,
    ) -> dict[str, Any]:
        """Compute the reversal a remit-violation bundle grounds (reversal/v1)."""
        body = {
            "bundleId": bundle_id,
            "bundle": bundle,
            "disputeRef": dispute_ref,
            "hold": hold,
            "payeeOrg": payee_org,
            "payeeSettlementAccount": payee_settlement_account,
        }
        return self._request("POST", "/v1/reversals", json=body).json()

    def usage(self, from_: Optional[str] = None, to: Optional[str] = None) -> UsageReport:
        """Usage by kind; retainer used-vs-included when applicable."""
        params = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        response = self._request("GET", "/v1/usage", params=params)
        return UsageReport.model_validate(response.json())

    def account(self) -> dict[str, Any]:
        """The account + plan."""
        return self._request("GET", "/v1/account").json()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
