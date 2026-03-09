"""Attestation query service — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auths._native import (
    get_latest_attestation as _get_latest,
    list_attestations as _list_all,
    list_attestations_by_device as _list_by_device,
)

if TYPE_CHECKING:
    from auths._client import Auths


@dataclass
class Attestation:
    """A cryptographic authorization linking an identity to a device or agent.

    The `.json` field contains the canonical JSON representation — pass it
    directly to `auths.verify()` or store it for later verification.
    """

    rid: str
    """Unique attestation resource identifier."""
    issuer: str
    """DID of the identity that issued this attestation."""
    subject: str
    """DID of the entity this attestation authorizes."""
    device_did: str
    """DID of the device key bound by this attestation."""
    capabilities: list[str]
    """Granted capabilities (e.g. `["sign", "verify"]`)."""
    signer_type: str | None
    """Signer classification: `"Human"`, `"Agent"`, or `"Workload"`."""
    expires_at: str | None
    """ISO 8601 expiry timestamp, or None for non-expiring attestations."""
    revoked_at: str | None
    """ISO 8601 revocation timestamp, or None if still active."""
    created_at: str | None
    """ISO 8601 creation timestamp."""
    delegated_by: str | None
    """DID of the delegating identity, if this is a delegation attestation."""
    json: str
    """Canonical JSON representation of the attestation."""

    @property
    def is_active(self) -> bool:
        """True if not revoked."""
        return self.revoked_at is None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def __repr__(self) -> str:
        status = "revoked" if self.is_revoked else "active"
        caps = ", ".join(self.capabilities[:3])
        if len(self.capabilities) > 3:
            caps += f" +{len(self.capabilities) - 3} more"
        rid_short = self.rid[:16] if len(self.rid) > 16 else self.rid
        subject_short = self.subject[:20] if len(self.subject) > 20 else self.subject
        return (
            f"Attestation(rid='{rid_short}...', "
            f"subject='{subject_short}...', "
            f"caps=[{caps}], status={status})"
        )


def _convert(py_att) -> Attestation:
    return Attestation(
        rid=py_att.rid,
        issuer=py_att.issuer,
        subject=py_att.subject,
        device_did=py_att.device_did,
        capabilities=list(py_att.capabilities),
        signer_type=py_att.signer_type,
        expires_at=py_att.expires_at,
        revoked_at=py_att.revoked_at,
        created_at=py_att.created_at,
        delegated_by=py_att.delegated_by,
        json=py_att.json,
    )


class AttestationService:
    """Query attestations in the identity graph.

    Usage:
        all_atts = auths.attestations.list()
        device_atts = auths.attestations.list(device_did="did:key:z...")
        latest = auths.attestations.latest("did:key:z...")
    """

    def __init__(self, client: Auths):
        self._client = client

    def list(
        self,
        *,
        identity_did: str | None = None,
        device_did: str | None = None,
    ) -> list[Attestation]:
        """List attestations, optionally filtered by identity or device.

        Args:
            identity_did: Filter to attestations issued by this identity.
            device_did: Filter to attestations for this device.

        Returns empty list if no attestations match (never raises for empty results).
        """
        if device_did is not None:
            raw = _list_by_device(self._client.repo_path, device_did)
        else:
            raw = _list_all(self._client.repo_path)

        result = [_convert(r) for r in raw]

        if identity_did is not None:
            result = [a for a in result if a.issuer == identity_did]

        return result

    def latest(self, device_did: str) -> Attestation | None:
        """Get the most recent attestation for a device.

        Returns None if the device has no attestations.
        """
        raw = _get_latest(self._client.repo_path, device_did)
        if raw is None:
            return None
        return _convert(raw)
