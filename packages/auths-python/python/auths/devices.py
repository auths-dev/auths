"""Device resource service — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auths._native import (
    link_device_to_identity as _link_device,
    revoke_device_from_identity as _revoke_device,
)

if TYPE_CHECKING:
    from auths._client import Auths


@dataclass
class Device:
    """A linked device."""

    did: str
    attestation_id: str


class DeviceService:
    """Resource service for device operations.

    Usage:
        device = auths.devices.link(identity_did="did:keri:...", capabilities=["sign"])
        auths.devices.revoke(device.did, identity_did="did:keri:...")
    """

    def __init__(self, client: Auths):
        self._client = client

    def link(
        self,
        identity_did: str,
        capabilities: list[str] | None = None,
        expires_in_days: int | None = None,
        passphrase: str | None = None,
    ) -> Device:
        """Link a new device to an identity.

        Args:
            identity_did: The identity to link this device to.
            capabilities: Device capabilities (default: []).
            expires_in_days: Optional expiry in days.
            passphrase: Key passphrase override.

        Usage:
            device = auths.devices.link(identity.did, capabilities=["sign"], expires_in_days=90)
        """
        pp = passphrase or self._client._passphrase
        device_did, attestation_id = _link_device(
            identity_did,
            capabilities or [],
            self._client.repo_path,
            pp,
            expires_in_days,
        )
        return Device(did=device_did, attestation_id=attestation_id)

    def revoke(
        self,
        device_did: str,
        identity_did: str,
        note: str | None = None,
        passphrase: str | None = None,
    ) -> None:
        """Revoke a device.

        Args:
            device_did: The device DID to revoke.
            identity_did: The parent identity's DID.
            note: Optional revocation note.
            passphrase: Key passphrase override.

        Usage:
            auths.devices.revoke(device.did, identity_did=identity.did, note="lost laptop")
        """
        pp = passphrase or self._client._passphrase
        _revoke_device(device_did, identity_did, self._client.repo_path, pp, note)
