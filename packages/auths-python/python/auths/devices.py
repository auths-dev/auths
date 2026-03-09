"""Device resource service — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auths._native import (
    extend_device_authorization_ffi as _extend_device,
    link_device_to_identity as _link_device,
    revoke_device_from_identity as _revoke_device,
)

if TYPE_CHECKING:
    from auths._client import Auths


@dataclass
class Device:
    """A linked device."""

    did: str
    """The device's DID (`did:key:z...`)."""
    attestation_id: str
    """RID of the attestation linking this device to its identity."""


@dataclass
class DeviceExtension:
    """Result of extending a device's authorization period."""

    device_did: str
    """The device's DID (`did:key:z...`)."""
    new_expires_at: str
    """ISO 8601 timestamp of the new expiry."""
    previous_expires_at: str | None
    """ISO 8601 timestamp of the previous expiry, or None if none was set."""

    def __repr__(self) -> str:
        return (
            f"DeviceExtension(device='{self.device_did[:20]}...', "
            f"expires='{self.new_expires_at}')"
        )


class DeviceService:
    """Resource service for device operations.

    Examples:
        ```python
        device = auths.devices.link(identity_did="did:keri:...", capabilities=["sign"])
        auths.devices.revoke(device.did, identity_did="did:keri:...")
        ```
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

        Returns:
            Device with the device DID and attestation ID.

        Raises:
            IdentityError: If the identity doesn't exist.
            StorageError: If writing the attestation fails.

        Examples:
            ```python
            device = auths.devices.link(identity.did, capabilities=["sign"], expires_in_days=90)
            ```
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

    def extend(
        self,
        device_did: str,
        identity_did: str,
        *,
        days: int = 90,
        passphrase: str | None = None,
    ) -> DeviceExtension:
        """Extend a device's authorization period.

        Renews the device's expiry without revoking and re-linking.
        Expired devices can be extended (grace period). Revoked devices cannot.

        Args:
            device_did: The device's DID (`did:key:z...`).
            identity_did: The identity key alias for signing.
            days: Number of days to extend from now (default: 90).
            passphrase: Optional passphrase for keychain access.

        Returns:
            DeviceExtension with the new and previous expiry timestamps.

        Raises:
            IdentityError: If the device or identity doesn't exist.
            VerificationError: If the device has been revoked.

        Examples:
            ```python
            ext = auths.devices.extend(device.did, identity.did, days=90)
            print(f"Extended until: {ext.new_expires_at}")
            ```
        """
        pp = passphrase or self._client._passphrase
        result = _extend_device(
            device_did, identity_did, days, self._client.repo_path, pp
        )
        return DeviceExtension(
            device_did=result.device_did,
            new_expires_at=result.new_expires_at,
            previous_expires_at=result.previous_expires_at,
        )

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

        Raises:
            IdentityError: If the device or identity doesn't exist.

        Examples:
            ```python
            auths.devices.revoke(device.did, identity_did=identity.did, note="lost laptop")
            ```
        """
        pp = passphrase or self._client._passphrase
        _revoke_device(device_did, identity_did, self._client.repo_path, pp, note)
