from __future__ import annotations

from typing import TYPE_CHECKING

import json

from auths._native import (
    get_token as _get_token,
    sign_action as _sign_action,
    sign_bytes as _sign_bytes,
    verify_action_envelope as _verify_action_envelope,
    verify_at_time as _verify_at_time,
    verify_at_time_with_capability as _verify_at_time_with_capability,
    verify_attestation as _verify_attestation,
    verify_attestation_with_capability as _verify_attestation_with_capability,
    verify_chain as _verify_chain,
    verify_chain_with_capability as _verify_chain_with_capability,
    verify_chain_with_witnesses as _verify_chain_with_witnesses,
    verify_device_authorization as _verify_device_authorization,
)
from auths._errors import CryptoError, NetworkError, VerificationError

if TYPE_CHECKING:
    from auths._native import VerificationReport, VerificationResult
    from auths.verify import WitnessConfig


def _map_verify_error(exc: Exception) -> Exception:
    msg = str(exc)
    if "public key" in msg.lower() or "hex" in msg.lower():
        return CryptoError(msg, code="invalid_key")
    if "rfc 3339" in msg.lower():
        return VerificationError(msg, code="invalid_timestamp")
    if "future" in msg.lower() and "timestamp" in msg.lower():
        return VerificationError(msg, code="future_timestamp")
    if "parse" in msg.lower() or "json" in msg.lower():
        return VerificationError(msg, code="invalid_signature")
    return VerificationError(msg, code="invalid_signature")


def _map_sign_error(exc: Exception) -> Exception:
    msg = str(exc)
    if "key" in msg.lower():
        return CryptoError(msg, code="invalid_key")
    return CryptoError(msg, code="signing_failed")


def _map_network_error(exc: Exception) -> Exception:
    msg = str(exc)
    if "unreachable" in msg.lower() or "connection" in msg.lower():
        return NetworkError(msg, code="connection_failed", should_retry=True)
    if "timeout" in msg.lower():
        return NetworkError(msg, code="timeout", should_retry=True)
    return NetworkError(msg, code="server_error")


class Auths:
    """Auths SDK client — decentralized identity for developers.

    Usage:
        auths = Auths()
        result = auths.verify(attestation_json=data, issuer_key=key)
        sig = auths.sign(b"hello", private_key=key_hex)
    """

    def __init__(self, repo_path: str = "~/.auths", passphrase: str | None = None):
        self.repo_path = repo_path
        self._passphrase = passphrase

        from auths.devices import DeviceService
        from auths.identity import IdentityService

        self.identities = IdentityService(self)
        self.devices = DeviceService(self)

    def verify(
        self,
        attestation_json: str,
        issuer_key: str,
        required_capability: str | None = None,
        at: str | None = None,
    ) -> VerificationResult:
        """Verify a single attestation, optionally at a specific historical timestamp.

        Args:
            attestation_json: The attestation JSON string.
            issuer_key: Issuer's public key hex.
            required_capability: If set, also verify the attestation grants this capability.
            at: RFC 3339 timestamp to verify against (e.g., "2024-06-15T00:00:00Z").
                When set, checks validity at that point in time instead of now.

        Usage:
            result = auths.verify(att_json, key, at="2024-06-15T00:00:00Z",
                                  required_capability="deploy:staging")
        """
        try:
            if at and required_capability:
                return _verify_at_time_with_capability(
                    attestation_json, issuer_key, at, required_capability
                )
            if at:
                return _verify_at_time(attestation_json, issuer_key, at)
            if required_capability:
                return _verify_attestation_with_capability(
                    attestation_json, issuer_key, required_capability
                )
            return _verify_attestation(attestation_json, issuer_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def verify_chain(
        self,
        attestations: list[str],
        root_key: str,
        required_capability: str | None = None,
        witnesses: WitnessConfig | None = None,
    ) -> VerificationReport:
        """Verify an attestation chain, optionally with witness quorum.

        Args:
            attestations: List of attestation JSON strings, ordered root-to-leaf.
            root_key: Root identity's public key hex.
            required_capability: If set, verify the chain grants this capability.
            witnesses: If set, enforces witness receipt quorum.

        Usage:
            report = auths.verify_chain(chain, root_key, witnesses=config)
        """
        try:
            if witnesses:
                keys_json = [
                    json.dumps({"did": k.did, "public_key_hex": k.public_key_hex})
                    for k in witnesses.keys
                ]
                return _verify_chain_with_witnesses(
                    attestations, root_key,
                    witnesses.receipts, keys_json, witnesses.threshold,
                )
            if required_capability:
                return _verify_chain_with_capability(
                    attestations, root_key, required_capability
                )
            return _verify_chain(attestations, root_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def verify_device(
        self,
        identity_did: str,
        device_did: str,
        attestations: list[str],
        identity_key: str,
    ) -> VerificationReport:
        """Verify device authorization against an identity."""
        try:
            return _verify_device_authorization(
                identity_did, device_did, attestations, identity_key
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def sign(self, message: bytes, private_key: str) -> str:
        """Sign raw bytes. Returns hex-encoded signature."""
        try:
            return _sign_bytes(private_key, message)
        except (ValueError, RuntimeError) as exc:
            raise _map_sign_error(exc) from exc

    def sign_action(
        self,
        action_type: str,
        payload: str,
        identity_did: str,
        private_key: str,
    ) -> str:
        """Sign an action envelope. Returns JSON envelope string."""
        try:
            return _sign_action(private_key, action_type, payload, identity_did)
        except (ValueError, RuntimeError) as exc:
            raise _map_sign_error(exc) from exc

    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult:
        """Verify an action envelope signature."""
        try:
            return _verify_action_envelope(envelope_json, public_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def sign_as(
        self,
        message: bytes,
        identity: str,
        passphrase: str | None = None,
    ) -> str:
        """Sign bytes using a keychain-stored identity key.

        Args:
            message: Bytes to sign.
            identity: The identity DID (did:keri:...) whose key to use.
            passphrase: Override passphrase (default: client passphrase or AUTHS_PASSPHRASE).

        Usage:
            identity = auths.identities.create(label="laptop")
            sig = auths.sign_as(b"hello", identity=identity.did)
        """
        from auths._native import sign_as_identity

        pp = passphrase or self._passphrase
        try:
            return sign_as_identity(message, identity, self.repo_path, pp)
        except (ValueError, RuntimeError) as exc:
            raise _map_sign_error(exc) from exc

    def sign_action_as(
        self,
        action_type: str,
        payload: str,
        identity: str,
        passphrase: str | None = None,
    ) -> str:
        """Sign an action envelope using a keychain-stored identity key.

        Args:
            action_type: Action type string.
            payload: JSON payload string.
            identity: The identity DID whose key to use.
            passphrase: Override passphrase.

        Usage:
            envelope = auths.sign_action_as("deploy", payload_json, identity=identity.did)
        """
        from auths._native import sign_action_as_identity

        pp = passphrase or self._passphrase
        try:
            return sign_action_as_identity(
                action_type, payload, identity, self.repo_path, pp
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_sign_error(exc) from exc

    def get_token(
        self,
        bridge_url: str,
        chain_json: str,
        root_key: str,
        capabilities: list[str] | None = None,
    ) -> str:
        """Exchange an attestation chain for a bearer token."""
        try:
            return _get_token(bridge_url, chain_json, root_key, capabilities or [])
        except ConnectionError as exc:
            raise _map_network_error(exc) from exc
        except (ValueError, RuntimeError) as exc:
            raise _map_network_error(exc) from exc
