from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from auths._native import (
    get_token as _get_token,
    sign_action as _sign_action,
    sign_bytes as _sign_bytes,
    verify_action_envelope as _verify_action_envelope,
    verify_attestation as _verify_attestation,
    verify_chain as _verify_chain,
    verify_device_authorization as _verify_device_authorization,
)
from auths._errors import CryptoError, NetworkError, VerificationError

if TYPE_CHECKING:
    from auths._native import VerificationReport, VerificationResult


def _map_verify_error(exc: Exception) -> Exception:
    msg = str(exc)
    if "public key" in msg.lower() or "hex" in msg.lower():
        return CryptoError(msg, code="invalid_key")
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

    def __init__(self, repo_path: str = "~/.auths", passphrase: Optional[str] = None):
        self.repo_path = repo_path
        self._passphrase = passphrase

        from auths.devices import DeviceService
        from auths.identity import IdentityService

        self.identities = IdentityService(self)
        self.devices = DeviceService(self)

    def verify(self, attestation_json: str, issuer_key: str) -> VerificationResult:
        """Verify a single attestation. Returns a VerificationResult."""
        try:
            return _verify_attestation(attestation_json, issuer_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def verify_chain(self, attestations: List[str], root_key: str) -> VerificationReport:
        """Verify an attestation chain. Returns a VerificationReport."""
        try:
            return _verify_chain(attestations, root_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_verify_error(exc) from exc

    def verify_device(
        self,
        identity_did: str,
        device_did: str,
        attestations: List[str],
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

    def get_token(
        self,
        bridge_url: str,
        chain_json: str,
        root_key: str,
        capabilities: Optional[List[str]] = None,
    ) -> str:
        """Exchange an attestation chain for a bearer token."""
        try:
            return _get_token(bridge_url, chain_json, root_key, capabilities or [])
        except ConnectionError as exc:
            raise _map_network_error(exc) from exc
        except (ValueError, RuntimeError) as exc:
            raise _map_network_error(exc) from exc
