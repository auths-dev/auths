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
from auths._errors import CryptoError, NetworkError, StorageError, VerificationError

if TYPE_CHECKING:
    from auths._native import VerificationReport, VerificationResult
    from auths.artifact import ArtifactPublishResult, ArtifactSigningResult
    from auths.commit import CommitSigningResult
    from auths.verify import WitnessConfig


_ERROR_CODE_MAP = {
    "AUTHS_ISSUER_SIG_FAILED": ("invalid_signature", VerificationError),
    "AUTHS_DEVICE_SIG_FAILED": ("invalid_signature", VerificationError),
    "AUTHS_ATTESTATION_EXPIRED": ("expired_attestation", VerificationError),
    "AUTHS_ATTESTATION_REVOKED": ("revoked_device", VerificationError),
    "AUTHS_TIMESTAMP_IN_FUTURE": ("future_timestamp", VerificationError),
    "AUTHS_MISSING_CAPABILITY": ("missing_capability", VerificationError),
    "AUTHS_CRYPTO_ERROR": ("invalid_key", CryptoError),
    "AUTHS_DID_RESOLUTION_ERROR": ("invalid_key", CryptoError),
    "AUTHS_INVALID_INPUT": ("invalid_signature", VerificationError),
    "AUTHS_SERIALIZATION_ERROR": ("invalid_signature", VerificationError),
    "AUTHS_BUNDLE_EXPIRED": ("expired_attestation", VerificationError),
    "AUTHS_KEY_NOT_FOUND": ("key_not_found", CryptoError),
    "AUTHS_INCORRECT_PASSPHRASE": ("signing_failed", CryptoError),
    "AUTHS_SIGNING_FAILED": ("signing_failed", CryptoError),
    "AUTHS_SIGNING_ERROR": ("signing_failed", CryptoError),
    "AUTHS_INPUT_TOO_LARGE": ("invalid_signature", VerificationError),
    "AUTHS_INTERNAL_ERROR": ("unknown", VerificationError),
    "AUTHS_ORG_VERIFICATION_FAILED": ("invalid_signature", VerificationError),
    "AUTHS_ORG_ATTESTATION_EXPIRED": ("expired_attestation", VerificationError),
    "AUTHS_ORG_DID_RESOLUTION_FAILED": ("invalid_key", CryptoError),
}


def _map_error(exc: Exception, *, default_cls: type = VerificationError) -> Exception:
    msg = str(exc)
    code = None
    if msg.startswith("[AUTHS_") and "] " in msg:
        code = msg[1:msg.index("]")]
        msg = msg[msg.index("] ") + 2:]
    if code and code in _ERROR_CODE_MAP:
        py_code, cls = _ERROR_CODE_MAP[code]
        return cls(msg, code=py_code)
    return default_cls(msg, code="unknown")


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

        from auths.attestation_query import AttestationService
        from auths.devices import DeviceService
        from auths.identity import IdentityService

        self.identities = IdentityService(self)
        self.devices = DeviceService(self)
        self.attestations = AttestationService(self)

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
            raise _map_error(exc) from exc

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
            raise _map_error(exc) from exc

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
            raise _map_error(exc) from exc

    def sign(self, message: bytes, private_key: str) -> str:
        """Sign raw bytes. Returns hex-encoded signature."""
        try:
            return _sign_bytes(private_key, message)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

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
            raise _map_error(exc, default_cls=CryptoError) from exc

    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult:
        """Verify an action envelope signature."""
        try:
            return _verify_action_envelope(envelope_json, public_key)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc) from exc

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
            raise _map_error(exc, default_cls=CryptoError) from exc

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
            raise _map_error(exc, default_cls=CryptoError) from exc

    def get_public_key(
        self,
        identity: str,
        passphrase: str | None = None,
    ) -> str:
        """Retrieve the Ed25519 public key (hex) for an identity.

        Args:
            identity: The identity DID (did:keri:...).
            passphrase: Override passphrase.

        Usage:
            pub_key = auths.get_public_key(identity.did)
        """
        from auths._native import get_identity_public_key

        pp = passphrase or self._passphrase
        try:
            return get_identity_public_key(identity, pp)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def sign_as_agent(
        self,
        message: bytes,
        key_alias: str,
        passphrase: str | None = None,
    ) -> str:
        """Sign bytes using a delegated agent's own key.

        Unlike sign_as() which resolves by identity DID, this uses the agent's
        key alias directly — enabling delegated agents (did:key:) to sign.

        Args:
            message: Bytes to sign.
            key_alias: The agent's key alias (e.g., "deploy-bot-agent").
            passphrase: Override passphrase.

        Usage:
            agent = auths.identities.delegate_agent(identity.did, "bot", ["sign"])
            sig = auths.sign_as_agent(b"hello", key_alias=agent.key_alias)
        """
        from auths._native import sign_as_agent as _sign_as_agent

        pp = passphrase or self._passphrase
        try:
            return _sign_as_agent(message, key_alias, pp)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def sign_action_as_agent(
        self,
        action_type: str,
        payload: str,
        key_alias: str,
        agent_did: str,
        passphrase: str | None = None,
    ) -> str:
        """Sign an action envelope using a delegated agent's own key.

        Args:
            action_type: Action type string.
            payload: JSON payload string.
            key_alias: The agent's key alias.
            agent_did: The agent's DID (included in the envelope).
            passphrase: Override passphrase.

        Usage:
            agent = auths.identities.delegate_agent(identity.did, "bot", ["deploy"])
            envelope = auths.sign_action_as_agent("deploy", payload, agent.key_alias, agent.did)
        """
        from auths._native import sign_action_as_agent as _sign_action_as_agent

        pp = passphrase or self._passphrase
        try:
            return _sign_action_as_agent(action_type, payload, key_alias, agent_did, pp)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def sign_commit(
        self,
        data: bytes,
        *,
        identity_did: str,
        passphrase: str | None = None,
    ) -> CommitSigningResult:
        """Sign git commit/tag data, producing an SSHSIG PEM signature.

        Uses a 3-tier fallback:
        1. ssh-agent (fastest, works on dev machines with agent running)
        2. auto-start agent (starts a transient agent process)
        3. direct signing (works everywhere, including headless CI)

        Args:
            data: The raw commit or tag bytes to sign.
            identity_did: The KERI DID of the identity to sign with.
            passphrase: Optional passphrase (for headless envs without ssh-agent).

        Usage:
            result = auths.sign_commit(commit_bytes, identity_did=identity.did)
        """
        from auths._native import sign_commit as _sign_commit
        from auths.commit import CommitSigningResult

        pp = passphrase or self._passphrase
        try:
            raw = _sign_commit(data, identity_did, self.repo_path, pp)
            return CommitSigningResult(
                signature_pem=raw.signature_pem,
                method=raw.method,
                namespace=raw.namespace,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def sign_artifact(
        self,
        path: str,
        *,
        identity_did: str,
        expires_in_days: int | None = None,
        note: str | None = None,
    ) -> ArtifactSigningResult:
        """Sign a file artifact, producing a dual-signed attestation.

        Computes SHA-256 digest of the file and creates an attestation binding
        the digest to your identity.

        Args:
            path: Path to the file to sign.
            identity_did: The identity DID to sign with (used as key alias).
            expires_in_days: Optional expiry for the attestation.
            note: Optional human-readable note.

        Usage:
            result = auths.sign_artifact("release.tar.gz", identity_did=identity.did)
        """
        from auths._native import sign_artifact as _sign_artifact
        from auths.artifact import ArtifactSigningResult

        pp = self._passphrase
        try:
            raw = _sign_artifact(
                path, identity_did, self.repo_path, pp, expires_in_days, note,
            )
            return ArtifactSigningResult(
                attestation_json=raw.attestation_json,
                rid=raw.rid,
                digest=raw.digest,
                file_size=raw.file_size,
            )
        except FileNotFoundError:
            raise
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def sign_artifact_bytes(
        self,
        data: bytes,
        *,
        identity_did: str,
        expires_in_days: int | None = None,
        note: str | None = None,
    ) -> ArtifactSigningResult:
        """Sign raw bytes, producing a dual-signed attestation.

        Use this for non-file artifacts: container manifest digests,
        git tree hashes, API response bodies.

        Args:
            data: The raw bytes to sign.
            identity_did: The identity DID to sign with (used as key alias).
            expires_in_days: Optional expiry for the attestation.
            note: Optional human-readable note.

        Usage:
            result = auths.sign_artifact_bytes(manifest_bytes, identity_did=did)
        """
        from auths._native import sign_artifact_bytes as _sign_artifact_bytes
        from auths.artifact import ArtifactSigningResult

        pp = self._passphrase
        try:
            raw = _sign_artifact_bytes(
                data, identity_did, self.repo_path, pp, expires_in_days, note,
            )
            return ArtifactSigningResult(
                attestation_json=raw.attestation_json,
                rid=raw.rid,
                digest=raw.digest,
                file_size=raw.file_size,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=CryptoError) from exc

    def publish_artifact(
        self,
        attestation_json: str,
        *,
        registry_url: str,
        package_name: str | None = None,
    ) -> "ArtifactPublishResult":
        """Publish a signed attestation to a registry.

        Args:
            attestation_json: The attestation JSON string from sign_artifact().
            registry_url: Base URL of the target registry.
            package_name: Optional ecosystem-prefixed identifier (e.g. "npm:react@18.3.0").

        Usage:
            signed = auths.sign_artifact("release.tar.gz", identity_did=did)
            result = auths.publish_artifact(
                signed.attestation_json,
                registry_url="https://registry.example.com",
            )
        """
        from auths._native import publish_artifact as _publish_artifact
        from auths.artifact import ArtifactPublishResult

        try:
            raw = _publish_artifact(attestation_json, registry_url, package_name)
            return ArtifactPublishResult(
                attestation_rid=raw.attestation_rid,
                package_name=raw.package_name,
                signer_did=raw.signer_did,
            )
        except (ValueError, RuntimeError) as exc:
            msg = str(exc)
            if "duplicate_attestation" in msg:
                raise StorageError(msg, code="duplicate_attestation") from exc
            if "verification_failed" in msg:
                raise VerificationError(msg, code="verification_failed") from exc
            raise _map_error(exc) from exc

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
