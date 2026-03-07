"""Identity and agent resource services — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auths._native import (
    create_identity as _create_identity,
    create_agent_identity as _create_agent_identity,
    delegate_agent as _delegate_agent,
    rotate_identity_ffi as _rotate_identity,
)
from auths.rotation import IdentityRotationResult

if TYPE_CHECKING:
    from auths._client import Auths


@dataclass
class Identity:
    """An Auths identity (represents a did:keri: identifier)."""

    did: str
    key_alias: str
    label: str
    repo_path: str
    public_key: str


@dataclass
class AgentIdentity:
    """Standalone agent identity (did:keri:). Created via identities.create_agent()."""

    did: str
    key_alias: str
    attestation: str
    public_key: str


@dataclass
class DelegatedAgent:
    """Agent delegated under a parent identity (did:key:). Created via identities.delegate_agent()."""

    did: str
    key_alias: str
    attestation: str
    public_key: str


class IdentityService:
    """Resource service for identity operations.

    Usage:
        auths = Auths()
        identity = auths.identities.create(label="laptop")
        agent = auths.identities.delegate_agent(identity.did, name="ci-bot", capabilities=["sign"])
    """

    def __init__(self, client: Auths):
        self._client = client

    def create(
        self,
        label: str = "main",
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> Identity:
        """Create a new identity.

        Args:
            label: Human-readable label for this identity (default: "main").
            repo_path: Git repo path (default: client's repo_path).
            passphrase: Key passphrase (default: client's passphrase or AUTHS_PASSPHRASE env var).

        Usage:
            identity = auths.identities.create(label="laptop")
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        did, key_alias, public_key_hex = _create_identity(label, rp, pp)
        return Identity(did=did, key_alias=key_alias, label=label, repo_path=rp, public_key=public_key_hex)

    def rotate(
        self,
        identity_did: str,
        *,
        passphrase: str | None = None,
    ) -> IdentityRotationResult:
        """Rotate an identity's keys using the KERI pre-rotation ceremony.

        This is a single atomic operation. If any step fails, the previous key
        remains active and no partial state is written.

        After rotation:
        - Old attestations remain valid (verified via Key Event Log history)
        - New signing operations use the rotated key automatically
        - Device links are unaffected (bound to DID, not key)

        Args:
            identity_did: The KERI DID of the identity to rotate.
            passphrase: Optional passphrase for keychain access.

        Usage:
            result = auths.identities.rotate(identity.did)
            print(f"Rotated to sequence {result.sequence}")
        """
        pp = passphrase or self._client._passphrase
        native_result = _rotate_identity(self._client.repo_path, None, None, pp)
        return IdentityRotationResult(
            controller_did=native_result.controller_did,
            new_key_fingerprint=native_result.new_key_fingerprint,
            previous_key_fingerprint=native_result.previous_key_fingerprint,
            sequence=native_result.sequence,
        )

    def create_agent(
        self,
        name: str,
        capabilities: list[str],
        passphrase: str | None = None,
    ) -> AgentIdentity:
        """Create a standalone agent identity (did:keri:).

        Args:
            name: Human-readable agent name.
            capabilities: List of capabilities (e.g., ["sign", "verify"]).
            passphrase: Key passphrase override.

        Usage:
            agent = auths.identities.create_agent("ci-bot", ["sign"])
        """
        pp = passphrase or self._client._passphrase
        bundle = _create_agent_identity(
            name, capabilities, self._client.repo_path, pp,
        )
        return AgentIdentity(
            did=bundle.agent_did, key_alias=bundle.key_alias,
            attestation=bundle.attestation_json, public_key=bundle.public_key_hex,
        )

    def delegate_agent(
        self,
        identity_did: str,
        name: str,
        capabilities: list[str],
        expires_in_days: int | None = None,
        passphrase: str | None = None,
    ) -> DelegatedAgent:
        """Delegate an agent under an identity (did:key:).

        Args:
            identity_did: The parent identity's DID.
            name: Human-readable agent name.
            capabilities: List of capabilities (e.g., ["sign", "verify"]).
            expires_in_days: Optional TTL in days.
            passphrase: Key passphrase override.

        Usage:
            agent = auths.identities.delegate_agent(identity.did, "ci-bot", ["sign"])
        """
        pp = passphrase or self._client._passphrase
        bundle = _delegate_agent(
            name, capabilities, self._client.repo_path, pp, expires_in_days,
            identity_did,
        )
        return DelegatedAgent(
            did=bundle.agent_did, key_alias=bundle.key_alias,
            attestation=bundle.attestation_json, public_key=bundle.public_key_hex,
        )
