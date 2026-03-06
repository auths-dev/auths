"""Identity and agent resource services — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auths._native import (
    create_identity as _create_identity,
    provision_agent as _provision_agent,
)

if TYPE_CHECKING:
    from auths._client import Auths


@dataclass
class Identity:
    """An Auths identity (represents a did:keri: identifier)."""

    did: str
    public_key: str
    label: str
    repo_path: str


@dataclass
class Agent:
    """A provisioned agent with its attestation chain."""

    did: str
    label: str
    attestation: str


class IdentityService:
    """Resource service for identity operations.

    Usage:
        auths = Auths()
        identity = auths.identities.create(label="laptop")
        agent = auths.identities.provision_agent(identity.did, name="ci-bot", capabilities=["sign"])
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
        did, key_alias = _create_identity(label, rp, pp)
        return Identity(did=did, public_key=key_alias, label=label, repo_path=rp)

    def provision_agent(
        self,
        identity_did: str,
        name: str,
        capabilities: list[str],
        expires_in_secs: int | None = None,
        passphrase: str | None = None,
    ) -> Agent:
        """Provision an agent under an identity.

        Args:
            identity_did: The parent identity's DID.
            name: Human-readable agent name.
            capabilities: List of capabilities (e.g., ["sign", "verify"]).
            expires_in_secs: Optional TTL in seconds.
            passphrase: Key passphrase override.

        Usage:
            agent = auths.identities.provision_agent(identity.did, "ci-bot", ["sign"])
        """
        pp = passphrase or self._client._passphrase
        bundle = _provision_agent(
            name, capabilities, self._client.repo_path, pp, expires_in_secs
        )
        return Agent(
            did=bundle.agent_did, label=name, attestation=bundle.attestation_json
        )
