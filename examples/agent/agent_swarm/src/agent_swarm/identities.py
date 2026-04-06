"""Swarm identity tree — human → orchestrator → sub-agents.

All identities use the auths SDK to produce real did:keri:E... identifiers
backed by a KERI event log in a local demo repository.

Note: `sign_action_as_identity` has a known SDK bug where every other call
in a Python process produces an unverifiable signature. Until that is fixed,
this module creates real did:keri:E... identities (for canonical DIDs) and
signs delegation tokens using the raw key approach via `sign_action`, which
is reliable for multiple calls in the same process.
"""

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from auths._native import create_agent_identity, create_identity, sign_action

DEMO_REPO = Path(".auths-demo")
_PASSPHRASE = os.environ.get("AUTHS_DEMO_PASSPHRASE", "Demo@Pass1!2xyz")


@dataclass(frozen=True)
class SwarmIdentity:
    """An agent identity with its did:keri:E... DID, capabilities, and delegation token.

    Args:
        name: Human-readable label (e.g. "DataAgent").
        did: did:keri:E... identifier from the KERI event log.
        pub_hex: 64-char hex Ed25519 public key for verification.
        priv_hex: 64-char hex Ed25519 private seed for signing.
        capabilities: Actions this identity is permitted to perform.
        delegation_token: JSON envelope signed by the parent granting authority.
        delegated_by: Parent DID, if this identity was delegated.
    """

    name: str
    did: str
    pub_hex: str
    priv_hex: str
    capabilities: list[str]
    delegation_token: str | None
    delegated_by: str | None


def _make_keypair() -> tuple[str, str]:
    """Generate a fresh in-process Ed25519 keypair.

    Returns:
        (pub_hex, priv_hex) — 64-char hex strings.
    """
    seed = secrets.token_bytes(32)
    priv_key = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pub_bytes.hex(), seed.hex()


def _sign_delegation(parent: SwarmIdentity, child_did: str, capabilities: list[str]) -> str:
    """Return a delegation token signed by parent for child_did.

    Args:
        parent: The delegating identity.
        child_did: DID of the identity being delegated to.
        capabilities: Capabilities granted to the child.
    """
    payload = json.dumps(
        {"delegate_to": child_did, "capabilities": capabilities},
        sort_keys=True,
    )
    return sign_action(parent.priv_hex, "delegation", payload, parent.did)


def make_swarm() -> tuple[SwarmIdentity, SwarmIdentity, list[SwarmIdentity]]:
    """Build the full identity tree: human → orchestrator → [data, analysis, notify].

    Creates real KERI identities in DEMO_REPO. All identities have did:keri:E...
    DIDs. Delegation tokens are signed action envelopes using in-process keys
    to avoid the known SDK bug in sign_action_as_identity.

    Returns:
        (human, orchestrator, sub_agents) where sub_agents is
        [DataAgent, AnalysisAgent, NotifyAgent].

    Usage:
        >>> DEMO_REPO.mkdir(exist_ok=True)
        >>> human, orch, agents = make_swarm()
    """
    DEMO_REPO.mkdir(exist_ok=True)
    repo = str(DEMO_REPO)

    # Root human identity — KERI DID + fresh in-process signing key
    human_did, _, _ = create_identity("human", repo, _PASSPHRASE)
    human_pub, human_priv = _make_keypair()
    human = SwarmIdentity(
        name="Human",
        did=human_did,
        pub_hex=human_pub,
        priv_hex=human_priv,
        capabilities=["delegate", "read_data", "analyze", "notify"],
        delegation_token=None,
        delegated_by=None,
    )

    # Orchestrator — KERI DID + fresh in-process signing key
    orch_caps = ["delegate", "read_data", "analyze", "notify"]
    orch_bundle = create_agent_identity("Orchestrator", orch_caps, repo, _PASSPHRASE)
    orch_pub, orch_priv = _make_keypair()
    orch_token = _sign_delegation(human, orch_bundle.agent_did, orch_caps)
    orchestrator = SwarmIdentity(
        name="Orchestrator",
        did=orch_bundle.agent_did,
        pub_hex=orch_pub,
        priv_hex=orch_priv,
        capabilities=orch_caps,
        delegation_token=orch_token,
        delegated_by=human_did,
    )

    # Sub-agents — each delegated by the orchestrator
    sub_specs = [
        ("DataAgent", ["read_data"]),
        ("AnalysisAgent", ["analyze"]),
        ("NotifyAgent", ["notify"]),
    ]
    sub_agents = []
    for name, caps in sub_specs:
        bundle = create_agent_identity(name, caps, repo, _PASSPHRASE)
        pub_hex, priv_hex = _make_keypair()
        token = _sign_delegation(orchestrator, bundle.agent_did, caps)
        sub_agents.append(
            SwarmIdentity(
                name=name,
                did=bundle.agent_did,
                pub_hex=pub_hex,
                priv_hex=priv_hex,
                capabilities=caps,
                delegation_token=token,
                delegated_by=orchestrator.did,
            )
        )

    return human, orchestrator, sub_agents
