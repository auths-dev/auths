"""Append-only audit log and swarm key registry."""

import json
from pathlib import Path

from agent_swarm.identities import SwarmIdentity

AUDIT_FILE = Path("audit.jsonl")
KEYS_FILE = Path(".swarm-keys.json")


def save_swarm_keys(
    human: SwarmIdentity,
    orchestrator: SwarmIdentity,
    sub_agents: list[SwarmIdentity],
) -> None:
    """Persist all swarm public keys indexed by DID for later verification.

    Args:
        human: Root human identity.
        orchestrator: Orchestrator identity.
        sub_agents: List of sub-agent identities.

    Usage:
        >>> save_swarm_keys(human, orch, agents)
    """
    registry = {
        identity.did: {"name": identity.name, "pub_hex": identity.pub_hex}
        for identity in [human, orchestrator, *sub_agents]
    }
    KEYS_FILE.write_text(json.dumps(registry, indent=2))


def load_swarm_keys() -> dict[str, dict]:
    """Load the swarm key registry written by save_swarm_keys().

    Returns:
        Mapping of DID → {"name": str, "pub_hex": str}.

    Usage:
        >>> keys = load_swarm_keys()
        >>> pub = keys[did]["pub_hex"]
    """
    if not KEYS_FILE.exists():
        msg = f"Swarm key file not found: {KEYS_FILE}. Run `run-swarm` first."
        raise FileNotFoundError(msg)
    return json.loads(KEYS_FILE.read_text())


def clear() -> None:
    """Remove the audit log from a previous run.

    Usage:
        >>> clear()
    """
    if AUDIT_FILE.exists():
        AUDIT_FILE.unlink()


def append_envelope(envelope_json: str) -> None:
    """Append one signed action envelope to the audit log.

    Args:
        envelope_json: JSON string returned by sign_tool_call().

    Usage:
        >>> append_envelope(sign_tool_call(agent, "read_csv", {"path": "f.csv"}, "read_data"))
    """
    with AUDIT_FILE.open("a") as f:
        f.write(envelope_json + "\n")


def read_all() -> list[dict]:
    """Return all envelope records from the audit log.

    Usage:
        >>> entries = read_all()
    """
    if not AUDIT_FILE.exists():
        return []
    return [
        json.loads(line)
        for line in AUDIT_FILE.read_text().splitlines()
        if line.strip()
    ]
