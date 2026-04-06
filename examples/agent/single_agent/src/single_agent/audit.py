"""Append-only audit log for signed action envelopes."""

import json
from pathlib import Path

AUDIT_FILE = Path("audit.jsonl")
KEY_FILE = Path(".agent-key.json")


def save_agent_key(did: str, public_key_hex: str) -> None:
    """Persist the agent's public key so verify_log can read it later.

    Args:
        did: Agent's did:keri:E... identifier.
        public_key_hex: 64-char hex Ed25519 public key.

    Usage:
        >>> save_agent_key(did, pub_hex)
    """
    KEY_FILE.write_text(json.dumps({"did": did, "public_key_hex": public_key_hex}))


def load_agent_key() -> dict:
    """Load the agent public key written by save_agent_key().

    Usage:
        >>> info = load_agent_key()
        >>> pub_hex = info["public_key_hex"]
    """
    if not KEY_FILE.exists():
        msg = f"Agent key file not found: {KEY_FILE}. Run `run-agent` first."
        raise FileNotFoundError(msg)
    return json.loads(KEY_FILE.read_text())


def clear() -> None:
    """Remove the audit log from a previous run.

    Usage:
        >>> clear()
    """
    if AUDIT_FILE.exists():
        AUDIT_FILE.unlink()


def append_envelope(envelope_json: str) -> None:
    """Append one signed action envelope to the audit log (one JSON object per line).

    Args:
        envelope_json: JSON string returned by sign_tool_call().

    Usage:
        >>> append_envelope(sign_tool_call(did, "read_csv", {"path": "f.csv"}))
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
