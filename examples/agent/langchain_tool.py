"""
AI Agent Signed Tool Call Example
=================================

Demonstrates how an AI agent signs tool calls with Auths action envelopes,
and how a server verifies them before execution.

Requirements:
    pip install auths-verifier

Security Note:
    This example passes key material as hex strings for simplicity. Python
    strings are immutable and not zeroizable. For production, store keys in
    a secure enclave, hardware security module, or secret manager (e.g.,
    AWS KMS, HashiCorp Vault, macOS Keychain).

Usage:
    python langchain_tool.py
"""

import json
import sys

try:
    from auths_verifier import sign_action, verify_action_envelope
except ImportError:
    print("Install auths-verifier: pip install auths-verifier")
    sys.exit(1)


def generate_test_keypair():
    """Generate an Ed25519 keypair for demonstration.

    In production, use `auths id create` to generate keys stored in the
    system keychain, then export the seed for agent use.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        private_key = Ed25519PrivateKey.generate()
        seed_hex = private_key.private_bytes_raw().hex()
        pub_hex = private_key.public_key().public_bytes_raw().hex()
        return seed_hex, pub_hex
    except ImportError:
        print("Install cryptography for key generation: pip install cryptography")
        print("(or use a pre-generated key from `auths id create`)")
        sys.exit(1)


# --- Agent Side ---


def agent_execute_tool(agent_seed_hex: str, agent_did: str, tool_name: str, args: dict) -> str:
    """Agent signs a tool call and returns the signed envelope.

    This would typically be called by a LangChain tool wrapper or similar
    agent framework before sending the request to a server.
    """
    payload = {"tool": tool_name, "args": args}

    envelope_json = sign_action(
        private_key_hex=agent_seed_hex,
        action_type="tool_call",
        payload_json=json.dumps(payload),
        identity_did=agent_did,
    )

    return envelope_json


# --- Server Side ---


def server_verify_and_execute(envelope_json: str, trusted_keys: dict) -> dict:
    """Server verifies the signed envelope and executes the tool call.

    Args:
        envelope_json: The signed action envelope from the agent
        trusted_keys: Mapping of DID -> public key hex for authorized agents

    Returns:
        Execution result or error
    """
    envelope = json.loads(envelope_json)

    # 1. Look up the agent's public key by DID
    identity = envelope.get("identity", "")
    pub_key_hex = trusted_keys.get(identity)
    if pub_key_hex is None:
        return {"error": f"Unknown identity: {identity}"}

    # 2. Verify the signature
    result = verify_action_envelope(envelope_json, pub_key_hex)
    if not result.valid:
        return {"error": f"Signature verification failed: {result.error}"}

    # 3. Execute the tool call (application logic)
    payload = envelope.get("payload", {})
    tool = payload.get("tool", "unknown")
    args = payload.get("args", {})

    print(f"  Verified agent: {identity}")
    print(f"  Executing tool: {tool}")
    print(f"  Arguments: {json.dumps(args, indent=2)}")

    return {"status": "executed", "tool": tool, "result": "success"}


# --- Demo ---


def main():
    print("=== Auths AI Agent Signed Tool Call Demo ===\n")

    # Generate keys for the demo
    agent_seed, agent_pubkey = generate_test_keypair()
    agent_did = "did:keri:EAgent123"

    print(f"Agent DID:        {agent_did}")
    print(f"Agent public key: {agent_pubkey[:16]}...")
    print()

    # Server's trusted key registry
    trusted_keys = {agent_did: agent_pubkey}

    # Agent signs a tool call
    print("1. Agent signs a tool call:")
    envelope_json = agent_execute_tool(
        agent_seed_hex=agent_seed,
        agent_did=agent_did,
        tool_name="execute_sql",
        args={"query": "SELECT COUNT(*) FROM users", "database": "analytics"},
    )

    envelope = json.loads(envelope_json)
    print(f"   Type:      {envelope['type']}")
    print(f"   Identity:  {envelope['identity']}")
    print(f"   Timestamp: {envelope['timestamp']}")
    print(f"   Signature: {envelope['signature'][:32]}...")
    print()

    # Server verifies and executes
    print("2. Server verifies and executes:")
    result = server_verify_and_execute(envelope_json, trusted_keys)
    print(f"   Result: {result}")
    print()

    # Demonstrate rejection of tampered envelope
    print("3. Tampered envelope is rejected:")
    tampered = json.loads(envelope_json)
    tampered["payload"]["args"]["query"] = "DROP TABLE users"
    tampered_json = json.dumps(tampered)

    result = server_verify_and_execute(tampered_json, trusted_keys)
    print(f"   Result: {result}")
    print()

    # Demonstrate rejection of unknown identity
    print("4. Unknown identity is rejected:")
    unknown = json.loads(envelope_json)
    unknown["identity"] = "did:keri:EUnknown"
    unknown_json = json.dumps(unknown)

    result = server_verify_and_execute(unknown_json, trusted_keys)
    print(f"   Result: {result}")


if __name__ == "__main__":
    main()
