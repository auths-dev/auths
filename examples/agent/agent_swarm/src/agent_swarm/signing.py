"""Signed action dispatch with capability enforcement.

Every tool call is signed by the sub-agent's in-process key and embeds the
delegation token issued by the orchestrator — so both the action and its
authorization chain are verifiable from a single envelope.
"""

import json

from auths._native import sign_action

from agent_swarm.identities import SwarmIdentity


class CapabilityError(Exception):
    """Raised when an agent attempts an action outside its granted capabilities."""


def require_capability(identity: SwarmIdentity, capability: str) -> None:
    """Raise CapabilityError if the identity lacks the required capability.

    Args:
        identity: The agent requesting the action.
        capability: The capability the action requires.

    Raises:
        CapabilityError: If the identity's capabilities do not include capability.

    Usage:
        >>> require_capability(data_agent, "read_data")  # passes
        >>> require_capability(data_agent, "notify")     # raises CapabilityError
    """
    if capability not in identity.capabilities:
        raise CapabilityError(
            f"'{identity.name}' lacks '{capability}' capability "
            f"(granted: {identity.capabilities})"
        )


def sign_tool_call(
    identity: SwarmIdentity,
    tool_name: str,
    args: dict,
    required_cap: str,
) -> str:
    """Sign a tool invocation with the agent's key; embed the delegation token.

    The signed payload contains the tool name, args, and the full delegation
    envelope issued by the parent — so a verifier can confirm both the action
    signature and the authorization chain from a single JSON object.

    Args:
        identity: The sub-agent performing the action.
        tool_name: Name of the tool being called.
        args: Keyword arguments passed to the tool.
        required_cap: Capability this tool requires (enforced before signing).

    Returns:
        JSON string of the signed ActionEnvelope.

    Raises:
        CapabilityError: If identity lacks required_cap.

    Usage:
        >>> env = sign_tool_call(data_agent, "read_csv", {"path": "f.csv"}, "read_data")
    """
    require_capability(identity, required_cap)

    payload: dict = {"tool": tool_name, "args": args}
    if identity.delegation_token:
        payload["delegation_token"] = json.loads(identity.delegation_token)

    payload_json = json.dumps(payload, sort_keys=True)
    return sign_action(identity.priv_hex, "tool_call", payload_json, identity.did)
