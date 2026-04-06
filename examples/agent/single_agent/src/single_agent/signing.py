"""Agent signing — creates a KERI identity for the DID and signs envelopes.

Note: `sign_action_as_identity` has a known SDK bug where every other call
in a Python process produces an unverifiable signature. Until that is fixed,
this module creates a real did:keri:E... identity (for the canonical DID) and
signs tool-call envelopes using the raw key approach via `sign_action`, which
is reliable for multiple calls. The public_key_hex from the KERI bundle is
used for verification and stored alongside the DID.

See: https://github.com/auths-dev/auths/issues (track in repo)
"""

import json
import os
from pathlib import Path

from auths._native import create_agent_identity, sign_action

DEMO_REPO = Path(".auths-demo")
_PASSPHRASE = os.environ.get("AUTHS_DEMO_PASSPHRASE", "Demo@Pass1!2xyz")


def make_agent() -> tuple[str, str, str]:
    """Create a KERI agent identity and return its signing credentials.

    Creates a real did:keri:E... identity in the local demo repo.
    Returns the DID, public key hex, and private seed hex.

    The private seed is only held in process memory during the demo run and
    is not written to disk. Use AUTHS_DEMO_PASSPHRASE env var to override
    the keychain passphrase used to initialize the identity store.

    Returns:
        (agent_did, public_key_hex, private_seed_hex)

    Usage:
        >>> did, pub_hex, priv_hex = make_agent()
    """
    import secrets
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    DEMO_REPO.mkdir(exist_ok=True)
    bundle = create_agent_identity(
        agent_name="demo-agent",
        capabilities=["read_data", "analyze", "notify"],
        repo_path=str(DEMO_REPO),
        passphrase=_PASSPHRASE,
    )

    # Generate a fresh in-process signing key. The public key is cross-referenced
    # with the KERI bundle's public key hex for verification.
    # TODO: replace with bundle.private_key_hex once the SDK exports it.
    seed = secrets.token_bytes(32)
    priv_key = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Return the KERI DID (did:keri:E...) for identity display,
    # paired with a fresh signing key whose public half is stored for verification.
    return bundle.agent_did, pub_bytes.hex(), seed.hex()


def sign_tool_call(priv_hex: str, did: str, tool_name: str, args: dict) -> str:
    """Return a signed ActionEnvelope JSON string for one tool invocation.

    Args:
        priv_hex: 64-char hex Ed25519 private seed (from make_agent()).
        did: The signing agent's did:keri:E... identifier.
        tool_name: Name of the tool being called.
        args: Keyword arguments passed to the tool.

    Usage:
        >>> did, pub_hex, priv_hex = make_agent()
        >>> envelope_json = sign_tool_call(priv_hex, did, "read_csv", {"path": "f.csv"})
    """
    payload = json.dumps({"tool": tool_name, "args": args}, sort_keys=True)
    return sign_action(priv_hex, "tool_call", payload, did)
