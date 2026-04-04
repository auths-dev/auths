"""Testing helpers — lightweight, no filesystem/keychain/Git required."""

from auths._native import (
    generate_inmemory_keypair,
    sign_bytes,
    sign_action,
    verify_action_envelope,
)


class EphemeralIdentity:
    """In-memory identity for tests, demos, and CI.

    Generates a fresh Ed25519 keypair on construction. The resulting DID is
    ``did:key:z...`` (not ``did:keri:``), which is valid for ``sign_action``
    and ``verify_action_envelope`` but cannot be used with KERI operations.

    Usage::

        from auths.testing import EphemeralIdentity

        alice = EphemeralIdentity()
        sig = alice.sign(b"hello")
        envelope = alice.sign_action("tool_call", '{"tool": "web_search"}')
        result = alice.verify_action(envelope)
        assert result.valid
    """

    def __init__(self) -> None:
        private_key, public_key, did = generate_inmemory_keypair()
        self._private_key_hex = private_key
        self._public_key_hex = public_key
        self._did = did

    @property
    def did(self) -> str:
        """The ``did:key:z...`` identifier for this ephemeral identity."""
        return self._did

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded 32-byte Ed25519 public key."""
        return self._public_key_hex

    @property
    def private_key_hex(self) -> str:
        """Hex-encoded 32-byte Ed25519 seed (private key)."""
        return self._private_key_hex

    def sign(self, message: bytes) -> str:
        """Sign arbitrary bytes. Returns hex-encoded signature."""
        return sign_bytes(self._private_key_hex, message)

    def sign_action(self, action_type: str, payload_json: str) -> str:
        """Sign an action envelope. Returns JSON envelope string."""
        return sign_action(self._private_key_hex, action_type, payload_json, self._did)

    def verify_action(self, envelope_json: str):
        """Verify an action envelope against this identity's public key."""
        return verify_action_envelope(envelope_json, self._public_key_hex)
