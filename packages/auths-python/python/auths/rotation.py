"""Key rotation result types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IdentityRotationResult:
    """Result of a KERI key rotation ceremony.

    After rotation, old attestations remain valid — verifiers walk the Key Event Log
    to find the key that was active at signing time.
    """

    controller_did: str
    """The identity's KERI DID."""
    new_key_fingerprint: str
    """Fingerprint of the newly rotated-in key."""
    previous_key_fingerprint: str
    """Fingerprint of the key that was rotated out."""
    sequence: int
    """KERI sequence number after rotation."""

    def __repr__(self) -> str:
        return (
            f"IdentityRotationResult(did='{self.controller_did[:25]}...', "
            f"seq={self.sequence}, "
            f"new_key='{self.new_key_fingerprint[:16]}...')"
        )
