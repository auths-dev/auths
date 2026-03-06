"""Key rotation result types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RotationResult:
    """Result of a KERI key rotation ceremony.

    After rotation, old attestations remain valid — verifiers walk the Key Event Log
    to find the key that was active at signing time.
    """

    controller_did: str
    new_key_fingerprint: str
    previous_key_fingerprint: str
    sequence: int

    def __repr__(self) -> str:
        return (
            f"RotationResult(did='{self.controller_did[:25]}...', "
            f"seq={self.sequence}, "
            f"new_key='{self.new_key_fingerprint[:16]}...')"
        )
