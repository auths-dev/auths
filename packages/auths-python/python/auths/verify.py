from __future__ import annotations

import json
from dataclasses import dataclass

from auths._native import (
    verify_at_time,
    verify_at_time_with_capability,
    verify_attestation,
    verify_attestation_with_capability,
    verify_chain,
    verify_chain_with_capability,
    verify_chain_with_witnesses as _verify_chain_with_witnesses,
    verify_device_authorization,
)


@dataclass
class WitnessKey:
    """A witness node's identity and public key."""

    did: str
    """The witness node's DID."""
    public_key_hex: str
    """Hex-encoded Ed25519 public key of the witness."""

    def __repr__(self) -> str:
        return f"WitnessKey(did='{self.did[:20]}...')"


@dataclass
class WitnessConfig:
    """Configuration for witness quorum verification.

    Usage:
        config = WitnessConfig(
            receipts=[receipt1_json, receipt2_json],
            keys=[WitnessKey("did:key:z...", "ab12...")],
            threshold=2,
        )
    """

    receipts: list[str]
    """JSON-serialized witness receipt strings."""
    keys: list[WitnessKey]
    """Witness public keys to verify receipts against."""
    threshold: int
    """Minimum number of valid witness receipts required."""

    def __post_init__(self):
        if self.threshold < 1:
            raise ValueError(f"threshold must be >= 1, got {self.threshold}")
        if self.threshold > len(self.keys):
            raise ValueError(
                f"threshold ({self.threshold}) cannot exceed number of "
                f"witness keys ({len(self.keys)})"
            )


def verify_chain_with_witnesses(
    attestations_json: list[str],
    root_pk_hex: str,
    witnesses: WitnessConfig,
):
    """Verify an attestation chain with witness receipt quorum enforcement.

    Args:
        attestations_json: List of attestation JSON strings, ordered root-to-leaf.
        root_pk_hex: Root identity's Ed25519 public key (hex-encoded).
        witnesses: Witness configuration with receipts, keys, and threshold.

    Usage:
        report = verify_chain_with_witnesses(chain, root_key, config)
    """
    keys_json = [
        json.dumps({"did": k.did, "public_key_hex": k.public_key_hex})
        for k in witnesses.keys
    ]
    return _verify_chain_with_witnesses(
        attestations_json,
        root_pk_hex,
        witnesses.receipts,
        keys_json,
        witnesses.threshold,
    )


__all__ = [
    "WitnessConfig",
    "WitnessKey",
    "verify_at_time",
    "verify_at_time_with_capability",
    "verify_attestation",
    "verify_attestation_with_capability",
    "verify_chain",
    "verify_chain_with_capability",
    "verify_chain_with_witnesses",
    "verify_device_authorization",
]
