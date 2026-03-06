"""Artifact attestation signing — Stripe-style API."""

from __future__ import annotations

from dataclasses import dataclass


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


@dataclass
class ArtifactSigningResult:
    """Result of signing a file or byte artifact.

    The `.attestation_json` can be shipped alongside the artifact for
    downstream verification. The `.digest` and `.rid` identify the artifact.
    """

    attestation_json: str
    rid: str
    digest: str
    file_size: int

    def __repr__(self) -> str:
        size = _human_size(self.file_size)
        rid_short = self.rid[:24] if len(self.rid) > 24 else self.rid
        return f"ArtifactSigningResult(rid='{rid_short}...', size={size})"


@dataclass
class ArtifactPublishResult:
    """Result of publishing an artifact attestation to a registry.

    The `.attestation_rid` is the stable registry identifier for the stored
    attestation. Use it to reference the attestation in future queries.
    """

    attestation_rid: str
    package_name: str | None
    signer_did: str

    def __repr__(self) -> str:
        rid_short = self.attestation_rid[:20] + "..." if len(self.attestation_rid) > 20 else self.attestation_rid
        did_tail = self.signer_did[-12:]
        pkg = f", pkg={self.package_name!r}" if self.package_name else ""
        return f"ArtifactPublishResult(rid='{rid_short}'{pkg}, signer='…{did_tail}')"
