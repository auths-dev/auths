"""Transparency log — append artifact digests, prove inclusion, and verify it offline.

The append/prove/verify logic lives in the Rust SDK (`auths_sdk::workflows::transparency`)
and the offline verifier (`auths_verifier::evidence_pack`); this module is a thin,
Pythonic wrapper over the native bindings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from auths._native import log_append as _log_append
from auths._native import log_prove as _log_prove
from auths._native import log_verify_inclusion as _log_verify_inclusion

PathLike = Union[str, "Path"]


@dataclass
class LogAppendResult:
    """Outcome of appending an artifact digest to a local transparency log.

    Pin `.log_public_key` to later verify the evidence `log_prove` mints; the
    `.checkpoint_json` is the full signed checkpoint the leaf is anchored to.
    """

    artifact_digest: str
    """Canonical ``sha256:<hex>`` digest that was logged."""
    leaf_hash: str
    """Hex-encoded Merkle leaf hash the digest was stored under."""
    index: int
    """Zero-based index the leaf was sequenced at."""
    size: int
    """Tree size of the checkpoint that now includes the leaf."""
    root: str
    """Hex-encoded Merkle root of that checkpoint."""
    origin: str
    """The log's origin line."""
    log_public_key: str
    """Hex-encoded Ed25519 key the checkpoint is signed with."""
    checkpoint_json: str
    """The full signed checkpoint, JSON-serialized."""

    def __repr__(self) -> str:
        return f"LogAppendResult(index={self.index}, size={self.size}, origin={self.origin!r})"


def log_append(
    artifact_digest: str,
    log_dir: PathLike,
    origin: str = "auths.local/log",
) -> LogAppendResult:
    """Append an artifact digest to a local tile-backed transparency log.

    Creates the log directory and signing key on first use. The log is
    append-only: repeated calls grow the tree and return increasing indices.

    Args:
        artifact_digest: The digest to log (``sha256:<64 hex>``).
        log_dir: Directory holding the tile store and ``log.key``.
        origin: The log's origin line, written into every checkpoint.

    Returns:
        A :class:`LogAppendResult` with the sequenced position and checkpoint.
    """
    r = _log_append(artifact_digest, str(log_dir), origin)
    return LogAppendResult(
        artifact_digest=r.artifact_digest,
        leaf_hash=r.leaf_hash,
        index=r.index,
        size=r.size,
        root=r.root,
        origin=r.origin,
        log_public_key=r.log_public_key,
        checkpoint_json=r.checkpoint_json,
    )


def log_prove(
    artifact_digest: str,
    log_dir: PathLike,
    origin: str = "auths.local/log",
) -> str:
    """Emit offline inclusion evidence (JSON) for an already-appended digest.

    Args:
        artifact_digest: The digest to prove (``sha256:<64 hex>``).
        log_dir: Directory holding the tile store and ``log.key``.
        origin: The log's origin line (must match the appended log).

    Returns:
        A serialized ``TransparencyInclusion`` verifiable with zero network.
    """
    return _log_prove(artifact_digest, str(log_dir), origin)


def log_verify_inclusion(
    evidence_json: str,
    artifact_digest: str,
    log_public_key: str,
) -> bool:
    """Verify inclusion evidence against a pinned log key, fully offline.

    Fail-closed: the evidence must bind to this artifact (leaf re-derives from
    the digest), the Merkle proof must verify against the embedded signed
    checkpoint, and that checkpoint must be signed by ``log_public_key``. A
    forged, absent, or mismatched proof raises :class:`ValueError`.

    Args:
        evidence_json: The serialized inclusion evidence from :func:`log_prove`.
        artifact_digest: The canonical ``sha256:<hex>`` digest to bind to.
        log_public_key: Hex-encoded Ed25519 key the checkpoint must be signed by.

    Returns:
        ``True`` on success; raises ``ValueError`` on any failure.
    """
    return _log_verify_inclusion(evidence_json, artifact_digest, log_public_key)
