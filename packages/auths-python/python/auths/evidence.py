"""Evidence-layer surface: spend re-derivation, offline bundle verification, and
activity-attestation checks — the Rust ``auths-evidence`` trust core, verbatim.

A tool author never implements crypto: every function here returns the versioned
JSON contract (``audit/v1``, ``receipts/v1``, ``activity/v1``) computed by the
same Rust implementation the gateway CLI and the first-party servers run.

Usage:
    import auths.evidence as evidence
    report = evidence.verify_spend(log, registry, agent, root)
    verdict = evidence.verify_offline(bundle)
    assert verdict["ok"] and verdict["tx"] == my_disputed_tx  # S4 binding
"""

from __future__ import annotations

import json
from typing import Any

from . import _native


def verify_spend(log_path: str, registry_path: str, agent: str, root: str) -> dict[str, Any]:
    """Re-derive an agent's spend from its signed log (the ``audit/v1`` report)."""
    return json.loads(_native.verify_spend(log_path, registry_path, agent, root))


def verify_offline(bundle: dict[str, Any] | str) -> dict[str, Any]:
    """Fully-offline verification of a ``receipts/v1`` EvidenceBundle.

    Always assert the echoed ``subject`` / ``tx`` / ``callIndex`` match the
    transaction YOU are adjudicating (security S4) — a valid bundle about a
    different call is not evidence about yours.
    """
    raw = bundle if isinstance(bundle, str) else json.dumps(bundle)
    return json.loads(_native.verify_offline(raw))


def verify_activity(attestation: dict[str, Any] | str, registry_path: str) -> dict[str, Any]:
    """Verify a published ``activity/v1`` attestation against a registry copy
    (identity resolution only — no per-call data is ever fetched)."""
    raw = attestation if isinstance(attestation, str) else json.dumps(attestation)
    return json.loads(_native.verify_activity(raw, registry_path))


def receipts_v1_schema() -> dict[str, Any]:
    """The ``receipts/v1`` JSON schema."""
    return json.loads(_native.receipts_v1_schema())


def audit_v1_schema() -> dict[str, Any]:
    """The ``audit/v1`` JSON schema."""
    return json.loads(_native.audit_v1_schema())
