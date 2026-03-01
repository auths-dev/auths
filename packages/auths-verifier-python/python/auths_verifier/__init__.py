"""
Auths Verifier - Attestation verification library

This package provides cryptographic verification of Auths attestations.

Example:
    >>> from auths_verifier import verify_attestation, verify_chain
    >>>
    >>> # Verify a single attestation
    >>> result = verify_attestation(attestation_json, issuer_pk_hex)
    >>> if result.valid:
    ...     print("Valid!")
    >>>
    >>> # Verify a chain of attestations
    >>> report = verify_chain([att1_json, att2_json], root_pk_hex)
    >>> if report.is_valid():
    ...     print("Chain verified!")
"""

from auths_verifier._native import (
    VerificationResult,
    VerificationStatus,
    ChainLink,
    VerificationReport,
    verify_attestation,
    verify_chain,
    verify_device_authorization,
    sign_bytes,
    sign_action,
    verify_action_envelope,
)
from auths_verifier.git import (
    CommitResult,
    ErrorCode,
    LayoutError,
    LayoutInfo,
    VerifyResult,
    discover_layout,
    verify_commit_range,
)

from importlib.metadata import version as _pkg_version, PackageNotFoundError

try:
    __version__ = _pkg_version("auths-verifier")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
__all__ = [
    "VerificationResult",
    "VerificationStatus",
    "ChainLink",
    "VerificationReport",
    "verify_attestation",
    "verify_chain",
    "verify_device_authorization",
    "sign_bytes",
    "sign_action",
    "verify_action_envelope",
    "CommitResult",
    "ErrorCode",
    "VerifyResult",
    "LayoutInfo",
    "LayoutError",
    "discover_layout",
    "verify_commit_range",
]
