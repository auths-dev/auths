"""Auths Python SDK — decentralized identity for developers and AI agents."""

from auths._client import Auths
from auths._errors import (
    AuthsError,
    CryptoError,
    IdentityError,
    KeychainError,
    NetworkError,
    StorageError,
    VerificationError,
)
from auths._native import (
    ChainLink,
    VerificationReport,
    VerificationResult,
    VerificationStatus,
    get_token,
    sign_action,
    sign_bytes,
    verify_action_envelope,
    verify_at_time,
    verify_at_time_with_capability,
    verify_attestation,
    verify_attestation_with_capability,
    verify_chain,
    verify_chain_with_capability,
    verify_device_authorization,
)
from auths.agent import AgentAuth
from auths.devices import Device, DeviceService
from auths.identity import Agent, Identity, IdentityService
from auths.rotation import RotationResult
from auths.verify import WitnessConfig, WitnessKey
from auths.git import (
    CommitResult,
    ErrorCode,
    LayoutError,
    LayoutInfo,
    VerifyResult,
    discover_layout,
    verify_commit_range,
)

__all__ = [
    "Auths",
    "AuthsError",
    "VerificationError",
    "CryptoError",
    "KeychainError",
    "StorageError",
    "NetworkError",
    "IdentityError",
    "VerificationResult",
    "VerificationStatus",
    "ChainLink",
    "VerificationReport",
    "verify_at_time",
    "verify_at_time_with_capability",
    "verify_attestation",
    "verify_chain",
    "verify_attestation_with_capability",
    "verify_chain_with_capability",
    "verify_device_authorization",
    "sign_bytes",
    "sign_action",
    "verify_action_envelope",
    "get_token",
    "AgentAuth",
    "CommitResult",
    "ErrorCode",
    "VerifyResult",
    "LayoutInfo",
    "LayoutError",
    "discover_layout",
    "verify_commit_range",
    "Identity",
    "Agent",
    "IdentityService",
    "Device",
    "DeviceService",
    "RotationResult",
    "WitnessConfig",
    "WitnessKey",
]
