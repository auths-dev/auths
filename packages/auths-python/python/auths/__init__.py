"""Auths Python SDK — decentralized identity for developers and AI agents."""

from auths._client import Auths
from auths._errors import (
    AuthsError,
    CryptoError,
    IdentityError,
    KeychainError,
    NetworkError,
    OrgError,
    PairingError,
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
from auths.doctor import Check, DiagnosticReport, DoctorService
from auths.audit import AuditReport, AuditService, AuditSummary, CommitRecord
from auths.org import Org, OrgMember, OrgService
from auths.pairing import PairingResponse, PairingResult, PairingService, PairingSession
from auths.trust import TrustEntry, TrustService
from auths.witness import Witness, WitnessService
from auths.artifact import ArtifactPublishResult, ArtifactSigningResult
from auths.attestation_query import Attestation, AttestationService
from auths.commit import CommitSigningResult
from auths.jwt import AuthsClaims
from auths.policy import PolicyBuilder
from auths.devices import Device, DeviceExtension, DeviceService
from auths.identity import AgentIdentity, DelegatedAgent, Identity, IdentityService
from auths.rotation import IdentityRotationResult
from auths.verify import WitnessConfig, WitnessKey, verify_chain_with_witnesses
from auths.policy import compile_policy
from auths.git import (
    CommitResult,
    ErrorCode,
    LayoutError,
    LayoutInfo,
    VerifyResult,
    discover_layout,
    generate_allowed_signers,
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
    "verify_chain_with_witnesses",
    "verify_device_authorization",
    "sign_bytes",
    "sign_action",
    "verify_action_envelope",
    "get_token",
    "AgentAuth",
    "ArtifactPublishResult",
    "ArtifactSigningResult",
    "Attestation",
    "AttestationService",
    "CommitSigningResult",
    "AuthsClaims",
    "PolicyBuilder",
    "compile_policy",
    "CommitResult",
    "ErrorCode",
    "VerifyResult",
    "LayoutInfo",
    "LayoutError",
    "discover_layout",
    "generate_allowed_signers",
    "verify_commit_range",
    "Identity",
    "AgentIdentity",
    "DelegatedAgent",
    "IdentityService",
    "Device",
    "DeviceExtension",
    "DeviceService",
    "IdentityRotationResult",
    "WitnessConfig",
    "WitnessKey",
    "Org",
    "OrgMember",
    "OrgService",
    "OrgError",
    "AuditReport",
    "AuditService",
    "AuditSummary",
    "CommitRecord",
    "TrustEntry",
    "TrustService",
    "Witness",
    "WitnessService",
    "Check",
    "DiagnosticReport",
    "DoctorService",
    "PairingResponse",
    "PairingResult",
    "PairingService",
    "PairingSession",
    "PairingError",
]
