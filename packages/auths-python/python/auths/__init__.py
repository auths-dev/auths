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
    CredentialReport,
    CredentialStatus,
    PresentationReport,
    PresentationStatus,
    VerificationReport,
    VerificationResult,
    VerificationStatus,
    generate_inmemory_keypair,
    get_token,
    sign_action,
    sign_artifact_bytes_raw,
    sign_bytes,
    verify_action_envelope,
    verify_at_time,
    verify_attestation,
    verify_chain,
    verify_credential,
    verify_device_authorization,
    verify_presentation,
)
from auths.agent import AgentAuth
from auths.doctor import Check, DiagnosticReport, DoctorService
from auths.audit import (
    AuditReport,
    AuditService,
    AuditSummary,
    CommitRecord,
    IdentityBundleInfo,
    parse_identity_bundle,
    parse_identity_bundle_info,
)
from auths.org import Org, OrgMember, OrgService
from auths.pairing import PairingResponse, PairingResult, PairingService, PairingSession
from auths.trust import TrustEntry, TrustLevel, TrustService
from auths.witness import Witness, WitnessService
from auths.artifact import ArtifactPublishResult, ArtifactSigningResult
from auths.tlog import LogAppendResult, log_append, log_prove, log_verify_inclusion
from auths.attestation_query import Attestation, AttestationService
from auths.commit import CommitSigningResult
from auths.jwt import AuthsClaims
from auths.policy import Outcome, PolicyBuilder, ReasonCode, eval_context_from_commit_result
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
    verify_commit_range,
)

__all__ = [
    # Core verification (the launch use case)
    "verify_attestation",
    "verify_chain",
    "VerificationResult",
    "VerificationReport",
    "VerificationError",

    # Keyless service-to-service verify (Epic D2)
    "verify_presentation",
    "verify_credential",
    "PresentationReport",
    "PresentationStatus",
    "CredentialReport",
    "CredentialStatus",

    # Client
    "Auths",

    # Common types users will encounter
    "AuthsError",
    "ChainLink",
    "VerificationStatus",
]
