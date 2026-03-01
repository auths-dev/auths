"""Type stubs for auths_verifier"""

from typing import Optional, List
from dataclasses import dataclass

class VerificationResult:
    """Result of a single attestation verification."""

    valid: bool
    """Whether the attestation is valid."""

    error: Optional[str]
    """Error message if verification failed."""

    def __bool__(self) -> bool:
        """Returns True if valid."""
        ...

class VerificationStatus:
    """Status of a verification operation."""

    status_type: str
    """Type of status: 'Valid', 'Expired', 'Revoked', 'InvalidSignature', 'BrokenChain'."""

    at: Optional[str]
    """Timestamp (ISO 8601) for Expired/Revoked status."""

    step: Optional[int]
    """Step number for InvalidSignature status."""

    missing_link: Optional[str]
    """Missing link identifier for BrokenChain status."""

    def is_valid(self) -> bool:
        """Returns True if status is Valid."""
        ...

class ChainLink:
    """A single link in the attestation chain."""

    issuer: str
    """Issuer DID."""

    subject: str
    """Subject DID."""

    valid: bool
    """Whether this link verified successfully."""

    error: Optional[str]
    """Error message if verification failed."""

class VerificationReport:
    """Complete verification report for chain verification."""

    status: VerificationStatus
    """Overall status of the verification."""

    chain: List[ChainLink]
    """Details of each link in the chain."""

    warnings: List[str]
    """Warnings (non-fatal issues)."""

    def is_valid(self) -> bool:
        """Returns True if status is Valid."""
        ...

def verify_attestation(
    attestation_json: str, issuer_pk_hex: str
) -> VerificationResult:
    """
    Verify a single attestation against an issuer's public key.

    Args:
        attestation_json: The attestation as a JSON string
        issuer_pk_hex: The issuer's Ed25519 public key in hex format (64 chars)

    Returns:
        VerificationResult with valid flag and optional error message

    Raises:
        ValueError: If the input is invalid (bad JSON, invalid hex, wrong key length)
    """
    ...

def verify_chain(
    attestations_json: List[str], root_pk_hex: str
) -> VerificationReport:
    """
    Verify a chain of attestations from a root identity to a leaf device.

    Args:
        attestations_json: List of attestation JSON strings
        root_pk_hex: The root identity's Ed25519 public key in hex format

    Returns:
        VerificationReport with status, chain details, and warnings

    Raises:
        ValueError: If the input is invalid
        RuntimeError: If chain verification encounters an internal error
    """
    ...

def verify_device_authorization(
    identity_did: str,
    device_did: str,
    attestations_json: List[str],
    identity_pk_hex: str,
) -> VerificationReport:
    """
    Full cryptographic verification that a device is authorized.

    Unlike `is_device_listed()`, this function verifies cryptographic signatures
    to ensure attestations have not been forged or tampered with.

    Args:
        identity_did: The identity DID string
        device_did: The device DID string
        attestations_json: List of attestation JSON strings
        identity_pk_hex: The identity's Ed25519 public key in hex format (64 chars)

    Returns:
        VerificationReport with verification details

    Raises:
        ValueError: If the input is invalid
        RuntimeError: If verification encounters an internal error
    """
    ...

def sign_bytes(private_key_hex: str, message: bytes) -> str:
    """
    Sign arbitrary bytes with an Ed25519 private key.

    Args:
        private_key_hex: Ed25519 seed (private key) as hex string (64 chars = 32 bytes)
        message: The bytes to sign

    Returns:
        Hex-encoded Ed25519 signature (128 chars = 64 bytes)

    Raises:
        ValueError: If the private key hex is invalid or wrong length
        RuntimeError: If signing fails

    Security Note:
        Python strings are immutable and not zeroizable. For production use,
        store keys in a secure enclave or secret manager.
    """
    ...

def sign_action(
    private_key_hex: str,
    action_type: str,
    payload_json: str,
    identity_did: str,
) -> str:
    """
    Sign an action envelope per the Auths action envelope specification.

    Builds a signed JSON envelope with version, type, identity, payload,
    timestamp, and signature fields. Uses JSON Canonicalization (RFC 8785)
    for the signing input.

    Args:
        private_key_hex: Ed25519 seed as hex string (64 chars = 32 bytes)
        action_type: Application-defined action type (e.g. "tool_call")
        payload_json: JSON string for the payload field
        identity_did: Signer's identity DID (e.g. "did:keri:E...")

    Returns:
        JSON string of the complete signed envelope

    Raises:
        ValueError: If the private key hex or payload JSON is invalid
        RuntimeError: If signing or canonicalization fails
    """
    ...

def verify_action_envelope(
    envelope_json: str, public_key_hex: str
) -> VerificationResult:
    """
    Verify an action envelope's Ed25519 signature.

    Reconstructs the canonical signing input from the envelope fields
    (excluding signature), then verifies the Ed25519 signature.

    Args:
        envelope_json: The complete action envelope as a JSON string
        public_key_hex: The signer's Ed25519 public key in hex format (64 chars)

    Returns:
        VerificationResult with valid flag and optional error message

    Raises:
        ValueError: If the public key hex or envelope JSON is invalid
    """
    ...

class ErrorCode:
    """Stable error codes for commit verification failures."""

    UNSIGNED: str
    GPG_NOT_SUPPORTED: str
    UNKNOWN_SIGNER: str
    INVALID_SIGNATURE: str
    NO_ATTESTATION_FOUND: str
    DEVICE_REVOKED: str
    DEVICE_EXPIRED: str
    LAYOUT_DISCOVERY_FAILED: str

@dataclass
class CommitResult:
    """Result of verifying a single commit's SSH signature (evidence)."""

    commit_sha: str
    """The full SHA of the commit, or ``"<layout>"`` for layout errors."""

    is_valid: bool
    """Whether the commit signature is valid."""

    signer: Optional[str]
    """Principal who signed, if identified."""

    error: Optional[str]
    """Error message if verification failed."""

    error_code: Optional[str]
    """One of :class:`ErrorCode` constants, or ``None`` on success."""

@dataclass
class VerifyResult:
    """Wrapper around commit verification results (decision)."""

    commits: List[CommitResult]
    """Per-commit verification results."""

    passed: bool
    """``True`` if the policy allows merge."""

    mode: str
    """``"enforce"`` or ``"warn"``."""

    summary: str
    """Human-readable summary, e.g. ``"3/3 commits verified"``."""

@dataclass
class LayoutInfo:
    """Resolved location of Auths identity data in a repository."""

    bundle: Optional[str]
    """Path to identity-bundle.json, if found."""

    refs: Optional[List[str]]
    """List of refs/auths/* ref names, if found."""

    source: str
    """How the layout was discovered: ``"file"`` or ``"git-refs"``."""

class LayoutError(Exception):
    """Raised when Auths identity data cannot be found in the repo."""

    code: str
    """Error code (``ErrorCode.LAYOUT_DISCOVERY_FAILED``)."""

    def __init__(self, code: str, message: str) -> None: ...

def discover_layout(repo_root: str = ".") -> LayoutInfo:
    """
    Try to find Auths identity data in the repo.

    Checks ``.auths/identity-bundle.json`` then ``refs/auths/*``.

    Args:
        repo_root: Path to the repository root

    Returns:
        LayoutInfo with resolved paths

    Raises:
        LayoutError: If no identity data found
    """
    ...

def verify_commit_range(
    commit_range: str,
    identity_bundle: Optional[str] = None,
    allowed_signers: str = ".auths/allowed_signers",
    mode: str = "enforce",
) -> VerifyResult:
    """
    Verify SSH signatures for every commit in a git revision range.

    Requires ``git`` and ``ssh-keygen`` on PATH.

    Args:
        commit_range: A git revision range (e.g. ``origin/main..HEAD``)
        identity_bundle: Path to an Auths identity-bundle JSON file
        allowed_signers: Path to an ssh-keygen allowed_signers file
        mode: ``"enforce"`` or ``"warn"``

    Returns:
        VerifyResult with per-commit results and a pass/fail decision

    Raises:
        ValueError: If mode is not ``"enforce"`` or ``"warn"``
    """
    ...
