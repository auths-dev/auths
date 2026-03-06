from typing import List, Optional
from dataclasses import dataclass

# -- Client --

class Auths:
    repo_path: str
    identities: IdentityService
    devices: DeviceService
    def __init__(self, repo_path: str = "~/.auths", passphrase: Optional[str] = None) -> None: ...
    def verify(self, attestation_json: str, issuer_key: str) -> VerificationResult: ...
    def verify_chain(self, attestations: List[str], root_key: str) -> VerificationReport: ...
    def verify_device(self, identity_did: str, device_did: str, attestations: List[str], identity_key: str) -> VerificationReport: ...
    def sign(self, message: bytes, private_key: str) -> str: ...
    def sign_action(self, action_type: str, payload: str, identity_did: str, private_key: str) -> str: ...
    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult: ...
    def get_token(self, bridge_url: str, chain_json: str, root_key: str, capabilities: Optional[List[str]] = None) -> str: ...

# -- Errors --

class AuthsError(Exception):
    message: str
    code: str
    context: dict
    def __init__(self, message: str, code: str, **context: object) -> None: ...

class VerificationError(AuthsError): ...
class CryptoError(AuthsError): ...
class KeychainError(AuthsError): ...
class StorageError(AuthsError): ...

class NetworkError(AuthsError):
    should_retry: bool
    def __init__(self, message: str, code: str, should_retry: bool = False, **context: object) -> None: ...

class IdentityError(AuthsError): ...

# -- Native types --

class VerificationResult:
    valid: bool
    error: Optional[str]
    def __bool__(self) -> bool: ...

class VerificationStatus:
    status_type: str
    at: Optional[str]
    step: Optional[int]
    missing_link: Optional[str]
    required: Optional[int]
    verified: Optional[int]
    def is_valid(self) -> bool: ...

class ChainLink:
    issuer: str
    subject: str
    valid: bool
    error: Optional[str]

class VerificationReport:
    status: VerificationStatus
    chain: List[ChainLink]
    warnings: List[str]
    def is_valid(self) -> bool: ...

# -- Verify functions --

def verify_attestation(attestation_json: str, issuer_pk_hex: str) -> VerificationResult: ...
def verify_chain(attestations_json: List[str], root_pk_hex: str) -> VerificationReport: ...
def verify_device_authorization(identity_did: str, device_did: str, attestations_json: List[str], identity_pk_hex: str) -> VerificationReport: ...

# -- Sign functions --

def sign_bytes(private_key_hex: str, message: bytes) -> str: ...
def sign_action(private_key_hex: str, action_type: str, payload_json: str, identity_did: str) -> str: ...
def verify_action_envelope(envelope_json: str, public_key_hex: str) -> VerificationResult: ...

# -- Token --

def get_token(bridge_url: str, chain_json: str, root_public_key: str, capabilities: List[str]) -> str: ...

# -- Identity resources --

@dataclass
class Identity:
    did: str
    public_key: str
    label: str
    repo_path: str

@dataclass
class Agent:
    did: str
    label: str
    attestation: str

class IdentityService:
    def create(self, label: str = "main", repo_path: Optional[str] = None, passphrase: Optional[str] = None) -> Identity: ...
    def provision_agent(self, identity_did: str, name: str, capabilities: List[str], expires_in_secs: Optional[int] = None, passphrase: Optional[str] = None) -> Agent: ...

# -- Device resources --

@dataclass
class Device:
    did: str
    attestation_id: str

class DeviceService:
    def link(self, identity_did: str, capabilities: Optional[List[str]] = None, expires_in_days: Optional[int] = None, passphrase: Optional[str] = None) -> Device: ...
    def revoke(self, device_did: str, identity_did: str, note: Optional[str] = None, passphrase: Optional[str] = None) -> None: ...

# -- Agent --

class AgentAuth:
    bridge_url: str
    def __init__(self, bridge_url: str, attestation_chain_path: str, root_public_key: Optional[str] = None) -> None: ...
    def get_token(self, capabilities: Optional[List[str]] = None) -> str: ...

AuthsAgentAuth = AgentAuth

# -- Git --

class ErrorCode:
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
    commit_sha: str
    is_valid: bool
    signer: Optional[str]
    error: Optional[str]
    error_code: Optional[str]

@dataclass
class VerifyResult:
    commits: List[CommitResult]
    passed: bool
    mode: str
    summary: str

@dataclass
class LayoutInfo:
    bundle: Optional[str]
    refs: Optional[List[str]]
    source: str

class LayoutError(Exception):
    code: str
    def __init__(self, code: str, message: str) -> None: ...

def discover_layout(repo_root: str = ".") -> LayoutInfo: ...
def verify_commit_range(commit_range: str, identity_bundle: Optional[str] = None, allowed_signers: str = ".auths/allowed_signers", mode: str = "enforce") -> VerifyResult: ...
