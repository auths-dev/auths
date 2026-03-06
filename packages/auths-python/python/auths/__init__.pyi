from dataclasses import dataclass

# -- Client --

class Auths:
    repo_path: str
    identities: IdentityService
    devices: DeviceService
    def __init__(self, repo_path: str = "~/.auths", passphrase: str | None = None) -> None: ...
    def verify(self, attestation_json: str, issuer_key: str, required_capability: str | None = None, at: str | None = None) -> VerificationResult: ...
    def verify_chain(self, attestations: list[str], root_key: str, required_capability: str | None = None, witnesses: WitnessConfig | None = None) -> VerificationReport: ...
    def verify_device(self, identity_did: str, device_did: str, attestations: list[str], identity_key: str) -> VerificationReport: ...
    def sign(self, message: bytes, private_key: str) -> str: ...
    def sign_action(self, action_type: str, payload: str, identity_did: str, private_key: str) -> str: ...
    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult: ...
    def sign_as(self, message: bytes, identity: str, passphrase: str | None = None) -> str: ...
    def sign_action_as(self, action_type: str, payload: str, identity: str, passphrase: str | None = None) -> str: ...
    def get_token(self, bridge_url: str, chain_json: str, root_key: str, capabilities: list[str] | None = None) -> str: ...

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
    error: str | None
    def __bool__(self) -> bool: ...

class VerificationStatus:
    status_type: str
    at: str | None
    step: int | None
    missing_link: str | None
    required: int | None
    verified: int | None
    def is_valid(self) -> bool: ...

class ChainLink:
    issuer: str
    subject: str
    valid: bool
    error: str | None

class VerificationReport:
    status: VerificationStatus
    chain: list[ChainLink]
    warnings: list[str]
    def is_valid(self) -> bool: ...

# -- Verify functions --

@dataclass
class WitnessKey:
    did: str
    public_key_hex: str

@dataclass
class WitnessConfig:
    receipts: list[str]
    keys: list[WitnessKey]
    threshold: int

def verify_at_time(attestation_json: str, issuer_pk_hex: str, at_rfc3339: str) -> VerificationResult: ...
def verify_at_time_with_capability(attestation_json: str, issuer_pk_hex: str, at_rfc3339: str, required_capability: str) -> VerificationResult: ...
def verify_attestation(attestation_json: str, issuer_pk_hex: str) -> VerificationResult: ...
def verify_chain(attestations_json: list[str], root_pk_hex: str) -> VerificationReport: ...
def verify_attestation_with_capability(attestation_json: str, issuer_pk_hex: str, required_capability: str) -> VerificationResult: ...
def verify_chain_with_capability(attestations_json: list[str], root_pk_hex: str, required_capability: str) -> VerificationReport: ...
def verify_device_authorization(identity_did: str, device_did: str, attestations_json: list[str], identity_pk_hex: str) -> VerificationReport: ...

# -- Sign functions --

def sign_bytes(private_key_hex: str, message: bytes) -> str: ...
def sign_action(private_key_hex: str, action_type: str, payload_json: str, identity_did: str) -> str: ...
def verify_action_envelope(envelope_json: str, public_key_hex: str) -> VerificationResult: ...

# -- Token --

def get_token(bridge_url: str, chain_json: str, root_public_key: str, capabilities: list[str]) -> str: ...

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

@dataclass
class RotationResult:
    controller_did: str
    new_key_fingerprint: str
    previous_key_fingerprint: str
    sequence: int

class IdentityService:
    def create(self, label: str = "main", repo_path: str | None = None, passphrase: str | None = None) -> Identity: ...
    def rotate(self, identity_did: str, *, passphrase: str | None = None) -> RotationResult: ...
    def provision_agent(self, identity_did: str, name: str, capabilities: list[str], expires_in_secs: int | None = None, passphrase: str | None = None) -> Agent: ...

# -- Device resources --

@dataclass
class Device:
    did: str
    attestation_id: str

@dataclass
class DeviceExtension:
    device_did: str
    new_expires_at: str
    previous_expires_at: str | None

class DeviceService:
    def link(self, identity_did: str, capabilities: list[str] | None = None, expires_in_days: int | None = None, passphrase: str | None = None) -> Device: ...
    def extend(self, device_did: str, identity_did: str, *, days: int = 90, passphrase: str | None = None) -> DeviceExtension: ...
    def revoke(self, device_did: str, identity_did: str, note: str | None = None, passphrase: str | None = None) -> None: ...

# -- Agent --

class AgentAuth:
    bridge_url: str
    def __init__(self, bridge_url: str, attestation_chain_path: str, root_public_key: str | None = None) -> None: ...
    def get_token(self, capabilities: list[str] | None = None) -> str: ...

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
    signer: str | None
    error: str | None
    error_code: str | None

@dataclass
class VerifyResult:
    commits: list[CommitResult]
    passed: bool
    mode: str
    summary: str

@dataclass
class LayoutInfo:
    bundle: str | None
    refs: list[str] | None
    source: str

class LayoutError(Exception):
    code: str
    def __init__(self, code: str, message: str) -> None: ...

def discover_layout(repo_root: str = ".") -> LayoutInfo: ...
def verify_commit_range(commit_range: str, identity_bundle: str | None = None, allowed_signers: str = ".auths/allowed_signers", mode: str = "enforce") -> VerifyResult: ...
