from dataclasses import dataclass

# -- Client --

class Auths:
    repo_path: str
    identities: IdentityService
    devices: DeviceService
    attestations: AttestationService
    def __init__(self, repo_path: str = "~/.auths", passphrase: str | None = None) -> None: ...
    def verify(self, attestation_json: str, issuer_key: str, required_capability: str | None = None, at: str | None = None) -> VerificationResult: ...
    def verify_chain(self, attestations: list[str], root_key: str, required_capability: str | None = None, witnesses: WitnessConfig | None = None) -> VerificationReport: ...
    def verify_device(self, identity_did: str, device_did: str, attestations: list[str], identity_key: str) -> VerificationReport: ...
    def sign(self, message: bytes, private_key: str) -> str: ...
    def sign_action(self, action_type: str, payload: str, identity_did: str, private_key: str) -> str: ...
    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult: ...
    def sign_commit(self, data: bytes, *, identity_did: str, passphrase: str | None = None) -> CommitSigningResult: ...
    def sign_artifact(self, path: str, *, identity_did: str, expires_in_days: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
    def sign_artifact_bytes(self, data: bytes, *, identity_did: str, expires_in_days: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
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

@dataclass
class Attestation:
    rid: str
    issuer: str
    subject: str
    device_did: str
    capabilities: list[str]
    signer_type: str | None
    expires_at: str | None
    revoked_at: str | None
    created_at: str | None
    delegated_by: str | None
    json: str
    @property
    def is_active(self) -> bool: ...
    @property
    def is_revoked(self) -> bool: ...

@dataclass
class CommitSigningResult:
    signature_pem: str
    method: str
    namespace: str

@dataclass
class ArtifactSigningResult:
    attestation_json: str
    rid: str
    digest: str
    file_size: int

class AttestationService:
    def list(self, *, identity_did: str | None = None, device_did: str | None = None) -> list[Attestation]: ...
    def latest(self, device_did: str) -> Attestation | None: ...

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

def sign_commit(data: bytes, identity_key_alias: str, repo_path: str, passphrase: str | None = None) -> CommitSigningResult: ...

def sign_artifact(file_path: str, identity_key_alias: str, repo_path: str, passphrase: str | None = None, expires_in_days: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
def sign_artifact_bytes(data: bytes, identity_key_alias: str, repo_path: str, passphrase: str | None = None, expires_in_days: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...

def list_attestations(repo_path: str) -> list[Attestation]: ...
def list_attestations_by_device(repo_path: str, device_did: str) -> list[Attestation]: ...
def get_latest_attestation(repo_path: str, device_did: str) -> Attestation | None: ...

class CompiledPolicy:
    def check(self, context: EvalContext) -> Decision: ...
    def to_json(self) -> str: ...

class EvalContext:
    def __init__(self, issuer: str, subject: str, *, capabilities: list[str] | None = None, role: str | None = None, revoked: bool = False, expires_at: str | None = None, repo: str | None = None, environment: str | None = None, signer_type: str | None = None, delegated_by: str | None = None, chain_depth: int | None = None) -> None: ...

@dataclass
class Decision:
    outcome: str
    reason: str
    message: str
    @property
    def allowed(self) -> bool: ...
    @property
    def denied(self) -> bool: ...
    def __bool__(self) -> bool: ...

def compile_policy(policy_json: str) -> CompiledPolicy: ...

def discover_layout(repo_root: str = ".") -> LayoutInfo: ...
def verify_commit_range(commit_range: str, identity_bundle: str | None = None, allowed_signers: str = ".auths/allowed_signers", mode: str = "enforce") -> VerifyResult: ...
