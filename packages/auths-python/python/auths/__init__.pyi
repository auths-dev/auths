from dataclasses import dataclass

# -- Client --

class Auths:
    repo_path: str
    identities: IdentityService
    devices: DeviceService
    attestations: AttestationService
    orgs: OrgService
    audit: AuditService
    trust: TrustService
    pairing: PairingService
    witnesses: WitnessService
    doctor: DoctorService
    def __init__(self, repo_path: str = "~/.auths", passphrase: str | None = None) -> None: ...
    def verify(self, attestation_json: str, issuer_key: str, required_capability: str | None = None, at: str | None = None) -> VerificationResult: ...
    def verify_chain(self, attestations: list[str], root_key: str, required_capability: str | None = None, witnesses: WitnessConfig | None = None) -> VerificationReport: ...
    def verify_device(self, identity_did: str, device_did: str, attestations: list[str], identity_key: str) -> VerificationReport: ...
    def sign(self, message: bytes, private_key: str) -> str: ...
    def sign_action(self, action_type: str, payload: str, identity_did: str, private_key: str) -> str: ...
    def verify_action(self, envelope_json: str, public_key: str) -> VerificationResult: ...
    def sign_commit(self, data: bytes, *, identity_did: str, passphrase: str | None = None) -> CommitSigningResult: ...
    def sign_artifact(self, path: str, *, identity_did: str, expires_in: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
    def sign_artifact_bytes(self, data: bytes, *, identity_did: str, expires_in: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
    def sign_as(self, message: bytes, identity: str, passphrase: str | None = None) -> str: ...
    def sign_action_as(self, action_type: str, payload: str, identity: str, passphrase: str | None = None) -> str: ...
    def get_public_key(self, identity: str, passphrase: str | None = None) -> str: ...
    def sign_as_agent(self, message: bytes, key_alias: str, passphrase: str | None = None) -> str: ...
    def sign_action_as_agent(self, action_type: str, payload: str, key_alias: str, agent_did: str, passphrase: str | None = None) -> str: ...
    def publish_artifact(self, attestation_json: str, *, registry_url: str, package_name: str | None = None) -> ArtifactPublishResult: ...
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
class OrgError(AuthsError): ...
class PairingError(AuthsError): ...

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

# -- In-memory keypair --

def generate_inmemory_keypair() -> tuple[str, str, str]:
    """Generate an in-memory Ed25519 keypair. Returns (private_key_hex, public_key_hex, did_key)."""
    ...

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
class AgentIdentity:
    did: str
    attestation: str
    public_key: str

@dataclass
class DelegatedAgent:
    did: str
    attestation: str
    public_key: str

@dataclass
class IdentityRotationResult:
    controller_did: str
    new_key_fingerprint: str
    previous_key_fingerprint: str
    sequence: int

class IdentityService:
    def create(self, label: str = "main", repo_path: str | None = None, passphrase: str | None = None) -> Identity: ...
    def rotate(self, identity_did: str, *, passphrase: str | None = None) -> IdentityRotationResult: ...
    def create_agent(self, name: str, capabilities: list[str], passphrase: str | None = None) -> AgentIdentity: ...
    def delegate_agent(self, identity_did: str, name: str, capabilities: list[str], expires_in: int | None = None, passphrase: str | None = None) -> DelegatedAgent: ...

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

@dataclass
class ArtifactPublishResult:
    attestation_rid: str
    package_name: str | None
    signer_did: str

class AttestationService:
    def list(self, *, identity_did: str | None = None, device_did: str | None = None) -> list[Attestation]: ...
    def latest(self, device_did: str) -> Attestation | None: ...

class DeviceService:
    def link(self, identity_did: str, capabilities: list[str] | None = None, expires_in: int | None = None, passphrase: str | None = None) -> Device: ...
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

def sign_artifact(file_path: str, identity_key_alias: str, repo_path: str, passphrase: str | None = None, expires_in: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...
def sign_artifact_bytes(data: bytes, identity_key_alias: str, repo_path: str, passphrase: str | None = None, expires_in: int | None = None, note: str | None = None) -> ArtifactSigningResult: ...

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

class PolicyBuilder:
    def __init__(self) -> None: ...
    @classmethod
    def standard(cls, capability: str) -> PolicyBuilder: ...
    @classmethod
    def any_of(cls, *builders: PolicyBuilder) -> PolicyBuilder: ...
    def not_revoked(self) -> PolicyBuilder: ...
    def not_expired(self) -> PolicyBuilder: ...
    def expires_after(self, seconds: int) -> PolicyBuilder: ...
    def issued_within(self, seconds: int) -> PolicyBuilder: ...
    def require_capability(self, cap: str) -> PolicyBuilder: ...
    def require_all_capabilities(self, caps: list[str]) -> PolicyBuilder: ...
    def require_any_capability(self, caps: list[str]) -> PolicyBuilder: ...
    def require_issuer(self, did: str) -> PolicyBuilder: ...
    def require_issuer_in(self, dids: list[str]) -> PolicyBuilder: ...
    def require_subject(self, did: str) -> PolicyBuilder: ...
    def require_delegated_by(self, did: str) -> PolicyBuilder: ...
    def require_agent(self) -> PolicyBuilder: ...
    def require_human(self) -> PolicyBuilder: ...
    def require_workload(self) -> PolicyBuilder: ...
    def require_repo(self, repo: str) -> PolicyBuilder: ...
    def require_env(self, env: str) -> PolicyBuilder: ...
    def max_chain_depth(self, depth: int) -> PolicyBuilder: ...
    def or_policy(self, other: PolicyBuilder) -> PolicyBuilder: ...
    def negate(self) -> PolicyBuilder: ...
    def build(self) -> CompiledPolicy: ...
    def to_json(self) -> str: ...

def compile_policy(policy_json: str) -> CompiledPolicy: ...

@dataclass
class AuthsClaims:
    sub: str
    keri_prefix: str
    capabilities: list[str]
    iss: str
    aud: str
    exp: int
    iat: int
    jti: str
    signer_type: str | None
    delegated_by: str | None
    witness_quorum: dict | None
    github_actor: str | None
    github_repository: str | None
    def has_capability(self, cap: str) -> bool: ...
    def has_any_capability(self, caps: list[str]) -> bool: ...
    def has_all_capabilities(self, caps: list[str]) -> bool: ...
    @property
    def is_agent(self) -> bool: ...
    @property
    def is_human(self) -> bool: ...
    @property
    def is_delegated(self) -> bool: ...

class AuthsJWKSClient:
    def __init__(self, jwks_url: str, *, cache_ttl: int = 300) -> None: ...
    def verify_token(self, token: str, *, audience: str, issuer: str | None = None, leeway: int = 60) -> AuthsClaims: ...

def discover_layout(repo_root: str = ".") -> LayoutInfo: ...
def generate_allowed_signers(repo_path: str = "~/.auths") -> str: ...
def verify_commit_range(commit_range: str, identity_bundle: str | None = None, allowed_signers: str = ".auths/allowed_signers", mode: str = "enforce") -> VerifyResult: ...
def verify_chain_with_witnesses(attestations_json: list[str], root_pk_hex: str, witnesses: WitnessConfig) -> VerificationReport: ...
def verify_token(token: str, *, jwks_url: str, audience: str, issuer: str | None = None, leeway: int = 60) -> AuthsClaims: ...

# -- Organization --

@dataclass
class Org:
    prefix: str
    did: str
    label: str
    repo_path: str

@dataclass
class OrgMember:
    member_did: str
    role: str
    capabilities: list[str]
    issuer_did: str
    attestation_rid: str
    revoked: bool
    expires_at: str | None

class OrgService:
    def create(self, label: str, repo_path: str | None = None, passphrase: str | None = None) -> Org: ...
    def add_member(self, org_did: str, member_did: str, role: str = "member", capabilities: list[str] | None = None, note: str | None = None, repo_path: str | None = None, passphrase: str | None = None, member_public_key_hex: str | None = None) -> OrgMember: ...
    def revoke_member(self, org_did: str, member_did: str, note: str | None = None, repo_path: str | None = None, passphrase: str | None = None, member_public_key_hex: str | None = None) -> OrgMember: ...
    def update_member(self, org_did: str, member_did: str, role: str | None = None, capabilities: list[str] | None = None, note: str | None = None, repo_path: str | None = None, passphrase: str | None = None, member_public_key_hex: str | None = None) -> OrgMember: ...
    def list_members(self, org_did: str, include_revoked: bool = False, repo_path: str | None = None) -> list[OrgMember]: ...
    def get_member(self, org_did: str, member_did: str, repo_path: str | None = None) -> OrgMember | None: ...

# -- Audit --

@dataclass
class AuditSummary:
    total_commits: int
    signed_commits: int
    unsigned_commits: int
    auths_signed: int
    gpg_signed: int
    ssh_signed: int
    verification_passed: int
    verification_failed: int
    @property
    def signing_rate(self) -> float: ...

@dataclass
class CommitRecord:
    oid: str
    author_name: str
    author_email: str
    date: str
    message: str
    signature_type: str | None
    signer_did: str | None
    verified: bool | None

@dataclass
class AuditReport:
    commits: list[CommitRecord]
    summary: AuditSummary

class AuditService:
    def report(self, repo_path: str | None = None, since: str | None = None, until: str | None = None, author: str | None = None, limit: int = 500) -> AuditReport: ...
    def is_compliant(self, repo_path: str | None = None, since: str | None = None, until: str | None = None) -> bool: ...

# -- Trust --

@dataclass
class TrustEntry:
    did: str
    label: str | None
    trust_level: str
    first_seen: str
    kel_sequence: int | None
    pinned_at: str

class TrustService:
    def pin(self, did: str, label: str | None = None, trust_level: str = "manual", repo_path: str | None = None) -> TrustEntry: ...
    def remove(self, did: str, repo_path: str | None = None) -> None: ...
    def list(self, repo_path: str | None = None) -> list[TrustEntry]: ...
    def get(self, did: str, repo_path: str | None = None) -> TrustEntry | None: ...
    def is_trusted(self, did: str, repo_path: str | None = None) -> bool: ...

# -- Witness --

@dataclass
class Witness:
    url: str
    did: str | None
    label: str | None

class WitnessService:
    def add(self, url: str, label: str | None = None, repo_path: str | None = None) -> Witness: ...
    def remove(self, url: str, repo_path: str | None = None) -> None: ...
    def list(self, repo_path: str | None = None) -> list[Witness]: ...

# -- Doctor --

@dataclass
class Check:
    name: str
    passed: bool
    message: str
    fix_hint: str | None

@dataclass
class DiagnosticReport:
    checks: list[Check]
    all_passed: bool
    version: str

class DoctorService:
    def check(self, repo_path: str | None = None) -> DiagnosticReport: ...
    def check_one(self, name: str, repo_path: str | None = None) -> Check: ...

# -- Testing --

class EphemeralIdentity:
    did: str
    public_key_hex: str
    private_key_hex: str
    def __init__(self) -> None: ...
    def sign(self, message: bytes) -> str: ...
    def sign_action(self, action_type: str, payload_json: str) -> str: ...
    def verify_action(self, envelope_json: str) -> VerificationResult: ...

# -- Pairing --

@dataclass
class PairingResponse:
    device_did: str
    device_name: str | None
    device_public_key_hex: str
    capabilities: list[str]

@dataclass
class PairingResult:
    device_did: str
    device_name: str | None
    attestation_rid: str | None

class PairingSession:
    session_id: str
    short_code: str
    endpoint: str
    token: str
    controller_did: str
    def wait_for_response(self, timeout_secs: int = 300) -> PairingResponse: ...
    def stop(self) -> None: ...
    def __enter__(self) -> PairingSession: ...
    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object | None) -> bool: ...

class PairingService:
    def create_session(self, capabilities: list[str] | None = None, timeout_secs: int = 300, bind_address: str = "0.0.0.0", enable_mdns: bool = True, repo_path: str | None = None, passphrase: str | None = None) -> PairingSession: ...
    def join(self, short_code: str, endpoint: str, token: str, device_name: str | None = None, repo_path: str | None = None, passphrase: str | None = None) -> PairingResult: ...
    def complete(self, session: PairingSession, response: PairingResponse, repo_path: str | None = None, passphrase: str | None = None) -> PairingResult: ...
