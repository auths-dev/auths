# auths-api: Product & Implementation Roadmap

## fn-89 Foundation: What It Enables

The fn-89 epic (domain-driven architecture, fn-89.0 contracts) establishes the **foundational layers** for auths-api:

**What fn-89 Delivers**:
- **Domain clarity**: identity, auth, compliance, webhooks domains with explicit ownership
- **Transaction safety**: bootstrap/provisioning workflows with atomicity guarantees
- **Event-driven architecture**: all domain operations emit webhooks (provision, revoke, expire, refresh)
- **Observability**: per-domain metrics, Grafana dashboards, SLO-based alerting
- **SDK parity**: Rust + Python SDKs mirror domain structure (users understand via domain concepts)
- **Scalability foundation**: sharding strategy, per-shard failover, horizontal deployment patterns

**Market Positioning**:
- Supply chain security (fintech, infra platforms, critical OSS)
- Multi-tenant SaaS with cryptographic delegation (orgs provision agents for services)
- Audit-driven security (full event trail with domain event sourcing)

## Roadmap Overview

After fn-89, auths-api is **provisionally deployable** but **functionally limited**. The roadmap builds on this foundation to unlock strategic use cases:

| Epic | Use Case | Complexity | Value |
|------|----------|-----------|-------|
| fn-100 | Policy-driven agent provisioning | High | Very High |
| fn-101 | Artifact attestation & verification | Medium | Very High |
| fn-102 | Key rotation & renewal automation | Medium | High |
| fn-103 | Approval workflows (sensitive ops) | Medium | High |
| fn-104 | Agent quotas & rate limiting | Low | Medium |
| fn-105 | Multi-org federation & cross-org delegation | Very High | High |
| fn-106 | Compliance & audit export (SOC2, FedRAMP) | Medium | High |
| fn-107 | Agent analytics & usage observability | Low | Medium |

---

## fn-100: Policy-Driven Agent Provisioning

**Goal**: Orgs define rules that automatically provision agents based on namespace config, without manual admin intervention.

**Use Case**:
- Org admin: "Whenever a CI pipeline starts in namespace X, auto-provision a ci-runner agent with signing + artifact capabilities, TTL 1 hour"
- Org admin: "Allow developers to self-provision personal agents for CLI use, limited to read-only capabilities"
- Org admin: "Revoke all agents in namespace Y that haven't been used in 30 days"

### Sub-task fn-100.1: Policy Schema & Evaluation Engine

**Description**: Define policy language and evaluation logic for agent provisioning rules.

**Deliverables**:
- Policy schema (JSON): trigger rules, agent templates, capability grants
- Policy evaluator: given namespace context, determine which agents to provision
- Admin API: `POST /v1/policies { namespace, rules, [triggers] }`

**Pseudo-code**:
```rust
// Policy schema
pub struct AgentPolicy {
    namespace: String,
    rules: Vec<PolicyRule>,
}

pub enum PolicyTrigger {
    OnNamespaceBoot { }, // when namespace initializes
    OnCiPipelineStart { ci_platform: String }, // "github", "gitlab"
    OnDeveloperLogin { }, // when human logs in
    OnSchedule { cron: String }, // "0 2 * * *" = daily 2am
}

pub struct PolicyRule {
    name: String,
    trigger: PolicyTrigger,
    condition: String, // "namespace.platform == 'github' && team == 'infra'"
    agent_template: AgentTemplate,
}

pub struct AgentTemplate {
    name_pattern: String, // "ci-runner-{platform}-{id}"
    capabilities: Vec<String>, // ["sign_artifacts", "publish_releases"]
    ttl_seconds: u64,
    rotation_period: Option<u64>, // auto-rotate every N seconds
}

// Evaluator
pub async fn evaluate_policy(
    namespace: &str,
    policy: &AgentPolicy,
    trigger: &PolicyTrigger,
    context: &PolicyContext, // env vars, CI platform info, etc.
) -> Result<Vec<AgentTemplate>> {
    // 1. Filter rules by trigger type
    // 2. Evaluate conditions against context
    // 3. Return matching templates
}

pub async fn apply_policy(
    namespace: &str,
    templates: Vec<AgentTemplate>,
    identity_service: &dyn IdentityService,
) -> Result<Vec<Agent>> {
    // 1. For each template, provision agent
    // 2. Emit policy.agent_provisioned event (webhook)
    // 3. Log to compliance domain
}
```

**Acceptance Criteria**:
- Policy schema supports at least 4 trigger types (boot, ci_start, login, schedule)
- Condition evaluator handles namespace context, env vars, user attributes
- Policy rules can grant multiple capabilities
- Admin can list, update, delete policies
- Policy changes take effect immediately (no restart)

---

### Sub-task fn-100.2: Scheduled Policy Evaluation (Cron-like)

**Description**: Periodic evaluation of policies (e.g., "revoke unused agents daily").

**Deliverables**:
- Background job: periodic policy evaluation based on cron schedule
- Metrics: policies evaluated/hour, agents auto-provisioned, agents auto-revoked
- Admin endpoint to trigger manual evaluation

**Pseudo-code**:
```rust
pub struct ScheduledPolicy {
    policy_id: String,
    schedule: String, // cron expression
}

pub async fn scheduled_policy_evaluator(
    policies: Arc<Vec<ScheduledPolicy>>,
    scheduler: &dyn Scheduler,
) {
    for policy in policies.iter() {
        scheduler.schedule(
            policy.schedule.clone(),
            move || {
                Box::pin(async {
                    let templates = evaluate_policy(&policy).await?;
                    apply_policy(templates).await?;
                })
            },
        ).await?;
    }
}

// Example: auto-revoke unused agents
pub async fn revoke_unused_agents(
    namespace: &str,
    threshold_days: u64,
) -> Result<Vec<String>> {
    // 1. Query audit logs: which agents haven't been used in threshold_days
    // 2. Batch revoke them
    // 3. Emit agent.revoked events (webhooks)
    // 4. Return revoked agent IDs
}
```

**Acceptance Criteria**:
- Cron-based scheduling works (daily, hourly, etc.)
- Unused agent cleanup runs reliably
- Metrics exposed: scheduled_policy_evaluations, agents_auto_provisioned, agents_auto_revoked
- Manual trigger endpoint: `POST /v1/policies/{id}/evaluate` for testing

---

### Sub-task fn-100.3: Multi-Namespace Policies & Inheritance

**Description**: Org-level policy templates that cascade to namespaces, with override capability.

**Deliverables**:
- Policy hierarchy: global > org > namespace > agent
- Inheritance: namespaces inherit org policies unless explicitly overridden
- Conflict resolution: most-specific policy wins

**Pseudo-code**:
```rust
pub struct PolicyHierarchy {
    global: Option<AgentPolicy>,     // Auths platform-wide
    org: Option<AgentPolicy>,        // Org-level defaults
    namespace: AgentPolicy,           // Namespace-specific
}

pub async fn resolve_policies(
    namespace: &str,
    org_id: &str,
) -> Result<AgentPolicy> {
    // 1. Load global policy (if any)
    // 2. Load org policy (if any)
    // 3. Load namespace policy
    // 4. Merge: namespace overrides org, org overrides global
    // 5. Return merged policy
}
```

**Acceptance Criteria**:
- Policy inheritance documented with examples
- Override syntax clear (namespace policy `extends` org policy)
- Conflict resolution predictable

---

## fn-101: Artifact Attestation & Verification

**Goal**: Agents sign artifacts (commits, releases, container images); third parties verify provenance without needing artifact server access.

**Use Case**:
- CI agent signs build artifact (binary, container image, release tarball)
- Developer pushes signed artifact + attestation to public registry
- User downloads artifact, verifies signature: "This build came from org X's CI, signed with agent ID Y, approved on date Z"
- Supply chain attack prevention: fake artifact rejected because signature doesn't verify

### Sub-task fn-101.1: Artifact Signing Service

**Description**: Agents create deterministic, canonicalized signatures over artifacts.

**Deliverables**:
- Artifact signing API: `POST /v1/artifacts/sign { agent_id, artifact_hash, metadata }`
- Returns: signed attestation (JSON)
- Attestation includes: artifact hash, agent DID, timestamp, signature

**Pseudo-code**:
```rust
pub struct ArtifactAttestation {
    version: String,                // "1.0"
    artifact_hash: String,          // sha256 of artifact
    artifact_hash_algorithm: String, // "sha256"
    agent_id: String,
    agent_did: String,
    signer_did: String,            // dev who triggered the sign
    signed_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    metadata: Map<String, Value>,  // platform, build_id, version, etc.
    signature: String,             // base64url(ed25519_sig)
}

pub async fn sign_artifact(
    agent_id: &str,
    artifact_hash: &str,
    metadata: Map<String, Value>,
    artifact_service: &dyn ArtifactService,
    auth_domain: &dyn AuthDomain,
) -> Result<ArtifactAttestation> {
    // 1. Validate agent has "sign_artifacts" capability
    // 2. Load agent's device key from device domain
    // 3. Canonicalize attestation (json-canon, RFC 8785)
    // 4. Sign with agent's key
    // 5. Return attestation
}

pub async fn verify_artifact_attestation(
    attestation: &ArtifactAttestation,
    identity_resolver: &dyn IdentityResolver,
    current_time: DateTime<Utc>,
) -> Result<AttestationValidity> {
    // 1. Validate signature (Ed25519 over canonical JSON)
    // 2. Check not expired
    // 3. Resolve agent_did from IdentityResolver
    // 4. Return validity
}
```

**Acceptance Criteria**:
- Artifacts can be signed atomically with hash only (no file upload needed)
- Attestations are JSON, machine-readable
- Canonical form verified (json-canon)
- Verification works offline (given agent DID + public key)

---

### Sub-task fn-101.2: Attestation Storage & Distribution

**Description**: Store attestations for lookup and verification.

**Deliverables**:
- Attestation registry: `POST /v1/attestations { artifact_hash, attestation }`
- List attestations: `GET /v1/attestations?artifact_hash=...&agent_did=...`
- Storage: Redis (hot cache) + audit log (immutable)

**Pseudo-code**:
```rust
pub struct AttestationRegistry {
    backend: Arc<dyn AttestationStorage>,
}

pub async fn register_attestation(
    attestation: ArtifactAttestation,
    registry: &AttestationRegistry,
    compliance: &dyn ComplianceDomain,
) -> Result<()> {
    // 1. Validate attestation signature
    // 2. Store in Redis: attestations:{artifact_hash}:{agent_did}
    // 3. Emit attestation.registered event (webhook)
    // 4. Log to compliance domain
}

pub async fn get_attestations(
    artifact_hash: &str,
    agent_did: Option<&str>,
    registry: &AttestationRegistry,
) -> Result<Vec<ArtifactAttestation>> {
    // 1. Query Redis by artifact_hash
    // 2. Optionally filter by agent_did
    // 3. Return sorted by signed_at (newest first)
}
```

**Acceptance Criteria**:
- Attestations queryable by artifact hash + optional agent DID
- Immutable (no updates, only append)
- Exported in audit logs

---

### Sub-task fn-101.3: Integration: Git Commit Signing

**Description**: Extend Git commit signing to embed artifact attestations.

**Deliverables**:
- auths-cli: `auths sign-commit` can include attestation hash
- Commit signatures include attestation reference
- Verification: git signature validates + attestation is lookupable

**Pseudo-code**:
```rust
pub struct CommitSignatureWithAttestation {
    commit_hash: String,
    commit_signature: String,     // existing
    attestation_hash: Option<String>, // hash of artifact being committed
    attestation_reference: Option<String>, // URL to attestation registry
}

pub async fn sign_commit_with_attestation(
    commit_hash: &str,
    artifact_hash: Option<&str>,
    agent_service: &dyn AgentService,
) -> Result<CommitSignatureWithAttestation> {
    // 1. Sign commit (existing logic)
    // 2. If artifact_hash provided:
    //    a. Look up attestation
    //    b. Include reference in signature metadata
    // 3. Return signature + attestation ref
}
```

**Acceptance Criteria**:
- Git commits can link to artifact attestations
- Attestation reference immutable after commit
- Verification chain: commit sig → attestation sig → agent DID

---

## fn-102: Key Rotation & Renewal Automation

**Goal**: Agents automatically rotate their signing keys on a schedule, maintaining continuous signing capability.

**Use Case**:
- Long-lived agent (CI runner, bot) rotates its key every 30 days automatically
- Old key revoked after grace period (new key already active)
- No service disruption (clients always get latest key)

### Sub-task fn-102.1: Agent Key Rotation Policy

**Description**: Define rotation schedules and execution logic.

**Deliverables**:
- Policy schema: rotation period, grace period, notifications
- Rotation scheduler: periodic background job
- Pre-rotation notification: webhook to inform subscribers

**Pseudo-code**:
```rust
pub struct KeyRotationPolicy {
    agent_id: String,
    rotation_period: Duration, // e.g., 30 days
    grace_period: Duration,     // e.g., 7 days (old key still valid)
    notify_before: Duration,    // e.g., 3 days before rotation
    auto_rotate: bool,
}

pub async fn schedule_key_rotation(
    agent_id: &str,
    policy: KeyRotationPolicy,
    scheduler: &dyn Scheduler,
) -> Result<()> {
    // 1. Calculate next rotation time: now + policy.rotation_period
    // 2. Schedule webhook notification: now + (rotation_period - notify_before)
    // 3. Schedule rotation: now + rotation_period
    // 4. Store scheduled rotations in Redis
}

pub async fn perform_key_rotation(
    agent_id: &str,
    device_service: &dyn DeviceService,
) -> Result<RotationResult> {
    // 1. Generate new device key
    // 2. Add new key to agent's device list
    // 3. Mark old key as "rotating" (valid until grace_period expires)
    // 4. Emit device.key_rotated event
    // 5. Old key expires after grace_period (cleanup job)
}

pub struct RotationResult {
    agent_id: String,
    old_key_did: String,
    new_key_did: String,
    new_key_public: String,
    old_key_expires_at: DateTime<Utc>,
}
```

**Acceptance Criteria**:
- Rotation period configurable per agent
- Pre-rotation notification sent (webhook event)
- Old key valid during grace period, then revoked automatically
- Audit trail: all rotations logged

---

### Sub-task fn-102.2: Client Handling of Key Rotation

**Description**: SDK clients handle transparent key rotation (fetch new key, use it).

**Deliverables**:
- SDK: automatic key refresh on rotation
- Cache invalidation: old key removed from cache on expiry
- Error handling: retry with new key if old key rejected

**Pseudo-code**:
```rust
// Rust SDK
pub async fn sign_with_rotation_aware(
    agent_id: &str,
    data: &[u8],
    sdk: &Agent,
) -> Result<String> {
    loop {
        match sdk.sign(data).await {
            Ok(sig) => return Ok(sig),
            Err(SignError::KeyExpired) => {
                // Key was just rotated, refresh and retry
                sdk.refresh_keys().await?;
                // retry the sign
            }
            Err(e) => return Err(e),
        }
    }
}

// Python SDK equivalent
async def sign_with_rotation_aware(agent_id: str, data: bytes) -> str:
    while True:
        try:
            sig = await agent.sign(data)
            return sig
        except KeyExpiredError:
            await agent.refresh_keys()
            # retry
```

**Acceptance Criteria**:
- SDK automatically detects key rotation
- Seamless retry on key expiry
- Logging: key rotation events visible in client logs

---

### Sub-task fn-102.3: Renewal Before Expiry

**Description**: Extend agent TTL automatically before expiration (similar to token refresh).

**Deliverables**:
- Renewal scheduler: check agents expiring within N days
- Auto-renewal: extend TTL by another rotation period
- Notification: alert if auto-renewal fails (manual intervention)

**Pseudo-code**:
```rust
pub async fn schedule_agent_renewals(
    namespace: &str,
    renewal_threshold: Duration, // e.g., 7 days
    scheduler: &dyn Scheduler,
) -> Result<()> {
    // 1. Find agents expiring within threshold
    // 2. Schedule renewal job: now + (agent.expires_at - renewal_threshold)
    // 3. On job trigger: extend TTL + emit agent.renewed event
}

pub async fn renew_agent_before_expiry(
    namespace: &str,
    agent_id: &str,
    new_ttl: Duration,
) -> Result<Agent> {
    // 1. Validate agent not already expired
    // 2. Update agent.expires_at = now + new_ttl
    // 3. Store in Redis
    // 4. Emit agent.renewed event
    // 5. Log to compliance
}
```

**Acceptance Criteria**:
- Agents auto-renew before expiry (no service gap)
- Renewal events visible in audit logs
- Admin notified if renewal fails

---

## fn-103: Approval Workflows for Sensitive Operations

**Goal**: High-stakes operations (revoke agent, rotate keys, change policies) require human approval.

**Use Case**:
- CI agent provisioning is automatic (fn-100)
- But revoking an agent requires approval from 2 org admins
- Deployment policy changes require approval from security team

### Sub-task fn-103.1: Approval Request & Decision

**Description**: Create, manage, approve/deny sensitive operations.

**Deliverables**:
- Approval schema: operation type, requester, approvers, deadline
- API: `POST /v1/approvals/request { operation, reason, requires_approvers }`
- API: `POST /v1/approvals/{id}/approve { approver_did, decision, note }`

**Pseudo-code**:
```rust
pub enum ApprovalOperation {
    RevokeAgent { agent_id: String },
    RotateAgentKey { agent_id: String },
    ChangePolicy { policy_id: String, old: Policy, new: Policy },
    DeleteNamespace { namespace: String },
}

pub struct ApprovalRequest {
    id: String,
    namespace: String,
    operation: ApprovalOperation,
    requester_did: String,
    required_approvers: Vec<String>, // DIDs of required approvers
    approvals: Map<String, Approval>, // approver_did -> decision
    deadline: DateTime<Utc>,
    status: ApprovalStatus, // pending, approved, rejected, expired
}

pub struct Approval {
    approver_did: String,
    decision: ApprovalDecision, // Approved, Rejected
    reason: String,
    approved_at: DateTime<Utc>,
}

pub async fn request_approval(
    operation: ApprovalOperation,
    requester_did: &str,
    approvers: Vec<String>,
    deadline: Duration,
) -> Result<ApprovalRequest> {
    // 1. Create request
    // 2. Store in Redis: approvals:{request_id}
    // 3. Emit approval.requested event (sends to approvers)
    // 4. Log to compliance domain
}

pub async fn approve_operation(
    request_id: &str,
    approver_did: &str,
    decision: ApprovalDecision,
) -> Result<ApprovalRequest> {
    // 1. Record approval
    // 2. If all required approvals received: apply operation
    // 3. Emit approval.decided event
}
```

**Acceptance Criteria**:
- Approval rules configurable per operation type
- Multiple approvers supported
- Deadline enforced (requests expire)
- Audit trail of all approvals

---

### Sub-task fn-103.2: Conditional Execution (After Approval)

**Description**: Execute operations only after approval(s) received.

**Deliverables**:
- Approval-gated operations: revoke, rotate, policy change
- Execution: automatic or manual trigger after approved
- Rollback: undo operation if approval is later revoked

**Pseudo-code**:
```rust
pub async fn revoke_agent_with_approval(
    namespace: &str,
    agent_id: &str,
    requester_did: &str,
) -> Result<ApprovalRequest> {
    // 1. Create approval request (operation: RevokeAgent)
    // 2. Determine required approvers (from policy)
    // 3. Return request (client must wait for approvals)
}

pub async fn execute_approved_operation(
    approval_request: &ApprovalRequest,
) -> Result<OperationResult> {
    // 1. Validate request is fully approved
    // 2. Check deadline not exceeded
    // 3. Execute operation (revoke, rotate, etc.)
    // 4. Emit operation.executed event
    // 5. Log to compliance
}

pub async fn revoke_approval_and_undo(
    approval_request: &ApprovalRequest,
    approver_who_revoked: &str,
) -> Result<()> {
    // 1. Mark approval as revoked
    // 2. If operation already executed: undo it (restore agent, etc.)
    // 3. Emit approval.revoked event
}
```

**Acceptance Criteria**:
- Operations block until approval received
- Automatic execution vs. manual trigger (configurable)
- Approval can be revoked with undo capability

---

## fn-104: Agent Quotas & Rate Limiting

**Goal**: Prevent resource exhaustion and abuse; fair allocation across namespaces.

**Use Case**:
- Org limit: max 1000 agents per namespace
- Rate limit: max 100 agents provisioned/hour
- Quota enforcement: prevent over-provisioning

### Sub-task fn-104.1: Quota Tracking & Enforcement

**Description**: Track agent counts, enforce limits.

**Deliverables**:
- Quota schema: max agents, max provisions/hour
- Quota check: before provisioning, verify limits
- Metrics: quota usage, rejections

**Pseudo-code**:
```rust
pub struct AgentQuota {
    namespace: String,
    max_agents: u64,
    max_provisions_per_hour: u64,
}

pub async fn check_quota(
    namespace: &str,
    quota: &AgentQuota,
    agent_service: &dyn AgentService,
) -> Result<QuotaStatus> {
    // 1. Count current agents in namespace
    // 2. Count provisions in last hour (from audit log)
    // 3. Return { agents_available, provisions_available }
}

pub async fn provision_agent_with_quota(
    namespace: &str,
    config: ProvisionConfig,
) -> Result<Agent> {
    // 1. Check quota
    // 2. If exceeded: return QuotaExceededError
    // 3. Otherwise: proceed with provision
}

pub struct QuotaStatus {
    agents_used: u64,
    agents_available: u64,
    provisions_this_hour: u64,
    provisions_available: u64,
}
```

**Acceptance Criteria**:
- Quotas enforced at provision time
- Soft limit warnings + hard limit rejections
- Quotas configurable per namespace
- Quota usage visible via metrics

---

### Sub-task fn-104.2: Rate Limiting (Leaky Bucket)

**Description**: Leaky bucket rate limiter for agent operations.

**Deliverables**:
- Rate limit: X operations/second per namespace
- Burst allowance: allow spikes up to Y requests
- Headers: X-RateLimit-* in API responses

**Pseudo-code**:
```rust
pub struct RateLimiter {
    capacity: f64,           // max tokens
    refill_rate: f64,        // tokens per second
    current_tokens: f64,
}

pub async fn check_rate_limit(
    namespace: &str,
    limiter: &mut RateLimiter,
    cost: f64, // tokens to consume
) -> Result<RateLimitStatus> {
    // 1. Refill tokens based on elapsed time
    // 2. If tokens >= cost: consume and allow
    // 3. Otherwise: reject (too fast)
}

pub struct RateLimitStatus {
    allowed: bool,
    tokens_remaining: f64,
    reset_at: DateTime<Utc>,
}
```

**Acceptance Criteria**:
- Rate limits configurable (default: 100 ops/sec)
- Burst allowance (e.g., 50 tokens)
- Metrics: rate limit hits, rejections
- Headers: X-RateLimit-{Limit,Used,Remaining,ResetAt}

---

## fn-105: Multi-Org Federation & Cross-Org Delegation

**Goal**: Organizations trust each other; agent from org A can act on behalf of org B (with permission).

**Use Case**:
- Company A uses Company B's SaaS platform
- Company A's CI agent provisions its own agents on platform B
- Company A's agents can sign artifacts on platform B without sharing keys with B

### Sub-task fn-105.1: Cross-Org Agent Recognition

**Description**: Org A's agent is recognized as legitimate by org B.

**Deliverables**:
- Trust anchor: org B trusts org A's DIDs
- Agent delegation: org A agent can act in org B context
- Verification: cross-org signatures validate

**Pseudo-code**:
```rust
pub struct OrgTrustAnchor {
    org_a_id: String,
    org_b_id: String,
    org_a_root_did: String, // root DID of org A
    delegated_capabilities: Vec<String>, // [sign_artifacts, publish_releases]
    expires_at: DateTime<Utc>,
}

pub async fn establish_trust(
    org_a: &str,
    org_b: &str,
    root_did: &str,
    capabilities: Vec<String>,
) -> Result<OrgTrustAnchor> {
    // 1. Org B admin approves trust anchor (approval workflow)
    // 2. Store in Redis: trust_anchors:{org_b}:{org_a}
    // 3. Emit trust.established event
}

pub async fn verify_cross_org_delegation(
    agent_id: &str,
    agent_org: &str,
    target_org: &str,
    required_capability: &str,
    identity_resolver: &dyn IdentityResolver,
) -> Result<bool> {
    // 1. Resolve agent's org and DID
    // 2. Check trust anchor: agent_org → target_org exists
    // 3. Verify required_capability in delegated_capabilities
    // 4. Return true if delegated, false otherwise
}
```

**Acceptance Criteria**:
- Cross-org trust relationships configurable
- Delegation verified before operation
- Audit trail: cross-org operations logged

---

### Sub-task fn-105.2: Shared Agent Pool (Federation Lite)

**Description**: Multiple orgs share a pool of agents (e.g., shared CI runners).

**Deliverables**:
- Shared namespace: agents available to multiple orgs
- Attribution: operations tied to requesting org
- Resource isolation: quotas per org in shared pool

**Pseudo-code**:
```rust
pub struct SharedNamespace {
    id: String,
    participating_orgs: Vec<String>,
    agents: Vec<Agent>, // shared pool
    quotas: Map<String, AgentQuota>, // per-org limits
}

pub async fn provision_from_shared_pool(
    shared_namespace: &str,
    requesting_org: &str,
    config: ProvisionConfig,
) -> Result<Agent> {
    // 1. Check org quota in shared namespace
    // 2. Tag agent with org_id (attribution)
    // 3. Provision agent
    // 4. Log: agent provisioned by org X in shared namespace Y
}

pub async fn audit_shared_namespace(
    shared_namespace: &str,
) -> Result<Vec<AuditEvent>> {
    // 1. Query audit log: all events in shared namespace
    // 2. Organize by org (attribution)
    // 3. Return usage per org
}
```

**Acceptance Criteria**:
- Shared pool manageable via API
- Per-org quotas enforced
- Attribution clear (audit trail shows which org provisioned agent)

---

## fn-106: Compliance & Audit Export (SOC2, FedRAMP)

**Goal**: Organizations need audit logs for compliance (SOC2, FedRAMP, HIPAA); export in standard formats.

**Use Case**:
- SOC2 auditor: "Show me all agent provisioning events for the last 90 days"
- FedRAMP: "Export audit logs in CEF (Common Event Format)"
- Compliance officer: "Generate report: who provisioned which agents, when, why"

### Sub-task fn-106.1: Audit Log Retention & Queryability

**Description**: Store audit logs for X years; fast queries by date range, agent, user.

**Deliverables**:
- Retention policy: configurable (default 7 years for compliance)
- Query endpoint: `GET /v1/audit?start_date=...&end_date=...&agent_id=...&event_type=...`
- Export formats: JSON, CSV, CEF

**Pseudo-code**:
```rust
pub async fn query_audit_logs(
    namespace: &str,
    filter: AuditFilter,
    format: ExportFormat, // JSON, CSV, CEF
) -> Result<Vec<u8>> {
    // 1. Query compliance domain: audit events matching filter
    // 2. Sort by timestamp
    // 3. Format as requested (JSON, CSV, CEF)
    // 4. Return bytes
}

pub struct AuditFilter {
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    event_types: Option<Vec<String>>, // agent.provisioned, agent.revoked, etc.
    agent_ids: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
}

pub enum ExportFormat {
    Json,
    Csv,
    Cef, // Common Event Format (for SIEM integration)
}

// CEF format example:
// CEF:0|auths|auths-api|1.0|agent.provisioned|Agent Provisioned|5|agent_id=abc123 delegator_did=did:keri:E... capabilities=sign_artifacts created_at=2026-03-29T10:00:00Z
```

**Acceptance Criteria**:
- Query by date range, agent, event type, user
- Export in at least 2 formats (JSON, CSV)
- CEF export for SIEM integration
- Retention configurable per namespace

---

### Sub-task fn-106.2: Compliance Report Generation

**Description**: Automated reports for compliance auditors.

**Deliverables**:
- Report templates: SOC2, FedRAMP, HIPAA, PCI-DSS
- Report generation: `POST /v1/compliance/reports { template, namespace, date_range }`
- Report includes: summary, detailed events, risk assessment

**Pseudo-code**:
```rust
pub enum ComplianceTemplate {
    SOC2,
    FedRAMP,
    HIPAA,
    PciDss,
}

pub struct ComplianceReport {
    template: ComplianceTemplate,
    generated_at: DateTime<Utc>,
    namespace: String,
    summary: ReportSummary,
    findings: Vec<Finding>,
    audit_logs: Vec<AuditEvent>,
}

pub struct ReportSummary {
    total_agents: u64,
    agents_provisioned_period: u64,
    agents_revoked_period: u64,
    policy_changes: u64,
    unapproved_operations: u64, // red flag
}

pub async fn generate_compliance_report(
    namespace: &str,
    template: ComplianceTemplate,
    date_range: DateRange,
) -> Result<ComplianceReport> {
    // 1. Query audit logs for period
    // 2. Check for policy violations (unapproved ops, quota exceeds)
    // 3. Generate summary
    // 4. Format as report
}
```

**Acceptance Criteria**:
- At least 2 compliance templates (SOC2, FedRAMP)
- Reports include summary + detailed audit trail
- Automated risk flagging (e.g., unapproved operations)

---

## fn-107: Agent Analytics & Usage Observability

**Goal**: Understand agent usage patterns; identify unused/underutilized agents; capacity planning.

**Use Case**:
- Dashboard: "Which agents haven't been used in 30 days?" (cleanup candidates)
- Metrics: "Agent provisioning trend: 100/month → 500/month" (growth signal)
- Forecast: "At current growth, we'll hit quota in 45 days"

### Sub-task fn-107.1: Agent Usage Metrics

**Description**: Track which agents are actively used; expose usage trends.

**Deliverables**:
- Usage metrics: last_used, usage_count, operations_performed
- Dashboard: agent usage heatmap, trend lines
- Alerts: unused agents (>30 days), low-usage agents

**Pseudo-code**:
```rust
pub struct AgentUsageMetrics {
    agent_id: String,
    provisioned_at: DateTime<Utc>,
    first_used_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    usage_count: u64,
    operations: Map<String, u64>, // sign_artifacts: 42, publish_releases: 10
    days_since_last_use: u64,
}

pub async fn compute_agent_usage(
    namespace: &str,
    days_back: u64, // e.g., 30
    agent_service: &dyn AgentService,
) -> Result<Vec<AgentUsageMetrics>> {
    // 1. Query all agents in namespace
    // 2. For each agent: query audit log for operations in last N days
    // 3. Compute last_used_at, usage_count, operations
    // 4. Return sorted by last_used_at (oldest first)
}

pub async fn identify_unused_agents(
    namespace: &str,
    threshold_days: u64, // e.g., 30
) -> Result<Vec<Agent>> {
    // 1. Compute usage metrics
    // 2. Filter: days_since_last_use >= threshold
    // 3. Return unused agents
}
```

**Acceptance Criteria**:
- Usage metrics queryable per agent, namespace
- Last-used timestamp tracked accurately
- Operations per agent visible
- Unused agents easily identifiable

---

### Sub-task fn-107.2: Capacity & Growth Analytics

**Description**: Forecast capacity; alert on quota approach; plan scaling.

**Deliverables**:
- Forecast: project agent count 30/60/90 days out
- Alerts: "At current rate, you'll hit quota in 30 days"
- Recommendations: "Consider increasing quota or cleaning unused agents"

**Pseudo-code**:
```rust
pub struct CapacityForecast {
    namespace: String,
    current_agents: u64,
    quota: u64,
    utilization: f64, // percentage
    provisioning_rate: f64, // agents/day
    forecast_30d: u64,
    forecast_60d: u64,
    days_to_quota: Option<u64>, // None if declining
    recommendations: Vec<String>,
}

pub async fn forecast_capacity(
    namespace: &str,
    days_history: u64, // e.g., 90
) -> Result<CapacityForecast> {
    // 1. Compute provisioning rate (agents/day) from audit log
    // 2. Project forward 30, 60, 90 days
    // 3. Calculate days to quota at current rate
    // 4. Generate recommendations
}

pub fn generate_recommendations(
    forecast: &CapacityForecast,
) -> Vec<String> {
    let mut recs = vec![];
    if forecast.days_to_quota.is_some() && forecast.days_to_quota < Some(30) {
        recs.push("Consider increasing quota".into());
    }
    // ... more logic
    recs
}
```

**Acceptance Criteria**:
- Linear regression on provisioning rate (last 90 days)
- Forecast 30/60/90 days out
- Alerts when approaching quota (<30 days)
- Recommendations actionable (increase quota, cleanup unused)

---

## Cross-Cutting Considerations

**Testing Strategy**:
- Integration tests for each epic (fn-100 through fn-107)
- Simulation: synthetic workloads (high provisioning rates, quota hits)
- Compliance validation: audit logs match expected events

**Observability**:
- Per-epic metrics (policy evaluations, attestations signed, approvals, etc.)
- Distributed tracing: trace a provisioning request through all domain layers
- Runbooks: playbooks for common scenarios (quota exceeded, approval stuck, key rotation failure)

**Documentation**:
- User guides: how to use each feature (policies, attestations, approvals)
- Operator guides: deployment, monitoring, troubleshooting
- API reference: all endpoints, request/response schemas
- Examples: concrete workflows (supply chain signing, policy-driven CI)

---

## Summary: From fn-89 to Production

**fn-89** provides the **foundational infrastructure** (domain architecture, transactions, observability).

**fn-100–107** unlock **strategic use cases**:
- Policy-driven automation (fn-100)
- Supply chain security (fn-101)
- Operational continuity (fn-102, fn-104)
- Governance & approval (fn-103)
- Federation (fn-105)
- Compliance (fn-106)
- Operations intelligence (fn-107)

**Market Positioning**:
- Early: auths-api is infrastructure (supply chain signing, audit trails)
- Scale: policy-driven provisioning, approval workflows, federation
- Mature: compliance automation, analytics, advanced governance

**Timeline Estimate**:
- fn-89: 4–6 weeks (foundation)
- fn-100–103: 6–8 weeks (core features)
- fn-104–107: 4–6 weeks (optimization & intelligence)
- **Total to production-ready**: 3–4 months

**Go-to-Market**:
1. **Closed beta** (fn-89 + fn-100): fintech, infra platforms
2. **Open beta** (fn-89 + fn-100–103): broader enterprise
3. **GA** (fn-89–107): full feature set for compliance-heavy orgs
