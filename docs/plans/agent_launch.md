# Auths Agent Identity: Engineering Roadmap & Market Strategy

## Executive Summary

The agentic AI market is projected to grow from $7.55B (2025) to $199B by 2034 (CAGR 43.8%). NIST released its [NCCoE concept paper on AI agent identity](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) in February 2026, signaling that agent identity is now a regulatory-grade concern. The [MCP specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) now mandates OAuth 2.1 for tool authorization. An [IETF draft](https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-01.html) formalizes "on behalf of" delegation for AI agents. Auth0 launched a [Token Vault](https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/) specifically for AI agent credential management. HashiCorp positions [SPIFFE as the "TCP/IP of agent identity"](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors).

Auths has a structural advantage none of these players possess: **cryptographic delegation chains with capability narrowing from human to agent to sub-agent, verifiable offline, stored in Git**. This document maps the feedback's valuation milestones against the actual codebase state and defines the engineering work to capture this market.

---

## Part 1: What Exists vs. What's Missing

### Already Built (the feedback underestimates this)

| Capability | Location | Status |
|-----------|----------|--------|
| Agent provisioning API (headless, CI-ready) | `auths-id/src/agent_identity.rs` | Full. `provision_agent_identity()` with persistent/ephemeral storage modes, `AgentProvisioningConfig`, `AgentIdentityBundle`. |
| `SignerType` enum (Human/Agent/Workload) | `auths-verifier/src/core.rs:686-698` | Full. Signed into canonical attestation data — cannot be forged post-signing. |
| Delegation chains with `delegated_by` | `auths-verifier/src/core.rs:676-678` | Full. Field included in signed envelope. |
| Chain verification with capability narrowing | `auths-verifier/src/verifier.rs:138-166` | Full. Set-intersection semantics — capabilities can only narrow, never expand. |
| Policy engine (IsAgent/IsHuman/IsWorkload predicates) | `auths-policy/src/eval.rs:380-411` | Full. Also: `MaxChainDepth`, `WorkloadIssuerIs`, `WorkloadClaimEquals`, `DelegatedBy`. |
| OIDC bridge (attestation chain -> JWT) | `auths-oidc-bridge/src/` | Full. Token exchange, JWKS endpoint, cloud provider auto-detection (AWS/GCP/Azure). |
| GitHub Actions OIDC cross-referencing | `auths-oidc-bridge/src/github_oidc.rs` | Full. Confused-deputy prevention via actor/repo validation. |
| Agent signing daemon (IPC over Unix socket) | `auths-cli/src/commands/agent.rs` | Full. start/stop/status/lock/unlock/install-service (launchd/systemd). |
| Ephemeral agent identities (InMemory mode) | `auths-id/src/agent_identity.rs:62-64` | Full. Stateless containers (Fargate, Docker). Identity dies with process. |
| MCP integration pattern | `docs/architecture/oidc-bridge.md:92-102` | Documented. Agent exchanges attestation chain for JWT, presents to MCP server as Bearer token. |
| SPIFFE comparison & positioning | `docs/architecture/oidc-bridge.md:104-117` | Documented. Auths covers delegation gap SPIFFE doesn't address. |

### Not Yet Built

| Capability | NIST Alignment | Gap Size |
|-----------|---------------|----------|
| MCP tool server with Auths-native auth | NIST Focus Area 2 (Authorization) | Medium -- need an `auths-mcp-server` crate |
| SPIFFE SVID compatibility layer | NIST scope (SPIFFE referenced) | Medium -- bidirectional translation, not replacement |
| OAuth 2.1 "on behalf of" (IETF draft) | NIST Focus Area 3 (Access Delegation) | Medium -- extend OIDC bridge with `act` claim |
| Automatic chain depth calculation | Internal gap | Small -- ~50 lines in verify.rs |
| OIDC trust registry | NIST Focus Area 2 | Medium -- covered in v2_launch.md |
| Non-repudiation audit logging | NIST Focus Area 4 (Logging) | Large -- new crate |
| Human-in-the-loop approval gates | NIST Focus Area 3 | Medium -- policy + webhook |
| SCIM provisioning API | Enterprise IAM integration | Medium -- REST handlers |
| NGAC graph-based authorization | Beyond current policy engine | Large -- research-grade |
| HSM/hardware key storage | Enterprise compliance | Large -- covered in v2_launch.md |

---

## Part 2: Feedback Corrections

The feedback structures valuation milestones ($4M -> $500M) around building capabilities that **largely already exist**. Here's what the feedback gets wrong:

### 1. "Static Service Accounts" as the only competitor

The landscape has shifted dramatically since the feedback was written. The real competitors in 2026 are:

- **Auth0 Token Vault**: [Launched](https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/) with RFC 8693 token exchange for AI agents, 30+ pre-integrated OAuth providers, MCP support. Backed by Okta/Auth0 distribution. However: centralized, no delegation chains, no offline verification.
- **HashiCorp Vault + SPIFFE**: [Positioning SPIFFE for agentic AI](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors). Vault Enterprise 1.21 adds SPIFFE integration. However: requires SPIRE server (centralized), no human->agent delegation, no capability narrowing.
- **Google A2A Protocol**: Agent-to-agent communication protocol. No identity primitive -- relies on external identity providers.
- **MCP Authorization Layer**: [MCP spec](https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol) now requires OAuth 2.1, but "leaves authorization up to the implementer." This is the gap Auths fills.

### 2. "$10M: Implement SPIFFE/SPIRE Baselines"

Wrong framing. Auths should not implement SPIFFE -- it should **bridge to SPIFFE**. SPIFFE handles infrastructure-level workload identity (container attestation, node attestation). Auths handles the layer above: who authorized this workload, what can it do, and who is accountable. The two are complementary, not competitive. The OIDC bridge already provides the integration surface.

### 3. "NGAC (Next Generation Access Control)"

Premature. The existing `auths-policy` engine is already attribute-based with 30+ evaluation predicates, three-valued logic (Allow/Deny/Indeterminate), and composable expressions. NGAC's graph-based model adds complexity without clear user demand. The right move is to extend the existing engine with context-aware predicates rather than replace it with NGAC.

### 4. "Decouple Orchestration from Authorization"

Already done. The SDK's `AuthsContext` injects all dependencies. The `CommitSigningWorkflow` in `auths-sdk/src/workflows/signing.rs` is fully decoupled from CLI concerns. Ports (`AgentSigningPort`, `GitLogProvider`, etc.) abstract all I/O.

### 5. "Ephemeral State Management"

Already done. `AgentStorageMode::InMemory` creates a process-lifetime tempdir. Identity is torn down when the process exits (`std::mem::forget(tmp)` prevents premature cleanup but the OS reclaims on exit).

---

## Part 3: Revised Epics (NIST-Aligned)

The NIST NCCoE concept paper defines [four focus areas](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization). Every epic below maps to one or more:

1. **Identification**: Distinguishing AI agents from humans, managing agent metadata
2. **Authorization**: OAuth 2.0/2.1, policy-based access control
3. **Access Delegation**: Linking user identities to agents, maintaining accountability
4. **Logging & Transparency**: Linking agent actions to non-human entities

---

### Epic 1: MCP-Native Agent Authorization

**NIST alignment**: Focus Areas 1, 2
**Priority: P0**
**Effort: 3-4 weeks**

MCP is becoming the universal protocol for AI agents accessing tools. The [MCP spec now classifies servers as OAuth Resource Servers](https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol), but "leaves authorization up to the implementer." Auths fills this gap: MCP gets OAuth tokens, but those tokens carry cryptographic delegation provenance.

#### 1.1 Create `auths-mcp-server` crate

A reference MCP tool server that demonstrates Auths-backed authorization. This is the developer on-ramp -- an AI engineer drops it into their agent framework and gets cryptographic identity for free.

**File to create:** `crates/auths-mcp-server/src/lib.rs`

```rust
/// MCP tool server middleware that validates Auths-backed JWTs.
///
/// Extracts the Bearer token from the Authorization header, validates it
/// against the OIDC bridge's JWKS endpoint, and checks capabilities
/// against the requested tool.
///
/// Args:
/// * `jwks_url`: The OIDC bridge's `/.well-known/jwks.json` endpoint.
/// * `tool_capabilities`: Map of tool names to required capabilities.
///
/// Usage:
/// ```ignore
/// let auth = AuthsToolAuth::new(
///     "https://oidc.example.com/.well-known/jwks.json",
///     HashMap::from([
///         ("read_file", "fs:read"),
///         ("write_file", "fs:write"),
///         ("deploy", "deploy:staging"),
///     ]),
/// );
/// ```
pub struct AuthsToolAuth {
    jwks_url: String,
    tool_capabilities: HashMap<String, String>,
    jwks_cache: Arc<RwLock<CachedJwks>>,
}

impl AuthsToolAuth {
    /// Validate an incoming MCP tool invocation against the agent's capabilities.
    ///
    /// Args:
    /// * `bearer_token`: The JWT from the Authorization header.
    /// * `tool_name`: The MCP tool being invoked.
    pub async fn authorize_tool_call(
        &self,
        bearer_token: &str,
        tool_name: &str,
    ) -> Result<VerifiedAgent, AuthError> {
        let claims = self.validate_jwt(bearer_token).await?;
        let required_cap = self.tool_capabilities.get(tool_name)
            .ok_or(AuthError::UnknownTool(tool_name.to_string()))?;

        if !claims.capabilities.contains(&required_cap.to_string()) {
            return Err(AuthError::InsufficientCapabilities {
                required: required_cap.to_string(),
                granted: claims.capabilities.clone(),
            });
        }

        Ok(VerifiedAgent {
            did: claims.sub,
            keri_prefix: claims.keri_prefix,
            signer_type: claims.signer_type(),
            capabilities: claims.capabilities,
            delegated_by: claims.delegated_by(),
        })
    }
}
```

**Why this matters**: Every MCP tool server today does ad-hoc authorization (API keys, service accounts). This crate makes it one line to add cryptographic agent identity to any MCP server. The developer experience is: `cargo add auths-mcp-server`, configure tool->capability mapping, done.

#### 1.2 Agent-side MCP client helper

**File to create:** `crates/auths-sdk/src/workflows/mcp.rs`

```rust
/// Acquires an OAuth Bearer token for MCP tool server access.
///
/// Exchanges the agent's attestation chain for a scoped JWT via the OIDC bridge,
/// then attaches it to outgoing MCP requests.
///
/// Args:
/// * `bridge_url`: The OIDC bridge endpoint.
/// * `chain`: The agent's attestation chain.
/// * `root_public_key`: The root identity's Ed25519 public key.
/// * `requested_capabilities`: Capabilities needed for this MCP session.
///
/// Usage:
/// ```ignore
/// let token = acquire_mcp_token(&bridge_url, &chain, &root_pk, &["fs:read"]).await?;
/// ```
pub async fn acquire_mcp_token(
    bridge_url: &str,
    chain: &[Attestation],
    root_public_key: &[u8],
    requested_capabilities: &[&str],
) -> Result<String, McpAuthError> {
    // POST to bridge /token endpoint with attestation chain
    // Returns JWT with scoped capabilities
    todo!()
}
```

#### 1.3 Python SDK wrapper for AI frameworks

Most AI agent frameworks (LangChain, AutoGen, CrewAI, Semantic Kernel) are Python. The `auths-verifier` WASM bindings or C FFI provide the bridge, but a thin Python SDK is the adoption accelerant.

**File to create:** `sdks/python/auths_agent/auth.py`

```python
"""Auths agent identity for Python AI frameworks.

Usage with LangChain:
    from auths_agent import AuthsAgentAuth

    auth = AuthsAgentAuth(
        bridge_url="https://oidc.example.com",
        attestation_chain_path="~/.auths-agent/chain.json",
    )

    # Get Bearer token for MCP tool access
    token = auth.get_token(capabilities=["fs:read", "web:search"])
"""
```

**Testing (E2E):**
```bash
# 1. Provision agent identity
auths agent provision --name "mcp-test-agent" --capabilities "fs:read,fs:write"

# 2. Start OIDC bridge
auths-oidc-bridge --config bridge.toml &

# 3. Start reference MCP server with Auths auth
cargo run -p auths-mcp-server -- --bridge-url http://localhost:3300 &

# 4. Agent exchanges attestation for JWT and calls MCP tool
curl -X POST http://localhost:8080/mcp/tools/read_file \
  -H "Authorization: Bearer $(auths token exchange --capabilities fs:read)" \
  -d '{"path": "/tmp/test.txt"}'

# 5. Attempt unauthorized tool -- should fail
curl -X POST http://localhost:8080/mcp/tools/deploy \
  -H "Authorization: Bearer $(auths token exchange --capabilities fs:read)" \
  -d '{"env": "production"}'
# Expected: 403 Forbidden -- missing "deploy:staging" capability
```

---

### Epic 2: OAuth 2.1 "On Behalf Of" Delegation

**NIST alignment**: Focus Area 3 (Access Delegation)
**Priority: P0**
**Effort: 2-3 weeks**

The [IETF draft for OAuth 2.0 "on behalf of" for AI agents](https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-01.html) formalizes the pattern Auths already implements cryptographically. The draft introduces `requested_actor` and `actor_token` parameters so authorization servers can issue tokens that explicitly represent "Agent X acting on behalf of User Y."

Auths' attestation chains already encode this relationship (`delegated_by` + `signer_type`). The gap is surfacing it in the JWT format the IETF draft expects.

#### 2.1 Add `act` (actor) claim to bridge-issued JWTs

The IETF draft specifies an `act` claim in issued JWTs that identifies the actor (agent) distinct from the subject (human). Currently, the OIDC bridge issues `sub` as the root KERI DID. The `act` claim should identify the leaf agent.

**File to modify:** `crates/auths-oidc-bridge/src/token.rs`

```rust
/// Extended OIDC claims with RFC 8693 actor claim.
pub struct OidcClaims {
    // ... existing fields ...

    /// RFC 8693 actor claim -- identifies the agent acting on behalf of the subject.
    /// Present when the attestation chain has depth > 0 (delegation occurred).
    ///
    /// Usage:
    /// ```ignore
    /// // JWT payload:
    /// // "sub": "did:keri:EHuman123...",   // the human who authorized
    /// // "act": { "sub": "did:keri:EAgent456..." }  // the agent performing the action
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
}

/// The actor performing actions on behalf of the subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// The actor's DID (the leaf agent in the delegation chain).
    pub sub: String,
    /// The actor's signer type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<String>,
}
```

#### 2.2 Support RFC 8693 token exchange at the bridge

The OIDC bridge currently accepts attestation chains at `/token`. Extend it to also accept RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` requests, where an existing JWT can be exchanged for a narrower-scoped JWT. This enables agent->sub-agent delegation through standard OAuth flows.

**File to modify:** `crates/auths-oidc-bridge/src/routes.rs`

Add a new route handler for token exchange:

```rust
/// RFC 8693 token exchange endpoint.
///
/// Accepts a subject_token (existing JWT) and an actor_token (agent attestation),
/// and issues a new JWT with narrowed capabilities representing the actor
/// acting on behalf of the original subject.
///
/// Args:
/// * `grant_type`: Must be `urn:ietf:params:oauth:grant-type:token-exchange`
/// * `subject_token`: The parent agent's JWT
/// * `actor_token`: The sub-agent's attestation chain (JSON)
/// * `scope`: Requested capabilities (subset of parent's)
async fn handle_token_exchange(
    State(state): State<BridgeState>,
    Form(params): Form<TokenExchangeParams>,
) -> Result<Json<TokenExchangeResponse>, BridgeError> {
    // 1. Validate the subject_token JWT
    // 2. Verify the actor's attestation chain
    // 3. Intersect requested scope with subject_token's capabilities
    // 4. Issue new JWT with act claim pointing to the sub-agent
    todo!()
}
```

**Testing:**
```bash
# 1. Human's agent gets initial JWT
TOKEN=$(auths token exchange \
  --bridge http://localhost:3300 \
  --capabilities "sign:commit,deploy:staging")

# 2. Agent delegates to sub-agent via RFC 8693 token exchange
SUB_TOKEN=$(curl -X POST http://localhost:3300/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "actor_token=$(cat sub-agent-chain.json)" \
  -d "scope=deploy:staging")

# 3. Verify sub-token has act claim and narrowed scope
echo $SUB_TOKEN | jwt decode
# Expected: sub=did:keri:EHuman, act.sub=did:keri:ESubAgent, capabilities=[deploy:staging]
```

---

### Epic 3: Non-Repudiation Audit Logging

**NIST alignment**: Focus Area 4 (Logging & Transparency)
**Priority: P1**
**Effort: 3-4 weeks**

The NIST concept paper's fourth focus area is "Linking specific AI agent actions to their non-human entity to enable effective visibility into system activity." Auths' Git-native storage provides a natural append-only ledger. Every agent action can be logged as a signed Git commit, creating a tamper-evident audit trail traceable to the authorizing human.

#### 3.1 Create `auths-audit` crate

**File to create:** `crates/auths-audit/src/lib.rs`

```rust
/// An audit entry recording an agent's action, cryptographically bound to
/// its attestation chain and the authorizing human's identity.
///
/// Stored as signed JSON blobs under `refs/auths/audit/<agent-did>/`.
///
/// Args:
/// * `agent_did`: The agent's KERI identity.
/// * `action`: What the agent did (e.g., "tool:read_file", "deploy:staging").
/// * `target`: What was acted upon (e.g., file path, deployment ID).
/// * `attestation_rid`: The attestation RID that authorized this action.
/// * `delegation_chain_root`: The human DID at the root of the delegation chain.
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_did: String,
    pub action: String,
    pub target: String,
    pub attestation_rid: String,
    pub delegation_chain_root: String,
    pub signer_type: SignerType,
    /// Ed25519 signature over the canonical JSON of this entry.
    pub signature: Vec<u8>,
}
```

#### 3.2 Audit middleware for MCP server

Every tool invocation through `auths-mcp-server` automatically logs an `AuditEntry`. The audit log is a Git ref (`refs/auths/audit/`) -- tamper-evident, replicable, and queryable with standard Git tools.

#### 3.3 CLI audit query commands

```bash
# Show all actions by a specific agent
auths audit log --agent did:keri:EAgent456...

# Show all actions authorized by a specific human
auths audit log --root did:keri:EHuman123...

# Show all deploy actions in the last 24h
auths audit log --action "deploy:*" --since 24h

# Export as JSON for SIEM integration
auths audit export --format json --since 7d > audit.json
```

**Testing:**
```bash
# 1. Agent performs MCP tool call
curl -X POST http://localhost:8080/mcp/tools/read_file \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"path": "/tmp/test.txt"}'

# 2. Verify audit entry was created
auths audit log --agent did:keri:EAgent456... --since 1m
# Expected: timestamp | agent DID | tool:read_file | /tmp/test.txt | root:did:keri:EHuman123...

# 3. Verify audit entry signature
auths audit verify --entry <entry-id>
# Expected: "Signature valid. Authorized by: did:keri:EHuman123... via delegation chain."
```

---

### Epic 4: SPIFFE Bridge (Not Replacement)

**NIST alignment**: Focus Areas 1, 2
**Priority: P1**
**Effort: 2-3 weeks**

SPIFFE handles infrastructure-level identity ("this container is running in Kubernetes namespace X"). Auths handles authorization-level identity ("this agent is authorized by Human Y to do Z"). The bridge connects them: a SPIFFE SVID proves the runtime environment, an Auths attestation proves the authorization chain. Together they answer both "where is this running?" and "who said it could?"

#### 4.1 SPIFFE SVID verification in the OIDC bridge

**File to modify:** `crates/auths-oidc-bridge/src/lib.rs`

Accept a SPIFFE SVID as an optional attestation of the runtime environment during token exchange. The bridge embeds the SPIFFE ID in the issued JWT as a `spiffe_id` claim, binding the cryptographic identity to the physical execution boundary.

```rust
/// Optional SPIFFE workload attestation submitted alongside the attestation chain.
///
/// When present, the bridge verifies the X.509 SVID against the SPIFFE trust bundle
/// and embeds the SPIFFE ID in the issued JWT.
///
/// Usage:
/// ```ignore
/// POST /token
/// {
///   "attestation_chain": [...],
///   "root_public_key": "...",
///   "spiffe_svid": "<base64-encoded X.509 SVID>",
///   "spiffe_trust_bundle": "<base64-encoded trust bundle>"
/// }
/// ```
pub struct SpiffeAttestation {
    pub svid: Vec<u8>,
    pub trust_bundle: Vec<u8>,
}
```

#### 4.2 SVID-to-Attestation translation

For environments that already use SPIFFE, provide a function to bootstrap an Auths attestation chain from a verified SVID. The SVID proves runtime identity; the Auths chain adds capability scoping and human-traceable delegation.

**Testing:**
```bash
# 1. In a SPIRE-managed environment, get SVID
SVID=$(spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock)

# 2. Exchange SVID + attestation chain for JWT
curl -X POST http://localhost:3300/token \
  -d "{
    \"attestation_chain\": $(cat chain.json),
    \"root_public_key\": \"...\",
    \"spiffe_svid\": \"$SVID\"
  }"

# 3. Verify JWT contains both KERI and SPIFFE identifiers
echo $TOKEN | jwt decode
# Expected: sub=did:keri:E..., spiffe_id=spiffe://cluster.local/ns/default/sa/agent
```

---

### Epic 5: Human-in-the-Loop Approval Gates

**NIST alignment**: Focus Area 3 (Access Delegation)
**Priority: P2**
**Effort: 2-3 weeks**

The NIST concept paper specifically calls out "human-in-the-loop approval to autonomous action" as a spectrum that identity systems must support. The policy engine already has the predicates; what's missing is the execution mechanism that pauses an agent when it hits a policy boundary.

#### 5.1 Policy-driven approval gates

Extend the policy engine with a new decision outcome: `RequiresApproval`. When an action exceeds a risk threshold (e.g., deploying to production, deleting data), the policy engine returns this outcome instead of Allow/Deny. The MCP server or SDK pauses execution and emits an approval request.

**File to modify:** `crates/auths-policy/src/decision.rs`

```rust
pub enum Outcome {
    Allow,
    Deny,
    Indeterminate,
    /// Action requires human approval before proceeding.
    /// The agent's execution is paused until an approval attestation is received.
    RequiresApproval,
}
```

#### 5.2 Approval attestation format

A human approves by issuing a short-lived, single-use attestation:

```json
{
  "version": 1,
  "issuer": "did:keri:EHuman123...",
  "subject": "did:keri:EAgent456...",
  "capabilities": ["deploy:production"],
  "signer_type": "Human",
  "expires_at": "2026-03-05T10:35:00Z",
  "note": "Approved deploy to production for release v2.1.0"
}
```

This attestation is verified by the MCP server/SDK before allowing the action to proceed. The 5-minute expiry ensures the approval is contextual, not blanket.

#### 5.3 Approval notification channels

- **CLI**: `auths approve --request <request-id>` (for local development)
- **Webhook**: POST to configured URL with approval request payload (for Slack/Teams integration)
- **MCP**: Use MCP's [elicitation](https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/) to request user confirmation through the agent's UI

---

### Epic 6: SCIM Provisioning API

**NIST alignment**: Focus Area 1 (Identification)
**Priority: P2**
**Effort: 2-3 weeks**

Enterprises manage identities through SCIM (System for Cross-domain Identity Management). Adding SCIM support means IT teams can provision/deprovision agent identities through their existing directory (Okta, Azure AD, Google Workspace) rather than running CLI commands.

#### 6.1 SCIM resource types for agents

**File to create:** `crates/auths-scim/src/lib.rs`

Map Auths agent identities to SCIM resource types:

```rust
/// SCIM User resource representing an Auths agent identity.
///
/// Maps SCIM standard attributes to Auths identity fields:
/// - `userName` -> agent name
/// - `externalId` -> KERI DID
/// - `active` -> not revoked
/// - `entitlements` -> capabilities
/// - Custom schema extension for delegation chain metadata
pub struct ScimAgentResource {
    pub schemas: Vec<String>,
    pub id: String,          // Auths internal ID
    pub external_id: String, // KERI DID
    pub user_name: String,   // Agent name
    pub active: bool,        // Not revoked
    pub entitlements: Vec<ScimEntitlement>, // Capabilities
}
```

#### 6.2 REST endpoints

Standard SCIM endpoints (`/scim/v2/Users`, `/scim/v2/Groups`) backed by the Git registry. When an enterprise directory deprovisions an agent, the SCIM handler revokes the agent's attestation.

---

### Epic 7: Context-Aware Dynamic Authorization

**NIST alignment**: Focus Area 2 (Authorization)
**Priority: P3**
**Effort: 3-4 weeks**

The feedback proposes NGAC (graph-based authorization). The pragmatic move is to extend the existing policy engine with **context-reactive predicates** rather than replace it with a new graph model. This delivers the same outcome (dynamic authorization based on changing context) with far less complexity.

#### 7.1 Data classification predicates

When an agent retrieves a document classified as "Internal Confidential," its ability to call external tools should be automatically restricted. Extend the policy engine:

**File to modify:** `crates/auths-policy/src/expr.rs`

```rust
/// Checks if the current data context has a classification at or below the threshold.
/// Example: If context has "confidential" data, deny "webhook:external" capability.
DataClassificationBelow(String),

/// Checks if the current session has accumulated data from multiple sensitivity levels.
/// Prevents confused deputy attacks where an agent aggregates sensitive data
/// then exfiltrates it through a low-sensitivity channel.
NoSensitivityEscalation,
```

#### 7.2 Session-scoped capability reduction

The SDK maintains a session context that narrows available capabilities as the agent interacts with sensitive resources. This is an enforcement mechanism, not just a policy check -- the session's effective capabilities are recomputed after every tool call.

---

## Part 4: Valuation Milestones (Revised)

The feedback's milestones are directionally correct but miscalibrate what's already built. Here's a recalibrated view:

### Current State (~$4-6M Seed)

What exists today is **not** a fragile prototype. It's a production-grade identity primitive with:
- Full delegation chain verification (offline, no server)
- Three-tier signing workflow with platform keychain integration
- OIDC federation to AWS/GCP/Azure
- Policy engine with 30+ predicates
- Mobile FFI (UniFFI), WASM, and C FFI
- Agent provisioning API with ephemeral/persistent modes

The gap is **ecosystem integration, not core capability**.

### $10-15M (Post-Seed / Pre-Series A)

**Deliverables:** Epics 1 + 2 (MCP integration + OAuth 2.1 OBO)

The product becomes usable by AI engineers without leaving their framework. A LangChain developer adds `auths-agent` to their Python project, calls `auth.get_token()`, and gets cryptographic identity for their agent's MCP tool calls. Every action is traceable to a human principal.

**Proof point:** Working demo of "Agent signs a commit and deploys to staging, fully traceable to the authorizing human, with capability narrowing enforced at every hop."

### $20-30M (Series A)

**Deliverables:** Epics 3 + 4 + 6 (Audit logging + SPIFFE bridge + SCIM)

Enterprise IT teams can provision agent identities through their existing directory (Okta/Azure AD via SCIM), bind them to SPIFFE runtime attestation, and get tamper-evident audit logs. SOCs can answer "which human authorized this agent to deploy to production at 3am?"

**Proof point:** Integration with a Fortune 500's CI/CD pipeline. Audit logs feed into Splunk/Datadog.

### $60-100M (Series B)

**Deliverables:** Epics 5 + 7 (HITL approval gates + dynamic authorization)

The platform enforces real-time authorization boundaries. An agent that reads a confidential document is automatically blocked from calling external webhooks. High-risk actions (production deploys, data deletion) require human approval via MCP elicitation or Slack webhook. This is the "confused deputy" mitigation that the NIST concept paper calls for.

**Proof point:** NIST NCCoE demonstration project participation. FedRAMP authorization in progress.

### $300M+ (Series C / Category Leader)

**Deliverables:** Protocol standardization + cross-domain federation

Auths attestation chains become the wire format for agent-to-agent trust across enterprise boundaries. Company A's procurement agent presents an attestation chain to Company B's supply chain agent. Both verify offline. The OIDC bridge handles trust translation. Auths is the protocol layer, not just a product.

**Proof point:** IETF RFC or NIST SP referencing Auths' delegation chain format.

---

## Part 5: The Structural Moat

Every competitor in this space has a centralized dependency:

| Competitor | Central Dependency | What happens when it's down? |
|-----------|-------------------|-------------------------------|
| Auth0 Token Vault | Auth0's servers | All agent auth fails |
| HashiCorp Vault + SPIFFE | SPIRE server | No new SVIDs issued |
| Google A2A | Google's identity services | No agent-to-agent trust |
| Okta/CyberArk NHI | Vendor's cloud | All non-human identity fails |

Auths has **none**. Verification is a pure computation over the attestation chain and a root public key. No network call. No server dependency. Works in air-gapped environments, on submarines, in disconnected edge deployments.

The delegation chain is the second moat. No other system provides:

```
Human (KERI, hardware-backed)
  -> Device (Ed25519 dual-signed)
    -> AI Agent (scoped: sign:commit, 24h TTL)
      -> Sub-Agent (scoped: deploy:staging, 1h TTL)
        -> MCP Tool Call (scoped: fs:read, single-use)
```

Each link is independently verifiable. Capabilities only narrow. Any link can be revoked without affecting the chain above it. This is the zero-trust delegation model that the NIST concept paper describes but no one else has implemented.

---

## Part 6: Execution Priority Summary

| # | Epic | NIST Focus | Priority | Effort | Impact |
|---|------|-----------|----------|--------|--------|
| 1 | MCP-native agent authorization | 1, 2 | P0 | 3-4 weeks | Developer on-ramp, framework integration |
| 2 | OAuth 2.1 "on behalf of" | 3 | P0 | 2-3 weeks | Standards compliance, delegation chain in JWT |
| 3 | Non-repudiation audit logging | 4 | P1 | 3-4 weeks | Enterprise SOC requirement |
| 4 | SPIFFE bridge | 1, 2 | P1 | 2-3 weeks | Infrastructure interop |
| 5 | Human-in-the-loop approval | 3 | P2 | 2-3 weeks | Risk management, confused deputy prevention |
| 6 | SCIM provisioning | 1 | P2 | 2-3 weeks | Enterprise directory integration |
| 7 | Context-aware dynamic auth | 2 | P3 | 3-4 weeks | Advanced authorization, data classification |

**Critical path:** Epics 1 + 2 are the immediate priority. They transform Auths from "identity primitive" to "agent authorization infrastructure" and align directly with the NIST NCCoE demonstration scope.

---

## Sources

- [NIST NCCoE: Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- [NIST NCCoE Concept Paper (PDF, Feb 2026)](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)
- [IETF Draft: OAuth 2.0 On-Behalf-Of for AI Agents](https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-01.html)
- [MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [Stack Overflow: Authentication and Authorization in MCP](https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol)
- [Auth0 Token Vault for AI Agents](https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/)
- [HashiCorp: SPIFFE for Agentic AI and Non-Human Actors](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors)
- [HashiCorp: Zero Trust for Agentic Systems](https://www.hashicorp.com/en/blog/zero-trust-for-agentic-systems-managing-non-human-identities-at-scale)
- [Red Hat: Zero Trust for Autonomous Agentic AI Systems](https://next.redhat.com/2026/02/26/zero-trust-for-autonomous-agentic-ai-systems-building-more-secure-foundations/)
- [SPIFFE Meets OAuth2: Workload Identity in the Agentic AI Era](https://riptides.io/blog-post/spiffe-meets-oauth2-current-landscape-for-secure-workload-identity-in-the-agentic-ai-era/)
- [Agentic AI Market Size: $199B by 2034, CAGR 43.8%](https://www.precedenceresearch.com/agentic-ai-market)
- [Auth0 MCP Spec Updates (June 2025)](https://auth0.com/blog/mcp-specs-update-all-about-auth/)
- [Securing MCP: OAuth, mTLS, Zero Trust](https://dasroot.net/posts/2026/02/securing-model-context-protocol-oauth-mtls-zero-trust/)
