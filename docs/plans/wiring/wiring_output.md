# Wiring Output — Product-Driven Engineering Improvements

---

## Step 1 — Product Experience Analysis

### Are backend capabilities visible to users?

**Fully Exposed (9 capabilities):**
- Identity resolution, KEL management, attestation verification, device management
- Org membership, challenge-response auth, encrypted chat, artifact search, network stats

**Partially Exposed (4 capabilities):**

| Capability | What's Missing |
|---|---|
| Transparency log | Activity feed exists on web, but no inclusion proofs, no checkpoint viewer, no consistency verification UI |
| Policy engine | Org policy is display-only JSON on web — no lint, compile, explain, test, or diff tools |
| Org analytics | Backend has `/v1/orgs/{orgDid}/analytics` with signing coverage, member adoption, key health — **frontend never calls it** |
| Trust tier | Server computes `server_trust_tier` + `server_trust_score` but frontend falls back to client-side computation |

**Not Exposed (8 capabilities):**

| Capability | Backend Location | Impact |
|---|---|---|
| Agent delegation | `auths-sdk::workflows::org` + `auths-agent-demo` | Core differentiator for AI-age identity — invisible to web users |
| Audit/compliance reports | `auths-sdk::workflows::audit::AuditWorkflow` | CLI-only; orgs can't see signing compliance on web |
| System diagnostics | `auths-sdk::workflows::diagnostics::DiagnosticsWorkflow` | No self-service health checks |
| Policy diff + risk scoring | `auths-sdk::workflows::policy_diff` | Policy changes are blind — no risk preview |
| Allowed signers management | `auths-sdk::workflows::allowed_signers` | SSH integration invisible to web |
| IdP binding (Okta/Entra/Google/SAML) | `auths-cloud::auths-idp` | Enterprise onboarding has no web flow |
| Key rotation | `auths-sdk::workflows::rotation` | Critical security operation — CLI-only |
| Billing/subscription (Stripe) | Registry server `/v1/billing/*` | Backend wired but no frontend pages |

### Are APIs optimized for UI needs?

**No — several gaps:**

1. **Auth state not persisted.** `auth-context.tsx` stores tokens in React state only — page reload = logged out. No `localStorage`, no refresh token, no session cookie.

2. **Org members inferred from audit feed.** `org-client.tsx` extracts member DIDs from activity feed `org_add_member` entries. The backend has a proper `GET /v1/orgs/{orgDid}/members` endpoint with role, capabilities, and pagination — but the frontend doesn't use it.

3. **No batch verification endpoint used.** Frontend verifies artifacts via WASM one-at-a-time. Backend has `POST /v1/attestations/verify` but frontend never calls it.

4. **No identity creation on web.** `POST /v1/identities` exists and is public/self-authenticating. The `/try/individual` flow tells users to install the CLI. A web-based DID creation flow is feasible.

5. **Analytics endpoints built but unused.** Backend serves signing coverage, member adoption, and key health at `/v1/orgs/{orgDid}/analytics` — no frontend page consumes this.

### Are there product features blocked by architecture?

1. **Web-based identity creation** — Not architecturally blocked (API exists), but frontend doesn't implement it. Requires WebCrypto Ed25519 key generation client-side.
2. **Agent delegation dashboard** — SDK workflows exist but no REST API wraps them. Needs new registry endpoints.
3. **Policy playground** — `auths-policy` crate has `compile()`, `evaluate()`, `enforce()` — needs REST endpoints and a web editor.
4. **Mobile app** — 6 `/mobile/*` endpoints referenced by mobile clients don't exist in the registry server.

---

## Step 2 — Improvement Opportunities

### A. Backend Capabilities Not Surfaced

| # | Capability | SDK Function | Effort |
|---|---|---|---|
| A1 | Org analytics dashboard | `GET /v1/orgs/{orgDid}/analytics` (exists) | Low — frontend only |
| A2 | Org members direct listing | `GET /v1/orgs/{orgDid}/members` (exists) | Low — frontend only |
| A3 | Agent delegation management | `sdk::workflows::org::add_organization_member()` | Medium — needs REST + UI |
| A4 | Audit compliance reports | `sdk::workflows::audit::AuditWorkflow::generate_report()` | Medium — needs REST + UI |
| A5 | Policy playground | `auths_policy::compile()`, `evaluate3()`, `enforce()` | Medium — needs REST + UI |
| A6 | Billing/subscription pages | `/v1/billing/checkout`, `/billing/portal`, `/billing/info` | Low — frontend only |

### B. Missing Feature Pipelines

| # | Pipeline | Current State | Fix |
|---|---|---|---|
| B1 | Mobile API | Frontend references `/mobile/*` — endpoints don't exist | Add mobile routes to registry server |
| B2 | GitHub App verification | Webhook handlers log events but verification is TODO | Wire `auths-verifier` into webhook handler |
| B3 | Web identity creation | `/try/individual` points to CLI install | Add WebCrypto key gen + `POST /v1/identities` |
| B4 | SCIM → OIDC bridge | SCIM provisions agents but doesn't connect to OIDC | Wire provisioned agent capabilities into token claims |
| B5 | Invite acceptance flow | `POST /v1/invites/{code}/accept` exists but `/join/[code]` page may not call it | Verify and wire frontend |

### C. Inefficient APIs / Frontend Patterns

| # | Problem | Fix |
|---|---|---|
| C1 | Auth tokens not persisted across page reloads | Add `localStorage` persistence with expiry checks |
| C2 | Org members scraped from audit feed | Use `GET /v1/orgs/{orgDid}/members` directly |
| C3 | Client-side trust tier when server computes it | Ensure backend always returns `server_trust_tier` |
| C4 | No error retry/recovery | Add React Query `retry` configuration |

### D. Dead Code

| # | Item | Action |
|---|---|---|
| D1 | `auths-github-app` stub handlers | Either implement or remove |
| D2 | MCP `deploy`/`read_file`/`write_file` mock tools | Either implement or remove |
| D3 | `auths-agent-demo` disconnected simulation | Convert to integration test or remove |
| D4 | `transparency-placeholder.tsx` | Remove |
| D5 | Deleted subprojects (auths-legacy, auths-releases, auths-verify-action) | Clean git state |
| D6 | 15 deleted roadmap markdown files | Clean git state |

---

## Step 3 — Engineering Epics

### Epic 1: Surface Org Analytics & Members on Web

Expose the existing backend org analytics and member listing endpoints to the frontend. Zero backend work — purely frontend wiring.

### Epic 2: Persist Auth State

Fix the auth context so users stay logged in across page reloads. Add token refresh or at minimum `localStorage` persistence.

### Epic 3: Agent Delegation Dashboard

Build the REST API and web UI for managing AI agent delegations — the product's core differentiator for the AI era.

### Epic 4: Policy Playground

Expose the policy engine (lint, compile, evaluate, diff) via REST and build an interactive web editor.

### Epic 5: Audit & Compliance Dashboard

Surface commit signing audit reports on the web for organizations.

### Epic 6: Billing & Subscription Pages

Wire the existing Stripe billing endpoints to frontend pages for checkout, portal, and usage tracking.

### Epic 7: Web-Based Identity Creation

Allow users to create an identity directly from the browser using WebCrypto, removing the CLI installation requirement for first-time users.

### Epic 8: Remove Dead Code & Stubs

Clean up stub handlers, mock tools, disconnected demos, and deleted-but-tracked files.

### Epic 9: Mobile API Endpoints

Implement the `/mobile/*` API routes that the mobile clients reference but don't exist.

---

## Step 4 — Implementation Tasks

---

### Epic 1: Surface Org Analytics & Members on Web

#### Task 1.1: Add org analytics API calls to registry client

**Repository:** `auths-site`

**Files:** `apps/web/src/lib/api/registry.ts`

**Current code:**
```typescript
// No analytics fetch functions exist
export async function fetchOrgStatus(
  orgDid: string,
  token: string,
  signal?: AbortSignal,
): Promise<OrgStatusResponse> {
  return registryFetchAuth<OrgStatusResponse>(
    `/v1/orgs/${encodeURIComponent(orgDid)}/status`,
    token,
    signal,
  );
}
```

**Improved code:**
```typescript
export interface AnalyticsSummary {
  signing_coverage: {
    total_commits_verified: number;
    auths_signed: number;
    gpg_signed: number;
    ssh_signed: number;
    unsigned: number;
    coverage_percent: number;
  };
  member_adoption: {
    total_members: number;
    auths_active: number;
    active_signers: number;
    adoption_percent: number;
  };
  key_health: {
    total_keys: number;
    keys_due_for_rotation: number;
    keys_expiring_soon: number;
    keys_revoked: number;
  };
  period: { start: string; end: string; days: number };
}

export async function fetchOrgAnalytics(
  orgDid: string,
  token: string,
  signal?: AbortSignal,
): Promise<AnalyticsSummary> {
  return registryFetchAuth<AnalyticsSummary>(
    `/v1/orgs/${encodeURIComponent(orgDid)}/analytics`,
    token,
    signal,
  );
}

export interface MemberResponse {
  member_did: string;
  role: string | null;
  capabilities: string[];
  issuer: string;
  revoked_at: string | null;
  expires_at: string | null;
  added_at: string | null;
}

export async function fetchOrgMembers(
  orgDid: string,
  token: string,
  params?: { role?: string; include_revoked?: boolean; limit?: number; after?: string },
  signal?: AbortSignal,
): Promise<MemberResponse[]> {
  return registryFetchAuth<MemberResponse[]>(
    `/v1/orgs/${encodeURIComponent(orgDid)}/members`,
    token,
    signal,
    params as Record<string, string>,
  );
}
```

**Explanation:** The backend already serves org analytics at `GET /v1/orgs/{orgDid}/analytics` with signing coverage, member adoption, and key health. The backend also has `GET /v1/orgs/{orgDid}/members` with role/capability/pagination support. Adding these fetch functions unlocks the data for the frontend.

---

#### Task 1.2: Add React Query hooks for org analytics and members

**Repository:** `auths-site`

**Files:** `apps/web/src/lib/queries/registry.ts`

**Current code:**
```typescript
// Only orgPolicy and orgStatus hooks exist
orgPolicy: (orgDid: string) => [...registryKeys.all, 'orgPolicy', orgDid] as const,
orgStatus: (orgDid: string) => [...registryKeys.all, 'orgStatus', orgDid] as const,
```

**Improved code:**
```typescript
orgPolicy: (orgDid: string) => [...registryKeys.all, 'orgPolicy', orgDid] as const,
orgStatus: (orgDid: string) => [...registryKeys.all, 'orgStatus', orgDid] as const,
orgAnalytics: (orgDid: string) => [...registryKeys.all, 'orgAnalytics', orgDid] as const,
orgMembers: (orgDid: string) => [...registryKeys.all, 'orgMembers', orgDid] as const,
```

And add hooks:

```typescript
export function useOrgAnalytics(orgDid: string, token: string) {
  return useQuery({
    queryKey: registryKeys.orgAnalytics(orgDid),
    queryFn: ({ signal }) => fetchOrgAnalytics(orgDid, token, signal),
    enabled: orgDid.length > 0 && token.length > 0,
    staleTime: 300_000,
  });
}

export function useOrgMembers(orgDid: string, token: string) {
  return useQuery({
    queryKey: registryKeys.orgMembers(orgDid),
    queryFn: ({ signal }) => fetchOrgMembers(orgDid, token, signal),
    enabled: orgDid.length > 0 && token.length > 0,
    staleTime: 120_000,
  });
}
```

**Explanation:** These hooks follow existing patterns (TanStack Query, staleTime, signal forwarding) and unlock org analytics and member data for components.

---

#### Task 1.3: Replace audit-feed-inferred members with direct member listing

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/org-client.tsx`

**Current code:**
```typescript
function OrgMembers({ members }: { members: FeedEntry[] }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? members : members.slice(0, INITIAL_CAP);
  const hasMore = members.length > INITIAL_CAP;

  // Extracts member_did from activity feed entries
  const memberDid = entry.metadata.member_did as string | undefined;
}
```

**Improved code:**
```typescript
function OrgMembers({ orgDid, token }: { orgDid: string; token: string }) {
  const { data: members, isLoading } = useOrgMembers(orgDid, token);
  const [showAll, setShowAll] = useState(false);

  if (isLoading) return <MembersSkeleton />;
  if (!members?.length) return <EmptyMembers />;

  const active = members.filter((m) => !m.revoked_at);
  const visible = showAll ? active : active.slice(0, INITIAL_CAP);

  return (
    <section>
      <h2>Members ({active.length})</h2>
      {visible.map((member) => (
        <MemberRow
          key={member.member_did}
          did={member.member_did}
          role={member.role}
          capabilities={member.capabilities}
          addedAt={member.added_at}
        />
      ))}
      {active.length > INITIAL_CAP && !showAll && (
        <button onClick={() => setShowAll(true)}>Show all</button>
      )}
    </section>
  );
}
```

**Explanation:** Replaces the fragile pattern of inferring members from the audit activity feed with a direct call to `GET /v1/orgs/{orgDid}/members`. This gives us proper roles, capabilities, and revocation status — data that was lost when scraping from audit entries.

---

#### Task 1.4: Add org analytics dashboard section to org page

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/org-client.tsx` (new section)

**Current code:**
```typescript
// No analytics section exists on org page
```

**Improved code:**
```typescript
function OrgAnalyticsDashboard({ orgDid, token }: { orgDid: string; token: string }) {
  const { data, isLoading } = useOrgAnalytics(orgDid, token);

  if (isLoading) return <AnalyticsSkeleton />;
  if (!data) return null;

  const { signing_coverage, member_adoption, key_health } = data;

  return (
    <section className="grid grid-cols-3 gap-4">
      <StatCard
        label="Signing Coverage"
        value={`${signing_coverage.coverage_percent.toFixed(1)}%`}
        detail={`${signing_coverage.auths_signed} auths-signed of ${signing_coverage.total_commits_verified} verified`}
      />
      <StatCard
        label="Member Adoption"
        value={`${member_adoption.adoption_percent.toFixed(1)}%`}
        detail={`${member_adoption.auths_active} active of ${member_adoption.total_members} members`}
      />
      <StatCard
        label="Key Health"
        value={`${key_health.total_keys - key_health.keys_due_for_rotation - key_health.keys_revoked}`}
        detail={`${key_health.keys_due_for_rotation} due for rotation, ${key_health.keys_expiring_soon} expiring soon`}
        warn={key_health.keys_due_for_rotation > 0}
      />
    </section>
  );
}
```

**Explanation:** The backend already computes signing coverage (what % of commits are signed), member adoption (what % of members use auths), and key health (rotation/expiry status). Surfacing this on the org page turns the product into a compliance dashboard — the primary value proposition for enterprise buyers.

---

### Epic 2: Persist Auth State

#### Task 2.1: Add localStorage persistence to auth context

**Repository:** `auths-site`

**Files:** `apps/web/src/lib/auth/auth-context.tsx`

**Current code:**
```typescript
interface AuthState {
  token: string;
  did: string;
  expiresAt: string;
}

// In provider:
const [auth, setAuthState] = useState<AuthState | null>(null);
```

**Improved code:**
```typescript
const AUTH_STORAGE_KEY = 'auths_auth_state';

function loadPersistedAuth(): AuthState | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) return null;
  const parsed = JSON.parse(raw) as AuthState;
  if (Date.now() >= Date.parse(parsed.expiresAt)) {
    localStorage.removeItem(AUTH_STORAGE_KEY);
    return null;
  }
  return parsed;
}

// In provider:
const [auth, setAuthState] = useState<AuthState | null>(loadPersistedAuth);

const setAuth = useCallback((state: AuthState) => {
  setAuthState(state);
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(state));
}, []);

const clearAuth = useCallback(() => {
  setAuthState(null);
  localStorage.removeItem(AUTH_STORAGE_KEY);
}, []);
```

**Explanation:** Currently, every page reload logs the user out because auth state is held only in React state. This adds `localStorage` persistence with automatic expiry checking. The DID challenge-response flow requires the user to run a CLI command — losing that session on reload is a terrible UX.

---

### Epic 3: Agent Delegation Dashboard

#### Task 3.1: Add delegation REST endpoints to registry server

**Repository:** `auths-cloud`

**Files:** `crates/auths-registry-server/src/routes/delegation.rs` (new file)

**Current code:**
```
// No delegation endpoints exist
```

**Improved code:**
```rust
use axum::{extract::State, routing::{get, post, delete}, Json, Router};
use crate::{middleware::identity_auth::AuthenticatedIdentity, state::ServerState, error::ApiError};

pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/", post(create_delegation))
        .route("/", get(list_delegations))
        .route("/{delegation_rid}", get(get_delegation))
        .route("/{delegation_rid}/revoke", post(revoke_delegation))
}

#[derive(Deserialize)]
pub struct CreateDelegationRequest {
    pub delegate_did: String,
    pub capabilities: Vec<String>,
    pub expires_in_seconds: Option<u64>,
    pub delegate_type: DelegateType,  // Agent | Human | Workload
}

#[derive(Serialize)]
pub struct DelegationResponse {
    pub rid: String,
    pub issuer: String,
    pub delegate_did: String,
    pub delegate_type: String,
    pub capabilities: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub status: String,  // active | expired | revoked
}

async fn create_delegation(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
    Json(req): Json<CreateDelegationRequest>,
) -> Result<Json<DelegationResponse>, ApiError> {
    // Uses auths-sdk::workflows::org::add_organization_member()
    // with delegate_type to distinguish agent/human/workload
    todo!()
}

async fn list_delegations(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
) -> Result<Json<Vec<DelegationResponse>>, ApiError> {
    // Query delegations issued by auth.did
    todo!()
}

async fn revoke_delegation(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
    Path(rid): Path<String>,
) -> Result<Json<DelegationResponse>, ApiError> {
    // Uses auths-sdk revocation workflow
    todo!()
}
```

**Explanation:** Agent delegation is the product's core differentiator. The SDK has full support for scoped, time-bounded delegation to AI agents with capability-based authorization. But there's no REST API — it's only usable from the CLI. This endpoint enables the web dashboard.

---

#### Task 3.2: Add delegation management page to frontend

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/delegations/page.tsx` (new), `apps/web/src/app/registry/org/[did]/delegations/delegations-client.tsx` (new)

**Current code:**
```
// No delegation UI exists
```

**Improved code:**
```typescript
// delegations-client.tsx
'use client';

export function DelegationsClient({ orgDid }: { orgDid: string }) {
  const { auth } = useAuth();
  const { data: delegations, isLoading } = useDelegations(orgDid, auth?.token ?? '');
  const [showCreate, setShowCreate] = useState(false);

  return (
    <div>
      <header className="flex justify-between items-center">
        <h1>Agent Delegations</h1>
        <button onClick={() => setShowCreate(true)}>New Delegation</button>
      </header>

      <div className="grid gap-4">
        {delegations?.map((d) => (
          <DelegationCard
            key={d.rid}
            delegation={d}
            onRevoke={() => revokeDelegation(d.rid)}
          />
        ))}
      </div>

      {showCreate && (
        <CreateDelegationModal
          orgDid={orgDid}
          onClose={() => setShowCreate(false)}
        />
      )}
    </div>
  );
}

function DelegationCard({ delegation, onRevoke }: {
  delegation: DelegationResponse;
  onRevoke: () => void;
}) {
  return (
    <div className="border border-zinc-800 rounded-lg p-4">
      <div className="flex justify-between">
        <div>
          <span className="text-xs text-zinc-500">{delegation.delegate_type}</span>
          <p className="font-mono text-sm">{delegation.delegate_did}</p>
        </div>
        <StatusBadge status={delegation.status} />
      </div>
      <div className="flex gap-2 mt-2">
        {delegation.capabilities.map((cap) => (
          <span key={cap} className="px-2 py-0.5 bg-zinc-800 rounded text-xs">{cap}</span>
        ))}
      </div>
      <div className="flex justify-between mt-3 text-xs text-zinc-500">
        <span>Expires: {delegation.expires_at ?? 'never'}</span>
        {delegation.status === 'active' && (
          <button onClick={onRevoke} className="text-red-400 hover:text-red-300">
            Revoke
          </button>
        )}
      </div>
    </div>
  );
}

function CreateDelegationModal({ orgDid, onClose }: {
  orgDid: string;
  onClose: () => void;
}) {
  const [delegateDid, setDelegateDid] = useState('');
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [delegateType, setDelegateType] = useState<'agent' | 'human' | 'workload'>('agent');
  const [expiresIn, setExpiresIn] = useState('3600');

  return (
    <dialog open className="bg-zinc-900 border border-zinc-700 rounded-xl p-6 max-w-lg">
      <h2>Create Delegation</h2>

      <label>Delegate DID</label>
      <input value={delegateDid} onChange={(e) => setDelegateDid(e.target.value)} />

      <label>Type</label>
      <select value={delegateType} onChange={(e) => setDelegateType(e.target.value as any)}>
        <option value="agent">AI Agent</option>
        <option value="human">Human</option>
        <option value="workload">Workload</option>
      </select>

      <label>Capabilities</label>
      <CapabilityPicker selected={capabilities} onChange={setCapabilities} />

      <label>Expires in (seconds)</label>
      <input type="number" value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)} />

      <div className="flex gap-2 mt-4">
        <button onClick={onClose}>Cancel</button>
        <button onClick={() => { /* submit */ }}>Create</button>
      </div>
    </dialog>
  );
}
```

**Explanation:** This page gives users a visual interface for managing scoped, time-bounded delegations to AI agents — the core product differentiator. Users can create delegations with specific capabilities (`deploy:staging`, `sign_commit`, etc.), set expiry, and revoke instantly. This is the feature that makes Auths unique in the AI era.

---

### Epic 4: Policy Playground

#### Task 4.1: Add policy evaluation REST endpoints

**Repository:** `auths-cloud`

**Files:** `crates/auths-registry-server/src/routes/policy.rs` (new file)

**Current code:**
```
// No policy evaluation endpoints exist (only org policy GET/SET)
```

**Improved code:**
```rust
pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/lint", post(lint_policy))
        .route("/compile", post(compile_policy))
        .route("/evaluate", post(evaluate_policy))
        .route("/diff", post(diff_policies))
}

#[derive(Deserialize)]
pub struct PolicyInput {
    pub expression: serde_json::Value,  // Policy Expr as JSON
}

#[derive(Serialize)]
pub struct LintResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct EvalResult {
    pub decision: String,      // Allow | Deny | Abstain
    pub matched_predicates: Vec<String>,
    pub unmatched_predicates: Vec<String>,
}

#[derive(Deserialize)]
pub struct DiffRequest {
    pub old_policy: serde_json::Value,
    pub new_policy: serde_json::Value,
}

#[derive(Serialize)]
pub struct DiffResult {
    pub changes: Vec<PolicyChange>,
    pub overall_risk: String,  // HIGH | MEDIUM | LOW
}

#[derive(Serialize)]
pub struct PolicyChange {
    pub kind: String,         // added | removed | changed
    pub description: String,
    pub risk: String,
}

async fn lint_policy(
    Json(input): Json<PolicyInput>,
) -> Result<Json<LintResult>, ApiError> {
    // Uses auths_policy::compile() to validate syntax
    // Returns structured errors if invalid
    todo!()
}

async fn evaluate_policy(
    Json(input): Json<EvalRequest>,
) -> Result<Json<EvalResult>, ApiError> {
    // Uses auths_policy::evaluate3() with provided context
    todo!()
}

async fn diff_policies(
    Json(input): Json<DiffRequest>,
) -> Result<Json<DiffResult>, ApiError> {
    // Uses auths-sdk::workflows::policy_diff::compute_policy_diff()
    // + overall_risk_score()
    todo!()
}
```

**Explanation:** The `auths-policy` crate is a full expression-based policy engine with compile, evaluate, and diff capabilities. Exposing these via REST enables a web-based policy playground where org admins can write policies, test them against sample attestations, and preview the risk of policy changes before deploying.

---

#### Task 4.2: Add policy playground page to frontend

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/policy/page.tsx` (new), `apps/web/src/app/registry/org/[did]/policy/policy-playground.tsx` (new)

**Current code:**
```typescript
// OrgSigningPolicy in org-client.tsx is read-only JSON display:
function OrgSigningPolicy({ orgDid }: { orgDid: string }) {
  const { data: policy } = useOrgPolicy(orgDid);
  return (
    <pre className="text-xs">{JSON.stringify(policy, null, 2)}</pre>
  );
}
```

**Improved code:**
```typescript
// policy-playground.tsx
'use client';

export function PolicyPlayground({ orgDid }: { orgDid: string }) {
  const [expr, setExpr] = useState('');
  const [lintResult, setLintResult] = useState<LintResult | null>(null);
  const [evalResult, setEvalResult] = useState<EvalResult | null>(null);
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const { data: currentPolicy } = useOrgPolicy(orgDid);

  const handleLint = async () => {
    const result = await lintPolicy(JSON.parse(expr));
    setLintResult(result);
  };

  const handleDiff = async () => {
    if (!currentPolicy) return;
    const result = await diffPolicies(currentPolicy, JSON.parse(expr));
    setDiffResult(result);
  };

  return (
    <div className="grid grid-cols-2 gap-6">
      <div>
        <h2>Policy Editor</h2>
        <textarea
          value={expr}
          onChange={(e) => setExpr(e.target.value)}
          className="w-full h-64 font-mono text-sm bg-zinc-900 border border-zinc-700 rounded p-3"
          placeholder='{"And": [{"HasCapability": "sign_commit"}, {"NotRevoked": true}]}'
        />
        <div className="flex gap-2 mt-2">
          <button onClick={handleLint}>Lint</button>
          <button onClick={handleDiff}>Diff vs Current</button>
        </div>
      </div>

      <div>
        {lintResult && (
          <div>
            <h3>{lintResult.valid ? 'Valid' : 'Invalid'}</h3>
            {lintResult.errors.map((e, i) => (
              <p key={i} className="text-red-400 text-sm">{e}</p>
            ))}
          </div>
        )}

        {diffResult && (
          <div>
            <h3>Risk: <RiskBadge level={diffResult.overall_risk} /></h3>
            {diffResult.changes.map((c, i) => (
              <div key={i} className="border-l-2 border-zinc-700 pl-3 my-2">
                <span className="text-xs">{c.kind}</span>
                <p className="text-sm">{c.description}</p>
                <RiskBadge level={c.risk} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

**Explanation:** Org admins need to understand the impact of policy changes before deploying them. The policy playground lets admins write a new policy expression, lint it for syntax, evaluate it against test scenarios, and see a semantic diff with risk classification (HIGH/MEDIUM/LOW) against the current production policy. This prevents accidental lockouts or permission escalation.

---

### Epic 5: Audit & Compliance Dashboard

#### Task 5.1: Add audit report REST endpoint

**Repository:** `auths-cloud`

**Files:** `crates/auths-registry-server/src/routes/audit.rs` (new file)

**Current code:**
```
// Only GET /v1/orgs/{orgDid}/audit exists for raw audit log
// No compliance report generation
```

**Improved code:**
```rust
pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/report", get(get_audit_report))
}

#[derive(Serialize)]
pub struct AuditReportResponse {
    pub summary: AuditSummaryResponse,
    pub period: AuditPeriod,
    pub entries: Vec<AuditEntryResponse>,
}

#[derive(Serialize)]
pub struct AuditSummaryResponse {
    pub total_commits: u64,
    pub signed_commits: u64,
    pub verified_commits: u64,
    pub unsigned_commits: u64,
    pub unknown_signer_commits: u64,
    pub signing_rate: f64,
    pub verification_rate: f64,
    pub unique_signers: u64,
}

async fn get_audit_report(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
    Path(org_did): Path<String>,
    Query(params): Query<AuditReportQuery>,
) -> Result<Json<AuditReportResponse>, ApiError> {
    // Uses auths-sdk::workflows::audit::AuditWorkflow::generate_report()
    // Scoped to org repositories
    todo!()
}
```

**Explanation:** The SDK has a complete audit workflow (`AuditWorkflow::generate_report()`) that analyzes git commit history for signing compliance. Exposing this via REST lets orgs generate compliance reports from the web. This is the data enterprise security teams need to see.

---

#### Task 5.2: Add audit dashboard page to org view

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/audit/page.tsx` (new)

**Current code:**
```
// No audit dashboard page exists
```

**Improved code:**
```typescript
'use client';

export function AuditDashboard({ orgDid }: { orgDid: string }) {
  const { auth } = useAuth();
  const { data: report, isLoading } = useAuditReport(orgDid, auth?.token ?? '');

  if (isLoading) return <AuditSkeleton />;
  if (!report) return null;

  const { summary } = report;

  return (
    <div>
      <h1>Signing Compliance</h1>

      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Signing Rate"
          value={`${summary.signing_rate.toFixed(1)}%`}
          detail={`${summary.signed_commits} of ${summary.total_commits} commits`}
        />
        <StatCard
          label="Verification Rate"
          value={`${summary.verification_rate.toFixed(1)}%`}
          detail={`${summary.verified_commits} fully verified`}
        />
        <StatCard
          label="Unsigned Commits"
          value={summary.unsigned_commits.toString()}
          warn={summary.unsigned_commits > 0}
        />
        <StatCard
          label="Unique Signers"
          value={summary.unique_signers.toString()}
        />
      </div>

      <section className="mt-8">
        <h2>Commit History</h2>
        <AuditEntryTable entries={report.entries} />
      </section>
    </div>
  );
}
```

**Explanation:** Turns the CLI-only audit report into a visual compliance dashboard. Enterprise customers need this to demonstrate signing compliance to security auditors and leadership. The signing rate and verification rate are the key metrics that justify adopting Auths.

---

### Epic 6: Billing & Subscription Pages

#### Task 6.1: Add billing API calls to frontend

**Repository:** `auths-site`

**Files:** `apps/web/src/lib/api/registry.ts`

**Current code:**
```
// No billing fetch functions exist
```

**Improved code:**
```typescript
export interface BillingInfo {
  org_did: string;
  plan: string;
  status: string;
  current_period_end: string;
  usage: { identities: number; attestations: number; members: number };
  limits: { identities: number; attestations: number; members: number };
}

export async function fetchBillingInfo(
  orgDid: string,
  token: string,
  signal?: AbortSignal,
): Promise<BillingInfo> {
  return registryFetchAuth<BillingInfo>(
    `/v1/billing/info?org_did=${encodeURIComponent(orgDid)}`,
    token,
    signal,
  );
}

export async function createCheckoutSession(
  orgDid: string,
  plan: string,
  token: string,
): Promise<{ url: string }> {
  return registryFetchAuth<{ url: string }>(
    '/v1/billing/checkout',
    token,
    undefined,
    undefined,
    { method: 'POST', body: JSON.stringify({ org_did: orgDid, plan }) },
  );
}

export async function createPortalSession(
  orgDid: string,
  token: string,
): Promise<{ url: string }> {
  return registryFetchAuth<{ url: string }>(
    '/v1/billing/portal',
    token,
    undefined,
    undefined,
    { method: 'POST', body: JSON.stringify({ org_did: orgDid }) },
  );
}
```

**Explanation:** The registry server already has Stripe-integrated billing endpoints (`/v1/billing/checkout`, `/v1/billing/portal`, `/v1/billing/info`) that return 501 when Stripe isn't configured. Adding frontend fetch functions wires up the billing flow for when Stripe keys are set.

---

#### Task 6.2: Add billing page to org settings

**Repository:** `auths-site`

**Files:** `apps/web/src/app/registry/org/[did]/billing/page.tsx` (new)

**Current code:**
```
// No billing page exists
```

**Improved code:**
```typescript
'use client';

export function BillingPage({ orgDid }: { orgDid: string }) {
  const { auth } = useAuth();
  const { data: billing, isLoading } = useBillingInfo(orgDid, auth?.token ?? '');

  if (isLoading) return <BillingSkeleton />;
  if (!billing) return <FreeTierCTA orgDid={orgDid} />;

  return (
    <div>
      <h1>Billing</h1>

      <div className="border border-zinc-800 rounded-lg p-6">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-lg font-medium">{billing.plan} Plan</p>
            <p className="text-sm text-zinc-500">
              Renews {new Date(billing.current_period_end).toLocaleDateString()}
            </p>
          </div>
          <button onClick={() => openPortal(orgDid)}>Manage Subscription</button>
        </div>
      </div>

      <section className="mt-6">
        <h2>Usage</h2>
        <UsageBar label="Identities" used={billing.usage.identities} limit={billing.limits.identities} />
        <UsageBar label="Attestations" used={billing.usage.attestations} limit={billing.limits.attestations} />
        <UsageBar label="Members" used={billing.usage.members} limit={billing.limits.members} />
      </section>
    </div>
  );
}
```

**Explanation:** Without billing pages, there's no monetization path. The backend has full Stripe integration — checkout, customer portal, usage tracking — but no frontend surfaces it. This page lets orgs see their plan, usage, and manage subscriptions via Stripe Customer Portal.

---

### Epic 7: Web-Based Identity Creation

#### Task 7.1: Add WebCrypto identity creation flow

**Repository:** `auths-site`

**Files:** `apps/web/src/app/try/individual/web-identity-step.tsx` (new)

**Current code:**
```typescript
// install-step.tsx tells users to install CLI:
// "Install the auths CLI to get started"
// brew install auths/tap/auths
```

**Improved code:**
```typescript
'use client';

export function WebIdentityStep({ onComplete }: { onComplete: (did: string) => void }) {
  const [state, setState] = useState<'idle' | 'generating' | 'registering' | 'done' | 'error'>('idle');

  const createIdentity = async () => {
    setState('generating');

    // Generate Ed25519 keypair in browser via WebCrypto
    const keyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    );

    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyHex = Array.from(new Uint8Array(publicKeyRaw))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    setState('registering');

    // Register with the registry (POST /v1/identities is public + self-authenticating)
    const response = await fetch(`${REGISTRY_BASE_URL}/v1/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key_hex: publicKeyHex,
        display_name: null,
      }),
    });

    if (!response.ok) {
      setState('error');
      return;
    }

    const { did } = await response.json();

    // Store private key in IndexedDB for future signing
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    await storeKeyInIndexedDB(did, privateKeyJwk);

    setState('done');
    onComplete(did);
  };

  return (
    <div>
      <h2>Create Your Identity</h2>
      <p className="text-zinc-400">
        Generate a cryptographic identity directly in your browser.
        Your private key never leaves this device.
      </p>

      {state === 'idle' && (
        <button onClick={createIdentity}>Create Identity</button>
      )}
      {state === 'generating' && <p>Generating Ed25519 keypair...</p>}
      {state === 'registering' && <p>Registering with the network...</p>}
      {state === 'done' && <p className="text-emerald-400">Identity created!</p>}
    </div>
  );
}
```

**Explanation:** The biggest onboarding friction is requiring CLI installation before users can do anything. The `POST /v1/identities` endpoint is public and self-authenticating — it doesn't require a pre-existing identity. By generating Ed25519 keys via WebCrypto and registering directly, users can create an identity in one click. The private key stays in IndexedDB. Users can export to CLI later.

---

### Epic 8: Remove Dead Code & Stubs

#### Task 8.1: Remove transparency-placeholder.tsx

**Repository:** `auths-site`

**Files:** `apps/web/src/components/transparency-placeholder.tsx`

**Current code:**
```typescript
// File exists but is not imported anywhere
export function TransparencyPlaceholder() { ... }
```

**Improved code:**
```
// Delete file
```

**Explanation:** No component imports this file. It's dead code.

---

#### Task 8.2: Remove or flag GitHub App stubs

**Repository:** `auths-github-app`

**Files:** `src/webhook.rs`, `src/github.rs`

**Current code:**
```rust
// webhook.rs: Push + PR handlers log events but verification is TODO
// github.rs: GitHub API client is a stub — no check runs posted
```

**Improved code:**
```
// Option A: Delete auths-github-app entirely and track as future epic
// Option B: Add TODO tracking issue and mark as experimental
```

**Explanation:** The GitHub App receives webhooks but does nothing with them — verification logic is TODO, check run creation is a stub. With zero users, keeping stub code increases maintenance burden. Either implement or remove.

---

#### Task 8.3: Clean deleted files from git

**Repository:** `auths-base` (root)

**Files:** 15 deleted roadmap files, 3 deleted subprojects

**Current code:**
```
git status shows:
 D auths-legacy/auths
 D auths-releases
 D auths-verify-action
 D crate_org_roadmap.md ... (15 files)
```

**Improved code:**
```bash
git add auths-legacy auths-releases auths-verify-action
git add crate_org_roadmap.md current_roadmap.md debate_roadmap.md \
       ecosystem_roadmap.md enterprise_roadmap.md financial_success_roadmap.md \
       gamification_roadmap.md http_security.md licensing_roadmap.md \
       milestone_roadmap_2.md new_roadmap.md roadmap_auths.md \
       roadmap_overall.md stripe_roadmap.md unicorn_roadmap.md
git commit -m "chore: remove legacy subprojects and obsolete roadmap files"
```

**Explanation:** 18 files are shown as deleted in `git status` but never committed. This clutters the working tree and makes it harder to see real changes. Commit the deletions to clean up.

---

### Epic 9: Mobile API Endpoints

#### Task 9.1: Add mobile API routes to registry server

**Repository:** `auths-cloud`

**Files:** `crates/auths-registry-server/src/routes/mobile.rs` (new file), `crates/auths-registry-server/src/routes/mod.rs`

**Current code:**
```
// No /mobile/* routes exist
// Mobile clients reference:
// GET  /mobile/identity
// GET  /mobile/devices
// POST /mobile/pair/initiate
// POST /mobile/pair/complete
// POST /mobile/emergency/freeze
// POST /mobile/notifications/register
```

**Improved code:**
```rust
pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/identity", get(get_mobile_identity))
        .route("/devices", get(list_mobile_devices))
        .route("/devices/{id}/revoke", post(revoke_mobile_device))
        .route("/pair/initiate", post(initiate_pairing))
        .route("/pair/complete", post(complete_pairing))
        .route("/emergency/freeze", post(emergency_freeze))
        .route("/notifications/register", post(register_notifications))
}

async fn get_mobile_identity(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
) -> Result<Json<MobileIdentityResponse>, ApiError> {
    // Optimized response for mobile: identity + devices + recent activity
    // Single round-trip instead of 3 separate calls
    todo!()
}

async fn emergency_freeze(
    State(state): State<ServerState>,
    auth: AuthenticatedIdentity,
) -> Result<Json<FreezeResponse>, ApiError> {
    // Mark identity as frozen — all attestations become invalid
    // Uses auths-id freeze enforcement
    todo!()
}
```

**Explanation:** The mobile apps (iOS SwiftUI + Android Compose) reference 6 `/mobile/*` endpoints that don't exist in the registry server. These endpoints are mobile-optimized variants that aggregate data (e.g., identity + devices in one call) to reduce round-trips on cellular connections. Without these, the mobile app is non-functional against the live backend.

---

## Step 5 — Priority

### Critical

| Task | Epic | Rationale |
|---|---|---|
| 2.1 Persist auth state | Epic 2 | Users lose session on every page reload — fundamental UX bug |
| 1.3 Replace audit-feed members with direct listing | Epic 1 | Members list is fragile — data extracted from wrong source |
| 8.3 Clean deleted files from git | Epic 8 | 18 deleted files pollute `git status` |

### High

| Task | Epic | Rationale |
|---|---|---|
| 1.1 Add org analytics API calls | Epic 1 | Backend exists, zero backend work, high product value |
| 1.2 Add org analytics/members hooks | Epic 1 | Unlocks data for components |
| 1.4 Add org analytics dashboard | Epic 1 | Enterprise compliance dashboard — key selling point |
| 7.1 Web-based identity creation | Epic 7 | Removes CLI requirement for first-time users — biggest onboarding friction |
| 3.1 Delegation REST endpoints | Epic 3 | Enables core differentiator (AI agent delegation) |
| 3.2 Delegation management page | Epic 3 | Frontend for core differentiator |

### Medium

| Task | Epic | Rationale |
|---|---|---|
| 4.1 Policy evaluation endpoints | Epic 4 | Policy playground enables enterprise admin self-service |
| 4.2 Policy playground page | Epic 4 | Frontend for policy management |
| 5.1 Audit report endpoint | Epic 5 | Compliance reporting — enterprise need |
| 5.2 Audit dashboard page | Epic 5 | Visual compliance dashboard |
| 6.1 Billing API calls | Epic 6 | Monetization path |
| 6.2 Billing page | Epic 6 | Monetization path |
| 9.1 Mobile API endpoints | Epic 9 | Mobile app is non-functional without these |

### Low

| Task | Epic | Rationale |
|---|---|---|
| 8.1 Remove transparency-placeholder | Epic 8 | Dead code, low impact |
| 8.2 Remove/flag GitHub App stubs | Epic 8 | Dead code, but could be implemented later |

---

## Summary

The architecture report reveals a system with **strong backend depth but incomplete frontend wiring**. Nine capabilities exist in the Rust SDK that users cannot access from the web. The most impactful improvements are:

1. **Fix auth persistence** (Critical) — session loss on reload is unacceptable
2. **Surface org analytics** (High) — backend data exists, zero backend work needed
3. **Web identity creation** (High) — remove CLI installation as onboarding gate
4. **Agent delegation dashboard** (High) — the product's unique value proposition is invisible

The system has zero users and no backward compatibility requirements, making this an ideal time for these structural improvements.
