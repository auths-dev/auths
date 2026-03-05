# AuthSec Competitive Analysis

## Executive Summary

AuthSec (`authsec.ai`) is an open-source, agent-first identity platform targeting MCP (Model Context Protocol) servers and AI agent infrastructure. It provides centralized authentication (OAuth 2.1, SAML, CIBA) and workload identity (SPIFFE/SPIRE X.509) with a managed SaaS backend.

**Auths and AuthSec are not direct competitors.** They solve adjacent problems with fundamentally different architectures. AuthSec is a centralized identity platform that bolts auth onto AI agents. Auths is a decentralized identity primitive that makes cryptographic identity infrastructure-free. Where they overlap is in workload identity, capability-scoped delegation, and OIDC token exchange — but their trust models are incompatible at the philosophical level.

The competitive risk is not technical substitution but **market confusion**: both use similar terminology (attestation, capabilities, workload identity, zero-trust) while meaning very different things. This document disambiguates them.

---

## Part 1: What AuthSec Actually Is

### 1.1 Architecture

AuthSec is a **four-service Go/Gin backend** behind `dev.api.authsec.dev`:

| Service | Purpose |
|---------|---------|
| User Management API (v4.0.0) | Multi-tenant user auth, MFA, directory sync |
| Auth Manager API (v1.1.0) | JWT generation, group management, token validation |
| Client Management API (v0.4.0) | Client CRUD, tenant-specific config |
| WebAuthn & MFA API (v2.0) | WebAuthn registration, TOTP, SMS verification |

**Stack**: Go/Gin + PostgreSQL + HashiCorp Vault + SPIRE + Prometheus. Frontend: React 19/Vite 6. Mobile: Expo 54/React Native.

All components are MIT-licensed. Self-hosting is supported. The managed service runs at `app.authsec.dev`.

### 1.2 Identity Model

AuthSec has a **dual identity plane**:

**User identity** (humans): OAuth 2.1 with PKCE, SAML 2.0, OIDC federation, CIBA (push-to-mobile), WebAuthn/FIDO2, TOTP. After authentication, a JWT is issued containing `email`, `tenant_id`, `user_id`, `org_id`, `roles`, `groups`, `scopes`, `resources`, `permissions`. This JWT drives all authorization decisions.

**Workload identity** (agents/services): SPIFFE/SPIRE issues X.509-SVIDs (short-lived certificates) through SPIRE agents. Attestation uses Kubernetes selectors (namespace, service account, pod labels). Certificates auto-rotate every 30 minutes. Workloads present mTLS certificates for service-to-service communication.

### 1.3 Authorization Model

Five-dimensional RBAC:

1. **Roles** — e.g., `admin`, `editor`, `viewer`
2. **Groups** — e.g., `engineering`, `devops`
3. **Scopes** — e.g., `read`, `write`, `deploy`
4. **Resources** — e.g., `production`, `staging`
5. **Permissions** — Composite `resource:action` strings

Evaluation supports AND/OR logic: `require_all=True` (all dimensions must match) or `require_all=False` (any one match suffices).

### 1.4 MCP Integration Pattern

The core value proposition — "3 lines of code" to add auth to an MCP server:

```python
@protected_by_AuthSec("tool_name", roles=["admin"], scopes=["write"])
async def my_tool(arguments: dict, session=None) -> list:
    user = arguments.get("_user_info")
    return [{"type": "text", "text": f"Hello {user['email']}"}]
```

**Flow**: Unauthenticated users see only OAuth management tools. After browser-redirect OAuth flow, JWT is decoded and cached. Protected tools become visible based on RBAC evaluation. Each tool call triggers upstream validation via the SDK Manager service. `_user_info` is injected into tool arguments automatically.

### 1.5 CIBA (Client-Initiated Backchannel Authentication)

Enables "headerless" authentication — no browser redirects. User receives a push notification on the AuthSec mobile authenticator, approves, and the agent receives a JWT. Designed for voice assistants, CLI tools, IoT devices, and desktop apps.

### 1.6 Delegation

The `DelegationClient` enables AI agents to act on behalf of users:
- Users grant scoped, time-limited permissions to agents
- Agents pull JWT-SVID delegation tokens
- Tokens contain: permissions list, audience, expiration
- Auto-refresh before expiry

### 1.7 Secret Management

`ServiceAccessSDK` wraps HashiCorp Vault for secure credential retrieval. MCP tools access third-party APIs without exposing raw credentials. All secrets are encrypted at rest and retrieved per-session.

---

## Part 2: Head-to-Head Comparison

### 2.1 Fundamental Architecture

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Trust model** | Self-certifying (no authority) | Centralized authority (SaaS or self-hosted) |
| **Identity primitive** | `did:keri:E...` (hash of inception event) | UUID/email in PostgreSQL |
| **Infrastructure requirement** | Git (already everywhere) | Go backend + PostgreSQL + Vault + SPIRE + Prometheus |
| **Key management** | Platform keychain (macOS/Linux/Windows) | HashiCorp Vault |
| **Verification model** | Offline, stateless (WASM/FFI embeddable) | Online (requires SDK Manager API call) |
| **Key rotation** | KERI pre-rotation (planned, safe) | SPIRE auto-rotation (30-min SVIDs) |
| **Identity portability** | Fully portable (`did:keri` is forge-agnostic) | Locked to AuthSec instance |
| **Vendor lock-in** | None | High (identity lives in their PostgreSQL) |
| **Offline capability** | Full (200KB WASM verifier) | None (all validation server-side) |

### 2.2 Workload Identity

This is the primary area of overlap.

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Workload credential** | Signed attestation chain → OIDC JWT | SPIFFE X.509-SVID → JWT |
| **Attestation** | Cryptographic (dual-signed, chain-verified) | Kubernetes selectors (namespace, service account) |
| **Trust anchor** | Self-certifying identity + optional witness quorum | SPIRE server trust bundle |
| **Capability model** | First-class, intersected along chain, policy-evaluated | RBAC roles/scopes (flat, not chain-intersected) |
| **Cloud provider bridge** | OIDC bridge → AWS STS / GCP WIF / Azure AD | Not built-in (separate integration) |
| **GitHub Actions integration** | OIDC cross-reference (verify OIDC token + KERI identity simultaneously) | Not built-in |
| **TTL enforcement** | Trust registry caps + bridge max TTL + policy | SVID rotation interval (30 min default) |

**Key insight**: AuthSec's workload identity is **Kubernetes-native** (SPIRE attestation via pod selectors). Auths' workload identity is **Git-native** (attestation chain from identity to device to workload). AuthSec requires Kubernetes. Auths requires Git.

### 2.3 Authorization / Policy

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Policy language** | Declarative expression AST (And/Or/Not + 20+ predicates) | Five-dimensional RBAC (roles/groups/scopes/resources/permissions) |
| **Evaluation** | Local, compiled, deterministic | Remote API call to SDK Manager |
| **Predicates** | `HasCapability`, `IssuerIs`, `NotExpired`, `RefMatches`, `PathAllowed`, `IsAgent`, `IsHuman`, `IsWorkload`, `RepoIs`, `EnvIs`, etc. | Role membership, scope check, resource check |
| **Composability** | Arbitrary nesting (And/Or/Not) with depth limits | AND/OR at top level only |
| **Audit trail** | `Decision` struct with `reason`, `message`, `policy_hash` | Server-side logging |
| **Policy storage** | JSON/TOML, compiled at startup | Dashboard UI + database |
| **Git ref scoping** | First-class (`RefMatches("refs/heads/main")`) | Not applicable |
| **File path scoping** | First-class (`PathAllowed(["src/**"])`) | Not applicable |

**Key insight**: Auths' policy engine is a **general-purpose authorization language** with developer-workflow predicates (Git refs, file paths, environments). AuthSec's RBAC is a **standard enterprise access control model** with no developer-workflow awareness.

### 2.4 Developer Experience

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Setup** | `cargo install auths && auths init` (30 seconds) | Register on dashboard, create workspace, obtain client_id, configure OAuth callbacks |
| **Git signing** | Native (`auths sign commit`, Git hook integration) | Not applicable |
| **Commit verification** | `auths verify HEAD` or embedded WASM | Not applicable |
| **CI/CD integration** | `auths init --profile ci` (ephemeral identity) | SPIRE agent + Kubernetes deployment |
| **MCP server auth** | Not yet built (but OIDC bridge enables it) | Core use case (decorator pattern) |
| **SDKs** | Rust (primary), WASM (browser/Node), FFI (C/Swift/Kotlin) | Python, TypeScript, Go |
| **Mobile** | Not yet built | Expo/React Native authenticator app |

### 2.5 Supply Chain & Provenance

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Artifact signing** | `auths artifact sign <file>` | Not applicable |
| **Commit signing** | Native (Ed25519 via Git) | Not applicable |
| **Attestation chains** | Core primitive (transitive delegation) | Not applicable |
| **Witness quorum** | Built-in (N-of-M independent receipting) | Not applicable |
| **Software provenance** | Core use case (Sigstore-complementary) | Not applicable |

### 2.6 Maturity & Ecosystem

| Dimension | Auths | AuthSec |
|-----------|-------|---------|
| **Codebase** | ~80K lines Rust, 18 crates, layered architecture | ~9 repos (Go + Python + TypeScript + React) |
| **GitHub activity** | Active development | 37 commits on main SDK repo, 1 star |
| **License** | (check project) | MIT across all repos |
| **Documentation** | CLAUDE.md, extensive inline docs, plan docs | Docusaurus site (partially broken at time of review) |
| **Community** | Early | Very early |
| **Production readiness** | Pre-launch (hardening in progress) | Pre-launch (v0.x APIs) |

---

## Part 3: Where AuthSec Has Advantages

### 3.1 MCP Server Integration (Today)

AuthSec has a **working MCP auth solution now**. The `@protected_by_AuthSec()` decorator pattern is trivial to adopt. Tool visibility control (hiding tools until authenticated) is a genuinely useful UX pattern. Auths does not currently have an MCP SDK.

**Mitigation**: Auths' OIDC bridge can issue JWTs consumable by MCP servers, but we lack the SDK wrapper and decorator pattern. Building `auths-mcp-sdk` (Python/TypeScript) would close this gap.

### 3.2 Mobile Authenticator

AuthSec has a mobile app (Expo/React Native) that supports TOTP, CIBA push notifications, and biometrics. This enables "approve from your phone" flows. Auths has no mobile presence.

**Mitigation**: Auths' WASM verifier could be embedded in a React Native app. The attestation-based model actually makes this simpler (no server round-trip needed for verification). But the app doesn't exist yet.

### 3.3 CIBA (Headerless Auth)

CIBA is genuinely useful for AI agents that can't do browser redirects. Voice assistants, CLI tools, and headless agents need this. Auths' model doesn't require browser redirects at all (attestations are bearer proofs), but we haven't marketed this or built the convenience wrappers.

### 3.4 Enterprise SSO (SAML, Active Directory)

AuthSec supports SAML 2.0, Active Directory sync (via `ad-agent`), and Entra ID integration. Enterprise buyers expect this. Auths has no SAML or AD integration.

**Mitigation**: Auths' identity model is orthogonal to SSO — a `did:keri` identity can be linked to an enterprise SSO identity via platform claims. But the integration doesn't exist yet.

### 3.5 Multi-Tenant Dashboard

AuthSec has a full React admin dashboard for managing users, roles, clients, and policies. Auths is CLI-only.

**Mitigation**: The CLI-first approach is a strength for developer adoption but a weakness for enterprise sales. A web dashboard for trust registry and policy management would address this.

---

## Part 4: Where Auths Has Structural Advantages

### 4.1 No Infrastructure Required

AuthSec requires Go backend + PostgreSQL + HashiCorp Vault + SPIRE + Prometheus. Auths requires Git. This is not a marginal difference — it's a category difference. Every developer already has Git. Nobody already has a SPIRE deployment.

**Implication**: Auths can achieve adoption at the individual developer level without any organizational procurement. AuthSec requires an infrastructure decision before a single developer can use it.

### 4.2 Identity Portability

AuthSec identities live in their PostgreSQL database. Migrating away means losing your identity. Auths identities are self-certifying — `did:keri:E...` is derived from the inception event hash, not from any platform. Your identity follows you across GitHub, GitLab, Radicle, Forgejo, or any future forge.

**Implication**: Auths identities survive platform death. AuthSec identities don't.

### 4.3 Offline Verification

AuthSec requires an API call to the SDK Manager for every authorization decision. Auths' verifier is a 200KB WASM module that runs offline — in browsers, CI runners, edge functions, mobile apps, or embedded systems. No network, no server, no single point of failure.

**Implication**: Auths can verify identity in air-gapped environments, submarines, Mars rovers, or just someone's laptop with no internet. AuthSec cannot.

### 4.4 Key Rotation Safety

AuthSec rotates SPIRE SVIDs every 30 minutes, which protects against compromise but doesn't help with identity continuity — if the SPIRE root CA is compromised, everything is compromised. Auths uses KERI pre-rotation: when creating an identity, you commit to the hash of your next key. If the current key is compromised, the attacker cannot rotate because they lack the pre-image of the next key hash. Rotation is a planned lifecycle event, not an emergency.

**Implication**: Auths' key compromise model is architecturally superior. Compromise in AuthSec requires trusting a single CA. Compromise in Auths requires breaking pre-rotation commitments AND witness quorum.

### 4.5 Witness Quorum (Decentralized Accountability)

Auths' witness model provides independent accountability without centralization. N-of-M independent witnesses must receipt a key event before it's accepted. This prevents an attacker from presenting different key histories to different verifiers. AuthSec has no equivalent — trust is centralized in SPIRE.

### 4.6 Supply Chain Security

Auths was built for commit signing, artifact signing, and attestation chains. This is the core use case. AuthSec has no supply chain capabilities — it's an auth platform bolted onto AI agent infrastructure.

**Implication**: Auths is positioned for SLSA compliance, software provenance, and supply chain integrity. AuthSec is positioned for API access control.

### 4.7 Policy Expressiveness

Auths' policy engine has 20+ predicates including developer-workflow-specific ones (`RefMatches`, `PathAllowed`, `EnvIs`, `IsAgent`, `IsHuman`). Policies compose arbitrarily with And/Or/Not and compile to deterministic evaluation. AuthSec has five-dimensional RBAC with AND/OR at the top level.

**Implication**: "Only human signers can modify `refs/heads/main`, but CI workloads can deploy to staging if they have `deploy_staging` capability and the attestation chain has witness quorum" — this is one policy expression in Auths. It's not expressible in AuthSec's RBAC model.

### 4.8 Cryptographic Attestation Chains

Auths' attestation chains are self-contained, offline-verifiable proofs of delegated authority. The verification question is "here's the proof" not "ask the server." Each link is dual-signed, capabilities are intersected, and the chain can be verified by anyone with the root public key.

AuthSec's delegation is JWT-based — you call the server, it gives you a token, the token is opaque to the relying party. If the server is down, delegation doesn't work.

---

## Part 5: Strategic Positioning

### 5.1 The Market Confusion Risk

Both projects use overlapping terminology:

| Term | Auths Meaning | AuthSec Meaning |
|------|--------------|-----------------|
| **Attestation** | Cryptographically signed, chain-verifiable delegation proof | Kubernetes pod selector matching via SPIRE |
| **Capability** | First-class, intersectable, policy-evaluated authorization scope | RBAC scope/permission string |
| **Zero-trust** | No central authority, self-certifying identities, offline verification | Short-lived certificates, mTLS, per-call validation |
| **Workload identity** | Git-native attestation chain + OIDC bridge | SPIFFE X.509-SVID via Kubernetes SPIRE |
| **Policy** | Declarative expression AST with 20+ predicates | Dashboard-configured RBAC rules |

**Risk**: Enterprise buyers searching for "workload identity" or "agent authentication" may find AuthSec and assume it covers the same ground as Auths. It doesn't — but the terminology overlap makes this non-obvious.

### 5.2 Complementary, Not Competitive

The two projects are actually complementary:

- **AuthSec** answers: "How do I add OAuth login to my MCP server?"
- **Auths** answers: "How do I cryptographically prove who wrote this code and what they're authorized to do?"

A realistic enterprise deployment could use both:
1. AuthSec for user-facing MCP server authentication (OAuth, RBAC, CIBA)
2. Auths for developer identity, commit signing, artifact provenance, and CI/CD capability delegation

The OIDC bridge is the natural integration point: Auths issues JWTs that AuthSec could consume as a trusted identity provider.

### 5.3 Where to Win

| Segment | Winner | Why |
|---------|--------|-----|
| MCP server auth (today) | AuthSec | They have SDKs and decorator patterns |
| Developer commit signing | Auths | AuthSec doesn't do this |
| Supply chain provenance | Auths | AuthSec doesn't do this |
| CI/CD capability delegation | Auths | Attestation chains + trust registry + policy engine |
| Enterprise SSO integration | AuthSec | SAML, AD sync, dashboard |
| Air-gapped / offline environments | Auths | WASM verifier, no server dependency |
| Kubernetes-native workloads | AuthSec | SPIFFE/SPIRE is purpose-built for K8s |
| Git-native developer workflows | Auths | Git refs, commit signing, ref-scoped policy |
| Individual developer adoption | Auths | `cargo install auths && auths init` vs. deploy 5 services |
| Enterprise procurement | AuthSec | Dashboard, multi-tenant, SAML |

### 5.4 Recommended Response

1. **Don't compete on MCP auth directly.** Build `auths-mcp-sdk` as a thin wrapper that uses the OIDC bridge, but don't try to replicate AuthSec's OAuth/SAML/CIBA stack. Instead, position Auths as the identity layer that MCP auth platforms (including AuthSec) can trust.

2. **Lean into supply chain.** AuthSec has zero supply chain capabilities. This is Auths' moat. Commit signing, artifact provenance, attestation chains, and SLSA compliance are areas where AuthSec cannot compete without rebuilding from scratch.

3. **Emphasize infrastructure-free.** "Works with Git you already have" vs. "deploy Go + PostgreSQL + Vault + SPIRE + Prometheus" is a devastating comparison for individual and small-team adoption.

4. **Publish the OIDC bridge as an integration point.** Position the bridge not as competition to AuthSec but as something AuthSec could consume. "AuthSec authenticates your users. Auths proves what your code is authorized to do."

5. **Build the trust registry dashboard.** The CLI-only story is fine for developers but insufficient for enterprise security teams. A minimal web UI for trust registry and policy management would close the enterprise gap without building a full SaaS platform.

---

## Part 6: Technical Gaps to Close

| Gap | Priority | Effort | Notes |
|-----|----------|--------|-------|
| MCP SDK (Python/TypeScript) | P2 | 1-2 weeks | Thin wrapper around OIDC bridge. Not core to mission but closes marketing gap. |
| Enterprise SSO (SAML) | P3 | 2-3 weeks | Only needed for enterprise sales. Could use existing OIDC bridge as adapter. |
| Trust registry web UI | P2 | 1-2 weeks | Minimal React/HTMX dashboard for policy and trust registry management. |
| Mobile verifier app | P3 | 2-3 weeks | WASM verifier in React Native. Enables "verify from phone" use case. |
| CIBA-equivalent flow | P3 | 1 week | Auths doesn't need CIBA (attestations are bearer proofs), but marketing should explain why. |
| Active Directory sync | P4 | 2 weeks | Only for enterprise. Low priority until enterprise pipeline exists. |
