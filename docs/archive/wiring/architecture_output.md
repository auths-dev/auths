# Architecture Output

## 1 Architecture Summary

### Product

Auths is a **decentralized identity and code signing platform** built on KERI (Key Event Receipt Infrastructure). It enables developers and organizations to cryptographically sign Git commits, manage device identities, delegate scoped authority to AI agents, and verify trust chains — all without a centralized certificate authority.

### System Overview

The codebase is a **polyglot monorepo** spanning Rust, TypeScript, Swift, Kotlin, Python, and Ruby across 12+ sub-projects.

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Core Backend** | Rust (27-crate workspace, Axum 0.8) | Identity, crypto, signing, verification |
| **Cloud Services** | Rust (Axum, 13 crates) | Registry, auth, chat relay, OIDC bridge, SCIM, witness, monitor |
| **Web Frontend** | Next.js 16 + React 19 + TypeScript | Explorer, network stats, org management, docs |
| **Verify Widget** | TypeScript Web Component (Shadow DOM) | Embeddable verification badge for any webpage |
| **iOS/macOS Chat** | SwiftUI + Rust FFI (UniFFI) | E2E encrypted messaging with KERI identities |
| **Mobile App** | SwiftUI (iOS) + Jetpack Compose (Android) + Rust FFI | Identity management, device pairing, emergency controls |
| **GitHub App** | Rust (Axum) | Webhook receiver for commit verification |
| **GitHub Action** | TypeScript (Node.js 20) | CI verification of commit signatures |
| **Agent Demo** | Python | Delegation/verification simulation |
| **CLI** | Rust (clap) | Developer-facing signing/verification tool |
| **Homebrew Tap** | Ruby | CLI distribution for macOS/Linux |

### Architecture Principles

- **Layered Rust crates** (6 levels): Crypto → Verification → Core → Domain → Services → Presentation
- **Port/adapter pattern**: All I/O trait-injected, no reverse dependencies
- **Git-first storage**: Identity data stored as Git refs (`refs/auths/`, `refs/keri/`)
- **PostgreSQL hot path**: Cloud registry uses Postgres for fast reads, Git for audit trail
- **Edge verification**: Clients can verify locally without contacting a server (WASM, CLI)
- **E2E encryption**: Chat uses X25519 ECDH + AES-256-GCM; server sees only ciphertext

### Key Services (Ports)

| Service | Default Port | Role |
|---------|-------------|------|
| auths-registry-server | 3000 | Central identity registry API |
| auths-auth-server | 3001 | Challenge/response authentication |
| auths-chat-server | 3002 | Encrypted message relay + WebSocket |
| auths-oidc-bridge | 3300 | KERI attestation → cloud JWT exchange |
| auths-pairing-daemon | (LAN) | mDNS device pairing |
| auths-mcp-server | 8080 | MCP tool server (JWT-gated) |
| auths-witness | 8080 | Transparency log witness |
| auths-scim-server | configurable | SCIM 2.0 agent provisioning |
| auths-github-app | 3001 | GitHub webhook handler |

---

## 2 Frontend → API Map

### auths-site (Next.js) → Registry API

| Component | Endpoint | Method | Feature |
|-----------|----------|--------|---------|
| `explorer-client.tsx` | `/v1/identities/{did}` | GET | DID/identity lookup |
| `explorer-client.tsx` | `/v1/identities/batch` | POST | Batch identity resolution (N+1 mitigation) |
| `explorer-client.tsx` | `/v1/artifacts` | GET | Artifact/package search (cursor pagination) |
| `explorer-client.tsx` | `/v1/pubkeys` | GET | Public keys + platform claims |
| `explorer-client.tsx` | `/v1/activity/feed` | GET | Unified activity feed (transparency log) |
| `explorer-client.tsx` | `/v1/namespaces` | GET | Namespace browsing |
| `explorer-client.tsx` | `/v1/identities/search` | GET | Identity search |
| Network page | `/v1/stats` | GET | Network statistics |
| Org management (`/try/org/`) | `/v1/orgs/{orgDid}/policy` | GET | Org policy retrieval |
| Org management (`/try/org/`) | `/v1/orgs/{orgDid}/status` | GET | Org status |
| Org management (`/try/org/`) | `/v1/orgs/{orgDid}/invite` | POST | Org invite creation |
| `challenge-auth.tsx` | `/auth/init` | POST | Auth challenge initiation (AUTH_BASE_URL) |
| `challenge-auth.tsx` | `/auth/verify` | POST | Auth challenge verification (AUTH_BASE_URL) |
| `platform-passport.tsx` | (read-only display) | — | Renders platform claims from identity data |
| `provenance-ledger.tsx` | (read-only display) | — | Renders package signature history |
| `trust-graph.tsx` | (read-only display) | — | Identity trust visualization |
| WASM bridge (`wasm-bridge.ts`) | (local WASM) | — | Client-side signature verification |

### auths-verify-widget (Web Component) → Forge APIs

| Component | Endpoint | Method | Feature |
|-----------|----------|--------|---------|
| `github.ts` resolver | GitHub REST API (`/repos/{owner}/{repo}/git/refs/auths/registry`) | GET | Fetch attestation refs from GitHub |
| `gitlab.ts` resolver | GitLab API (`/projects/{id}/repository/tree`) | GET | Fetch attestation refs from GitLab |
| `gitea.ts` resolver | Gitea API (`/repos/{owner}/{repo}/git/refs`) | GET | Fetch attestation refs from Gitea |
| `detect.ts` | (URL parsing) | — | Auto-detect forge type from repository URL |
| WASM verifier | (local WASM) | — | Ed25519 signature verification in browser |

### auths-chat (SwiftUI iOS/macOS) → Chat Server API

| Component | Endpoint | Method | Feature |
|-----------|----------|--------|---------|
| `ConversationListView` | `/conversations` | GET | List conversations |
| `NewConversationView` | `/conversations` | POST | Create conversation |
| `MessageThreadView` | `/conversations/{id}/messages` | GET | Fetch messages |
| `MessageThreadView` | `/conversations/{id}/messages` | POST | Send encrypted message |
| `ContentView` | WebSocket `/ws` | WS | Real-time message updates |
| `PairDeviceView` | `/auth/register` | POST | Register user DID |
| `ShowPairingQRView` | (local QR generation) | — | QR code for pairing |

### auths-mobile (SwiftUI + Compose) → Registry + Mobile API

| Component (iOS / Android) | Endpoint | Method | Feature |
|---------------------------|----------|--------|---------|
| `CreateIdentityView` / `OnboardingScreen` | `/v1/identities/{prefix}/kel` | POST | Create identity (inception event) |
| `IdentityView` / `IdentityScreen` | `/mobile/identity` | GET | Fetch identity |
| `DevicesView` / `DevicesScreen` | `/mobile/devices` | GET | List paired devices |
| `DevicesView` / `DevicesScreen` | `/mobile/devices/{id}/revoke` | POST | Revoke device |
| `PairDeviceView` / `PairDeviceScreen` | `/mobile/pair/initiate` | POST | Initiate pairing |
| `PairDeviceView` / `PairDeviceScreen` | `/mobile/pair/complete` | POST | Complete pairing |
| `EmergencyView` / `EmergencyScreen` | `/mobile/emergency/freeze` | POST | Emergency freeze |
| `SettingsView` / `SettingsScreen` | `/mobile/notifications/register` | POST | Push notification setup |

---

## 3 API → Backend Map

### Registry Server (auths-registry-server, port 3000)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `GET /v1/health` | health handler | — | Returns status |
| `GET /v1/identities/:prefix` | identity handler | `auths-storage` (Git + Postgres read) | Resolve identity by KERI prefix |
| `GET /v1/identities/:prefix/kel` | KEL handler | `auths-id` KERI state machine | Fetch Key Event Log |
| `POST /v1/identities/:prefix/kel` | KEL handler | `auths-id` KERI state machine | Append KEL event (inception/rotation) |
| `GET /v1/devices/:did` | device handler | `auths-storage` | Lookup device by DID |
| `GET /v1/devices/:did/attestation` | attestation handler | `auths-verifier` | Fetch device attestation |
| `GET /v1/orgs/:org_did/members` | org handler | `auths-id` registry | List org members |
| `POST /v1/orgs/:org_did/members` | org handler | `auths-sdk` org workflow | Add org member |
| `DELETE /v1/orgs/:org_did/members/:member_did` | org handler | `auths-sdk` org workflow | Remove member |
| `POST /v1/verify` | verify handler | `auths-verifier` | Verify attestation chain |
| `POST /v1/pairing/sessions` | pairing handler | `auths-pairing-protocol` | Create pairing session |
| `GET /v1/pairing/sessions/:id` | pairing handler | `auths-pairing-protocol` | Get session state |
| `DELETE /v1/pairing/sessions/:id` | pairing handler | `auths-pairing-protocol` | Cancel session |

### Auth Server (auths-auth-server, port 3001)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `/auth/init` | challenge handler | Challenge generation + store | Generates nonce, stores with TTL (300s default) |
| `/auth/verify` | verify handler | `auths-infra-http::HttpIdentityResolver` → registry | Resolves identity keys via registry, verifies signature |

### Chat Server (auths-chat-server, port 3002)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `POST /auth/register` | register handler | Identity resolution via registry | Register DID for chat |
| `GET /conversations` | conversation handler | SQLite store | List user conversations |
| `POST /conversations` | conversation handler | SQLite store | Create conversation |
| `GET /conversations/{id}/messages` | message handler | SQLite store | Fetch encrypted messages |
| `POST /conversations/{id}/messages` | message handler | SQLite store | Store encrypted message |
| WebSocket `/ws` | WS handler | Tokio broadcast | Real-time relay |

### OIDC Bridge (auths-oidc-bridge, port 3300)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `POST /token` (implied) | token handler | `auths-verifier` + JWT signing | Verifies attestation chain, issues cloud JWT |
| `GET /.well-known/openid-configuration` | metadata handler | Static config | OIDC discovery |
| `GET /jwks` | JWKS handler | Ed25519 public key export | Key set for JWT verification |

### Pairing Daemon (LAN, auths-pairing-daemon)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `GET /health` | `handle_health()` | — | Returns "ok" |
| `GET /v1/pairing/sessions/by-code/{code}` | `handle_lookup_by_code()` | `DaemonState` | Lookup by 6-char code |
| `GET /v1/pairing/sessions/{id}` | `handle_get_session()` | `DaemonState` | Get session details |
| `POST /v1/pairing/sessions/{id}/response` | `handle_submit_response()` | `DaemonState` + ECDH | Submit ECDH + signing keys |
| `POST /v1/pairing/sessions/{id}/confirm` | `handle_submit_confirmation()` | `DaemonState` + SAS | Submit SAS confirmation |
| `GET /v1/pairing/sessions/{id}/confirmation` | `handle_get_confirmation()` | `DaemonState` | Poll confirmation state |

### MCP Server (auths-mcp-server, port 8080)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `GET /health` | `health()` | — | Status + version |
| `GET /.well-known/oauth-protected-resource` | `protected_resource_metadata()` | Static | OAuth metadata |
| `GET /mcp/tools` | `list_tools()` | Tool registry | Enumerate tools + required capabilities |
| `POST /mcp/tools/{tool_name}` | `handle_tool_call()` | JWT middleware → tool executor | Execute tool (read_file, write_file, deploy) |

### Witness Server (auths-witness, port 8080)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| `POST /witness/{prefix}/event` | event handler | SQLite (first-seen-always-seen) | Submit KERI event for witnessing |
| `GET /witness/{prefix}/head` | head handler | SQLite | Latest observed sequence |
| `GET /witness/{prefix}/receipt/{said}` | receipt handler | SQLite + Ed25519 signing | Retrieve issued receipt |
| `GET /health` | health handler | — | Status + metrics |

### SCIM Server (auths-scim-server)

| Endpoint | Handler | Service/Logic | Notes |
|----------|---------|--------------|-------|
| SCIM 2.0 standard endpoints | SCIM handlers | PostgreSQL | Multi-tenant agent provisioning |

---

## 4 Backend → Database Map

### Git Storage (Primary — `~/.auths/` repository)

| Service | Refs/Tables | Operations | Data |
|---------|------------|------------|------|
| `auths-storage::git` | `refs/auths/registry/*` | Read/write Git refs + blobs | Attestation chains |
| `auths-storage::git` | `refs/keri/{prefix}/*` | Read/write Git refs | Key Event Logs (KEL) |
| `auths-infra-git` | `refs/auths/` | Clone, fetch, push | Identity bundles |
| `auths-id` KERI | `refs/keri/{prefix}/kel` | Append-only event log | Inception, rotation, interaction events |
| `auths-id` attestations | `refs/auths/attestations/{rid}` | Create/read blobs | Signed attestation JWTs |

### PostgreSQL (Cloud Hot Path)

| Service | Tables | Queries | Data Returned |
|---------|--------|---------|---------------|
| `auths-registry-server` | `identities`, `attestations`, `devices` | SELECT by prefix/DID, INSERT events | Identity records, attestation metadata |
| `auths-registry-server` | `org_members` | SELECT by org_did, INSERT/DELETE | Org membership records |
| `auths-auth-server` | `challenges` (optional, else in-memory) | INSERT challenge, SELECT + DELETE on verify | Challenge nonce + TTL |
| `auths-scim-server` | `tenants`, `agents` | SCIM CRUD operations | Agent provisioning records |
| `auths-storage::postgres` | Shard-partitioned tables | Indexed lookups | Attestation metadata, membership |

### SQLite (Local/Embedded)

| Service | Database | Tables | Data |
|---------|----------|--------|------|
| Witness Server (`auths-core::witness`) | `witness.db` | `first_seen_events` (prefix, sequence, d, t) | KERI event first-seen records |
| Witness Server | `witness.db` | `receipts` (prefix, said, receipt_json) | Issued witness receipts |
| Witness Server | `witness.db` | `duplicity_log` | Evidence of forked identities |
| `auths-index` | `index.db` | Attestation index by device DID | O(1) attestation lookups |
| `auths-chat-server` | `chat.db` | `messages`, `conversations` | Encrypted message ciphertext |

### Redis (Cache Tier 0)

| Service | Keys | Operations | Data |
|---------|------|------------|------|
| `auths-cache` | `identity:{prefix}` | GET/SET with TTL | Cached identity resolution |
| `auths-cache` | `attestation:{rid}` | GET/SET with TTL | Cached attestation data |

---

## 5 Feature Pipelines

### Pipeline 1: Identity Exploration (Web)

```
explorer-client.tsx (Next.js)
→ GET /v1/identities/{did} (registryFetch wrapper, 5s timeout)
→ auths-registry-server handler
→ auths-storage (Git refs + Postgres)
→ PostgreSQL SELECT / Git blob read
→ Identity JSON response
→ useIdentityProfile() hook (TanStack Query, 120s stale)
→ Trust tier computation (client-side: claims×20 + keys×15 + artifacts×5)
→ platform-passport.tsx + trust-graph.tsx render
```

### Pipeline 2: Commit Signing (CLI)

```
Developer runs: auths sign-commit
→ auths-cli sign command
→ auths-sdk signing workflow (signing.rs)
→ auths-core SecureSigner (platform keychain: macOS Keychain / Linux Secret Service)
→ Ed25519 signature generation
→ Git commit signed via SSH signature format
→ refs/auths/ updated in local repo
```

### Pipeline 3: Commit Verification (GitHub Action CI)

```
Push/PR event on GitHub
→ auths-verify-github-action triggers
→ src/main.ts reads inputs (allowed-signers, commit-range)
→ src/verifier.ts downloads + caches auths CLI binary (SHA256 verified)
→ Detects commit range from GitHub event context
→ Runs: auths verify-commit --json (per commit)
→ Classifies results (verified / unsigned / unknown key / corrupted)
→ Generates GitHub Step Summary (markdown table)
→ Optionally posts PR comment with fix instructions
→ Sets outputs: verified, results JSON, total, passed, failed
```

### Pipeline 4: Device Pairing (Mobile → LAN Daemon)

```
PairDeviceView (SwiftUI) / PairDeviceScreen (Compose)
→ QR code scan (camera)
→ POST /mobile/pair/initiate (to registry/mobile API)
→ GET /v1/pairing/sessions/by-code/{code} (LAN daemon)
→ DaemonState session lookup
→ POST /v1/pairing/sessions/{id}/response (ECDH key exchange)
→ SAS display on both devices
→ POST /v1/pairing/sessions/{id}/confirm (SAS confirmation)
→ Attestation created linking new device DID to identity
→ DevicesView updated with new paired device
```

### Pipeline 5: Challenge-Response Authentication (Web)

```
challenge-auth.tsx (React)
→ POST /auth/init (auths-auth-server:3001)
→ Challenge nonce generated + stored (TTL 300s)
→ Client signs challenge with device key (local keychain)
→ POST /auth/verify (auths-auth-server:3001)
→ HttpIdentityResolver → GET /v1/identities/{did} (registry:3000)
→ Fetch public keys for DID
→ Ed25519 signature verification
→ Auth session established
→ Auth context updated in React state
```

### Pipeline 6: Encrypted Chat (iOS/macOS)

```
MessageThreadView (SwiftUI)
→ EncryptionService.encrypt() (Rust FFI: X25519 ECDH + AES-256-GCM)
→ POST /conversations/{id}/messages (auths-chat-server:3002)
→ SQLite INSERT (ciphertext only, server cannot read)
→ WebSocket broadcast to other participants
→ Receiver: EncryptionService.decrypt() (Rust FFI)
→ MessageBubbleView renders plaintext
```

### Pipeline 7: Artifact Search + Provenance (Web)

```
Search input (explorer-client.tsx)
→ useRegistrySearch() hook (debounced 300ms)
→ GET /v1/artifacts?q=...&cursor=... (cursor pagination)
→ auths-registry-server → PostgreSQL query
→ Artifact list response
→ useArtifactSearch() infinite pagination
→ usePackageDetail() → POST /v1/identities/batch (top 10 signers)
→ provenance-ledger.tsx renders signature history
```

### Pipeline 8: Org Management (Web)

```
/try/org/ pages (Next.js App Router)
→ GET /v1/orgs/{orgDid}/policy (registry)
→ GET /v1/orgs/{orgDid}/status (registry)
→ POST /v1/orgs/{orgDid}/invite (create invite)
→ /join/[code] page (invite acceptance)
→ POST /v1/orgs/{orgDid}/members (registry → auths-sdk org workflow)
→ auths-id registry → PostgreSQL INSERT
→ Attestation created with Role + Capabilities
```

### Pipeline 9: KERI → Cloud JWT Exchange (OIDC Bridge)

```
Agent or service with attestation chain
→ POST /token (auths-oidc-bridge:3300)
→ auths-verifier validates attestation chain
→ Extract capabilities from attestations
→ Sign JWT with Ed25519 key
→ Return cloud JWT with scoped claims
→ Consumer verifies JWT via GET /jwks
```

### Pipeline 10: Emergency Freeze (Mobile)

```
EmergencyView (SwiftUI) / EmergencyScreen (Compose)
→ Biometric authentication (Face ID / fingerprint)
→ POST /mobile/emergency/freeze
→ Registry marks identity as frozen
→ All attestations under this identity become invalid
→ UI shows frozen state
```

---

## 6 Dead Code List

### Unused / Stub Endpoints

| Item | Location | Status |
|------|----------|--------|
| `auths-github-app` commit verification | `src/webhook.rs` | Push + PR handlers log events but verification logic is TODO |
| `auths-github-app` check run creation | `src/github.rs` | GitHub API client is a stub — no actual check runs posted |
| MCP `deploy` tool | `auths-mcp-server` tools | Mock implementation (returns "deployment queued") |
| MCP `read_file` / `write_file` | `auths-mcp-server` tools | Sandboxed to `/tmp` only — demonstration tools |

### Unused / Disconnected Services

| Item | Notes |
|------|-------|
| `auths-agent-demo` | Pure local simulation; no network calls. Demonstrates SDK but not wired to any running service |
| `auths-examples/` templates | Reference repos, not deployed. Some may reference APIs that don't exist yet |

### Potentially Unused Frontend Components

| Item | Location | Notes |
|------|----------|-------|
| Various diagram components | `auths-site` | Educational/documentation diagrams — may not be linked from navigation |
| Fixture/demo mode code | `auths-site`, `auths-mobile` | `USE_FIXTURES` flag enables test data — dead in production builds |

### Deleted / Removed Sub-projects (per git status)

| Item | Status |
|------|--------|
| `auths-legacy/auths` | Deleted |
| `auths-releases` | Deleted |
| `auths-verify-action` | Deleted (replaced by `auths-verify-github-action`) |

### Deleted Planning Documents (per git status)

| File | Status |
|------|--------|
| `crate_org_roadmap.md`, `current_roadmap.md`, `debate_roadmap.md`, `ecosystem_roadmap.md`, `enterprise_roadmap.md`, `financial_success_roadmap.md`, `gamification_roadmap.md`, `http_security.md`, `licensing_roadmap.md`, `milestone_roadmap_2.md`, `new_roadmap.md`, `roadmap_auths.md`, `roadmap_overall.md`, `stripe_roadmap.md`, `unicorn_roadmap.md` | All deleted |

---

## 7 Backend Capabilities Inventory

| Capability | Description | Exposure |
|-----------|-------------|----------|
| **Identity Resolution** | Resolve KERI identities by prefix/DID | **Exposed** — registry API → web explorer, mobile, auth server |
| **KEL Management** | Create/append Key Event Log (inception, rotation, interaction) | **Exposed** — registry API → CLI, mobile |
| **Attestation Verification** | Verify Ed25519 signature chains | **Exposed** — registry API, WASM widget, CLI, GitHub Action |
| **Device Management** | Register, list, revoke devices | **Exposed** — registry API → mobile app |
| **Device Pairing** | LAN mDNS + ECDH pairing protocol | **Exposed** — pairing daemon → mobile, chat |
| **Org Membership** | Add/remove members with roles + capabilities | **Exposed** — registry API → web org management |
| **Challenge-Response Auth** | DID-based un-phishable authentication | **Exposed** — auth server → web challenge-auth |
| **OIDC Bridge** | Exchange attestation chains for cloud JWTs | **Exposed** — OIDC bridge server → MCP server, enterprise consumers |
| **Encrypted Messaging** | E2E encrypted chat relay (X25519 + AES-256-GCM) | **Exposed** — chat server → iOS/macOS chat app |
| **SCIM Provisioning** | SCIM 2.0 multi-tenant agent provisioning | **Exposed** — SCIM server → enterprise IdP systems |
| **Transparency Log** | Append-only log with Merkle tree consistency proofs | **Partially exposed** — activity feed on web; witness + monitor running |
| **Artifact Search** | Search signed artifacts/packages | **Exposed** — registry API → web explorer |
| **Network Statistics** | Aggregate network health/stats | **Exposed** — registry API → web network page |
| **Namespace Browsing** | Browse identity namespaces | **Exposed** — registry API → web explorer |
| **Identity Search** | Full-text identity search | **Exposed** — registry API → web explorer |
| **Trust Tier Computation** | Weighted scoring of identity trustworthiness | **Exposed** — client-side in web (claims×20, keys×15, artifacts×5) |
| **Key Rotation** | KERI pre-rotation with forward security | **Exposed** — CLI workflow, SDK; mobile app supports inception |
| **Emergency Freeze** | Instantly invalidate all identity attestations | **Exposed** — mobile app → registry |
| **Git Allowed Signers** | Generate SSH `allowed_signers` files from attestations | **Partially exposed** — CLI + GitHub Action only; no web UI |
| **Policy Engine** | Capability-based authorization (sign_commit, deploy:staging, etc.) | **Partially exposed** — used internally by SDK/MCP; org policy visible on web |
| **Agent Delegation** | Scoped, time-bounded delegation to AI agents | **Not exposed to frontend** — demonstrated in agent-demo only; SDK supports it |
| **IdP Binding** | Bind KERI identities to corporate IdPs (Okta, Google, Entra, SAML) | **Not exposed to frontend** — cloud-cli only; no web UI |
| **Diagnostics** | System health checks (keychains, Git, crypto) | **Not exposed to frontend** — CLI only |
| **Audit Events** | Structured audit event emission | **Not exposed to frontend** — internal to SDK workflows |
| **Cache Tiering** | Redis (Tier 0) + Git (Tier 1) identity cache | **Not exposed** — internal infrastructure |
| **Webhook Processing** | GitHub push/PR event handling | **Not exposed to frontend** — GitHub App (backend-only, partially implemented) |
| **MCP Tool Execution** | JWT-gated tool execution (file I/O, deploy) | **Not exposed to frontend** — MCP server only; mock tools |
| **Witness Receipting** | KERI event witnessing with first-seen enforcement | **Not exposed to frontend** — witness server (backend infrastructure) |
| **Log Monitoring** | Periodic transparency log integrity verification | **Not exposed** — background service |
| **Push Notifications** | Mobile push notification registration | **Partially exposed** — mobile app registers; no visible notification UI yet |

---

## 8 Broken Pipelines

### Frontend Exists → Backend Missing

| Frontend | Expected Backend | Status |
|----------|-----------------|--------|
| `auths-mobile` calls `GET /mobile/identity` | No `/mobile/identity` endpoint found in registry-server routes | **Missing** — mobile-specific API routes not defined in registry-server |
| `auths-mobile` calls `GET /mobile/devices` | No `/mobile/devices` endpoint found in registry-server routes | **Missing** — mobile device management API not defined |
| `auths-mobile` calls `POST /mobile/pair/initiate` | No `/mobile/pair/initiate` endpoint in registry-server | **Missing** — mobile pairing initiation route missing from cloud |
| `auths-mobile` calls `POST /mobile/pair/complete` | No `/mobile/pair/complete` endpoint in registry-server | **Missing** — mobile pairing completion route missing |
| `auths-mobile` calls `POST /mobile/emergency/freeze` | No `/mobile/emergency/freeze` endpoint in registry-server | **Missing** — emergency freeze route not in registry |
| `auths-mobile` calls `POST /mobile/notifications/register` | No notification registration endpoint in registry-server | **Missing** — push notification backend not implemented |
| `auths-chat` (iOS/macOS) calls chat-server endpoints | `auths-chat-server` exists but may not be deployed | **Uncertain** — chat server crate exists but no fly.toml/deployment config for it |
| `auths-site` Org invite flow (`/join/[code]`) | Invite acceptance API endpoint | **Uncertain** — invite creation exists; acceptance flow may be incomplete |

### Backend Exists → API Missing

| Backend Capability | Expected API | Status |
|-------------------|--------------|--------|
| `auths-sdk` agent delegation workflows | No REST API for delegation management | **Missing** — only usable via SDK/CLI, no HTTP API |
| `auths-sdk` audit event workflows | No REST API for audit log retrieval | **Missing** — events emitted internally but not queryable via API |
| `auths-sdk` diagnostics | No REST API for system diagnostics | **Missing** — CLI-only |
| `auths-sdk` policy_diff analysis | No REST API for policy diff | **Missing** — SDK function only |
| `auths-cloud-sdk` IdP binding | No REST API for IdP management | **Missing** — cloud-cli only |
| `auths-sdk` allowed_signers generation | No REST API endpoint | **Missing** — CLI-only |
| `auths-core` keychain operations | No REST API for remote keychain management | **By design** — keychains are local-only |

### API Exists → Frontend Unused

| API Endpoint | Available In | Frontend Usage |
|-------------|-------------|----------------|
| `POST /v1/verify` (registry-server) | Registry API | **Not called from any frontend** — verification done client-side via WASM or CLI |
| `DELETE /v1/pairing/sessions/:id` (registry-server) | Registry API | **Not called from any frontend** — no cancel-pairing UI |
| `POST /witness/{prefix}/event` (witness server) | Witness API | **Not called from any frontend** — backend infrastructure only |
| `GET /witness/{prefix}/head` (witness server) | Witness API | **Not called from any frontend** — backend infrastructure only |
| `GET /witness/{prefix}/receipt/{said}` (witness server) | Witness API | **Not called from any frontend** — backend infrastructure only |
| MCP tool endpoints (`/mcp/tools/*`) | MCP server | **Not called from any frontend** — designed for machine-to-machine use |
| SCIM endpoints | SCIM server | **Not called from any frontend** — designed for enterprise IdP integration |
| `POST /v1/identities/:prefix/kel` (registry) | Registry API | **Only called from mobile/CLI** — no web UI for identity creation |

### Cross-Project Wiring Gaps

| Gap | Description |
|-----|-------------|
| GitHub App → Registry verification | `auths-github-app` receives webhooks but commit verification against registry is TODO |
| GitHub App → Check Runs | GitHub API client in `src/github.rs` is a stub; no check runs are posted |
| Chat server deployment | `auths-chat-server` has no deployment config (Dockerfile/fly.toml), unlike registry and auth servers |
| SCIM → Agent provisioning pipeline | SCIM server provisions agents in PostgreSQL, but no pipeline connects provisioned agents to the OIDC bridge or MCP server |
| Monitor alerts | `auths-monitor` verifies log integrity but has no alerting/notification output (logs only) |
| Push notifications | Mobile app registers for notifications, but no notification dispatch service exists |
