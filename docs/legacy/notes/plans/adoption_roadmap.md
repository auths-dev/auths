# Auths Adoption Risk Roadmap: 10 Existential Threats

## The Quick List

```
auths/                          ← existing Rust monorepo (stays focused)
├── crates/
│   ├── auths-core/             ← pairing protocol, recovery kit, capability types
│   ├── auths-cli/              ← emergency commands, jargon-free help text, audit
│   ├── auths-id/               ← unchanged
│   ├── auths-policy/           ← unchanged
│   ├── auths-verifier/         ← freshness modes, migration verifier
│   ├── auths-registry-server/  ← NEW: Axum HTTP API over PackedRegistryBackend
│   └── auths-index/            ← redb read cache (Epic from earlier)
├── packages/
│   ├── auths-verifier-go/      ← unchanged
│   ├── auths-verifier-python/  ← unchanged
│   ├── auths-verifier-swift/   ← unchanged (consumed by mobile repo)
│   └── auths-verifier-ts/      ← unchanged (consumed by dashboard repo)
└── actions/
    └── verify-action/          ← GitHub Action (self-contained, references CLI)
```

The monorepo stays as the **protocol layer**. Everything that touches cryptography, KERI, policy evaluation, or the core data model lives here. The registry server also lives here because it's a thin HTTP layer over `RegistryBackend` — no frontend, no business logic beyond auth.

Now the things that don't belong here:

**`auths-dashboard/` — separate repo**

The org dashboard is a React SPA with its own build toolchain, CI, deployment pipeline, and release cadence. It imports `auths-verifier-ts` (WASM) for client-side verification but otherwise talks to the registry server over HTTP. Putting a Node/React project in a Rust monorepo creates CI pain for everyone. The dashboard also likely becomes the `registry.auths.dev` frontend, so it deploys as a static site to a CDN with the registry server as its API backend.

**`auths-mobile/` — separate repo**

This is the clearest case for separation. It's a React Native or SwiftUI+Kotlin Multiplatform project that imports `auths-verifier-swift` and the Android equivalent. The build systems (Xcode, Gradle) have nothing in common with Cargo. The release cadence is dictated by App Store review, not crate publishing. It consumes the pairing protocol from `auths-core` via the FFI bindings that already exist in `packages/auths-verifier-swift/`.

The one subtlety: the pairing protocol implementation (the `PairingToken`, challenge-response, session management) lives in `auths-core` in the monorepo. The mobile app calls it through the Swift/Kotlin bindings. This means protocol changes happen in the monorepo and the mobile repo consumes them — you don't want protocol logic duplicated in Swift.

**`auths-github-app/` — separate repo**

The GitHub App is a deployed service (likely a small Node.js or Rust service on Cloudflare Workers or similar) that receives webhooks, calls the registry API, and posts check runs. It has its own deployment pipeline, OAuth credentials, and GitHub Marketplace listing. The GitHub Action in `actions/verify-action/` stays in the monorepo because it's a shell wrapper around the CLI binary — no separate build needed.

**Docs and onboarding — in the monorepo**

The jargon rewrite (Epic 7) touches CLI help text, README files, and the `auths learn` command — all of which live in the monorepo already. The marketing site and docs could be a separate repo or a `docs/` folder in the monorepo with a static site generator. I'd lean toward the monorepo so that CLI help text and docs stay in sync, but this is a lighter decision.

**Pricing and signup — part of the dashboard repo**

The signup flow, Stripe integration, and account management are frontend + backend features of the hosted service. They belong with the dashboard, not the protocol.

Here's the dependency graph:

```
auths (monorepo)
  │
  │  publishes crates + FFI bindings
  │
  ├──► auths-dashboard/        (imports auths-verifier-ts via npm)
  │      deploys to: registry.auths.dev
  │
  ├──► auths-mobile/           (imports auths-verifier-swift + android bindings)
  │      deploys to: App Store / Play Store
  │
  ├──► auths-github-app/       (calls registry HTTP API)
  │      deploys to: GitHub Marketplace
  │
  └──► auths-docs/             (or in-monorepo docs/ folder)
         deploys to: docs.auths.dev
```

The mapping back to your 10 epics below:

| Epic | Where | Why |
|------|-------|-----|
| 1. Managed service | `auths` monorepo (`auths-registry-server`) + `auths-dashboard` for UI | Server is a thin API crate; hosted infra is deployment config |
| 2. QR pairing | Protocol in `auths-core`, UX in `auths-mobile` + `auths-cli` | Protocol must be in Rust, presentation varies by platform |
| 3. GitHub badge | `auths-github-app/` repo + `actions/verify-action/` in monorepo | App is a deployed service with its own lifecycle |
| 4. Org dashboard | `auths-dashboard/` repo | Frontend project with different toolchain |
| 5. Mobile app | `auths-mobile/` repo | Xcode/Gradle builds, App Store releases |
| 6. Migration bridges | `auths-cli` in monorepo | CLI commands, no new repos needed |
| 7. Jargon rewrite | `auths` monorepo (CLI help, READMEs, docs) | Touches existing files only |
| 8. Incident response | `auths-cli` in monorepo + runbook templates in docs | CLI commands + documentation |
| 9. Analytics | `auths-registry-server` (API) + `auths-dashboard` (UI) | Backend in monorepo, visualization in dashboard |
| 10. Pricing | `auths-dashboard/` repo | Signup flow, Stripe, account mgmt |

---

## Epic 1: Managed Registry Service (`registry.auths.dev`)

**Risk:** Every competitor has a hosted offering. Sigstore has Rekor + Fulcio. GitHub has its own signing infra. Asking developers to self-host a Git repo for identity storage is like asking them to run their own DNS. Evaluators bounce in under 60 seconds.

**Success metric:** A new user can create an identity and have it verifiable by a third party within 5 minutes, with zero infrastructure.

### 1.1 — Registry HTTP API

A thin service in front of the `PackedRegistryBackend` that exposes identity operations over HTTPS. Git remains the storage layer underneath, but users never touch it directly.

```rust
// crates/auths-registry-server/src/routes.rs

use axum::{Router, Json, extract::Path};
use axum::http::StatusCode;

pub fn registry_routes() -> Router {
    Router::new()
        .route("/v1/identities/:prefix", axum::routing::get(get_identity))
        .route("/v1/identities/:prefix/kel", axum::routing::get(get_kel))
        .route("/v1/identities/:prefix/kel", axum::routing::post(append_event))
        .route("/v1/devices/:did", axum::routing::get(get_device))
        .route("/v1/devices/:did/attestation", axum::routing::get(get_attestation))
        .route("/v1/verify", axum::routing::post(verify_attestation))
        .route("/v1/health", axum::routing::get(health))
}

/// Public read — no auth required. Anyone can verify.
async fn get_identity(Path(prefix): Path<String>) -> Result<Json<IdentityResponse>, StatusCode> {
    // Read from redb cache, fall back to Git
    todo!()
}

/// Authenticated write — requires proof of key ownership.
/// The request body is a signed KEL event. The server validates
/// the signature and SAID chain before appending.
async fn append_event(
    Path(prefix): Path<String>,
    Json(req): Json<SignedEventRequest>,
) -> Result<StatusCode, ApiError> {
    // 1. Deserialize event
    // 2. Verify signature matches current key in KEL
    // 3. Verify SAID chain (event.p == previous event.d)
    // 4. Append to Git via PackedRegistryBackend
    // 5. Invalidate redb cache entry
    // No API keys needed — the event's own signature is the auth
    todo!()
}
```

Key insight: the API is **self-authenticating**. You don't need API keys or OAuth — every write operation carries its own cryptographic proof. This is the KERI advantage expressed as a product feature.

### 1.2 — Free tier with rate limits

- Free: 10 identities, 100 devices, 1000 verifications/day
- Team: unlimited identities, SLA, webhook integrations
- Enterprise: on-prem option, audit logs, SSO for the dashboard

### 1.3 — CLI integration with registry

```rust
// Addition to auths-cli/src/commands/init.rs

/// During `auths setup`, offer to publish identity to the public registry.
fn offer_registry_publication(identity: &ManagedIdentity) -> Result<()> {
    let publish = Confirm::new()
        .with_prompt("Publish your identity to registry.auths.dev? (makes it verifiable by anyone)")
        .default(true)
        .interact()?;

    if publish {
        let client = RegistryClient::new("https://registry.auths.dev");
        client.publish_identity(identity)?;
        println!("  ✓ Published: https://registry.auths.dev/id/{}", short_did(&identity.controller_did));
    }

    Ok(())
}
```

### 1.4 — Registry web UI

A read-only web interface at `registry.auths.dev/id/{did}` showing identity details, device chain, key rotation history, and current status. Think "keybase.io profile page" but for machine identity. No login required to view — verification is public by design.

---

## Epic 2: Cross-Device Pairing via QR Code

**Risk:** A developer sets up Auths on their MacBook. Next morning they open their work desktop. The current flow to link the second device involves understanding attestation chains, Git refs, and DID formats. Nobody will do this. Every identity system that succeeded (iCloud Keychain, 1Password, Signal) solved device pairing with a camera.

**Success metric:** Link a second device in under 30 seconds using only a phone camera or screen.

### 2.1 — Pairing protocol

The pairing flow is a short-lived, authenticated key exchange:

```
Device A (already set up)          Device B (new)
         │                              │
         │  1. Generate pairing token   │
         │     (ephemeral keypair +     │
         │      challenge nonce)        │
         │                              │
         │  2. Encode as QR / short     │
         │     code (6 digits)          │
         ├──────── QR/code ────────────►│
         │                              │
         │  3. Device B scans,          │
         │     generates its own        │
         │     keypair, signs challenge │
         │                              │
         │◄──── signed response ────────┤
         │                              │
         │  4. Device A verifies,       │
         │     creates attestation      │
         │     linking Device B's key   │
         │     to the identity          │
         │                              │
         │  5. Push attestation to      │
         │     registry / Git           │
         │                              │
         ✓  Paired                      ✓  Paired
```

```rust
// crates/auths-core/src/pairing.rs

use chrono::{Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// A short-lived pairing session initiated by an existing device.
#[derive(Debug, Serialize, Deserialize)]
pub struct PairingToken {
    pub session_id: String,
    pub identity_did: String,
    pub challenge: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub expires_at: chrono::DateTime<Utc>,
    pub capabilities: Vec<String>,
}

impl PairingToken {
    pub fn generate(identity_did: &str, capabilities: Vec<String>) -> Result<Self, PairingError> {
        let rng = SystemRandom::new();

        let mut session_id = vec![0u8; 16];
        rng.fill(&mut session_id).map_err(|_| PairingError::RngFailed)?;

        let mut challenge = vec![0u8; 32];
        rng.fill(&mut challenge).map_err(|_| PairingError::RngFailed)?;

        let ephemeral_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| PairingError::KeyGenFailed)?;
        let ephemeral = ring::signature::Ed25519KeyPair::from_pkcs8(ephemeral_pkcs8.as_ref())
            .map_err(|_| PairingError::KeyGenFailed)?;

        Ok(Self {
            session_id: hex::encode(&session_id),
            identity_did: identity_did.to_string(),
            challenge,
            ephemeral_pubkey: ephemeral.public_key().as_ref().to_vec(),
            expires_at: Utc::now() + Duration::minutes(5),
            capabilities,
        })
    }

    /// Encode as a compact string suitable for QR code or manual entry.
    ///
    /// Format: `auths://{session_id}@{registry_url}#{short_challenge}`
    /// Short enough for a QR code, contains enough to bootstrap the exchange.
    pub fn to_uri(&self, registry_url: &str) -> String {
        let short_challenge = &hex::encode(&self.challenge)[..8];
        format!("auths://{}@{}#{}", self.session_id, registry_url, short_challenge)
    }

    /// Encode as a 6-digit numeric code for manual entry.
    pub fn to_short_code(&self) -> String {
        let num = u32::from_be_bytes([
            self.challenge[0], self.challenge[1],
            self.challenge[2], self.challenge[3],
        ]);
        format!("{:06}", num % 1_000_000)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingResponse {
    pub session_id: String,
    pub device_pubkey: Vec<u8>,
    pub device_did: String,
    pub challenge_signature: Vec<u8>,
    pub device_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("RNG failed")]
    RngFailed,
    #[error("key generation failed")]
    KeyGenFailed,
    #[error("pairing session expired")]
    Expired,
    #[error("challenge signature invalid")]
    InvalidSignature,
}
```

### 2.2 — CLI pairing commands

```bash
# On Device A (existing):
$ auths pair
🔗 Pairing mode active

  Scan this QR code with your other device:
  ┌─────────────────┐
  │  ██ ▄▄ ██ ▄▄   │
  │  ▄▄ ██ ▄▄ ██   │  (QR rendered in terminal)
  │  ██ ▄▄ ██ ▄▄   │
  └─────────────────┘

  Or enter this code manually: 847 291

  Waiting for response... (expires in 4:58)

# On Device B (new):
$ auths pair --join 847291
  ✓ Connected to identity did:keri:EXq5...
  ✓ Device linked as "brians-desktop"
  ✓ Capabilities: sign_commit, sign_tag
```

### 2.3 — Pairing relay service

For cases where devices aren't on the same network, `registry.auths.dev` hosts a short-lived relay. The pairing token is uploaded encrypted, the new device downloads it by session ID, completes the exchange, and the relay deletes the session. The relay never sees private keys — it only shuttles encrypted payloads.

### 2.4 — Mobile pairing (companion app prerequisite)

The `auths://` URI scheme triggers the companion app (Epic 5) or falls back to browser-based pairing at `registry.auths.dev/pair/{session_id}`.

---

## Epic 3: GitHub / GitLab Native Verification

**Risk:** Developers live in pull request review screens. If Auths signatures don't show up as a green badge next to the commit, the tool is invisible. Invisible tools get uninstalled. Sigstore already has GitHub's "Verified" badge. GPG has had it for years.

**Success metric:** A PR signed with Auths shows a "Verified by Auths" badge in GitHub/GitLab UI, clickable to see the full identity chain.

### 3.1 — GitHub App for commit verification

A GitHub App that:

1. Listens to `push` and `pull_request` webhooks
2. Fetches the commit signature
3. Resolves the signer's Auths identity (via registry API or embedded `.auths/` in repo)
4. Verifies the attestation chain
5. Posts a commit status check or check run with verification details

```yaml
# .github/workflows/auths-verify.yml
# Until the native App exists, this GitHub Action provides the same value

name: Auths Verification
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: auths/verify-action@v1
        with:
          registry: https://registry.auths.dev
          # Optionally pin trusted roots
          roots: .auths/roots.json
          # Fail the check if any commit is unsigned
          require-all-signed: true
```

### 3.2 — Check run output format

The check run should render rich Markdown in the GitHub UI:

```markdown
## ✅ Auths Verification Passed

| Commit | Signer | Identity Age | Capabilities | Status |
|--------|--------|-------------|--------------|--------|
| `a1b2c3d` | Brian (did:keri:EXq5...YqaL) | 6 months | sign_commit | ✅ Valid |

**Chain:** Root → MacBook Pro (linked 2025-08-14) → Commit signature
**Policy:** `sign_commit` required for `refs/heads/main` — ✅ satisfied
**Key status:** Active (last rotated 12 days ago)
```

### 3.3 — GitLab CI component

Equivalent for GitLab using their CI Component system. Same verification logic, different presentation layer.

### 3.4 — `.auths/` convention for repo-embedded trust

Define a convention where repos can embed their trust roots:

```
.auths/
  roots.json          # Pinned trusted identity DIDs
  policy.json         # Required capabilities per branch/path
  registry-url.txt    # Optional: custom registry endpoint
```

This lets the GitHub Action/App verify without any external configuration — the trust model travels with the repo.

---

## Epic 4: Org Dashboard (Web UI)

**Risk:** The org admin persona — the person who decides whether to adopt Auths for a team — will never evaluate a CLI-only tool. They need to see members, devices, capabilities, and audit trails in a browser. If they can't answer "who has access to what?" in 10 seconds, they pick Okta/Auth0.

**Success metric:** An org admin can invite a member, assign capabilities, and revoke a device entirely through a web interface.

### 4.1 — Dashboard backend API

Extend the registry server with org management endpoints:

```rust
// crates/auths-registry-server/src/routes/org.rs

pub fn org_routes() -> Router {
    Router::new()
        .route("/v1/orgs/:org_did/members", axum::routing::get(list_members))
        .route("/v1/orgs/:org_did/members", axum::routing::post(invite_member))
        .route("/v1/orgs/:org_did/members/:member_did", axum::routing::delete(revoke_member))
        .route("/v1/orgs/:org_did/members/:member_did/capabilities", axum::routing::put(update_capabilities))
        .route("/v1/orgs/:org_did/audit", axum::routing::get(audit_log))
        .route("/v1/orgs/:org_did/policy", axum::routing::get(get_policy))
        .route("/v1/orgs/:org_did/policy", axum::routing::put(update_policy))
        .route("/v1/orgs/:org_did/devices", axum::routing::get(list_all_devices))
}
```

### 4.2 — Dashboard frontend

A React SPA served from `registry.auths.dev/dashboard`. Key views:

- **Members list:** Table with name, DID (truncated), role, capabilities, device count, last active, status badges (active/expired/revoked). Bulk actions for revoke/update.
- **Member detail:** Full attestation chain visualization (tree diagram), device list, capability timeline, rotation history.
- **Devices view:** All devices across the org. Filter by status, identity, capability. "Panic button" to revoke a specific device instantly.
- **Policy editor:** Visual policy builder (drag-and-drop capability assignment per role/branch/environment) that generates the JSON policy under the hood. Preview mode that shows "if this policy were active, these 3 members would lose access."
- **Audit log:** Timestamped stream of all identity events (creations, rotations, attestations, revocations) with filters and CSV export.

### 4.3 — Invite-by-email flow

Org admin enters an email address → system generates a single-use invite link → recipient clicks link → guided setup (Epic 3 from the original roadmap) → identity automatically linked to org with the specified role and capabilities. No CLI required for the invitee's first experience.

### 4.4 — SAML/OIDC bridge for enterprise SSO

Enterprises won't create a separate login for an Auths dashboard. Provide SAML and OIDC integration that maps corporate identities to Auths org membership. The corporate identity doesn't *replace* the Auths DID — it creates an attestation linking "brian@company.com authenticated via Okta" to "did:keri:EXq5...". This preserves the decentralized model while meeting enterprise procurement requirements.

---

## Epic 5: Mobile Companion App

**Risk:** Device pairing, key rotation approval, and emergency revocation all need to happen from a phone. Developers aren't at their laptop when they realize their work machine was stolen. The "global kill switch" value prop from the analysis doc is only real if there's a button they can press from the subway.

**Success metric:** Revoke a compromised device from your phone in under 10 seconds.

### 5.1 — Core app scope (iOS + Android)

The app is deliberately minimal — it's a *control plane*, not a full client:

- **Identity card:** Show your DID, current key status, linked devices, org memberships. Tap to copy DID.
- **Pair device:** Camera opens, scan QR from `auths pair` on another device. One tap to approve.
- **Approve requests:** Push notification when a new device tries to pair or when a policy requires multi-party approval. Approve/deny with biometric.
- **Emergency revoke:** Red button per device. "Revoke MacBook Pro?" → biometric confirm → attestation revoked, webhook fires, done.
- **Rotation reminder:** Push notification when key rotation is due per policy.

### 5.2 — Secure enclave as key storage

The phone's Secure Enclave (iOS) or StrongBox (Android) stores the identity's signing key. The key never leaves the hardware. This means the phone becomes the most secure device in the chain — not the laptop.

```rust
// This maps to the existing auths-verifier-swift bindings and
// auths-core/src/platform/ios.rs + android.rs modules

// The app uses the existing platform abstraction:
// - iOS: SecureEnclave via the Security framework (ios_keychain.rs exists)
// - Android: Android Keystore with StrongBox attestation (android_keystore.rs exists)
//
// The key architectural decision: the phone holds the ROOT identity key.
// Laptops and CI devices hold DELEGATED keys with scoped capabilities.
// This inverts the current model where the first device is implicitly root.
```

### 5.3 — Push notification infrastructure

Use APNs / FCM to deliver:
- Pairing requests
- Rotation reminders
- Revocation confirmations
- Policy violation alerts (e.g., "unsigned commit pushed to main")

### 5.4 — Offline revocation via signed SMS

For the extreme case where the phone has no data connection, support a "signed SMS" revocation. The app generates a pre-signed revocation attestation that can be texted to a known relay number. The relay publishes it to the registry. This is the "glass break" scenario.

---

## Epic 6: Migration Bridges from GPG / Sigstore / SSH

**Risk:** Teams with existing commit signing won't rip it out to try something new. If adopting Auths means "first, delete your GPG setup and retrain everyone," the answer is always "not worth the risk." Auths needs to run alongside existing tools, then gradually replace them.

**Success metric:** A team can enable Auths verification on their repo without any developer changing their signing setup, with a migration path that converts them one by one.

### 6.1 — Dual-verification mode

```rust
// crates/auths-cli/src/commands/verify_commit.rs — extend existing

/// Verification that accepts EITHER Auths signatures OR legacy signatures
/// during a migration period.
#[derive(Debug, Clone)]
pub struct MigrationVerifier {
    pub auths_roots: Vec<String>,
    pub accept_gpg: bool,
    pub accept_ssh: bool,
    pub gpg_keyring: Option<PathBuf>,
    pub ssh_allowed_signers: Option<PathBuf>,
}

impl MigrationVerifier {
    /// Verify a commit, trying Auths first, falling back to legacy.
    ///
    /// Returns which method succeeded, enabling migration tracking.
    pub fn verify_commit(&self, repo: &Repository, commit_id: &str) -> VerifyResult {
        // Try Auths first
        if let Ok(result) = self.verify_auths(repo, commit_id) {
            return VerifyResult::Auths(result);
        }

        // Fall back to GPG
        if self.accept_gpg {
            if let Ok(result) = self.verify_gpg(repo, commit_id) {
                return VerifyResult::Gpg(result);
            }
        }

        // Fall back to SSH
        if self.accept_ssh {
            if let Ok(result) = self.verify_ssh(repo, commit_id) {
                return VerifyResult::Ssh(result);
            }
        }

        VerifyResult::Unsigned
    }
}

pub enum VerifyResult {
    Auths(AuthsVerification),
    Gpg(GpgVerification),
    Ssh(SshVerification),
    Unsigned,
}
```

### 6.2 — GPG-to-Auths identity bridge

```bash
# Import existing GPG identity as the "genesis" of an Auths identity
$ auths migrate from-gpg --key-id 0xABCD1234
  ✓ Found GPG key: Brian <brian@example.com>
  ✓ Created Auths identity: did:keri:EXq5...
  ✓ Created cross-reference attestation:
    "GPG key 0xABCD1234 is controlled by did:keri:EXq5..."
    Signed by BOTH the GPG key and the new Auths key.

  Your existing GPG-signed commits remain valid.
  New commits will be signed with Auths.
  Run `auths migrate status` to track migration progress.
```

### 6.3 — Migration progress tracking

```bash
$ auths migrate status
  Repository: github.com/org/repo

  Last 100 commits:
    Auths-signed:  23  (23%)  ████░░░░░░░░░░
    GPG-signed:    61  (61%)  █████████░░░░░
    SSH-signed:    12  (12%)  ██░░░░░░░░░░░░
    Unsigned:       4   (4%)  █░░░░░░░░░░░░░

  Team migration:
    alice    ✅ Auths (migrated 2025-11-03)
    bob      🔄 GPG (invite sent, pending)
    charlie  🔄 SSH (invite sent, pending)
    ci-bot   ✅ Auths (ephemeral)
```

### 6.4 — Sigstore co-existence

For teams using Sigstore for artifact signing but wanting Auths for identity persistence, create an attestation that links a Sigstore OIDC identity to an Auths DID. This lets orgs keep their existing artifact verification pipeline while adding the persistent identity layer Sigstore lacks.

---

## Epic 7: Jargon-Free Onboarding

**Risk:** The README says "KERI," "KEL," "SAID," "pre-rotation," "self-certifying identifiers," and "DID" in the first paragraph. A platform engineer evaluating this for their team has no idea what any of that means. They leave. The people who *do* understand this jargon already have their own tools. Auths needs to sell the *outcome*, not the mechanism.

**Success metric:** A developer with zero cryptography knowledge can understand what Auths does, why they should care, and how to start in under 2 minutes.

### 7.1 — Rewrite all user-facing copy

The principle: **the CLI, docs, and website never mention KERI, KEL, SAID, or DID unless the user asks.** These are implementation details, not user-facing concepts.

Vocabulary mapping:

| Internal term | User-facing term |
|---------------|-----------------|
| DID | Identity ID |
| KEL | Identity history |
| SAID | Event fingerprint |
| Pre-rotation | Recovery key |
| Attestation | Device link / Authorization |
| Capability | Permission |
| Inception event | Identity creation |
| Rotation event | Key change |
| Witness | Verification server |
| Controller | Owner |

### 7.2 — Rewrite CLI help text

```
BEFORE:
  auths id init-did    Initialize a KERI-based DID with pre-rotation commitment

AFTER:
  auths id create      Create a new cryptographic identity

BEFORE:
  auths device link    Create an attestation linking a device key to the controller DID

AFTER:
  auths device add     Authorize this device to sign on behalf of your identity
```

### 7.3 — Interactive tutorial (`auths learn`)

A built-in interactive tutorial that walks through concepts with concrete examples:

```bash
$ auths learn

  Welcome to Auths! Let's walk through the basics.

  🔑 What is an identity?
  Your Auths identity is like a passport for your code.
  It proves that YOU made a specific change — not someone
  pretending to be you.

  Unlike a password, your identity is cryptographic:
  even if someone has your GitHub credentials, they can't
  forge your Auths signature.

  Let's create one. Press Enter to continue...

  [Creates a temporary sandbox identity and walks through
   signing a commit, verifying it, linking a device,
   and revoking access — all with real operations on
   a temp repo that gets cleaned up at the end]
```

### 7.4 — Landing page and docs restructure

The website should have three entry points:

1. **"I'm a developer"** → 5-minute quickstart ending with a signed commit
2. **"I'm a platform/security lead"** → Value prop focused on audit, compliance, agent control
3. **"I'm building AI agents"** → Agent identity, capability scoping, kill switch

The KERI deep-dive becomes a "How it works under the hood" page linked from the footer, not the homepage.

---

## Epic 8: Incident Response Playbook (Guided Recovery)

**Risk:** The moment a team has a real security incident — a stolen laptop, a compromised CI key, a rogue agent — they need to act in minutes. If the response is "read the KERI spec and figure out pre-rotation," they'll never use Auths again. Worse, they'll tell everyone it failed them.

**Success metric:** A non-expert can fully contain a key compromise in under 5 minutes using guided CLI commands.

### 8.1 — `auths emergency` command

```rust
// crates/auths-cli/src/commands/emergency.rs

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct EmergencyCommand {
    #[command(subcommand)]
    command: EmergencySubcommand,
}

#[derive(Subcommand, Debug)]
pub enum EmergencySubcommand {
    /// Immediately revoke a compromised device.
    RevokeDevice(RevokeDeviceArgs),
    /// Rotate identity key (requires recovery key).
    RotateNow(RotateNowArgs),
    /// Freeze all signing — revoke ALL devices for an identity.
    Freeze(FreezeArgs),
    /// Generate a post-incident report.
    Report(ReportArgs),
}

#[derive(Args, Debug)]
pub struct FreezeArgs {
    /// Revoke all devices and block all signing.
    /// This is the nuclear option — you'll need to re-link
    /// every device after resolving the incident.
    #[clap(long)]
    confirm_freeze_all: bool,
}
```

### 8.2 — Guided incident flow

```bash
$ auths emergency
  🚨 Auths Emergency Response

  What happened?
  1. A device was lost or stolen
  2. A private key may have been exposed
  3. An agent is behaving unexpectedly
  4. I need to freeze everything now

  > 1

  Which device was compromised?
  1. brians-macbook (did:key:z6Mk...a3F) — last active 2h ago
  2. ci-runner-prod (did:key:z6Mk...b7G) — last active 5m ago
  3. refactor-agent (did:key:z6Mk...c9H) — last active 1h ago

  > 1

  ⚠️  This will:
  - Revoke the device attestation for "brians-macbook"
  - Notify all configured webhooks
  - Publish revocation to registry.auths.dev
  - The device will be unable to sign anything

  Your identity and other devices are NOT affected.

  Proceed? [y/N] y

  ✓ Device revoked
  ✓ Webhook notifications sent (2/2 delivered)
  ✓ Registry updated
  ✓ Revocation published: https://registry.auths.dev/event/abc123

  Recommended next steps:
  1. Rotate your identity key: `auths key rotate`
  2. Review recent commits from this device: `auths audit --device brians-macbook --since 24h`
  3. Re-link a replacement device: `auths pair`
```

### 8.3 — Post-incident audit report

```bash
$ auths emergency report --device brians-macbook --since 7d --output report.html

  Scanning commits signed by "brians-macbook" in the last 7 days...

  Found 47 commits across 3 repositories.
  All commits are cryptographically valid (signed before revocation).
  No anomalous patterns detected.

  Report saved: report.html
```

The HTML report is designed to be attached to a security incident ticket — it includes commit hashes, timestamps, repos, and verification status in a format a compliance team can review.

### 8.4 — Runbook templates

Ship Markdown runbook templates for common scenarios:
- `stolen-laptop.md`
- `compromised-ci-key.md`
- `rogue-agent.md`
- `key-rotation-ceremony.md`

These live in the docs and are also accessible via `auths emergency --help-{scenario}`.

---

## Epic 9: Signing Coverage Analytics

**Risk:** Auths gets installed, configured, and then... ignored. Without visibility into "what percentage of our commits are signed?" and "which team members haven't set up yet?", the tool drifts into irrelevance. Security tools that can't prove their value get cut in the next budget cycle.

**Success metric:** An org admin can see a real-time dashboard showing signing coverage, policy compliance, and adoption trends.

### 9.1 — Analytics collection endpoint

```rust
// crates/auths-registry-server/src/routes/analytics.rs

/// Analytics are derived from verification events — not surveillance.
/// Every verification request to the registry is counted.
/// No commit content is stored, only metadata.

#[derive(Debug, Serialize)]
pub struct OrgAnalytics {
    pub org_did: String,
    pub period: AnalyticsPeriod,
    pub signing_coverage: SigningCoverage,
    pub member_adoption: MemberAdoption,
    pub key_health: KeyHealth,
    pub policy_compliance: PolicyCompliance,
}

#[derive(Debug, Serialize)]
pub struct SigningCoverage {
    pub total_commits_verified: u64,
    pub auths_signed: u64,
    pub legacy_signed: u64,
    pub unsigned: u64,
    pub coverage_percent: f64,
    pub trend_vs_last_period: f64,
}

#[derive(Debug, Serialize)]
pub struct MemberAdoption {
    pub total_members: u64,
    pub auths_active: u64,
    pub invited_pending: u64,
    pub legacy_only: u64,
}

#[derive(Debug, Serialize)]
pub struct KeyHealth {
    pub keys_due_for_rotation: u64,
    pub keys_overdue: u64,
    pub average_key_age_days: f64,
    pub devices_with_expired_attestations: u64,
}

#[derive(Debug, Serialize)]
pub struct PolicyCompliance {
    pub total_policy_evaluations: u64,
    pub allowed: u64,
    pub denied: u64,
    pub indeterminate: u64,
    pub top_denial_reasons: Vec<(String, u64)>,
}
```

### 9.2 — Dashboard analytics view

Add to the org dashboard (Epic 4):

- **Coverage chart:** Line graph showing signing percentage over time, with a target line (e.g., "goal: 100% by Q2")
- **Adoption funnel:** How many members invited → set up → actively signing
- **Key health heatmap:** Grid of members × key age, red cells for overdue rotations
- **Compliance feed:** Real-time stream of policy allow/deny events

### 9.3 — Slack/Teams integration for alerts

Weekly digest to a Slack channel:

```
📊 Auths Weekly Report — Acme Corp
   Signing coverage: 87% (+3% from last week)
   3 members haven't set up yet: @alice, @dave, @eve
   2 keys are overdue for rotation
   1 policy violation: unsigned commit to main by ci-bot-staging
```

### 9.4 — `auths audit` CLI for compliance

```bash
$ auths audit --repo . --since 2025-Q4 --format csv > q4-audit.csv
$ auths audit --repo . --require-all-signed --exit-code
  # Returns 0 if all commits signed, 1 if any unsigned
  # Use in CI as a gate
```

---

## Epic 10: Pricing, Packaging, and Self-Serve Signup

**Risk:** Even if the product is great, people need to know: is this free? Is it open source? What costs money? If a team lead can't figure out how to buy it (or confirm it's free), they won't invest time evaluating it. The absence of pricing communicates "this isn't a real product yet."

**Success metric:** A team of 5 can go from "what is Auths?" to "signed up and using it" without talking to a human.

### 10.1 — Pricing model

```
┌─────────────────┬───────────────┬──────────────────┬─────────────────────┐
│                 │ Open Source   │ Team             │ Enterprise          │
├─────────────────┼───────────────┼──────────────────┼─────────────────────┤
│ CLI tool        │ ✅ Free (MIT) │ ✅ Free (MIT)    │ ✅ Free (MIT)       │
│ Verifier libs   │ ✅ Free (MIT) │ ✅ Free (MIT)    │ ✅ Free (MIT)       │
│ Self-hosted     │ ✅ Free       │ ✅ Free          │ ✅ Free             │
│ registry.auths  │ 10 identities│ Unlimited        │ Unlimited           │
│   .dev          │ 100 devices  │ SLA 99.9%        │ SLA 99.99%          │
│                 │ Community     │ Priority support │ Dedicated support   │
│ Dashboard       │ Read-only    │ Full access      │ Full + SSO/SAML     │
│ Webhooks        │ ✗            │ ✅               │ ✅ + custom          │
│ Analytics       │ Basic        │ Full             │ Full + export       │
│ Compliance      │ ✗            │ Audit log (90d)  │ Audit log (∞) + SOC2│
│ Mobile app      │ ✅ Free       │ ✅ Free          │ ✅ + MDM integration │
│ Price           │ $0           │ $20/user/mo      │ Contact sales       │
└─────────────────┴───────────────┴──────────────────┴─────────────────────┘
```

The key principle: **the core protocol and tools are always free and open source.** You charge for the hosted service, the dashboard, and the enterprise features. This mirrors the Terraform/HashiCorp model, the GitLab model, and the Grafana model — all of which have succeeded in developer-first markets.

### 10.2 — Self-serve signup flow

```
registry.auths.dev/signup
  │
  ├── "Sign up with GitHub" (OAuth — maps GitHub org to Auths org)
  ├── "Sign up with GitLab"
  └── "Sign up with email"
        │
        ├── Create account
        ├── Create or import identity (guided)
        ├── Create org (optional)
        ├── Invite team members (email or GitHub username)
        ├── Install GitHub App (one click)
        └── First verification runs automatically on next push
```

### 10.3 — Stripe integration for Team tier

Standard SaaS billing: per-seat, monthly, self-serve upgrade/downgrade, usage displayed in dashboard.

### 10.4 — "Try without signing up" sandbox

A playground at `registry.auths.dev/playground` where anyone can:
- Create a throwaway identity
- Sign a test artifact
- Verify it
- See the attestation chain visualized

No account required. This is the "aha moment" that should be reachable in 60 seconds from the landing page.

---

## Execution Priority

```
Phase 1 — "Make it real" (without these, nobody takes Auths seriously)
├── Epic 7:  Jargon-free onboarding (2 weeks, unblocks everything)
├── Epic 3:  GitHub verification badge (4 weeks, makes value visible)
└── Epic 1:  Managed registry (6 weeks, removes hosting objection)

Phase 2 — "Make it usable for teams" (without these, no org adoption)
├── Epic 2:  QR code device pairing (3 weeks)
├── Epic 6:  Migration bridges (3 weeks, removes switching cost)
├── Epic 4:  Org dashboard (6 weeks)
└── Epic 10: Pricing and signup (2 weeks, parallel with dashboard)

Phase 3 — "Make it sticky" (without these, teams churn)
├── Epic 8:  Incident response (3 weeks)
├── Epic 9:  Analytics dashboard (4 weeks)
└── Epic 5:  Mobile app (8 weeks, longest lead time)
```

Phase 1 can begin immediately and ships in ~3 months.
Phase 2 overlaps with late Phase 1 and ships in ~3 months.
Phase 3 begins once there are real users generating real incidents.
