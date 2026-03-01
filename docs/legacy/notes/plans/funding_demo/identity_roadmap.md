# Identity Substrate Roadmap

> **Thesis:** Auths is a decentralized identity substrate. One identity, many devices, no platform dependency. Git commit signing is one application — not the product.

This roadmap covers the **genuinely missing** pieces. It does not re-describe features that already exist. Everything listed here was verified absent via `grep` on 2026-02-12.

---

## What already works

This is substantial — not stubs, real working code with tests:

| Feature | Location | Status |
|---------|----------|--------|
| Ed25519 cryptography (ring) | `auths-core/src/crypto/` | Done |
| Platform keychains (macOS, iOS, Linux, Windows, Android, file fallback) | `auths-core/src/storage/` | Done |
| KERI inception + rotation + abandonment | `auths-id/src/keri/rotation.rs` | Done — KEL chaining, commitment verification, multi-rotation chain tests |
| CLI `auths id rotate` | `auths-cli/src/commands/id.rs:520` | Done — alias management, passphrase, keychain integration |
| Typed `Capability` struct | `auths-verifier/src/core.rs` | Done — `sign_commit()`, `sign_release()`, `manage_members()`, `rotate_keys()`, custom validation |
| `check_trust()` / `resolve_trust()` with TOFU | `auths-core/src/trust/resolve.rs` | Done — `TrustDecision::FirstUse`, `TrustPolicy::Tofu`, `TrustPolicy::Explicit`, rotation continuity |
| `PinnedIdentityStore` (known_hosts model) | `auths-core/src/trust/pinned.rs` | Done — pin, unpin, update, list, concurrent-safe, advisory locking |
| `KelContinuityChecker` for rotation | `auths-core/src/trust/continuity.rs` | Done — verifies unbroken hash linkage from pinned tip to current tip |
| `verify_at_time()` (attestation expiry check) | `auths-verifier/src/verify.rs:119` | Done — time-aware attestation verification |
| Identity bundle export (`auths id export-bundle`) | `auths-cli/src/commands/id.rs:672` | Done — public-only `IdentityBundle` with DID, key, attestation chain |
| Witness HTTP server (Axum) | `auths-core/src/witness/server.rs` | Done — submit event, get head, get receipt, health, duplicity detection |
| Witness SQLite storage | `auths-core/src/witness/storage.rs` | Done — `record_first_seen`, `check_duplicity`, `store_receipt`, `get_receipt` |
| `ReceiptCollector` (async, threshold) | `auths-core/src/witness/collector.rs` | Done |
| `AsyncWitnessProvider` trait | `auths-core/src/witness/async_provider.rs` | Done — trait + `NoOpAsyncWitness` impl |
| Mobile FFI via UniFFI | `auths-mobile-ffi/src/lib.rs` | Done — identity creation, signing, pairing, DID generation |
| WASM verification bindings | `auths-verifier/src/wasm.rs` | Done — `verifyAttestationJson`, `verifyChainJson` |
| Org CLI (init, attest, revoke, members) | `auths-cli/src/commands/org.rs` (1044 lines) | Done — roles (Admin/Member/Readonly), delegation tracking |
| Multi-device pairing (QR, LAN, mDNS, offline) | `auths-cli/src/commands/pair/` | Done |
| Attestation model (dual-signed, JSON-canonical) | `auths-id/src/attestation/` | Done |
| DID resolution (`did:key`, `did:keri`) | `auths-id/src/identity/resolve.rs` | Done |

---

## Epic 1: Identity recovery

**Goal:** Lose your device, keep your identity. Today there's no recovery path — lose the device, lose the identity.

**What exists:** Key rotation works (`rotate_keys()`, `abandon_identity()`), pre-rotation commitments are embedded in inception events, keychain encrypt/decrypt works.

**What's missing:** No `RecoveryKit` struct, no `auths recover` command, no way to bootstrap a new device after losing the old one.

### Tasks

**1.1 — Recovery kit generation**

At `auths id init` time, offer to create a recovery kit: the pre-rotated next key encrypted with a user-chosen passphrase.

```rust
// crates/auths-core/src/recovery.rs

pub struct RecoveryKit {
    pub identity_did: String,
    pub next_key_digest: Vec<u8>,    // already in inception event
    pub encrypted_next_key: Vec<u8>, // encrypted with recovery passphrase
    pub salt: [u8; 32],
}

impl RecoveryKit {
    /// Generate at identity creation time.
    /// Uses `encrypt_keypair()` from `auths_core::crypto::signer`.
    pub fn generate(
        identity_did: &str,
        next_keypair_pkcs8: &[u8],
        recovery_passphrase: &str,
        rng: &SystemRandom,
    ) -> Result<Self, RecoveryError>;

    /// Decrypt on a new device.
    /// Returns the PKCS8 bytes that can be passed to `rotate_keys()`.
    pub fn decrypt_next_key(
        &self,
        recovery_passphrase: &str,
    ) -> Result<Zeroizing<Vec<u8>>, RecoveryError>;
}
```

**1.2 — `auths recover` CLI command**

```bash
auths recover --kit ~/recovery-kit.json
# 1. Prompts for recovery passphrase
# 2. Decrypts pre-rotated key → next_keypair_pkcs8
# 3. Calls rotate_keys(repo, prefix, next_keypair_pkcs8) from keri/rotation.rs
# 4. Creates new device attestation under same identity DID
# 5. Generates new recovery kit for future use
```

This plugs directly into the existing `rotate_keys()` function — the recovery kit just provides the `next_keypair_pkcs8` that `rotate_keys()` already expects.

---

## Epic 2: Cascading device revocation

**Goal:** Revoke a device and automatically revoke everything it delegated.

**What exists:** `auths org revoke-member`, `auths device revoke`, attestation revocation — all single-target. Delegation chain tracking exists in org commands.

**What's missing:** No graph walk. Revoking a device doesn't revoke devices it delegated. No `revoke_device_cascade()`.

### Tasks

**2.1 — Attestation graph query**

```rust
// crates/auths-id/src/attestation/graph.rs

/// Find all attestations issued by a given device DID.
/// This is the "who did this device authorize?" query.
pub fn find_delegated_by(
    source: &dyn AttestationSource,
    issuer_device_did: &str,
) -> Result<Vec<Attestation>>;
```

The `AttestationSource` trait already exists with `load_all_attestations()`. This adds a filtered query.

**2.2 — Cascading revocation**

```rust
// crates/auths-id/src/attestation/revocation.rs

pub struct RevocationReport {
    pub directly_revoked: String,     // the device we targeted
    pub cascade_revoked: Vec<String>, // devices it had delegated
}

pub fn revoke_cascade(
    source: &dyn AttestationSource,
    sink: &dyn AttestationSink,
    device_did: &str,
    signer: &dyn SecureSigner,
    provider: &dyn PassphraseProvider,
) -> Result<RevocationReport> {
    let mut queue = vec![device_did.to_string()];
    let mut revoked = vec![];

    while let Some(did) = queue.pop() {
        // Revoke this device's attestation
        // Find attestations this device issued → add subjects to queue
        for delegated in find_delegated_by(source, &did)? {
            if !delegated.revoked {
                queue.push(delegated.subject.clone());
            }
        }
        revoked.push(did);
    }
    // ...
}
```

**2.3 — CLI integration**

```bash
auths device revoke --did did:key:z6Mk... --cascade
# "Revoked did:key:z6Mk... and 2 delegated devices"
```

---

## Epic 3: HTTP witness client

**Goal:** Connect the existing witness server to the existing async provider trait.

**What exists:** `AsyncWitnessProvider` trait with `submit_event`, `observe_identity_head`, `get_receipt`. Witness HTTP server at `server.rs` with `POST /witness/:prefix/event`, `GET /witness/:prefix/head`, `GET /witness/:prefix/receipt/:said`. `ReceiptCollector` with threshold-based async collection. Only `NoOpAsyncWitness` impl — the doc example has `todo!()`.

**What's missing:** An `HttpWitnessClient` struct that implements `AsyncWitnessProvider` by calling the witness server over HTTP.

### Tasks

**3.1 — HTTP client implementation**

```rust
// crates/auths-core/src/witness/http_client.rs

pub struct HttpWitnessClient {
    base_url: Url,
    witness_did: String,
    client: reqwest::Client,
    timeout: Duration,
}

#[async_trait]
impl AsyncWitnessProvider for HttpWitnessClient {
    async fn submit_event(&self, prefix: &str, event_json: &[u8]) -> Result<Receipt, WitnessError> {
        let url = self.base_url.join(&format!("/witness/{}/event", prefix))?;
        let resp = self.client
            .post(url)
            .timeout(Duration::from_millis(self.timeout_ms()))
            .json(&serde_json::from_slice::<serde_json::Value>(event_json)?)
            .send().await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json::<Receipt>().await?),
            StatusCode::CONFLICT => {
                let err: ErrorResponse = resp.json().await?;
                Err(WitnessError::Duplicity(err.duplicity.unwrap()))
            }
            _ => Err(WitnessError::Network(resp.text().await?)),
        }
    }
    // ... observe_identity_head, get_receipt similarly
}
```

**3.2 — Integration with `auths id rotate`**

Wire `rotate_keri_identity` to optionally collect witness receipts via `ReceiptCollector` + `HttpWitnessClient`.

```bash
auths id rotate --alias mykey --witnesses https://w1.auths.dev,https://w2.auths.dev --threshold 1
```

**3.3 — `auths witness serve` CLI command**

Expose the existing `server.rs` via CLI:

```bash
auths witness serve --port 8080
# Starts the existing Axum server from auths-core/src/witness/server.rs
```

---

## Epic 4: Org-level verification

**Goal:** Answer: "Was this signed by a member of org X with capability Y?"

**What exists:** Full org CLI (init, attest, revoke, add-member, revoke-member, list-members). Roles (Admin, Member, Readonly) with default capabilities. Delegation chain tracking.

**What's missing:** No verification function that takes an attestation and checks org membership + capabilities. No `verify_org_authorization()`.

### Tasks

**4.1 — Org membership verification**

```rust
// crates/auths-verifier/src/org.rs

pub struct OrgVerificationReport {
    pub org_did: String,
    pub member_did: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub granted_by: String,
    pub attestation_valid: bool,
}

/// Check if an attestation was signed by a member of the given org
/// with the required capability.
pub fn verify_org_authorization(
    attestation: &Attestation,
    org_did: &str,
    required_capability: &Capability,
    org_attestations: &[Attestation], // loaded via AttestationSource
    org_identity_pk: &[u8],
) -> Result<OrgVerificationReport, AttestationError> {
    // 1. Find the member attestation linking signer → org
    // 2. Verify the member attestation signature against org root key
    // 3. Check capability is granted
    // 4. Check not revoked/expired
    // 5. Verify the original attestation signature
}
```

**4.2 — CLI integration**

```bash
auths verify --attestation release.json --org did:keri:EOrg789 --require-capability sign_release
# "Valid: signed by did:keri:EAlice123 (member of EOrg789, role: member, capability: sign_release)"
```

---

## Epic 5: Identity bundle import

**Goal:** Import an identity on a new device from an exported bundle.

**What exists:** `auths id export-bundle` creates a public-only `IdentityBundle` (identity DID, public key hex, attestation chain). The `IdentityBundle` struct is in `auths-verifier`.

**What's missing:** No encrypted private key export. No `auths id import` command. No way to use a bundle to bootstrap a new device.

### Tasks

**5.1 — Full bundle export with encrypted private key**

```rust
// Extend existing IdentityBundle in auths-verifier/src/lib.rs
// or create FullBundle in auths-id

pub struct FullIdentityBundle {
    pub identity_did: String,
    pub public_key_hex: String,
    pub attestation_chain: Vec<Attestation>,
    pub kel_events: Vec<serde_json::Value>,  // KEL for verification
    /// Encrypted with transfer passphrase via encrypt_keypair()
    pub encrypted_private_key: Option<Vec<u8>>,
    pub salt: Option<[u8; 32]>,
}
```

**5.2 — Import command**

```bash
# Export with private key for device transfer
auths id export-bundle --alias mykey --output transfer.json --include-private
# "Enter transfer passphrase: ****"

# Import on new device
auths id import --bundle transfer.json
# "Enter transfer passphrase: ****"
# "Identity imported: did:keri:EAbc123"
# "Key stored in macOS Keychain as 'imported-EAbc123'"
# "2 attestations imported"
```

---

## Epic 6: Challenge-response authentication

**Goal:** Use your Auths identity to authenticate to any service. "Sign in with your identity" without OAuth.

**What exists:** Nothing. No challenge/response protocol, no `auths auth` command.

**What already exists that this builds on:** `SecureSigner` for signing, `verify_with_keys()` for verification, `Capability::Authenticate` is a known capability, attestation chain verification works.

### Tasks

**6.1 — Protocol types**

```rust
// crates/auths-core/src/auth/challenge.rs

#[derive(Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: [u8; 32],
    pub service_did: String,
    pub scope: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub challenge_digest: Vec<u8>,
    pub identity_did: String,
    pub device_did: String,
    pub signature: Vec<u8>,
    pub device_attestation: Attestation,
}
```

**6.2 — Response creation**

```rust
impl AuthResponse {
    pub fn create(
        challenge: &AuthChallenge,
        signer: &dyn SecureSigner,
        provider: &dyn PassphraseProvider,
        device_attestation: &Attestation,
    ) -> Result<Self> {
        let digest = ring::digest::digest(&ring::digest::SHA256,
            &serde_json::to_vec(challenge)?);
        let signature = signer.sign(digest.as_ref(), provider)?;
        // ...
    }
}
```

**6.3 — Verification (embeddable in any server)**

```rust
// crates/auths-verifier/src/auth.rs

pub fn verify_auth_response(
    response: &AuthResponse,
    original_challenge: &AuthChallenge,
    issuer_pk: &[u8],
) -> Result<AuthenticatedIdentity, AttestationError> {
    // 1. Verify challenge wasn't tampered (recompute digest)
    // 2. Verify challenge hasn't expired
    // 3. Verify signature on digest
    // 4. Verify device attestation via verify_with_keys()
    // 5. Check Capability::Authenticate in attestation
}
```

**6.4 — CLI**

```bash
auths auth respond --challenge "eyJub25jZS..." --alias mykey
# Outputs signed AuthResponse JSON
```

---

## Epic 7: Cross-platform sync

**Goal:** Identity state syncs across devices without a central server.

**What exists:** Identity data stored in Git refs (`refs/keri/`, `refs/auths/`). KEL is append-only. Pairing links devices.

**What's missing:** No sync mechanism. Rotate a key on laptop, phone doesn't know. No `auths sync`, no fork detection.

### Tasks

**7.1 — Git-ref based sync**

```rust
// crates/auths-id/src/sync.rs

pub struct SyncConfig {
    pub remote: String,
    pub auto_push: bool,
    pub auto_pull: bool,
}

pub fn sync_identity(repo_path: &Path, config: &SyncConfig) -> Result<SyncReport> {
    // 1. git fetch origin refs/keri/* refs/auths/*
    // 2. Compare local vs remote for each prefix
    // 3. KEL is append-only: fast-forward if remote is ahead
    // 4. If diverged (different events at same sequence) → security alert
    // 5. Push local changes if auto_push
}
```

**7.2 — Fork detection**

A KEL fork (two different events at the same sequence number for the same prefix) is a security event — either a bug or a compromised device.

```rust
pub enum SyncResult {
    UpToDate,
    FastForward { new_events: usize },
    LocalAhead { events_to_push: usize },
    Fork { prefix: String, sequence: u64, local_said: String, remote_said: String },
}
```

**7.3 — CLI**

```bash
auths sync --remote git@github.com:user/auths-identity.git
# "Fetched 2 new KEL events for did:keri:EAbc123"
# "Pushed 1 local attestation"

auths sync
# "WARNING: KEL fork detected for did:keri:EAbc123 at sequence 5"
# "This may indicate a compromised device. Run 'auths audit' for details."
```

---

## Epic 8: KEL-aware verification

**Goal:** When verifying an attestation signed after a key rotation, resolve which key was active at signing time by walking the KEL.

**What exists:** `verify_at_time()` in `auths-verifier/src/verify.rs` checks attestation expiry at a given time. `validate_kel()` walks and validates a KEL chain. `KelContinuityChecker` verifies rotation continuity for trust resolution.

**What's missing:** No function that takes a KEL + attestation + signing time and resolves which key was active. Current `verify_at_time()` takes an explicit `issuer_pk_bytes` — it doesn't look up the key from the KEL.

### Tasks

**8.1 — Key-at-time resolution from KEL**

```rust
// crates/auths-verifier/src/kel_verify.rs

/// Given a KEL (sequence of events), determine which public key was active
/// at the given time. Returns the key from the most recent
/// inception/rotation before `at`.
pub fn resolve_key_at_time(
    kel_events: &[serde_json::Value],
    at: DateTime<Utc>,
) -> Result<Vec<u8>, AttestationError>;

/// Verify an attestation using the KEL to resolve the signing key.
/// This is the "verify after rotation" flow.
pub fn verify_with_kel(
    attestation: &Attestation,
    kel_events: &[serde_json::Value],
    signing_time: DateTime<Utc>,
) -> Result<(), AttestationError> {
    let key = resolve_key_at_time(kel_events, signing_time)?;
    verify_with_keys_at(attestation, &key, Some(signing_time))
}
```

**8.2 — CLI integration**

```bash
auths verify --attestation old-release.json --kel-from-repo
# Loads KEL from refs/keri/, resolves key active at signing time
# "Valid: signed by did:keri:EAbc123 at sequence 2 (key rotated to sequence 4)"
```

---

## Epic 9: `auths-sign` bug fixes

**Goal:** Make `auths-sign` work correctly as a git `gpg.ssh.program`.

**What exists:** `auths-sign` binary at `crates/auths-cli/src/bin/sign.rs` (594 lines). Handles `auths:<alias>` key format, delegates verification to `ssh-keygen`.

**What's broken:** Git passes `-Overify-time=<timestamp>` to `gpg.ssh.program` during verification. The `Args` struct has no `-O` option — clap rejects the flag before `run_verify()` can delegate to `ssh-keygen`.

### Tasks

**9.1 — Accept and forward `-O` flags**

```rust
// crates/auths-cli/src/bin/sign.rs

#[derive(Parser)]
struct Args {
    // ... existing fields ...

    /// Additional options passed by git (e.g., -Overify-time=...).
    /// Forwarded to ssh-keygen during verification.
    #[arg(short = 'O', action = ArgAction::Append)]
    options: Vec<String>,
}
```

Then in `run_verify()`, forward these to the `ssh-keygen` invocation.

**9.2 — Public key export for `allowed_signers`**

There's no easy way to get the auths signing public key for populating `.auths/allowed_signers`. Add:

```bash
auths key export --alias macbook --format ssh
# Outputs: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... auths:macbook
```

---

## Epic 10: SDK polish

**Goal:** `auths-core` and `auths-verifier` as documented, versioned libraries other developers can embed.

**What exists:** Mobile FFI via UniFFI (identity creation, signing, pairing). WASM verification. `auths-verifier` compiles to WASM and has C FFI. `auths-core` has `get_platform_keychain()`.

**What's missing:** No unified high-level API. Consumers need to understand the internal module structure. Mobile FFI has identity creation but not rotation or verification. WASM has verification but not identity creation.

### Tasks

**10.1 — High-level `auths-core` API**

```rust
// crates/auths-core/src/api.rs (clean public interface)

pub struct AuthsIdentity { /* ... */ }

impl AuthsIdentity {
    pub fn create(alias: &str, keychain: &dyn KeyStorage) -> Result<Self>;
    pub fn load(alias: &str, keychain: &dyn KeyStorage) -> Result<Self>;
    pub fn did(&self) -> &str;
    pub fn public_key(&self) -> &[u8];
    pub fn attest_device(&self, device_pk: &[u8], caps: &[Capability]) -> Result<Attestation>;
    pub fn rotate(&mut self, provider: &dyn PassphraseProvider) -> Result<()>;
    pub fn export_bundle(&self) -> Result<IdentityBundle>;
}
```

**10.2 — Extend mobile FFI**

Add to `auths-mobile-ffi`:
- `rotate_identity()` — expose key rotation to iOS/Android
- `verify_attestation()` — expose verification to mobile

**10.3 — Extend WASM**

Add to `auths-verifier/src/wasm.rs`:
- `createIdentity()` — WASM identity creation
- `verifyAuthResponse()` — verify challenge-response auth in browser

---

## Dependency graph

```
Epic 1  Recovery (creates recovery kit at init, recover command)
  │
  ├─► Epic 2  Cascading revocation (graph walk on revoke)
  │
  ├─► Epic 5  Bundle import (full device transfer)
  │
  └─► Epic 7  Cross-platform sync (git-ref based)

Epic 3  HTTP witness client (connects existing server to existing trait)

Epic 4  Org verification (verify membership + capability)

Epic 6  Challenge-response auth (new protocol)

Epic 8  KEL-aware verification (resolve key from KEL at signing time)

Epic 9  auths-sign bug fixes (accept -O flag, key export) ← do first, quick win

Epic 10 SDK polish (high-level API, extend mobile/WASM FFI)
```

Epic 9 is a quick win — fix the `-O` flag and add key export. Start there.

Epics 1, 3, 8 are the critical path for "one identity, many devices."

---

*Last updated: February 2026*
