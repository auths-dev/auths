# Auths Roadmap: The Authentication SDK

> **Mission:** Become the default identity primitive for decentralized software — the way `ring` is for crypto or `rustls` is for TLS.

---

## Strategic Framing

Auths sits at a unique intersection: KERI-inspired cryptographic identity, platform-native secure storage, and Git-native persistence. No other SDK offers all three. The path to becoming *the* authentication SDK requires ruthless focus on three things:

1. **Developer ergonomics** — If it's harder than `ssh-keygen`, you've already lost.
2. **Verification everywhere** — The verifier crate must run in every environment where trust decisions happen: browsers, edge functions, mobile apps, CI pipelines.
3. **Protocol gravity** — Integrations with Radicle, Nostr, and Git signing create network effects that no amount of marketing can replicate.

The roadmap is organized into six epics, each designed to be independently shippable while building toward the full vision.

---

## Epic 1: Harden the Core — "No More Seeds in the Wild"

**Priority:** P0 — Ship blocker. Nothing else matters if keys leak.

**Context:** Today, `Attestation::create` and `device link` accept raw seed bytes. The `SecureSigner` trait exists but isn't wired through the full stack. This epic eliminates every code path where private key material is passed as a function argument.

### 1.1 Wire `SecureSigner` Through `auths-id`

**What:** Replace all raw seed parameters in attestation creation and identity initialization with `SecureSigner` trait calls.

**Current problem:**
```rust
// auths-id/src/attestation/create.rs — signatures arrive as raw bytes
// auths-cli/src/commands/device.rs — seeds passed via CLI flags
```

**Target API:**
```rust
pub fn create_signed_attestation(
    rid: &str,
    identity_did: &str,
    device_did: &DeviceDID,
    device_public_key: &[u8],
    payload: Option<Value>,
    meta: &AttestationMetadata,
    signer: &dyn SecureSigner, // signs internally, never exposes key
    resolver: &dyn DidResolver,
) -> Result<Attestation, AttestationError>
```

**Tasks:**

- [ ] Add `sign_for_identity(&self, identity_did: &str, message: &[u8]) -> Result<Vec<u8>>` to `SecureSigner` trait — resolves alias from DID internally
- [ ] Refactor `create_signed_attestation` to accept `&dyn SecureSigner` instead of `identity_signature: &[u8]` + `device_signature: &[u8]`
- [ ] Refactor `create_signed_revocation` identically
- [ ] Update `handle_device` in `auths-cli` to construct `StorageSigner<MacOSKeychain>` and pass it through
- [ ] Remove `--identity-seed` and `--device-seed` flags from all CLI commands
- [ ] Add deprecation warnings to any remaining seed-accepting functions (one release cycle before removal)

### 1.2 `PassphraseProvider` Implementations

**What:** The trait exists. Ship real implementations beyond the CLI.

**Tasks:**

- [ ] `CliPassphraseProvider` — already exists, harden with `rpassword` for no-echo input
- [ ] `CallbackPassphraseProvider` — accepts `Box<dyn Fn(&str) -> Result<String>>` for GUI/FFI integration
- [ ] `BiometricPassphraseProvider` — iOS/macOS stub that calls into LAContext (Touch ID / Face ID) via FFI, returns a keychain-unlocked token rather than a literal passphrase
- [ ] `CachedPassphraseProvider` — wraps another provider, caches passphrase in `Zeroizing<String>` for a configurable TTL (for agent session lifetime)

### 1.3 Secure Key Lifecycle in Storage

**What:** `rotate_key` in `api/runtime.rs` rotates the local keychain entry but doesn't touch the Git identity. This is a landmine. Fix the abstraction.

**Tasks:**

- [ ] Introduce `KeyRotationEvent` struct — wraps old public key, new public key, timestamp, rotation signature
- [ ] Add `append_rotation_event` to `GitIdentityStorage` — writes to `refs/keri/kel` as a new commit
- [ ] Modify `rotate_key` to return `KeyRotationEvent` instead of `()`, forcing callers to persist the event
- [ ] Add `auths id rotate` CLI command that calls `rotate_key` + `append_rotation_event` atomically
- [ ] Add integration test: rotate key → verify old attestations still validate → verify new attestations use new key

### 1.4 Zeroize Audit

**What:** Grep the codebase for every `Vec<u8>` that ever holds private key material. Ensure it's `Zeroizing<Vec<u8>>`.

**Tasks:**

- [ ] Audit `AgentCore.keys` — already `Zeroizing`, confirm no `.clone()` leaks into non-zeroizing containers
- [ ] Audit `decrypt_keypair` return path — should return `Zeroizing<Vec<u8>>`, not `Vec<u8>`
- [ ] Audit `encrypt_keypair` input path — should accept `&[u8]` (borrowed), never own the plaintext
- [ ] Add `#[cfg(test)]` assertion that `Zeroizing` drop is called (use a wrapper with drop counter)
- [ ] Document the zeroize policy in `SECURITY.md`

---

## Epic 2: Verification Everywhere — "Trust at the Edge"

**Priority:** P0 — This is the adoption flywheel. If verification is easy, people will use Auths to *sign* things.

**Context:** `auths-verifier` already compiles to WASM and has C FFI. But the API surface is narrow (single attestation verification only) and missing critical use cases.

### 2.1 Verifier API Expansion

**What:** The verifier should handle every trust question a consumer might ask.

**Tasks:**

- [ ] `verify_chain(attestations: &[Attestation], root_pk: &[u8]) -> Result<VerificationReport>` — verifies a chain of attestations from root identity to leaf device, returns structured report with per-link status
- [ ] `verify_at_time(att: &Attestation, issuer_pk: &[u8], at: DateTime<Utc>) -> Result<()>` — point-in-time verification (for auditing historical attestations)
- [ ] `is_device_authorized(identity_did: &str, device_did: &DeviceDID, attestations: &[Attestation]) -> bool` — high-level convenience function
- [ ] `VerificationReport` struct — machine-readable result with `status: VerificationStatus`, `chain_depth: usize`, `warnings: Vec<String>`

```rust
pub struct VerificationReport {
    pub status: VerificationStatus,
    pub chain: Vec<ChainLink>,
    pub warnings: Vec<String>,
}

pub enum VerificationStatus {
    Valid,
    Expired { at: DateTime<Utc> },
    Revoked { at: Option<DateTime<Utc>> },
    InvalidSignature { step: usize },
    BrokenChain { missing_link: String },
}
```

### 2.2 Language Bindings

**What:** Ship verification to every platform where trust decisions happen.

**Tasks:**

- [ ] **TypeScript/npm:** Publish `@auths/verifier` — wraps WASM build with typed TS bindings, `verifyAttestation(json: string, issuerPkHex: string): VerificationResult`
- [ ] **Swift Package:** `AuthsVerifier` via UniFFI — expose `verifyAttestationJson` and `VerificationReport` as Swift structs
- [ ] **Kotlin/Android:** `auths-verifier-android` via UniFFI — same surface as Swift
- [ ] **Python:** `auths-verifier` on PyPI via `pyo3` — for CI/CD pipelines and scripts
- [ ] **Go:** CGo wrapper around the C FFI — for server-side verification in Go services

```typescript
// @auths/verifier (TypeScript)
import { verifyAttestation } from '@auths/verifier';

const result = verifyAttestation(attestationJson, issuerPublicKeyHex);
if (!result.valid) {
  console.error(`Verification failed: ${result.error}`);
}
```

### 2.3 Verification in CI/CD

**What:** A GitHub Action and generic CLI tool for verifying signatures in pipelines.

**Tasks:**

- [ ] `auths verify` CLI command — accepts attestation JSON + issuer PK, returns exit code 0/1
- [ ] `auths verify-commit` — verifies a Git commit signature against the Auths identity in the repo
- [ ] GitHub Action: `auths/verify-action` — runs `auths verify-commit` on PRs, posts status check
- [ ] Document: "Replacing GPG commit signing with Auths"

---

## Epic 3: Git Integration — "Sign Everything"

**Priority:** P1 — This is the first real adoption vector. Every developer uses Git.

### 3.1 `auths-sign` Binary

**What:** A standalone binary that implements the Git SSH signing protocol, so `git commit -S` uses Auths keys.

**Tasks:**

- [ ] Implement `auths-sign` binary — reads signing request from stdin, signs with agent, writes signature to stdout (SSH signing protocol)
- [ ] Implement `auths-verify` binary — reads signature + data, verifies against Auths identity in repo
- [ ] Ship as installable via `cargo install auths-cli` (include both binaries in the workspace)

```bash
# User setup (one-time)
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:my-key-alias"
git config --global commit.gpgSign true
```

### 3.2 Allowed Signers Integration

**What:** Git's `ssh.allowedSignersFile` maps email addresses to public keys. Auths should auto-generate this from attestations.

**Tasks:**

- [ ] `auths git allowed-signers` — scans the identity repo, emits an `allowed_signers` file mapping issuer email (from payload) to device public keys
- [ ] `auths git install-hooks` — installs a `post-merge` hook that regenerates `allowed_signers` when identity refs change
- [ ] Document the full Git signing + verification workflow end-to-end

### 3.3 Configurable Storage Layout Presets

**What:** `StorageLayoutConfig` exists but is under-documented and has no presets. Ship presets for known ecosystems.

**Tasks:**

- [ ] `StorageLayoutConfig::default()` — `refs/auths/*` (current)
- [ ] `StorageLayoutConfig::radicle()` — `refs/rad/keys/*`
- [ ] `StorageLayoutConfig::gitoxide()` — TBD based on gitoxide conventions
- [ ] `auths init --preset radicle` CLI flag
- [ ] Integration test per preset: init identity → link device → verify attestation

---

## Epic 4: Platform Backends — "Keys Stay in Hardware"

**Priority:** P1 — Cross-platform is table stakes for an SDK.

### 4.1 Linux Secret Service / GNOME Keyring

**What:** Linux has no single keychain. Target the freedesktop.org Secret Service API (works with GNOME Keyring, KWallet, KeePassXC).

**Tasks:**

- [ ] Implement `LinuxSecretServiceStorage` — uses `dbus` crate to talk to `org.freedesktop.secrets`
- [ ] Implement `KeyStorage` trait for it — `store_key`, `load_key`, `delete_key`, `list_keys`, `get_identity_for_alias`
- [ ] Fallback: `EncryptedFileStorage` for headless Linux (encrypted JSON file at `~/.auths/keys.enc`)
- [ ] Feature flag: `keychain-linux-secretservice` (default on `target_os = "linux"`)

### 4.2 Android Keystore

**What:** `platform/android.rs` exists but is empty. Implement via JNI or UniFFI callback.

**Tasks:**

- [ ] Define `AndroidKeystoreStorage` struct
- [ ] Implement using `android_hardware_keystore` crate or JNI FFI to `java.security.KeyStore`
- [ ] Key generation should use `PURPOSE_SIGN` with `ALGORITHM_EC` (Ed25519 where available, P-256 fallback with conversion layer)
- [ ] Biometric binding: `setUserAuthenticationRequired(true)` on key generation
- [ ] Integration test via Android emulator in CI

### 4.3 Windows Credential Manager

**What:** Windows Credential Manager via `windows-credentials` crate.

**Tasks:**

- [ ] Implement `WindowsCredentialStorage` using `windows::Security::Credentials`
- [ ] Implement `KeyStorage` trait
- [ ] Feature flag: `keychain-windows` (default on `target_os = "windows"`)
- [ ] CI: Add Windows runner to test matrix

### 4.4 `get_platform_keychain()` Auto-Detection

**What:** The function exists but needs to be the canonical entry point that Just Works™.

**Tasks:**

- [ ] Compile-time dispatch: `#[cfg(target_os)]` selects the right backend
- [ ] Runtime override: `AUTHS_KEYCHAIN_BACKEND=file` environment variable for testing/CI
- [ ] `auths doctor` command — probes the detected backend, reports status, suggests fixes

```rust
pub fn get_platform_keychain() -> Result<Box<dyn KeyStorage + Send + Sync>, AgentError> {
    #[cfg(target_os = "macos")]
    { Ok(Box::new(MacOSKeychain::new()?)) }
    #[cfg(target_os = "ios")]
    { Ok(Box::new(IOSKeychain::new()?)) }
    #[cfg(target_os = "linux")]
    { Ok(Box::new(LinuxSecretServiceStorage::new().unwrap_or_else(|_| EncryptedFileStorage::new()))) }
    #[cfg(target_os = "android")]
    { Ok(Box::new(AndroidKeystoreStorage::new()?)) }
    #[cfg(target_os = "windows")]
    { Ok(Box::new(WindowsCredentialStorage::new()?)) }
}
```

---

## Epic 5: Protocol Integrations — "Be Where Developers Are"

**Priority:** P1 — Network effects drive adoption.

### 5.1 Radicle Integration

**What:** Radicle is the most natural fit — both are Git-native, both are decentralized. Auths should be a first-class Radicle identity provider.

**Tasks:**

- [ ] Implement `DidRadResolver` — resolves `did:rad:<peer_id>` by looking up the peer's identity document in the Radicle network
- [ ] Publish `StorageLayoutConfig::radicle()` preset mapping Auths refs to Radicle's `refs/rad/` namespace
- [ ] Create `auths-radicle` feature flag on `auths-id` — optional dependency, zero cost when disabled
- [ ] End-to-end test: `auths id init` → `rad auth --provider auths` → push signed patches → verify
- [ ] Submit PR to Radicle for optional Auths provider support (or publish as a Radicle extension)

### 5.2 Nostr Integration

**What:** Nostr uses secp256k1 (not Ed25519), so this requires a signing adapter, not just plumbing.

**Tasks:**

- [ ] Add `Secp256k1KeyPair` support to `auths-core` crypto module (feature-gated: `crypto-secp256k1`)
- [ ] Implement NIP-07 compatible event signing: `auths nostr sign-event --event-json '{...}'`
- [ ] Implement NIP-46 (Nostr Connect) remote signer — Auths agent acts as the signer backend
- [ ] `auths-nostr` crate with `NostrSigner` struct wrapping `SecureSigner`
- [ ] Test with a real Nostr client (e.g., Damus, Amethyst)

### 5.3 SSH Agent Protocol

**What:** `AgentCore` and `AgentSession` exist. Polish them into a production-grade agent.

**Tasks:**

- [ ] `auths agent start` — daemonizes, writes `SSH_AUTH_SOCK` to `~/.auths/agent.env`
- [ ] `auths agent stop` — kills the daemon, cleans up socket
- [ ] `auths agent status` — reports loaded keys, socket path, PID
- [ ] Auto-lock after configurable idle timeout (default 30 minutes) — drop `Zeroizing` keys from `AgentCore`
- [ ] `eval $(auths agent env)` — shell integration for setting `SSH_AUTH_SOCK`
- [ ] launchd plist / systemd unit file generation: `auths agent install-service`

---

## Epic 6: Organizations & Delegation — "Teams Ship Software"

**Priority:** P2 — Builds on top of everything above. This is what turns Auths from a developer tool into an enterprise platform.

### 6.1 Organizational Identity

**What:** `auths-cli/src/commands/org.rs` exists with basic scaffolding. Build the full model.

**Tasks:**

- [ ] `OrgAttestation` struct — extends `Attestation` with `role: String`, `permissions: Vec<Permission>`, `delegated_by: Option<String>`
- [ ] `auths org init --name "Acme Corp"` — creates an org identity (DID) with the creator as root admin
- [ ] `auths org add-member --org <org-did> --member <member-did> --role admin|member|readonly`
- [ ] `auths org revoke-member --org <org-did> --member <member-did>`
- [ ] `auths org list-members --org <org-did>` — shows membership tree with roles
- [ ] Org attestations stored under `refs/auths/org/<org-did-sanitized>/members/<member-did-sanitized>`

### 6.2 Capability Delegation

**What:** Not all keys should sign everything. Introduce scoped capabilities.

**Tasks:**

- [ ] Define `Capability` enum: `SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys`, `Custom(String)`
- [ ] Add `capabilities: Vec<Capability>` field to `Attestation` (backward-compatible via `#[serde(default)]`)
- [ ] `auths device link --capabilities sign-commit,sign-release` — scope what a device key can do
- [ ] Verification checks capabilities: `verify_with_capability(att, required: &Capability) -> Result<()>`
- [ ] CLI: `auths verify --require-capability sign-release`

### 6.3 Threshold Signatures (Future)

**What:** High-value operations require M-of-N approval. This is Phase 5+ material but define the interface now.

**Tasks:**

- [ ] Research: Evaluate FROST (Flexible Round-Optimized Schnorr Threshold) for Ed25519 threshold signing
- [ ] Define `ThresholdPolicy` struct: `{ threshold: u8, signers: Vec<String>, ceremony_id: String }`
- [ ] Sketch `auths org set-threshold --m 2 --n 3 --scope sign-release` interface
- [ ] Write ADR (Architecture Decision Record) for threshold signing approach

---

## Epic 7: Developer Experience — "The SDK That Sells Itself"

**Priority:** Runs parallel to everything above. This is not optional.

### 7.1 Documentation

**Tasks:**

- [ ] `docs/quickstart.md` — Identity in 5 minutes: init → link device → sign → verify
- [ ] `docs/threat-model.md` — What Auths protects against, what it doesn't, trust boundaries
- [ ] `docs/integration-guide.md` — How to use `auths-core` and `auths-verifier` as libraries
- [ ] API docs on docs.rs — ensure every public type has a doc comment with examples
- [ ] `docs/faq.md` — Why not GPG? Why not blockchain? Why Git?

### 7.2 CLI Polish

**Tasks:**

- [ ] `auths doctor` — comprehensive health check (keychain access, Git repo state, agent status, binary versions)
- [ ] Shell completions: `auths completions bash|zsh|fish` via clap's built-in generator
- [ ] Colored output with `console` or `dialoguer` crate — key status, verification results, error messages
- [ ] `auths init` one-command setup — creates repo, generates key, stores in keychain, initializes identity (guided interactive flow)
- [ ] JSON output mode: `auths --output json id show` for scripting

### 7.3 Testing Infrastructure

**Tasks:**

- [ ] `InMemoryKeyStorage` — already partially exists as `memory.rs`, promote to first-class test utility, re-export from `auths-core::testing`
- [ ] `TestIdentityBuilder` — fluent API for creating test identities with linked devices in a temp Git repo
- [ ] CI matrix: macOS (arm64 + x86_64), Linux (Ubuntu), Windows, WASM (wasm-pack test)
- [ ] Property-based tests for attestation serialization roundtrip (use `proptest`)
- [ ] Benchmark suite: attestation creation, verification, Git storage read/write (use `criterion`)

```rust
// auths-core/src/testing.rs (re-exported for downstream crates)
pub struct TestIdentityBuilder { /* ... */ }

impl TestIdentityBuilder {
    pub fn new() -> Self { /* ... */ }
    pub fn with_device(mut self, alias: &str) -> Self { /* ... */ }
    pub fn build(self) -> (TempRepo, Identity, Vec<Attestation>) { /* ... */ }
}
```

### 7.4 Error Messages

**What:** Current errors are developer-facing (`AgentError::CryptoError(String)`). SDK consumers need actionable errors.

**Tasks:**

- [ ] Add `error_code: &'static str` to every error variant (e.g., `"AUTHS_KEY_NOT_FOUND"`, `"AUTHS_SIG_INVALID"`)
- [ ] Add `suggestion: Option<&'static str>` — human-readable fix suggestion (e.g., "Run `auths agent start` to load keys")
- [ ] `Display` impl should show the suggestion when present
- [ ] Document error codes in `docs/errors.md`

---

## Release Milestones

| Milestone | Target | Key Deliverables |
|-----------|--------|-----------------|
| **v0.3 — Hardened Core** | Q2 2025 | Epic 1 complete. No seeds in API. Zeroize audit done. |
| **v0.4 — Verify Everywhere** | Q3 2025 | Epic 2 complete. npm + PyPI packages. GitHub Action. |
| **v0.5 — Git Native** | Q3 2025 | Epic 3 complete. `git commit -S` works with Auths. |
| **v0.6 — Cross Platform** | Q4 2025 | Epic 4 complete. Linux + Android + Windows backends. |
| **v0.7 — Protocol Gravity** | Q1 2026 | Epic 5 (Radicle + SSH agen b bt). First external integration. |
| **v1.0 — The SDK** | Q2 2026 | Epic 7 polished. Stable API. Security audit complete. |
| **v1.x — Organizations** | H2 2026 | Epic 6. Org identity + capabilities. |

---

## Non-Goals (For Now)

These are explicitly out of scope to maintain focus:

- **Full KERI compliance** — We use KERI-inspired principles. Full spec compliance (KEL witnesses, delegated identifiers, multi-sig inception) is a 2027+ concern.
- **Blockchain anything** — No tokens, no gas, no consensus mechanisms. Git is the ledger.
- **GUI desktop app** — The CLI is the interface. Mobile apps (iOS/Android) serve the cross-device signing use case, not general identity management.
- **Identity federation** — Auths is not an IdP (Identity Provider) in the SAML/OIDC sense. It's a cryptographic primitive. Federation protocols can be built on top by consumers.

---

## How to Read This Roadmap
≥
**If you're an engineer:** Each task is scoped to ~1-3 days of work. The code snippets show the target API surface — the implementation details are yours to own. Start with the crate boundary (which trait, which struct) and work inward.

**If you're a PM:** The epics are ordered by dependency and impact. Epics 1-2 are non-negotiable foundations. Epics 3-5 are adoption vectors — pick the one where you have the strongest design partner. Epic 6 is the enterprise play. Epic 7 is continuous.

**If you're evaluating Auths:** Start with Epic 2 (verifier). If you can verify Auths attestations in your environment, you'll naturally want to create them — and that's when Epics 1, 3, and 5 become relevant to you.

---

*Last updated: February 2025*
*Maintainer: Auths Core Team*
