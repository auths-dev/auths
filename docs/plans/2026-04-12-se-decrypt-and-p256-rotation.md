# SE-Safe `decrypt_keypair` Callsites + P-256 Rotation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the two P0 ship-blockers from `ecosystem.md`:
1. All `decrypt_keypair` callsites either route through a hardware-safe helper or fail loudly with a clear SE diagnostic before decrypting an opaque SE handle as if it were PKCS8 ciphertext.
2. `auths id rotate` works for P-256 identities by refactoring the rotation workflow to dispatch through `TypedSeed` / curve-agnostic `auths_crypto::sign` and the curve-aware `generate_keypair_for_init(curve)`.

**Architecture:**
- `auths-core::storage::keychain` already exposes two SE-aware helpers (`sign_with_key` and `extract_public_key_bytes`) that branch on `is_hardware_backend()`. Every callsite whose *real* need is "sign" or "get pubkey" should call those helpers instead of hand-rolling `load_key → decrypt_keypair → parse → sign`. Callsites that genuinely need raw PKCS8 (pairing export, bundle export, legacy rotation) must guard with `is_hardware_backend()` and return a typed error — SE keys cannot leave the enclave.
- Rotation currently hard-codes `Ed25519KeyPair` through `ring` APIs (key generation, signing the rotation event, CESR encoding). The fix re-uses `auths_id::keri::inception::generate_keypair_for_init(curve)` (already curve-aware) to produce the new pre-committed key, signs the rotation event via `auths_crypto::sign(&TypedSeed, bytes)`, and encodes CESR using the same derivation-code logic inception uses (`D` for Ed25519, `1AAJ` for P-256). Curve propagates from `ManagedIdentity` → rotation functions → storage, never re-guessed.

**Tech Stack:** Rust (workspace), `cargo nextest`, `ring`, `p256`, `auths-crypto::TypedSeed`, `auths-keri::KeriPublicKey`, `auths-core::storage::keychain` (SE-aware helpers), Swift SE bridge (indirectly via `sign_with_handle` / `public_key_from_handle`).

**Out of scope (do NOT touch in this plan):**
- Mobile/Python/Node binding redesign beyond adding the SE guard. (The `packages/auths-python/src/pairing.rs` and `packages/auths-node/src/pairing.rs` paths need the guard but not a full rewrite.)
- Benchmarks (`crates/auths-core/benches/crypto.rs`) — they intentionally drive the primitive directly.
- `auths-core/src/storage/keychain.rs` lines 287/333 — those are *inside* helper functions that already branch on `is_hardware_backend()` earlier; they're unreachable for SE.
- Removing the `workflows/rotation.rs` vs `domains/identity/rotation.rs` duplication — that is a pre-existing technical debt tracked elsewhere. This plan keeps them in lock-step.

**Assumed pre-existing behavior (verify before editing):**
- `auths_core::storage::keychain::sign_with_key` and `extract_public_key_bytes` are already SE-safe (they short-circuit on `is_hardware_backend()` before calling `decrypt_keypair`). Confirmed at `crates/auths-core/src/storage/keychain.rs:259-345`.
- `auths_id::keri::inception::generate_keypair_for_init(curve)` returns a curve-tagged `GeneratedKeypair { pkcs8, public_key, cesr_encoded }`. Confirmed at `crates/auths-id/src/keri/inception.rs:63`.
- `auths_crypto::parse_key_material(bytes)` returns `ParsedKey { seed: TypedSeed, public_key }` with the curve baked in. Confirmed at `crates/auths-crypto/src/key_ops.rs:73`.

---

## Epic A — SE-Safe `decrypt_keypair` Callsites

**Classification of the 15 breaking callsites** (use this as the routing table — each task below references a row by number):

| # | File | Line | Real intent | Fix strategy |
|---|------|------|-------------|--------------|
| A1 | `crates/auths-cli/src/commands/auth.rs` | 86 | Sign auth challenge | Call `sign_with_key` |
| A2 | `crates/auths-cli/src/commands/id/identity.rs` | 605 | Derive pubkey for bundle export | Call `extract_public_key_bytes` |
| A3 | `crates/auths-cli/src/commands/org.rs` | 459 | Sign org attestation (delegates to `StorageSigner`) | Drop the dead pre-decrypt; `StorageSigner` already dispatches |
| A4 | `crates/auths-cli/src/commands/org.rs` | 550 | Validate passphrase before revoke-sign | Drop the dead pre-decrypt; let the downstream sign fail |
| A5 | `crates/auths-cli/src/commands/org.rs` | 1033 | Sign invite bearer token | Call `sign_with_key` |
| A6 | `crates/auths-cli/src/commands/agent/mod.rs` | 551 | Load agent key material | Guard with `is_hardware_backend()` → return `AgentKeyMustBeSoftware` error |
| A7 | `crates/auths-id/src/agent_identity.rs` | 343 | Get pubkey for agent provisioning | Replace with `extract_public_key_bytes` |
| A8 | `crates/auths-id/src/identity/rotate.rs` | 104 | Legacy GitKel rotation decrypts pre-committed key | Guard with `is_hardware_backend()` → `RotationRequiresSoftwareKey` error (legacy path; rotation lands in Epic B for the live path) |
| A9 | `crates/auths-id/src/identity/rotate.rs` | 211 | Legacy registry rotation decrypts pre-committed key | Same guard as A8 |
| A10 | `crates/auths-sdk/src/workflows/rotation.rs` | 354 | Live rotation decrypts pre-committed key | Handled in Epic B (add hardware guard + curve dispatch together) |
| A11 | `crates/auths-sdk/src/domains/identity/rotation.rs` | 354 | Mirror of A10 | Handled in Epic B |
| A12 | `crates/auths-sdk/src/domains/signing/service.rs` | 391 | Sign commit | Call `sign_with_key` (mirror of `workflows/signing.rs` which is already correct) |
| A13 | `crates/auths-sdk/src/pairing/mod.rs` | 582 | Extract device signing material (seed + pubkey) for pairing | Guard: pairing export requires a software key. Return `PairingError::HardwareKeyNotExportable` |
| A14 | `crates/auths-core/src/signing.rs` | 297 | Internal `StorageSigner::sign_with_alias` — already has SE branch at L265, the `decrypt_keypair` call is only reached in the software path | **No-op**, confirm by reading the function top-to-bottom |
| A15 | `crates/auths-core/src/api/runtime.rs` | 198, 396, 460 | Three FFI runtime entry points that decrypt to sign | Route each through `sign_with_key` / `extract_public_key_bytes` as appropriate |
| A16 | `crates/auths-core/src/api/ffi.rs` | 587 | FFI probe that decrypts to validate passphrase | Guard with `is_hardware_backend()` → return `AgentError::BackendUnavailable` with actionable reason |
| A17 | `packages/auths-python/src/pairing.rs` | 250 | Pairing export from Python binding | Same guard as A13 |
| A18 | `packages/auths-node/src/pairing.rs` | 333 | Pairing export from Node binding | Same guard as A13 |

> The ecosystem says "15 paths". The table has 18 rows; A14 is a no-op after verification, and A10/A11 roll into Epic B. Net behavioral fixes: **15**. Keep that invariant during review.

**Error-type prerequisite (Task A0):** We need a shared, typed error for "this operation requires a software-backed key." Add it once in `auths-core`; domain layers (`SDK`, `auths-id`, `CLI`) will map it.

---

### Task A0: Add `AgentError::HardwareKeyNotExportable` variant

**Files:**
- Modify: `crates/auths-core/src/error.rs` (add variant + error code)
- Modify: Any `match AgentError` arm that needs to be exhaustive (compiler will enumerate these)

**Step 1: Write the failing test**

Add to `crates/auths-core/src/error.rs` (under `#[cfg(test)] mod tests`):

```rust
#[test]
fn hardware_key_not_exportable_has_actionable_display() {
    let err = AgentError::HardwareKeyNotExportable {
        operation: "pairing".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("hardware"), "msg={msg}");
    assert!(msg.contains("pairing"), "msg={msg}");
}
```

**Step 2: Run test to verify it fails**

```
cargo nextest run -p auths-core -E 'test(hardware_key_not_exportable_has_actionable_display)'
```
Expected: FAIL (variant does not exist).

**Step 3: Add the variant**

In `crates/auths-core/src/error.rs`, inside `pub enum AgentError`:

```rust
/// Operation cannot be completed because the key is hardware-backed (SE/HSM)
/// and the operation requires raw key material.
#[error("Operation '{operation}' requires a software-backed key; hardware-backed keys (e.g. Secure Enclave) cannot export raw material")]
HardwareKeyNotExportable { operation: String },
```

Add the error code in the same file's `error_code()` match: `Self::HardwareKeyNotExportable { .. } => "AUTHS-E1050"` (pick the next free code in the file — verify by reading the existing match arms first).

**Step 4: Run tests to verify**

```
cargo nextest run -p auths-core
```
Expected: PASS. Fix any `match AgentError` sites the compiler flags as non-exhaustive (`#[non_exhaustive]` may already suppress this — check the enum attribute; if not, add wildcard arms or new arms as needed).

**Step 5: Do NOT commit yet.** The user commits at end; keep stacked per user policy.

---

### Task A1: `auth.rs` challenge signing

**Files:**
- Modify: `crates/auths-cli/src/commands/auth.rs` (replace lines ~79-105)
- Test: `crates/auths-cli/tests/` — add a case if not present (use an SE fake + a software fake to assert both paths)

**Step 1: Write the failing test (behavioral)**

Add a test in `crates/auths-cli/tests/cases/auth.rs` (create file & wire it into `tests/cases/mod.rs` if it does not exist):

```rust
#[test]
fn sign_auth_challenge_routes_through_sign_with_key() {
    // Use MemoryKeychainHandle to simulate software-backed key
    // Assert that handle_auth_challenge succeeds with a software key
    // (No direct SE fake in CLI tests yet — Epic-A0 adds the contract via AgentError)
    // ...
}
```
(If this test infrastructure doesn't exist yet, add a minimal unit test at `mod.rs` scope in the SDK's `auth` workflow instead — see `crates/auths-sdk/src/workflows/auth.rs`.)

**Step 2: Confirm it fails**

```
cargo nextest run -p auths-cli -E 'test(sign_auth_challenge_routes_through_sign_with_key)'
```

**Step 3: Replace the manual decrypt-and-sign block**

Change the body of `handle_auth_challenge` after `let key_alias_str = ...` so that the `load_key` + `decrypt_keypair` + `extract_seed_from_pkcs8` + `ed25519_public_key_from_seed_sync` + `sign_auth_challenge` block becomes:

```rust
let sshsig_msg = build_auth_challenge_message(nonce, domain);
let (signature_bytes, public_key_bytes, curve) =
    auths_core::storage::keychain::sign_with_key(
        auths_ctx.key_storage.as_ref(),
        &key_alias,
        passphrase_provider.as_ref(),
        &sshsig_msg,
    )
    .context("Failed to sign auth challenge")?;

let result = AuthChallengeResult {
    signature_hex: hex::encode(&signature_bytes),
    public_key_hex: hex::encode(&public_key_bytes),
    curve,
    did: controller_did.to_string(),
};
```

Move `build_auth_challenge_message` into `auths_sdk::workflows::auth` (it already lives there as part of `sign_auth_challenge` — extract the *message construction* half and leave only that in the SDK; the signing half moves to the keychain helper). Export `AuthChallengeResult`.

**Step 4: Run tests**

```
cargo nextest run -p auths-cli
cargo nextest run -p auths-sdk -E 'test(auth)'
```

**Step 5: No commit; continue.**

---

### Task A2: `id/identity.rs` bundle-export pubkey derivation

**Files:**
- Modify: `crates/auths-cli/src/commands/id/identity.rs:596-613` (the `ExportBundle` arm)

**Step 1: Write the failing test**

Add `tests/cases/bundle_export.rs` to `auths-cli` that asserts bundle export *does not require a passphrase when the key is hardware-backed* (because `extract_public_key_bytes` reads from the SE handle directly). Use a fake keychain with `is_hardware_backend() == true`. If no such fake exists in `auths-cli` tests yet, create a minimal one in a `tests/common/se_fake.rs` module.

**Step 2: Confirm it fails**

```
cargo nextest run -p auths-cli -E 'test(export_bundle)'
```

**Step 3: Replace the decrypt block**

In `identity.rs` `ExportBundle` arm, replace:
```rust
let pass = passphrase_provider.get_passphrase(...)?;
let pkcs8_bytes = auths_sdk::crypto::decrypt_keypair(&encrypted_key, &pass)?;
let keypair = auths_sdk::identity::load_keypair_from_der_or_seed(&pkcs8_bytes)?;
let public_key_hex = ... keypair.public_key() ...;
```
with:
```rust
let (public_key_bytes, _curve) =
    auths_core::storage::keychain::extract_public_key_bytes(
        keychain.as_ref(),
        &KeyAlias::new_unchecked(&alias),
        passphrase_provider.as_ref(),
    )
    .context("Failed to extract public key for bundle")?;
let public_key_hex =
    auths_verifier::PublicKeyHex::new_unchecked(hex::encode(&public_key_bytes));
```

Drop the unused import `auths_sdk::identity::load_keypair_from_der_or_seed` (compiler will flag).

**Step 4: Run tests**
```
cargo nextest run -p auths-cli -E 'test(export_bundle)'
```

**Step 5: No commit.**

---

### Task A3 & A4: `org.rs` attest + revoke (drop dead pre-decrypt)

**Files:**
- Modify: `crates/auths-cli/src/commands/org.rs:441-460` (Attest)
- Modify: `crates/auths-cli/src/commands/org.rs:541-550` (Revoke)

**Step 1: Write the failing test**

Add `crates/auths-cli/tests/cases/org_attest_with_se_key.rs` — asserts `org attest create` succeeds with a hardware-backed keychain fake (it currently explodes in `decrypt_keypair`).

**Step 2: Confirm failure**
```
cargo nextest run -p auths-cli -E 'test(org_attest_with_se_key)'
```

**Step 3: Remove the dead pre-decrypt**

In both arms, the `let _pkcs8_bytes = decrypt_keypair(...)` line exists only to validate the passphrase before the actual signing work that happens inside `create_signed_attestation` / subsequent sign call. Delete the `passphrase_provider.get_passphrase(...)` + `decrypt_keypair(...)` block entirely — the downstream `StorageSigner::sign_with_alias` already prompts and dispatches hardware-vs-software correctly. Delete the `_pkcs8_bytes` shadow. Keep the `stored_did == controller_did` DID-check (that one still matters).

**Step 4: Run tests**
```
cargo nextest run -p auths-cli -E 'test(org)'
```
Expected: PASS for both `org_attest_with_se_key` and existing passphrase-based tests.

**Step 5: No commit.**

---

### Task A5: `org.rs` invite-accept bearer signing

**Files:**
- Modify: `crates/auths-cli/src/commands/org.rs:1025-1057`

**Step 1: Write the failing test**

Add `tests/cases/invite_accept_with_se_key.rs` — asserts `invite accept` produces a valid bearer token signed by the hardware-backed key.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-cli -E 'test(invite_accept_with_se_key)'
```

**Step 3: Replace the rpassword + decrypt + ring::Ed25519KeyPair block**

```rust
let message = format!("{}\n{}", did, timestamp);
let (sig_bytes, pubkey, _curve) =
    auths_core::storage::keychain::sign_with_key(
        key_storage.as_ref(),
        &primary_alias,
        passphrase_provider.as_ref(),
        message.as_bytes(),
    )
    .context("failed to sign invite bearer token")?;
let signature = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
```

Note: this replaces the hard-coded `rpassword::prompt_password` with the CLI's injected `passphrase_provider`. If there is no `passphrase_provider` in scope here, thread it in from the parent — do not keep the dual-prompt path.

**Step 4: Run tests**
```
cargo nextest run -p auths-cli -E 'test(invite)'
```

**Step 5: No commit.**

---

### Task A6: `agent/mod.rs` refuse hardware keys

**Files:**
- Modify: `crates/auths-cli/src/commands/agent/mod.rs:543-555`

**Step 1: Write the failing test**

Add `tests/cases/agent_register_with_se_key_fails.rs` — asserts `agent register` returns a clear `HardwareKeyNotExportable` error when asked to load an SE-backed key into the SSH agent (agents require raw seed).

**Step 2: Confirm failure**
```
cargo nextest run -p auths-cli -E 'test(agent_register_with_se_key_fails)'
```

**Step 3: Add the guard**

Before the `passphrase_provider.get_passphrase(...)` + `decrypt_keypair` block, add:

```rust
if key_storage.is_hardware_backend() {
    return Err(anyhow!(
        "Agent-mode signing requires a software-backed key. The selected alias '{}' is \
         hardware-backed (Secure Enclave). Run agent against a software key, or use \
         direct signing (which dispatches through the SE).",
        key_alias
    ));
}
```

**Step 4: Run tests**
```
cargo nextest run -p auths-cli -E 'test(agent)'
```

**Step 5: No commit.**

---

### Task A7: `auths-id::agent_identity::extract_public_key` → delete duplicate

**Files:**
- Modify: `crates/auths-id/src/agent_identity.rs` — delete `fn extract_public_key` (lines ~329-350), replace its one callsite with `auths_core::storage::keychain::extract_public_key_bytes`.
- Update the import at line 37 (`use auths_core::crypto::signer::decrypt_keypair;`) — remove it.

**Step 1: Find the single internal caller**

```
grep -n "extract_public_key(" crates/auths-id/src/agent_identity.rs
```

**Step 2: Replace call with canonical helper**

At the one callsite, change `extract_public_key(&alias, &*provider, &*keychain)?` to:
```rust
auths_core::storage::keychain::extract_public_key_bytes(
    keychain.as_ref(),
    &alias,
    provider.as_ref(),
)
.map_err(|e| AgentProvisioningError::KeychainAccess(e.to_string()))?
```

**Step 3: Delete the old function** and the `decrypt_keypair` import.

**Step 4: Run tests**
```
cargo nextest run -p auths-id
```
Expected: PASS.

**Step 5: No commit.**

---

### Task A8 & A9: Legacy `auths-id/identity/rotate.rs` — hardware guard

**Files:**
- Modify: `crates/auths-id/src/identity/rotate.rs` (at lines ~99 and ~206, immediately before `decrypt_keypair(&encrypted_next, &next_pass)`)

**Context:** These are the *legacy* GitKel and registry rotation paths. The SDK workflow (Epic B) is the live rotate path the CLI uses. These legacy paths are only used by `auths-id` tests, but they still ship — fix-and-guard, do not remove.

**Step 1: Write the failing test**

Add `crates/auths-id/tests/cases/rotation_rejects_hardware_key.rs` — asserts `rotate_keri_identity` and `rotate_registry_identity` both return `InitError::InvalidData("Rotation requires a software-backed key ...")` when `keychain.is_hardware_backend() == true`.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-id -E 'test(rotation_rejects_hardware_key)'
```

**Step 3: Add the guard**

In both functions, immediately after `let (did, _role, _encrypted_current) = keychain.load_key(current_alias)?;`, add:

```rust
if keychain.is_hardware_backend() {
    return Err(InitError::InvalidData(
        "Rotation requires a software-backed key; current key is hardware-backed \
         (Secure Enclave). Rotate by initializing a new identity.".into(),
    ));
}
```

**Step 4: Run tests**
```
cargo nextest run -p auths-id
```

**Step 5: No commit.**

---

### Task A12: `domains/signing/service.rs` add SE branch

**Files:**
- Modify: `crates/auths-sdk/src/domains/signing/service.rs:380-400` (area around line 391)

**Context:** `workflows/signing.rs` already has the SE branch at lines 166-190 (see code inspection earlier). `domains/signing/service.rs` is its mirror and is missing the same branch.

**Step 1: Write the failing test**

Add a test in `crates/auths-sdk/tests/cases/signing_service_se.rs` that constructs a `SigningService` with a hardware-backend fake keychain and asserts it produces a signature via `sign_with_handle` without ever calling `decrypt_keypair`. Assert the returned PEM parses and verifies under the SE pubkey.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(signing_service_se)'
```

**Step 3: Mirror the workflow branch**

Copy the SE dispatch block from `workflows/signing.rs:166-190` (the `if ctx.key_storage.is_hardware_backend()` branch) into `domains/signing/service.rs` immediately before the existing `decrypt_keypair` call at line ~391. Keep both copies in sync — add a `// MIRROR: keep in sync with workflows/signing.rs` comment at the top of each branch.

**Step 4: Run tests**
```
cargo nextest run -p auths-sdk
```

**Step 5: No commit.**

---

### Task A13, A17, A18: Pairing export — hardware guard

**Files:**
- Modify: `crates/auths-sdk/src/pairing/mod.rs:542-590` (`load_device_signing_material`)
- Modify: `packages/auths-python/src/pairing.rs:240-260`
- Modify: `packages/auths-node/src/pairing.rs:320-345`

**Step 1: Write the failing test (SDK)**

Add `crates/auths-sdk/tests/cases/pairing_rejects_hardware_key.rs`:

```rust
#[test]
fn load_device_signing_material_rejects_hardware_key() {
    let ctx = hardware_ctx();
    let err = pairing::load_device_signing_material(&ctx).unwrap_err();
    assert!(matches!(err, PairingError::HardwareKeyNotExportable { .. }));
}
```

Add a new variant `PairingError::HardwareKeyNotExportable { alias: String }` in `crates/auths-sdk/src/pairing/error.rs` (or wherever `PairingError` is defined — locate with `grep -rn "pub enum PairingError"`).

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(pairing_rejects_hardware_key)'
```

**Step 3: Add the guard**

In `load_device_signing_material`, after loading the keychain entry but before `decrypt_keypair`:

```rust
if ctx.key_storage.is_hardware_backend() {
    return Err(PairingError::HardwareKeyNotExportable {
        alias: key_alias.to_string(),
    });
}
```

**Step 4: Mirror in bindings**

`packages/auths-python/src/pairing.rs:250` and `packages/auths-node/src/pairing.rs:333` — add the same early-return guard (map to the binding-specific error type).

**Step 5: Run tests**
```
cargo nextest run -p auths-sdk
cargo build -p auths-python
cargo build -p auths-node
```

**Step 6: No commit.**

---

### Task A15: `auths-core/api/runtime.rs` three FFI entry points

**Files:**
- Modify: `crates/auths-core/src/api/runtime.rs` around lines 198, 396, 460

**Step 1: Write the failing test**

Add `crates/auths-core/tests/cases/runtime_se_paths.rs` with three tests — one per callsite — asserting each FFI entry point either dispatches to the SE path (for hardware) or returns a clear error.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-core -E 'test(runtime_se_paths)'
```

**Step 3: For each of the three sites, classify by intent**

- Line 198 area: read the enclosing function. If it's a *sign* path → replace with `sign_with_key`. If it's a *load-raw-seed-for-X* path → guard with `is_hardware_backend()` and return `AgentError::HardwareKeyNotExportable`.
- Line 396 area: same classification.
- Line 460 area: same.

Do the classification via `Read` before editing — do not guess.

**Step 4: Run tests**
```
cargo nextest run -p auths-core
```

**Step 5: No commit.**

---

### Task A16: `auths-core/api/ffi.rs` passphrase probe

**Files:**
- Modify: `crates/auths-core/src/api/ffi.rs:587`

**Step 1: Write the failing test (probe rejects SE cleanly)**

Add a test that calls the FFI probe on a hardware-backed storage and asserts it returns the `BackendUnavailable` error code — not a cryptic decrypt failure.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-core -E 'test(ffi_probe)'
```

**Step 3: Add the guard**

Before `let _decrypted_pkcs8 = decrypt_keypair(...)`, add:

```rust
if storage.is_hardware_backend() {
    return Err(AgentError::BackendUnavailable {
        backend: storage.backend_name(),
        reason: "probe cannot decrypt hardware-backed key material".into(),
    });
}
```

**Step 4: Run tests**

```
cargo nextest run -p auths-core -E 'test(ffi)'
```

**Step 5: No commit.**

---

### Task A14-verify: `auths-core/signing.rs:297` (confirmation only)

**Files:**
- Read: `crates/auths-core/src/signing.rs:255-310`

**Step 1:** Verify by reading that the `decrypt_keypair` at line ~297 is only reachable when `is_hardware_backend()` is false (guard lives at line ~265). No code change.

**Step 2:** Grep for any *other* `decrypt_keypair` use in that file that could slip past the guard. None expected — confirm anyway.

**Step 3:** No commit.

---

## Epic B — P-256 Rotation (TypedSeed refactor)

**Architectural change:** rotation must stop consuming `&Ed25519KeyPair` and start consuming a curve-tagged signer. The cleanest shape:

```rust
/// A parsed signing key with curve tagged — used during rotation to sign the
/// rotation event and derive the new-current public key bytes + CESR encoding.
pub struct RotationSigner {
    pub seed: TypedSeed,
    pub public_key: Vec<u8>,  // 32 bytes Ed25519 / 33 bytes P-256 compressed
}

impl RotationSigner {
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        let parsed = auths_crypto::parse_key_material(bytes)?;
        Ok(Self { seed: parsed.seed, public_key: parsed.public_key })
    }

    pub fn cesr_encoded(&self) -> String {
        match self.seed.curve() {
            CurveType::Ed25519 => format!("D{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key)),
            CurveType::P256    => format!("1AAJ{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key)),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        auths_crypto::sign(&self.seed, msg)
    }
}
```

Add this struct in `auths-crypto` or `auths-id::identity::helpers` (prefer `auths-crypto::key_ops` since it sits alongside `TypedSeed` — it's a thin wrapper). Wire both rotation files (`workflows/rotation.rs` and `domains/identity/rotation.rs`) through it.

---

### Task B1: Add `RotationSigner` helper

**Files:**
- Create: body added to `crates/auths-crypto/src/key_ops.rs` (same file as `TypedSeed`)
- Export: `crates/auths-crypto/src/lib.rs` — `pub use key_ops::RotationSigner;`

**Step 1: Write the failing test**

Append to `crates/auths-crypto/src/key_ops.rs` `#[cfg(test)] mod tests`:

```rust
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
#[test]
fn rotation_signer_ed25519_roundtrip() {
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let s = RotationSigner::from_pkcs8(pkcs8.as_ref()).unwrap();
    assert_eq!(s.seed.curve(), CurveType::Ed25519);
    assert!(s.cesr_encoded().starts_with('D'));
    let sig = s.sign(b"msg").unwrap();
    assert_eq!(sig.len(), 64);
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
#[test]
fn rotation_signer_p256_roundtrip() {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let sk = SigningKey::random(&mut OsRng);
    let pkcs8 = sk.to_pkcs8_der().unwrap();
    let s = RotationSigner::from_pkcs8(pkcs8.as_bytes()).unwrap();
    assert_eq!(s.seed.curve(), CurveType::P256);
    assert!(s.cesr_encoded().starts_with("1AAJ"));
    let sig = s.sign(b"msg").unwrap();
    assert_eq!(sig.len(), 64);
}
```

**Step 2: Confirm failure**
```
cargo nextest run -p auths-crypto -E 'test(rotation_signer)'
```

**Step 3: Implement `RotationSigner`** in `crates/auths-crypto/src/key_ops.rs` per the shape above. Re-export it in `lib.rs`.

**Step 4: Run tests**
```
cargo nextest run -p auths-crypto
```

**Step 5: No commit.**

---

### Task B2: Refactor `compute_rotation_event` signature

**Files:**
- Modify: `crates/auths-sdk/src/workflows/rotation.rs` (function `compute_rotation_event`, lines 53-112)
- Modify: `crates/auths-sdk/src/domains/identity/rotation.rs` (identical mirror)

**Step 1: Write the failing test**

Add `crates/auths-sdk/tests/cases/rotation_p256.rs`:

```rust
#[test]
fn compute_rotation_event_accepts_p256_signer() {
    // Build a P-256 RotationSigner, feed into compute_rotation_event,
    // assert the emitted RotEvent.k[0] begins with "1AAJ" and the
    // embedded signature verifies under the P-256 pubkey.
}
```

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(compute_rotation_event_accepts_p256_signer)'
```

**Step 3: Change the signature**

Replace:
```rust
pub fn compute_rotation_event(
    state: &KeyState,
    next_keypair: &Ed25519KeyPair,
    new_next_keypair: &Ed25519KeyPair,
    ...
)
```
with:
```rust
pub fn compute_rotation_event(
    state: &KeyState,
    next_signer: &auths_crypto::RotationSigner,
    new_next_public_key: &[u8],
    new_next_curve: auths_crypto::CurveType,
    witness_config: Option<&WitnessConfig>,
) -> Result<(RotEvent, Vec<u8>), RotationError>
```

Inside the body:
- `new_current_pub_encoded = next_signer.cesr_encoded()` (remove the hand-rolled `format!("D{}", URL_SAFE_NO_PAD.encode(...))`)
- `new_next_commitment = compute_next_commitment(new_next_public_key)` — unchanged; `compute_next_commitment` hashes raw bytes so it is curve-agnostic.
- Replace `let sig = next_keypair.sign(&canonical);` with `let sig = next_signer.sign(&canonical).map_err(|e| RotationError::RotationFailed(format!("sign: {e}")))?;`

Keep the `new_next_curve` parameter even though the current body doesn't branch on it — adding it now prevents a second signature change when the CESR encoding helper centralizes.

**Step 4: Run tests**
```
cargo nextest run -p auths-sdk
```

**Step 5: No commit.**

---

### Task B3: Refactor `generate_rotation_keys`

**Files:**
- Modify: `crates/auths-sdk/src/workflows/rotation.rs:370-398` (`generate_rotation_keys`)
- Modify: `crates/auths-sdk/src/domains/identity/rotation.rs` (mirror)

**Step 1: Write the failing test**

Inside `tests/cases/rotation_p256.rs`:

```rust
#[test]
fn rotate_identity_p256_e2e() {
    // Provision a developer identity with CurveType::P256.
    // Call rotate_identity.
    // Assert the returned new_key_fingerprint decodes as 33-byte P-256 pubkey.
    // Assert the KEL's rot event has k[0] starting with "1AAJ".
}
```

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(rotate_identity_p256_e2e)'
```

**Step 3: Replace the Ed25519-only body**

Replace:
```rust
let rng = SystemRandom::new();
let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?;
let new_next_keypair = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref())?;
let next_keypair = load_keypair_from_der_or_seed(current_key_pkcs8)?;
let (rot, _event_bytes) = compute_rotation_event(state, &next_keypair, &new_next_keypair, witness_config.as_ref())?;
```
with:
```rust
let next_signer = auths_crypto::RotationSigner::from_pkcs8(current_key_pkcs8)
    .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

// Generate the new next-key using the SAME curve as the rotating key.
let generated = auths_id::keri::inception::generate_keypair_for_init(next_signer.seed.curve())
    .map_err(|e| RotationError::RotationFailed(format!("key generation failed: {e}")))?;

let (rot, _event_bytes) = compute_rotation_event(
    state,
    &next_signer,
    &generated.public_key,
    next_signer.seed.curve(),
    witness_config.as_ref(),
)?;
```

Change the return type from `ring::pkcs8::Document` to `Pkcs8Der` (what `generated.pkcs8` produces). Update call-sites that unwrap `.as_ref()` accordingly.

**Step 4: Propagate the curve to the final signature**

In `rotate_identity` (the orchestrator), update `new_key_fingerprint` derivation — `load_seed_and_pubkey` already returns curve; just pass through. The CLI `println!("   New key fingerprint: {}...", result.new_key_fingerprint)` does not need to know the curve, but add `curve` to `IdentityRotationResult` so downstream can render it.

**Step 5: Run tests**
```
cargo nextest run -p auths-sdk
cargo nextest run -p auths-id
```

**Step 6: No commit.**

---

### Task B4: Update `finalize_rotation_storage` for P-256 seed encoding

**Files:**
- Modify: `crates/auths-sdk/src/workflows/rotation.rs:412-466`
- Modify: `crates/auths-sdk/src/domains/identity/rotation.rs` (mirror)

**Context:** `extract_seed_bytes` + `encode_seed_as_pkcs8` in `auths-id/identity/helpers.rs` currently target Ed25519 PKCS8 v1. For P-256, the pkcs8 produced by `generate_keypair_for_init` is already in the correct P-256 PKCS8 format — we should store *that* directly rather than round-trip through `extract_seed_bytes → encode_seed_as_pkcs8`.

**Step 1: Write the failing test**

Assert that after rotation on a P-256 identity, loading the new pre-committed next key and parsing it with `auths_crypto::parse_key_material` yields `TypedSeed::P256`.

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(rotate_identity_p256_next_key_is_p256)'
```

**Step 3: Change `finalize_rotation_storage` to accept the raw PKCS8 instead of "seed bytes"**

Change `FinalizeParams::new_next_pkcs8: &'a [u8]` semantics: it's *already* the canonical PKCS8 for the new-next key's curve. Replace:
```rust
let new_next_seed = extract_seed_bytes(params.new_next_pkcs8)?;
let new_next_seed_pkcs8 = encode_seed_as_pkcs8(new_next_seed)?;
let encrypted_new_next = encrypt_keypair(&new_next_seed_pkcs8, &new_pass)?;
```
with:
```rust
let encrypted_new_next = encrypt_keypair(params.new_next_pkcs8, &new_pass)
    .map_err(|e| RotationError::RotationFailed(format!("encrypt new next key: {e}")))?;
```

**Step 4: Run tests**
```
cargo nextest run -p auths-sdk
```

**Step 5: No commit.**

---

### Task B5: Add hardware guard to live rotation (A10/A11 from Epic A)

**Files:**
- Modify: `crates/auths-sdk/src/workflows/rotation.rs:321-367` (`retrieve_precommitted_key`)
- Modify: `crates/auths-sdk/src/domains/identity/rotation.rs` (mirror)

**Step 1: Write the failing test**

```rust
#[test]
fn rotate_identity_rejects_hardware_key() {
    let ctx = hardware_ctx();
    let result = rotate_identity(config, &ctx, &SystemClock);
    assert!(matches!(result, Err(RotationError::HardwareKeyNotRotatable { .. })));
}
```

Add the new variant `RotationError::HardwareKeyNotRotatable { alias: String }` in `crates/auths-sdk/src/error.rs` (and the mirror in `domains/identity/error.rs`).

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(rotate_identity_rejects_hardware_key)'
```

**Step 3: Add the guard**

In `retrieve_precommitted_key`, immediately before `decrypt_keypair`:
```rust
if ctx.key_storage.is_hardware_backend() {
    return Err(RotationError::HardwareKeyNotRotatable {
        alias: target_alias.to_string(),
    });
}
```

**Step 4: Run tests**
```
cargo nextest run -p auths-sdk
```

**Step 5: No commit.**

---

### Task B6: End-to-end P-256 rotation test

**Files:**
- Create: `crates/auths-sdk/tests/cases/rotation_p256_e2e.rs`
- Wire into: `crates/auths-sdk/tests/cases/mod.rs`

**Step 1: Write the test**

```rust
#[test]
fn end_to_end_p256_rotation_produces_valid_kel() {
    let ctx = fake_ctx("Test-passphrase1!");
    let key_alias = provision_identity_with_curve(&ctx, CurveType::P256);

    let config = IdentityRotationConfig {
        repo_path: PathBuf::from("/unused"),
        identity_key_alias: Some(key_alias.clone()),
        next_key_alias: Some(KeyAlias::new_unchecked("rotated")),
    };

    let result = rotate_identity(config, &ctx, &SystemClock).unwrap();

    // Assert sequence advanced
    assert_eq!(result.sequence, 1);

    // Assert new-current key stored under alias "rotated" is P-256
    let (_, _, encrypted) = ctx.key_storage.load_key(&KeyAlias::new_unchecked("rotated")).unwrap();
    let pkcs8 = decrypt_keypair(&encrypted, "Test-passphrase1!").unwrap();
    let parsed = auths_crypto::parse_key_material(&pkcs8).unwrap();
    assert_eq!(parsed.seed.curve(), CurveType::P256);
    assert_eq!(parsed.public_key.len(), 33);

    // Assert KEL rot event is signed correctly — re-verify `rot.x` under P-256 pubkey
    let prefix = Prefix::new_unchecked(
        ctx.identity_storage.load_identity().unwrap()
            .controller_did.as_str()
            .strip_prefix("did:keri:").unwrap().to_string(),
    );
    let state = ctx.registry.get_key_state(&prefix).unwrap();
    let keri_key = KeriPublicKey::parse(state.current_keys[0].as_str()).unwrap();
    assert!(matches!(keri_key, KeriPublicKey::P256(_)));
}
```

`provision_identity_with_curve` is the existing `provision_identity` helper in `rotation.rs`'s test module — extract it to `tests/cases/common.rs` and make it take a `CurveType` parameter (it's already parameterized in the `initialize` builder via `.with_curve(...)`).

**Step 2: Confirm failure**
```
cargo nextest run -p auths-sdk -E 'test(end_to_end_p256_rotation)'
```

**Step 3: Fix anything the test surfaces** — this is the "real" regression test, any earlier task's skipped edge case shows up here.

**Step 4: Run full SDK tests**
```
cargo nextest run -p auths-sdk
```

**Step 5: No commit.**

---

## Epic C — Final verification pass

**Before declaring the plan done, execute (in this order):**

### Task C1: Workspace-wide clippy + fmt

```
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: no diagnostics. Clippy's `disallowed_methods` in domain code is the usual gotcha — if it fires, we accidentally added `Utc::now()` somewhere we shouldn't have.

### Task C2: Full test suite

```
cargo nextest run --workspace
cargo test --all --doc
```

### Task C3: Grep audit — every remaining `decrypt_keypair` site is accounted for

```
grep -rn "decrypt_keypair" crates/ packages/ \
  | grep -v "tests/" \
  | grep -v "benches/" \
  | grep -v "crypto/signer.rs"  # the definition site
```

For each remaining line, confirm it's either (a) inside a function whose prior control flow short-circuits on `is_hardware_backend()`, or (b) behind a hardware guard we added. No uncovered sites should remain.

### Task C4: Manual smoke-test (optional, SE hardware required)

On an Apple Silicon Mac with Secure Enclave:
```
cargo install --path crates/auths-cli
auths init --curve p256 --keychain secure-enclave --key-alias main-se
auths sign examples/hello.txt --key main-se     # expects Touch ID prompt → success
auths id rotate --key main-se                    # expects HardwareKeyNotRotatable error
auths auth challenge --nonce abc123 --domain test.example  # expects Touch ID prompt → success
```

### Task C5: Update docs

- `docs/architecture/crates/auths-core.md:151` — note that `decrypt_keypair` must never be called without an `is_hardware_backend()` guard; callers should prefer `sign_with_key` / `extract_public_key_bytes`.
- `ecosystem.md:290-292` — flip the two P0s from 🔴 to ✅ once C1-C4 pass.

---

## Handoff

After the user commits (the user commits, not Claude — per repo policy), run `npx gitnexus analyze` to refresh the code intelligence index, since rotation touched the call graph.
