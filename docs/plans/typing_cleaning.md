# Typing Cleaning: Strong Newtypes for Cryptographic String Fields

## Context

Many cryptographic and identity fields throughout the codebase are plain `String` where they should be strongly typed newtypes. The fn-62 epic already addresses `IdentityDID` and `DeviceDID` validation. This plan covers **everything else**: commit OIDs, public keys (hex), policy IDs, and consistent adoption of existing newtypes (`ResourceId`, `Prefix`, `Said`).

## Design Decisions

### Two newtype tiers (follow existing codebase convention)

| Tier | Pattern | Serde | Constructor | Example |
|------|---------|-------|-------------|---------|
| **Unvalidated** | `From<String>`, `Deref<Target=str>` | `#[serde(transparent)]` | `new()` | `ResourceId`, `PolicyId` |
| **Validated** | `TryFrom<String>`, `AsRef<str>` | `#[serde(try_from = "String")]` | `parse()` + `new_unchecked()` | `Capability`, `IdentityDID`, `CommitOid`, `PublicKeyHex` |

Validated types must NOT implement `From<String>` or `Deref<Target=str>` — these defeat type safety by allowing construction/coercion that bypasses validation.

### SQL boundary (sqlite crate, not rusqlite)

The codebase uses the `sqlite` crate (v0.32) with `BindableWithIndex`/`ReadableWithIndex` traits — NOT `rusqlite`. No `ToSql`/`FromSql` impls needed. Binding uses `stmt.bind((idx, value.as_str()))`, reading uses `stmt.read::<String, _>(idx)` then wraps with `new_unchecked()` (trust the DB — data was validated on write).

### FFI boundary (unchanged)

Both `packages/auths-python` (PyO3) and `packages/auths-node` (napi-rs) keep `String` fields at the FFI boundary. Conversion via `.to_string()` or `.as_str().to_owned()`. No wrapper impls needed. Python type stubs and Node type definitions remain unchanged.

### GitRef: reuse existing type

A `GitRef` type already exists at `crates/auths-id/src/storage/layout.rs:22-71` (unvalidated, with `Deref`, `Display`, `From<String>`, `join()`). Rather than create a competing type in auths-verifier, reuse the existing one by importing it where needed. If validation (`refs/` prefix check) is desired later, add it to the existing type.

### Excluded from scope

- **`IdentityEvent.previous_hash`**: This is a SHA-256 content hash of a commit OID string, NOT a commit OID itself. It stays as `String` (or gets its own `EventChainHash` type in a future epic).
- **`PairingResponse.device_x25519_pubkey`, `device_signing_pubkey`, `signature`**: These are base64url-encoded, NOT hex-encoded. They cannot be `PublicKeyHex` or `SignatureHex`. They stay as `String` (or get a `Base64UrlKey`/`Base64UrlSignature` type in a future epic).
- **KERI event fields** (`k: Vec<String>`, `n: Vec<String>`, `x: String`): Base64url CESR keys, tightly coupled to wire format. Defer to a future CESR typing epic.
- **`IndexedIdentity.current_keys: Vec<String>`**: Base64url KERI keys, same encoding concern.
- **`ThresholdPolicy.signers: Vec<String>`**: These are DID strings but mixed `IdentityDID`/`DeviceDID` — needs clarification on which DID type. Defer to fn-62 extension.

---

## Existing Newtypes (Already Done)

These live in `crates/auths-verifier/src/` and follow established patterns:

| Type | Inner | Location | Tier |
|------|-------|----------|------|
| `ResourceId(String)` | `String` | `core.rs:46` | Unvalidated |
| `IdentityDID(String)` | `String` | `types.rs:147` | Validated |
| `DeviceDID(String)` | `String` | `types.rs:303` | Validated |
| `Prefix(String)` | `String` | `keri.rs:66` | Validated |
| `Said(String)` | `String` | `keri.rs:163` | Validated |
| `Ed25519PublicKey([u8; 32])` | `[u8; 32]` | `core.rs:181` | Validated (byte-array) |
| `Ed25519Signature([u8; 64])` | `[u8; 64]` | `core.rs:283` | Validated (byte-array) |

**Shared conventions:**
- No macros — all hand-written
- All conditionally derive `schemars::JsonSchema` with `#[cfg_attr(feature = "schema", ...)]`
- Error types use `thiserror::Error`
- `#[repr(transparent)]` on validated string newtypes

---

## New Newtypes to Create

### 1. `CommitOid(String)` — Git commit hash (Validated)

**Where to define:** `crates/auths-verifier/src/core.rs`

**Validation:** 40-char lowercase hex (SHA-1) or 64-char (SHA-256). Use `parse()` + `new_unchecked()`.

**Serde:** `#[serde(try_from = "String")]` — rejects malformed OIDs on deserialization.

**Traits:** `Debug, Clone, PartialEq, Eq, Hash, Serialize` + `Display`, `AsRef<str>`, `TryFrom<String>`, `TryFrom<&str>`, `FromStr`, `From<Self> for String`

**No `Default`** — an empty `CommitOid` is semantically wrong.

**git2 interop:** Cannot implement `From<git2::Oid>` in auths-verifier (no git2 dep). Use `CommitOid::new_unchecked(oid.to_string())` at call sites, following the `oid_to_event_hash` pattern at `crates/auths-id/src/witness.rs:39-62`.

**Sites to update (3):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-index/src/index.rs:20` | `IndexedAttestation.commit_oid` | `String` |
| `crates/auths-index/src/schema.rs:9` | DB column | `TEXT` (keep as TEXT, convert at boundary) |
| `crates/auths-id/src/keri/cache.rs:42,247` | `CacheEntry.last_commit_oid` | `String` |

### 2. `PublicKeyHex(String)` — Hex-encoded Ed25519 public key (Validated)

**Where to define:** `crates/auths-verifier/src/core.rs`

**Validation:** 64-char hex string (32 bytes) — validate with `hex::decode` and length check.

**Serde:** `#[serde(try_from = "String")]`

**Conversion:** `pub fn to_ed25519(&self) -> Result<Ed25519PublicKey, Ed25519KeyError>`

**Sites to update (~12, excluding base64url-encoded fields):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-verifier/src/core.rs:667` | `IdentityBundle.public_key_hex` | `String` |
| `crates/auths-core/src/trust/roots_file.rs:47` | `TrustedRoot.public_key_hex` | `String` |
| `crates/auths-core/src/trust/pinned.rs:28` | `PinnedIdentity.public_key_hex` | `String` |
| `crates/auths-core/src/testing/builder.rs:69` | builder field | `String` |
| `crates/auths-cli/src/commands/device/authorization.rs:31` | `public_key` | `String` |
| `crates/auths-cli/src/commands/trust.rs:99` | `public_key_hex` | `String` |
| `crates/auths-sdk/src/workflows/org.rs:204,240,256,273` | org admin/member keys | `String` |
| `crates/auths-sdk/src/workflows/mcp.rs:16` | `root_public_key` | `String` |

### 3. `PolicyId(String)` — Policy identifier (Unvalidated)

**Where to define:** `crates/auths-verifier/src/core.rs`

**Serde:** `#[serde(transparent)]` — opaque identifier, no validation needed.

**Traits:** Follow `ResourceId` pattern — `From<String>`, `From<&str>`, `Deref<Target=str>`, `Display`

**Sites to update (2):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-verifier/src/core.rs:987` | `ThresholdPolicy.policy_id` | `String` |
| `crates/auths-verifier/src/core.rs:1000` | constructor param | `String` |

---

## Existing Newtypes: Inconsistent Adoption

These types already exist but aren't used everywhere they should be.

### `ResourceId` — exists at `core.rs:46`, used inconsistently

| File | Field/Param | Current Type | Should Be |
|------|-------------|-------------|-----------|
| `crates/auths-index/src/index.rs:12` | `IndexedAttestation.rid` | `String` | `ResourceId` |
| `crates/auths-index/src/index.rs:51` | `IndexedOrgMember.rid` | `String` | `ResourceId` |
| `crates/auths-id/src/identity/helpers.rs:28` | `IdentityHelper.rid` | `String` | `ResourceId` |
| `crates/auths-sdk/src/workflows/artifact.rs:28` | `ArtifactSigningRequest.attestation_rid` | `String` | `ResourceId` |
| `crates/auths-sdk/src/signing.rs:193` | `SignedAttestation.rid` | `String` | `ResourceId` |

### `Prefix` — exists at `keri.rs:66`, used inconsistently

| File | Field/Param | Current Type | Should Be |
|------|-------------|-------------|-----------|
| `crates/auths-index/src/index.rs:35` | `IndexedIdentity.prefix` | `String` | `Prefix` |
| `crates/auths-index/src/index.rs:48` | `IndexedOrgMember.org_prefix` | `String` | `Prefix` |

### `Said` — exists at `keri.rs:163`, used inconsistently

| File | Field/Param | Current Type | Should Be |
|------|-------------|-------------|-----------|
| `crates/auths-index/src/index.rs:38` | `IndexedIdentity.tip_said` | `String` | `Said` |

### `IdentityDID` / `DeviceDID` — partially addressed by fn-62

Additional sites beyond fn-62 scope (core/SDK layer, not CLI boundary):

| File | Field/Param | Current Type | Should Be |
|------|-------------|-------------|-----------|
| `crates/auths-index/src/index.rs:14,50` | `issuer_did` | `String` | `IdentityDID` |
| `crates/auths-index/src/index.rs:16,49` | `device_did`, `member_did` | `String` | `DeviceDID` |
| `crates/auths-id/src/keri/cache.rs:36,241` | `CacheEntry.did` | `String` | `IdentityDID` |
| `crates/auths-id/src/keri/resolve.rs:44` | `ResolveResult.did` | `String` | `IdentityDID` |
| `crates/auths-id/src/identity/helpers.rs:27` | `IdentityHelper.did` | `String` | `IdentityDID` |
| `crates/auths-sdk/src/types.rs:589` | `DeviceAttestation.device_did` | `String` | `DeviceDID` |
| `crates/auths-sdk/src/workflows/artifact.rs:32` | `ArtifactSigningResult.signer_did` | `String` | `IdentityDID` |
| `crates/auths-sdk/src/workflows/org.rs:196,236,252` | org workflow DIDs | `String` | `IdentityDID`/`DeviceDID` |
| `crates/auths-core/src/witness/server.rs:60,114` | `WitnessConfig.witness_did` | `String` | `DeviceDID` |
| `crates/auths-pairing-protocol/src/response.rs:20` | `PairingResponse.device_did` | `String` | `DeviceDID` |
| `crates/auths-pairing-protocol/src/types.rs:57,81` | pairing DIDs | `String` | `DeviceDID` |

---

## Cascade to FFI Packages

### Impact Assessment: **Minimal**

Both `packages/auths-python` (PyO3) and `packages/auths-node` (napi-rs) use a consistent adapter pattern: internal Rust newtypes are converted to `String` at the FFI boundary via `.to_string()` or `hex::encode()`. The FFI-exposed structs remain `String` fields.

**No wrapper impls needed.** As long as newtypes implement `Display`, the existing `.to_string()` calls continue to work.

### auths-python (PyO3)

Binding structs use `#[pyclass]` with `#[pyo3(get)]` on `String` fields. Python consumers receive `str`.

**Files with conversion points (`.to_string()` calls that may reference changed types):**
- `packages/auths-python/src/identity.rs` — ~6 conversion sites
- `packages/auths-python/src/commit_sign.rs` — signature/DID conversions
- `packages/auths-python/src/attestation_query.rs` — rid, DID conversions
- `packages/auths-python/src/org.rs` — org prefix, DID conversions
- `packages/auths-python/src/artifact_sign.rs` — rid conversions

**Type stubs (manually maintained, no change needed):**
- `packages/auths-python/python/auths/__init__.pyi` — fields remain `str`

### auths-node (napi-rs)

Binding structs use `#[napi(object)]` with `String` fields. JavaScript consumers receive `string`.

**Files with conversion points:**
- `packages/auths-node/src/identity.rs` — ~8 conversion sites
- `packages/auths-node/src/commit_sign.rs` — signature/DID conversions
- `packages/auths-node/src/artifact.rs` — rid, digest conversions
- `packages/auths-node/src/org.rs` — org prefix, DID conversions
- `packages/auths-node/src/types.rs` — defines all `Napi*` structs

**Type definitions (auto-generated, no change needed):**
- `packages/auths-node/index.d.ts` — regenerated by napi-rs build

### What Changes in FFI Code

For each conversion site, the change is mechanical:

```rust
// Before (if inner field was public):
did: result.did.0,
// After (Display impl handles it):
did: result.did.to_string(),
// Or for owned values:
did: result.did.into_inner(),
```

### auths-mobile-ffi (Swift/Kotlin)

- `crates/auths-mobile-ffi/src/lib.rs` — ~15 DID and public_key_hex fields as `String`
- Same pattern: convert via `.to_string()` at boundary, FFI types remain `String`

---

## Execution Plan

### Phase 1: Define New Newtypes (additive, non-breaking)

**Task: Create `CommitOid`, `PublicKeyHex`, `PolicyId` in auths-verifier**

File: `crates/auths-verifier/src/core.rs`

For **validated types** (`CommitOid`, `PublicKeyHex`), follow the `Capability` pattern:
1. Define struct with `#[serde(try_from = "String")]` and `#[repr(transparent)]`
2. Derive `Debug, Clone, PartialEq, Eq, Hash, Serialize`
3. Implement `parse()` + `new_unchecked()` + `as_str()` + `into_inner()`
4. Implement `Display`, `AsRef<str>`, `TryFrom<String>`, `TryFrom<&str>`, `FromStr`, `From<Self> for String`
5. Define error type (e.g. `CommitOidError`, `PublicKeyHexError`) with `thiserror::Error`

For **unvalidated types** (`PolicyId`), follow the `ResourceId` pattern:
1. Define struct with `#[serde(transparent)]`
2. Derive `Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize`
3. Implement `Deref<Target=str>`, `Display`, `From<String>`, `From<&str>`
4. Add `new()`, `as_str()` methods

Re-export all from `crates/auths-verifier/src/lib.rs`.

Add tests in `crates/auths-verifier/tests/cases/newtypes.rs`.

### Phase 2: Adopt Existing Newtypes in auths-index (`ResourceId`, `Prefix`, `Said`)

**Prerequisite:** Add `auths-verifier` to `auths-index/Cargo.toml` dependencies (Layer 4 → Layer 1, architecturally sound).

1. Replace `rid: String` with `rid: ResourceId` in `IndexedAttestation`, `IndexedOrgMember`
2. Replace `prefix: String` with `prefix: Prefix` in `IndexedIdentity`, `IndexedOrgMember`
3. Replace `tip_said: String` with `tip_said: Said` in `IndexedIdentity`
4. Update SQL write sites: `.as_str()` on newtypes for `stmt.bind()`
5. Update SQL read sites: wrap `stmt.read::<String, _>()` results with `::new_unchecked()` (trust the DB)
6. Adopt `ResourceId` in `auths-sdk` (`ArtifactSigningRequest.attestation_rid`, `SignedAttestation.rid`) and `auths-id` (`IdentityHelper.rid`)

### Phase 3: Thread `CommitOid` Through Codebase

1. Replace `commit_oid: String` with `commit_oid: CommitOid` in `IndexedAttestation`
2. Replace `last_commit_oid: String` with `last_commit_oid: CommitOid` in `CacheEntry` / `CachedKelState`
3. Update SQL boundary code (same pattern as Phase 2)
4. Update git2 conversion sites: `CommitOid::new_unchecked(oid.to_string())` at `auths-index/src/rebuild.rs:124`, `auths-id/src/keri/cache.rs:110`, `auths-id/src/storage/indexed.rs:94`

### Phase 4: Thread `PublicKeyHex` Through Codebase

1. Replace `public_key_hex: String` with `public_key_hex: PublicKeyHex` in:
   - `IdentityBundle` (auths-verifier)
   - `TrustedRoot`, `PinnedIdentity` (auths-core)
   - Org workflow structs (auths-sdk)
   - MCP config (auths-sdk)
2. Update builder patterns in `auths-core/src/testing/builder.rs`
3. Update CLI display code
4. Exclude `PairingResponse` fields (base64url, not hex) and `auths-mobile-ffi` fields (base64url)

### Phase 5: Thread `PolicyId` + DID types beyond fn-62

1. `PolicyId` in `ThresholdPolicy` (2 sites, auths-verifier internal)
2. After fn-62 completes, extend `IdentityDID`/`DeviceDID` adoption to:
   - `auths-index` — all DID fields
   - `auths-id` — cache, resolve, helpers
   - `auths-sdk` — workflows, types
   - `auths-pairing-protocol` — response and types
   - `auths-core` — witness config

### Phase 6: FFI Package Updates

After core types are threaded:
1. Update `packages/auths-python/src/*.rs` — change any `.0` field access to `.to_string()` or `.as_str().to_owned()`
2. Update `packages/auths-node/src/*.rs` — same pattern
3. Update `crates/auths-mobile-ffi/src/lib.rs` — same pattern
4. Verify Python type stubs unchanged
5. Verify Node type definitions regenerate correctly

---

## Summary Table

| Newtype | Tier | Define In | Sites | Phase |
|---------|------|-----------|-------|-------|
| `CommitOid` | Validated | auths-verifier | 3 | 1, 3 |
| `PublicKeyHex` | Validated | auths-verifier | ~12 | 1, 4 |
| `PolicyId` | Unvalidated | auths-verifier | 2 | 1, 5 |
| `ResourceId` (adopt) | — | already exists | 5 | 2 |
| `Prefix` (adopt) | — | already exists | 2 | 2 |
| `Said` (adopt) | — | already exists | 1 | 2 |
| `IdentityDID` (extend) | — | fn-62 | ~15 | 5 |
| `DeviceDID` (extend) | — | fn-62 | ~10 | 5 |

**Total: ~50 String fields across ~30 files** (reduced from original ~89 after excluding base64url fields, KERI event fields, and properly scoped exclusions)

---

## Verification Commands

```bash
# After each phase:
cargo build --workspace
cargo nextest run --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --doc

# WASM check (auths-verifier only):
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# FFI package checks:
cd packages/auths-node && npm run build
cd packages/auths-python && maturin develop
```

## Risks & Mitigations

1. **Serde backward compatibility** — Validated types use `#[serde(try_from = "String")]` which enforces format on deserialization. Risk: old cached files (e.g., `CachedKelState`) with malformed values fail to load. Mitigation: audit existing cached data before switching; use `new_unchecked()` in cache deserialization if needed.
2. **SQL boundary** — Uses `sqlite` crate (NOT `rusqlite`). No trait impls needed. Bind via `.as_str()`, read via `String` + `new_unchecked()` wrapper.
3. **git2 interop** — Cannot implement `From<git2::Oid>` in auths-verifier (no git2 dep, orphan rule). Use `CommitOid::new_unchecked(oid.to_string())` at call sites.
4. **auths-index dependency** — Must add `auths-verifier` to `auths-index/Cargo.toml`. Architecturally sound (Layer 4 → Layer 1).
5. **WASM compilation** — All new types in auths-verifier must compile for `wasm32-unknown-unknown`. The `hex` crate is already a dependency, so validation logic is fine.

## Deferred Items

- `EventChainHash(String)` for `IdentityEvent.previous_hash` (SHA-256 content hash, not commit OID)
- `Base64UrlKey(String)` for `PairingResponse` X25519/signing keys
- `Base64UrlSignature(String)` for `PairingResponse.signature`
- `CesrKey(String)` for KERI event `k`/`n`/`x` fields
- `SignatureHex(String)` — no confirmed hex-encoded signature String fields after excluding base64url ones
- `GitRef` type promotion from `auths-id` to `auths-verifier` (if needed for cross-crate use)
