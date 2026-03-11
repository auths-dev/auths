# Typing Cleaning: Strong Newtypes for Cryptographic String Fields

## Context

Many cryptographic and identity fields throughout the codebase are plain `String` where they should be strongly typed newtypes. The fn-62 epic already addresses `IdentityDID` and `DeviceDID` validation. This plan covers **everything else**: signatures, commit SHAs, public keys, resource IDs, KERI prefixes/SAIDs, git refs, and policy IDs.

## Existing Newtypes (Already Done)

These live in `crates/auths-verifier/src/` and follow established patterns:

| Type | Inner | Location | Derives |
|------|-------|----------|---------|
| `ResourceId(String)` | `String` | `core.rs:46` | `Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize` + `Deref, Display, From<String>, From<&str>` |
| `IdentityDID(String)` | `String` | `types.rs:147` | `Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash` + `Display, FromStr, Deref, AsRef<str>, Borrow<str>` |
| `DeviceDID(String)` | `String` | `types.rs:303` | Same as IdentityDID + Git-specific utilities |
| `Prefix(String)` | `String` | `keri.rs:66` | `Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize` + `Display, AsRef<str>, Borrow<str>` |
| `Said(String)` | `String` | `keri.rs:163` | Same as Prefix |
| `Ed25519PublicKey([u8; 32])` | `[u8; 32]` | `core.rs:181` | `Debug, Clone, Copy, PartialEq, Eq, Hash` + custom hex Serialize/Deserialize |
| `Ed25519Signature([u8; 64])` | `[u8; 64]` | `core.rs:283` | `Debug, Clone, PartialEq, Eq` + custom hex Serialize/Deserialize |

**Pattern notes:**
- No macros — all hand-written
- String-based types use `#[serde(transparent)]`
- Byte-array types use custom hex Serialize/Deserialize
- All conditionally derive `schemars::JsonSchema` with `#[cfg_attr(feature = "schema", ...)]`
- Validated types provide `new_unchecked()` + `parse()` constructors
- Error types use `thiserror::Error`

---

## New Newtypes to Create

### 1. `CommitOid(String)` — Git commit hash

**Where to define:** `crates/auths-verifier/src/core.rs` (alongside `ResourceId`)

**Validation:** 40-char lowercase hex string (SHA-1) or 64-char (SHA-256 for future Git)

**Derives & impls:** Same as `ResourceId` — `Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Deref, Display, From<String>`

**Sites to update (4):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-index/src/index.rs:20` | `IndexedAttestation.commit_oid` | `String` |
| `crates/auths-index/src/schema.rs:9` | DB column | `TEXT` (keep as TEXT, convert at boundary) |
| `crates/auths-id/src/keri/cache.rs:42,247` | `CacheEntry.last_commit_oid` | `String` |
| `crates/auths-id/src/identity/events.rs:21` | `IdentityEvent.previous_hash` | `String` |

### 2. `PublicKeyHex(String)` — Hex-encoded Ed25519 public key

**Where to define:** `crates/auths-verifier/src/core.rs`

**Validation:** 64-char hex string (32 bytes encoded) — validate with `hex::decode` and length check

**Conversion:** `pub fn to_ed25519(&self) -> Result<Ed25519PublicKey, Ed25519KeyError>` for parsing into the byte-array type

**Sites to update (~20):**

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
| `crates/auths-mobile-ffi/src/lib.rs:82,85,351,371,442` | device key fields | `String` |
| `crates/auths-pairing-protocol/src/response.rs:18,19` | x25519/signing pubkeys | `String` |

### 3. `SignatureHex(String)` — Hex-encoded Ed25519 signature

**Where to define:** `crates/auths-verifier/src/core.rs`

**Validation:** 128-char hex string (64 bytes encoded)

**Conversion:** `pub fn to_ed25519(&self) -> Result<Ed25519Signature, SignatureLengthError>`

**Sites to update (~2):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-pairing-protocol/src/response.rs:21` | `PairingResponse.signature` | `String` |
| `crates/auths-sdk/src/workflows/artifact.rs:169` (if applicable) | signature fields | `String` |

### 4. `GitRef(String)` — Git ref path

**Where to define:** `crates/auths-verifier/src/core.rs` or `crates/auths-storage/src/`

**Validation:** Must start with `refs/` — basic structural check

**Sites to update (3):**

| File | Field/Param | Current Type |
|------|-------------|-------------|
| `crates/auths-index/src/index.rs:18` | `IndexedAttestation.git_ref` | `String` |
| `crates/auths-policy/src/context.rs:62` | `VerificationContext.git_ref` | `Option<String>` → `Option<GitRef>` |
| `crates/auths-id/src/keri/kel.rs:88` | `Kel::with_ref()` param | `String` |

### 5. `PolicyId(String)` — Policy identifier

**Where to define:** `crates/auths-verifier/src/core.rs`

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
// or
did: result.did.to_string(),

// After (identical — Display impl handles it):
did: result.did.to_string(),
```

If a newtype's inner field was previously accessed directly (e.g., `resource_id.0`), change to `.to_string()` or `.as_str().to_owned()`.

### auths-mobile-ffi (Swift/Kotlin)

- `crates/auths-mobile-ffi/src/lib.rs` — ~15 DID and public_key_hex fields as `String`
- Same pattern: convert via `.to_string()` at boundary, FFI types remain `String`

---

## Execution Plan

### Phase 1: Define New Newtypes (additive, non-breaking)

**Task: Create `CommitOid`, `PublicKeyHex`, `SignatureHex`, `GitRef`, `PolicyId`**

File: `crates/auths-verifier/src/core.rs`

Follow the `ResourceId` pattern for each:
1. Define struct with `#[serde(transparent)]`
2. Derive `Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize`
3. Implement `Deref`, `Display`, `From<String>`, `From<&str>`, `AsRef<str>`
4. Add `new()`, `as_str()`, `into_inner()` methods
5. For types with validation (`PublicKeyHex`, `SignatureHex`, `CommitOid`): add `parse()` returning `Result<Self, NewtypeError>`
6. Re-export from `crates/auths-verifier/src/lib.rs`

Add tests in `crates/auths-verifier/tests/cases/newtypes.rs`.

**Estimated touch: 1 file + 1 test file**

### Phase 2: Adopt Existing Newtypes (`ResourceId`, `Prefix`, `Said`)

**Task: Replace `String` with existing newtypes where they should already be used**

This is mostly in `auths-index` and `auths-id`:
1. Add `auths-verifier` dependency to `auths-index/Cargo.toml` (if not present)
2. Replace `rid: String` with `rid: ResourceId` in `IndexedAttestation`, `IndexedOrgMember`, etc.
3. Replace `prefix: String` with `prefix: Prefix` in `IndexedIdentity`, `IndexedOrgMember`
4. Replace `tip_said: String` with `tip_said: Said` in `IndexedIdentity`
5. Update SQL binding code (rusqlite `to_sql`/`from_sql` — may need `impl ToSql for ResourceId` via `as_str()`)
6. Fix compilation in `auths-sdk` and `auths-id` for `rid`, `prefix`, `said` fields

**Estimated touch: ~8 files across auths-index, auths-id, auths-sdk**

### Phase 3: Thread `CommitOid` Through Codebase

1. Replace `commit_oid: String` with `commit_oid: CommitOid` in `IndexedAttestation`, `CacheEntry`
2. Replace `previous_hash: String` with `previous_hash: CommitOid` in `IdentityEvent`
3. Update SQL binding code
4. Update any git2 integration points (convert `git2::Oid` ↔ `CommitOid`)

**Estimated touch: ~4 files**

### Phase 4: Thread `PublicKeyHex` Through Codebase

1. Replace `public_key_hex: String` with `public_key_hex: PublicKeyHex` in:
   - `IdentityBundle` (auths-verifier)
   - `TrustedRoot`, `PinnedIdentity` (auths-core)
   - Org workflow structs (auths-sdk)
   - MCP config (auths-sdk)
2. Update builder patterns in `auths-core/src/testing/builder.rs`
3. Update CLI display code

**Estimated touch: ~12 files**

### Phase 5: Thread `SignatureHex`, `GitRef`, `PolicyId`

1. `SignatureHex` in pairing protocol
2. `GitRef` in index, policy, KEL
3. `PolicyId` in threshold policy

**Estimated touch: ~5 files**

### Phase 6: Thread DID Types Beyond fn-62

After fn-62 completes, extend `IdentityDID`/`DeviceDID` adoption to:
1. `auths-index` — all DID fields
2. `auths-id` — cache, resolve, helpers
3. `auths-sdk` — workflows, types
4. `auths-pairing-protocol` — response and types
5. `auths-core` — witness config

**Estimated touch: ~15 files**

### Phase 7: FFI Package Updates

After core types are threaded:
1. Update `packages/auths-python/src/*.rs` — change any `.0` field access to `.to_string()` or `.as_str()`
2. Update `packages/auths-node/src/*.rs` — same pattern
3. Update `crates/auths-mobile-ffi/src/lib.rs` — same pattern
4. Verify Python type stubs unchanged
5. Verify Node type definitions regenerate correctly

**Estimated touch: ~10 files, all mechanical**

---

## Summary Table

| Newtype | Define In | Sites to Update | Priority | Phase |
|---------|-----------|----------------|----------|-------|
| `CommitOid` | auths-verifier | 4 | HIGH | 1, 3 |
| `PublicKeyHex` | auths-verifier | ~20 | HIGH | 1, 4 |
| `SignatureHex` | auths-verifier | ~2 | MEDIUM | 1, 5 |
| `GitRef` | auths-verifier | 3 | MEDIUM | 1, 5 |
| `PolicyId` | auths-verifier | 2 | MEDIUM | 1, 5 |
| `ResourceId` (adopt) | already exists | 5 | HIGH | 2 |
| `Prefix` (adopt) | already exists | 2 | HIGH | 2 |
| `Said` (adopt) | already exists | 1 | HIGH | 2 |
| `IdentityDID` (extend) | fn-62 | ~15 | HIGH | 6 |
| `DeviceDID` (extend) | fn-62 | ~10 | HIGH | 6 |

**Total: ~89 String fields across ~40 files**

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

## Risks

1. **Serde backward compatibility** — Adding `#[serde(transparent)]` to new newtypes preserves JSON wire format. No breaking change for existing serialized data.
2. **SQL binding** — `rusqlite` needs `ToSql`/`FromSql` impls for newtypes used in index queries. Implement via `as_str()` delegation.
3. **git2 interop** — `CommitOid` needs conversion from `git2::Oid::to_string()`. Keep as simple `From` impl.
4. **KERI event fields** (`k: Vec<String>`, `n: Vec<String>`, `x: String` in `auths-id/src/keri/event.rs`) — These are base64url-encoded keys per CESR spec. Consider a `CesrKey(String)` type, but this is lower priority since KERI event structures are tightly coupled to the CESR wire format. Defer unless there's a clear validation benefit.
