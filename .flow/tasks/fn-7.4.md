# fn-7.4 Add SealType, KeriSequence, GitRef/BlobName, typed witness/receipt fields

## Description

Batch of auths-id internal types. No cross-crate ripple — all changes are within auths-id except WitnessConfig which is consumed by auths-sdk.

> **Note**: This task bundles 5 loosely-related changes. If the scope feels too wide during implementation, split into sub-PRs per section (e.g. "fn-7.4a SealType+KeriSequence", "fn-7.4b GitRef/BlobName", "fn-7.4c WitnessConfig+Receipts").

### 1. SealType enum (crates/auths-id/src/keri/seal.rs)

Replace `Seal.seal_type: String` with `SealType` enum:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SealType {
    DeviceAttestation,
    Revocation,
    Delegation,
}
```
- Update `Seal` struct: `seal_type: SealType`
- Update factory methods: `Seal::device_attestation()`, `Seal::revocation()`, `Seal::delegation()`
- Update `find_seal_in_kel()` in auths-verifier if it matches on seal_type strings

### 2. KeriSequence (crates/auths-id/src/keri/event.rs)

Replace `s: String` in IcpEvent, RotEvent, IxnEvent with `KeriSequence(u64)`:
- Custom serde: serialize as hex string (`"0"`, `"1"`, `"a"`), deserialize from hex string
- Methods: `new(u64)`, `value() -> u64`
- `Event::sequence()` becomes infallible — returns `KeriSequence` directly
- Delete `SequenceParseError` — validation moves to deserialization. Currently used in: `event.rs`, `validate.rs`, `incremental.rs`, `keri/mod.rs`
- Update all callers that currently call `.sequence()?` to use `.sequence().value()`

Files affected:
- `crates/auths-id/src/keri/event.rs` — type definition + Event impl
- `crates/auths-id/src/keri/validate.rs` — uses SequenceParseError
- `crates/auths-id/src/keri/incremental.rs` — uses SequenceParseError
- `crates/auths-id/src/keri/mod.rs` — re-exports SequenceParseError
- `crates/auths-verifier/src/keri.rs` — re-exports and uses KeriEvent types
- `crates/auths-id/src/keri/kel.rs` — sequence comparisons
- `crates/auths-id/src/rotation.rs` — sequence access

### 3. GitRef / BlobName (crates/auths-id/src/storage/layout.rs)

**GitRef:**
- `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`
- `#[serde(transparent)]`
- Methods: `new(impl Into<String>)`, `as_str() -> &str`, `join(&str) -> GitRef`
- Impls: `Display`, `Deref<Target=str>`

**BlobName:**
- `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`
- `#[serde(transparent)]`
- Methods: `new(impl Into<String>)`, `as_str() -> &str`
- Impls: `Display`, `Deref<Target=str>`

**StorageLayoutConfig fields:**
- `identity_ref: String` → `GitRef`
- `device_attestation_prefix: String` → `GitRef`
- `attestation_blob_name: String` → `BlobName`
- `identity_blob_name: String` → `BlobName`

Update `StorageLayoutConfig` presets: `Default::default()` (standard auths layout), `radicle()` (Radicle-compatible), `gitoxide()` (gitoxide-compatible).

Files affected:
- `crates/auths-id/src/storage/layout.rs` — definitions and presets
- `crates/auths-id/src/storage/git_storage.rs` — uses layout config
- `crates/auths-id/src/storage/mod.rs` — may re-export

### 4. WitnessConfig.witness_urls (crates/auths-id/src/witness_config.rs)

Replace `Vec<String>` with `Vec<url::Url>`:
- Add `url` crate as explicit dependency of auths-id (even if transitive via reqwest — explicit is better for `pub` API types)
- `url::Url` already implements `Serialize`/`Deserialize`
- `WitnessConfig` also has fields: `threshold: usize`, `timeout_ms: u64`, `policy: WitnessPolicy` (enum: Enforce, Warn, Skip) — these stay unchanged
- Update all WitnessConfig construction sites

Files affected:
- `crates/auths-id/src/witness_config.rs`
- `crates/auths-id/Cargo.toml` — add url dependency if needed
- `crates/auths-sdk/src/types.rs` — if WitnessConfig is exposed there

### 5. ReceiptVerificationResult typed fields (crates/auths-id/src/policy/mod.rs)

- `Duplicity { event_a: String, event_b: String }` → `{ event_a: Said, event_b: Said }`
- `InvalidSignature { witness_did: String }` → `{ witness_did: DeviceDID }`
- `Said` already exists in auths-verifier (re-exported from keri module)
- `DeviceDID` already exists in auths-verifier types

### Quick commands

```bash
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-verifier --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `SealType` enum with `#[serde(rename_all = "kebab-case")]`
- [ ] `KeriSequence(u64)` with hex serde, `SequenceParseError` deleted
- [ ] `GitRef` with `#[serde(transparent)]`, `join()` method
- [ ] `BlobName` with `#[serde(transparent)]`
- [ ] `StorageLayoutConfig` uses `GitRef`/`BlobName`
- [ ] `WitnessConfig.witness_urls` is `Vec<url::Url>`
- [ ] `ReceiptVerificationResult` uses `Said` and `DeviceDID`
- [ ] `cargo build -p auths-id --all-features` passes
- [ ] `cargo nextest run --workspace` passes

## Done summary
Completed all 5 sections: SealType enum, KeriSequence newtype with infallible sequence(), GitRef/BlobName newtypes with Deref/From/PartialEq impls, WitnessConfig witness_urls Vec<Url>, ReceiptVerificationResult typed fields (Said, DeviceDID). 31 files changed across auths-id, auths-cli, auths-sdk, auths-storage, auths-test-utils.
## Evidence
- Commits:
- Tests:
- PRs:
