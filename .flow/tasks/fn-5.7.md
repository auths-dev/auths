# fn-5.7 WASM Binding Audit for wasm_verify_device_link

## Description
## WASM Binding Audit for wasm_verify_device_link

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-verifier/src/wasm.rs`

### Design Principle
Mismatched JSON field names between Rust and TypeScript are the **most frequent cause of WASM integration bugs**. This audit must exhaustively verify every field serialized across the boundary.

### Context
`wasm_verify_device_link` at line 369-411 is WASM-exported as `verifyDeviceLink`. It takes `kel_json`, `attestation_json`, `device_did` strings and returns JSON-serialized `DeviceLinkVerification`.

The TypeScript wrapper at `packages/auths-verifier-ts/src/index.ts:269-285` calls this and returns `DeviceLinkResult`.

### What to do
1. Compare `DeviceLinkVerification` fields (verify.rs:205-240) with `DeviceLinkResult` interface (types.ts:1-98) — check every field name, type, and optionality
2. Verify JSON field names match exactly (check `#[serde(rename)]` and `#[serde(rename_all)]` annotations)
3. Verify `KeriKeyState` serialization: check if `#[serde(skip)]` on `current_key: Vec<u8>` (keri.rs:458) causes the TS side to get `undefined` where it expects data
4. Test WASM compilation: `cargo check -p auths-verifier --target wasm32-unknown-unknown --no-default-features --features wasm`
5. Document any mismatches and fix them
6. Verify the `Attestation` JSON input format matches what radicle-httpd's attestations endpoint will return (fn-5.10 depends on this contract)

### Key files
- `auths-verifier/src/wasm.rs:369-411` — WASM function
- `auths-verifier/src/verify.rs:205-240` — `DeviceLinkVerification` struct
- `auths-verifier/src/verify.rs:259-289` — `verify_device_link` core logic
- `auths-verifier/src/keri.rs:458` — `KeriKeyState` with `#[serde(skip)]`
- `packages/auths-verifier-ts/src/types.ts:1-98` — TypeScript interfaces
- `packages/auths-verifier-ts/src/index.ts:269-285` — TS wrapper
## WASM Binding Audit for wasm_verify_device_link

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-verifier/src/wasm.rs`

### Context
`wasm_verify_device_link` at line 369-411 is WASM-exported as `verifyDeviceLink`. It takes `kel_json`, `attestation_json`, `device_did` strings and returns JSON-serialized `DeviceLinkVerification`.

The TypeScript wrapper at `packages/auths-verifier-ts/src/index.ts:269-285` calls this and returns `DeviceLinkResult`.

### What to do
1. Compare `DeviceLinkVerification` fields (verify.rs:205-240) with `DeviceLinkResult` interface (types.ts:1-98)
2. Verify JSON field names match exactly (check `#[serde(rename)]` annotations)
3. Verify `KeriKeyState` serialization: check if `#[serde(skip)]` on `current_key: Vec<u8>` (keri.rs:458) causes the TS side to get `undefined` where it expects data
4. Test WASM compilation: `cargo check -p auths-verifier --target wasm32-unknown-unknown --no-default-features --features wasm`
5. Document any mismatches and fix them
6. Verify the `Attestation` JSON input format matches what radicle-httpd's attestations endpoint will return

### Key files
- `auths-verifier/src/wasm.rs:369-411` — WASM function
- `auths-verifier/src/verify.rs:205-240` — `DeviceLinkVerification` struct
- `auths-verifier/src/verify.rs:259-289` — `verify_device_link` core logic
- `auths-verifier/src/keri.rs:458` — `KeriKeyState` with `#[serde(skip)]`
- `packages/auths-verifier-ts/src/types.ts:1-98` — TypeScript interfaces
- `packages/auths-verifier-ts/src/index.ts:269-285` — TS wrapper
## Acceptance
- [ ] All fields in Rust `DeviceLinkVerification` serialize to match TS `DeviceLinkResult`
- [ ] No silent field drops via `#[serde(skip)]` that the TS side expects
- [ ] `cargo check -p auths-verifier --target wasm32-unknown-unknown --no-default-features --features wasm` passes
- [ ] Input format for `attestation_json` is documented and matches httpd response format
## Done summary
- Audited all field names between Rust `DeviceLinkVerification` and TS `DeviceLinkResult` — exact match
- Audited `KeriKeyState` fields — all match; `#[serde(skip)]` on `current_key: Vec<u8>` is correct (TS doesn't expect raw bytes, only `current_key_encoded`)
- Verified `Attestation` input format matches TS interface
- No mismatches found — no code changes required

Why:
- WASM boundary field mismatches are the most common integration bug; this audit confirms correctness

Verification:
- `cargo check -p auths-verifier --target wasm32-unknown-unknown --no-default-features --features wasm` passes
- Manual field-by-field comparison confirms exact match
## Evidence
- Commits:
- Tests: cargo check --target wasm32-unknown-unknown
- PRs:
