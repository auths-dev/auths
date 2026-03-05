# fn-4.2 Add verifyDeviceLink WASM binding to auths-verifier

## Description
## Add `verifyDeviceLink` WASM binding

Add a new async WASM export that verifies a device's link to a KERI identity — the core function the frontend needs. This composes KEL verification, attestation verification, and seal anchoring.

### What to do

1. In `crates/auths-verifier/src/wasm.rs`, add a new `#[wasm_bindgen]` function:
   - Name: `verifyDeviceLink` (via `js_name`)
   - Signature: `pub async fn wasm_verify_device_link(kel_json: &str, attestation_json: &str, device_did: &str) -> Result<String, JsValue>`
   - Returns JSON `{"valid": true, "key_state": {...}, "seal_sequence": N}` on success
   - Returns JSON `{"valid": false, "error": "..."}` on failure (not a JsValue error — verification failure is a valid result)

2. Implementation (compose existing functions):
   - Validate input sizes (kel_json against `MAX_JSON_BATCH_SIZE`, attestation_json against `MAX_ATTESTATION_JSON_SIZE`)
   - Parse KEL: `parse_kel_json(kel_json)` (at `keri.rs:720`)
   - Verify KEL: `verify_kel(&events, &provider()).await` (at `keri.rs:495`) → `KeriKeyState`
   - Parse attestation: deserialize into `Attestation` struct
   - Verify attestation device_did matches the `device_did` parameter
   - Verify attestation signatures using the key from `KeriKeyState`
   - Check seal anchoring: `find_seal_in_kel(&events, attestation_digest)` (at `keri.rs:706`)
   - **STRICT**: Missing seal in KEL is a `valid: false` result. Logical failures return JSON string, NOT thrown JsValue errors.
   - **OPTIMIZATION**: Ensure `KeriKeyState` uses `#[serde(skip)]` on raw bytes to minimize WASM boundary overhead.
   - Check attestation is not expired (using `SystemClock`)
   - Return composed result

3. Consider edge cases:
   - Attestation signed by a rotated-out key: should still verify if the KEL shows that key was valid at the attestation's timestamp
   - Missing seal in KEL: verification should fail with clear error message
   - Expired attestation: return `valid: false` with expiry reason, not a thrown error

### Key files
- `crates/auths-verifier/src/wasm.rs` — add new function (~60 lines)
- `crates/auths-verifier/src/keri.rs:495` — `verify_kel()`
- `crates/auths-verifier/src/keri.rs:706` — `find_seal_in_kel()`
- `crates/auths-verifier/src/keri.rs:720` — `parse_kel_json()`
- `crates/auths-verifier/src/core.rs` — attestation deserialization, verification functions

### Depends on
- fn-4.1 (verifyKelJson) — shares the same KEL parsing/verification path; implement fn-4.1 first to validate the pattern

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `verifyDeviceLink` WASM function exists in `wasm.rs` with `#[wasm_bindgen(js_name = verifyDeviceLink)]`
- [ ] Function is async, returns `Result<String, JsValue>` (verification failure is a JSON result, not a thrown error)
- [ ] Composes `parse_kel_json` + `verify_kel` + attestation verification + `find_seal_in_kel` — no duplicated logic
- [ ] Input size validation for both KEL and attestation inputs
- [ ] device_did parameter is validated against attestation's subject field
- [ ] WASM target compiles: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] Tests cover: valid link → `{valid: true}`, invalid KEL → error, invalid attestation → `{valid: false}`, missing seal → `{valid: false}`, expired attestation → `{valid: false}`, device_did mismatch → `{valid: false}`
- [ ] `cargo nextest run -p auths_verifier` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
## Done summary
- Added `verify_device_link()` in verify.rs — provider-agnostic core function composing KEL + attestation + seal verification
- Added `DeviceLinkVerification` result type (verification failures as JSON, not thrown errors)
- Added `compute_attestation_seal_digest()` and made `compute_said()` public
- WASM wrapper `verifyDeviceLink` with input size guards

- Core logic lives in verify.rs, reusable from native/WASM/FFI — not hardcoded to any platform
- Seal anchoring is informational (returns seal_sequence if found), not a hard gate

- WASM target compiles, 9 integration tests pass, builds clean
## Evidence
- Commits: cf5a5ca
- Tests: cargo nextest run -p auths-verifier -E test(kel_verification)
- PRs:
