# fn-4.1 Add verifyKelJson WASM binding to auths-verifier

## Description
## Add `verifyKelJson` WASM binding

Add a new async WASM export that takes a KEL JSON string and returns the verified key state.

### What to do

1. In `crates/auths-verifier/src/wasm.rs`, add a new `#[wasm_bindgen]` function:
   - Name: `verifyKelJson` (via `js_name`)
   - Signature: `pub async fn wasm_verify_kel_json(kel_json: &str) -> Result<String, JsValue>`
   - Returns JSON-serialized `KeriKeyState` on success, `JsValue` error on failure

2. Implementation (reuse existing code, do NOT reimplement):
   - Validate input size against `MAX_JSON_BATCH_SIZE` (at `core.rs:17`)
   - Call `parse_kel_json(kel_json)` (at `keri.rs:720`) to parse events
   - Call `verify_kel(&events, &provider()).await` (at `keri.rs:495`) to verify
   - Serialize the resulting `KeriKeyState` to JSON and return

3. Follow existing patterns:
   - Use `console_log!` for debug logging (behind `#[cfg(feature = "wasm")]`)
   - Convert errors via `JsValue::from_str(&format!(...))` (matching existing pattern)
   - Add input size guard matching `wasm_verify_chain_json` pattern

4. Add unit test in `crates/auths-verifier/tests/cases/` for the new binding logic (test the underlying composition, not the WASM export itself)

### Key files
- `crates/auths-verifier/src/wasm.rs` — add new function (~30 lines)
- `crates/auths-verifier/src/keri.rs:495` — `verify_kel()` to reuse
- `crates/auths-verifier/src/keri.rs:720` — `parse_kel_json()` to reuse
- `crates/auths-verifier/src/core.rs:13-17` — size constants

### Reuse points
- `verify_kel()` — DO NOT reimplement KEL validation
- `parse_kel_json()` — DO NOT reimplement KEL parsing
- `provider()` helper at `wasm.rs` top — reuse for CryptoProvider
- `console_log!` macro — reuse for debug output

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `verifyKelJson` WASM function exists in `wasm.rs` with `#[wasm_bindgen(js_name = verifyKelJson)]`
- [ ] Function is async and returns `Result<String, JsValue>`
- [ ] Input size validation matches existing pattern (MAX_JSON_BATCH_SIZE)
- [ ] Reuses `parse_kel_json()` and `verify_kel()` — no duplicated logic
- [ ] WASM target compiles: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] Unit test covers: valid KEL → returns key state JSON, invalid KEL → returns error, oversized input → returns error
- [ ] `cargo nextest run -p auths_verifier` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
## Done summary
- Added `Serialize` derive to `KeriKeyState` with `#[serde(skip)]` on raw bytes field
- Added `verifyKelJson` async WASM binding composing `parse_kel_json` + `verify_kel`
- Added input size validation against `MAX_JSON_BATCH_SIZE`

- Enables frontend to verify KEL integrity client-side via WASM
- Follows existing WASM binding patterns (console_log, JsValue errors, size guards)

- WASM target compiles: `cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- 6 new integration tests pass (serialization, error paths)
- `cargo clippy --all-targets --all-features -- -D warnings` passes
## Evidence
- Commits: 86bf7a531a3c5684f63dfa5dbd214e6895eb2852
- Tests: cargo nextest run -p auths-verifier, cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
- PRs:
