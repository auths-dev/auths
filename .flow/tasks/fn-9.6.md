# fn-9.6 Fix remaining unwraps in auths-core (crypto, config, witness, FFI)

## Description
## Fix remaining unwraps in auths-core (crypto, config, witness, FFI)

After mutex unwraps (fn-9.5) and anyhow removal (fn-9.2), fix all remaining `unwrap()`/`expect()` in auths-core non-test code.

### Categories

1. **Crypto conversions** (`src/crypto/encryption.rs:256,258,260`, `src/crypto/secp256k1.rs:45,94`):
   - Byte slice `try_into().unwrap()` for `u32::from_le_bytes` — structurally guaranteed after length validation
   - `SigningKey::from_bytes(field_bytes).expect(...)` — key bytes validated upstream
   - Policy: `#[allow(clippy::expect_used)]` with `// SAFETY:` comment

2. **Static runtime creation** (`src/crypto/provider_bridge.rs:18`):
   - `.expect("failed to create fallback crypto runtime")` in `Lazy::new`
   - Policy: `#[allow(clippy::expect_used)]` with `// SAFETY: unrecoverable — process cannot function without runtime`

3. **API FFI** (`src/api/ffi.rs:200`):
   - `.expect("FFI string inputs must be valid UTF-8")` — deprecated function
   - Replace with proper error return or `#[allow]` noting deprecation

4. **API runtime** (`src/api/runtime.rs:590`):
   - `.expect("Length checked")` — seed_bytes length validated above
   - `#[allow]` with SAFETY comment or convert to `?`

5. **Witness server** (`src/witness/server.rs:212,218,228,415`):
   - `.expect("receipt serialization should not fail")` — serde_json on known-good struct
   - `.expect("signing should not fail with valid seed")` — crypto op with validated input
   - `.as_object_mut().unwrap()` — JSON manipulation on known object
   - Convert to `?` propagation returning appropriate error/status codes

### Files to modify
- `crates/auths-core/src/crypto/encryption.rs`
- `crates/auths-core/src/crypto/secp256k1.rs`
- `crates/auths-core/src/crypto/provider_bridge.rs`
- `crates/auths-core/src/api/ffi.rs`
- `crates/auths-core/src/api/runtime.rs`
- `crates/auths-core/src/witness/server.rs`

### Smoke test
```bash
cargo nextest run -p auths_core
cargo clippy -p auths_core --all-targets --all-features -- -D warnings
```
## Acceptance
- [ ] All remaining `unwrap()`/`expect()` in `crates/auths-core/src/` (outside mutex locks) replaced or annotated
- [ ] Every `#[allow]` has a corresponding `// SAFETY:` comment
- [ ] Witness server error paths return proper HTTP status codes instead of panicking
- [ ] `cargo nextest run -p auths_core` passes
- [ ] `cargo clippy -p auths_core --all-targets --all-features -- -D warnings` passes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
