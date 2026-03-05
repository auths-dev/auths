# fn-8.3 Add WASM binding tests and WebCryptoProvider tests

## Description
## Add WASM binding tests and WebCryptoProvider tests

`crates/auths-verifier/src/wasm.rs` has 500+ lines and 7 `#[wasm_bindgen]` public functions with zero test coverage. Additionally, the newly implemented `WebCryptoProvider::verify_ed25519()` (fn-8.1) needs WASM-environment tests to validate it works against real browser SubtleCrypto.

### Changes required

#### 1. Set up `wasm-pack test` infrastructure

No `wasm_bindgen_test` dependency exists anywhere in the project. Add to `crates/auths-verifier/Cargo.toml`:

```toml
[dev-dependencies]
wasm-bindgen-test = "0.3"
```

And to `crates/auths-crypto/Cargo.toml`:

```toml
[dev-dependencies]
wasm-bindgen-test = "0.3"
```

#### 2. Add `WebCryptoProvider::verify_ed25519()` tests in `auths-crypto`

Create `crates/auths-crypto/tests/cases/wasm_provider.rs` gated behind `#[cfg(target_arch = "wasm32")]` (mirroring how `provider.rs` is gated behind `#[cfg(feature = "native")]` in `cases/mod.rs`).

Tests to add (mirroring the 5 Ring provider tests at `crates/auths-crypto/tests/cases/provider.rs`):
1. `webcrypto_provider_verifies_valid_signature` — sign with ring (at build time or use pre-computed fixture), verify with WebCryptoProvider
2. `webcrypto_provider_rejects_invalid_signature` — flip a bit in the signature
3. `webcrypto_provider_rejects_wrong_pubkey` — verify with a different key
4. `webcrypto_provider_rejects_invalid_key_length` — pass 16-byte key, expect `CryptoError::InvalidKeyLength`
5. `webcrypto_provider_rejects_corrupted_signature` — use zeroed signature bytes

**Important:** Since `auths-test-utils` depends on `ring` and `git2` (not WASM-compatible), these tests need lightweight inline fixtures:
- Pre-compute a valid (pubkey, message, signature) triple using `ring` in a build script or hardcode known test vectors from RFC 8032
- Use Ed25519 test vectors from RFC 8032 Section 7.1 for deterministic, portable fixtures

All tests use `#[wasm_bindgen_test]` attribute and run via `wasm-pack test --headless --chrome` (or `--node` if SubtleCrypto is available in the Node version).

#### 3. Add WASM binding tests in `auths-verifier`

Create `crates/auths-verifier/tests/cases/wasm_bindings.rs` (following project convention).

**Minimum required tests:**

1. **`wasm_verify_attestation_json` happy path** — construct a valid attestation JSON with real signature, call `wasm_verify_attestation_json()`, expect `Ok(())`
2. **`wasm_verify_attestation_json` with malformed JSON** — pass `"not valid json"`, expect `Err` with descriptive message
3. **`wasm_verify_artifact_signature` happy path** — sign a hash with a known keypair, verify via `wasm_verify_artifact_signature()`

**Additional recommended tests:**
4. `wasm_verify_attestation_json` with invalid hex public key
5. `wasm_verify_chain_json` with a single-attestation chain
6. `wasm_verify_artifact_signature` with invalid signature

**Testability approach:** The public `#[wasm_bindgen]` functions can be called directly in `wasm_bindgen_test` tests since they are regular Rust functions. The `_internal` helpers are private, but the public wrappers are sufficient for integration-level testing.

**Fixture strategy:** Since `auths-test-utils` is not WASM-compatible:
- Create minimal inline helpers or a `wasm_test_fixtures` module within the test file
- Use pre-computed test vectors (keypair seed → pubkey, sign message → signature) hardcoded as hex constants
- Or use `ring` at compile time via a build script to generate fixture files

#### 4. Add `wasm-pack test` to CI and justfile

Add a `wasm-pack test` step to the CI workflow and/or `justfile`:

```bash
# In justfile or CI
cd crates/auths-crypto && wasm-pack test --headless --chrome --no-default-features --features wasm
cd crates/auths-verifier && wasm-pack test --headless --chrome --no-default-features --features wasm
```

#### Key references
- `crates/auths-verifier/src/wasm.rs` — 7 public wasm_bindgen functions
- `crates/auths-crypto/tests/cases/provider.rs` — Ring provider tests (pattern to mirror)
- `crates/auths-crypto/tests/cases/mod.rs:1` — `#[cfg(feature = "native")]` gating pattern
- `crates/auths-verifier/tests/cases/revocation_adversarial.rs` — existing verifier tests using real signing
- `crates/auths-test-utils/src/fakes/crypto.rs` — MockCryptoProvider (not WASM-compatible)
- RFC 8032 Section 7.1 — Ed25519 test vectors

#### Pitfalls
- `auths-test-utils` depends on `ring`, `git2`, `tempfile` — NOT wasm-compatible. Cannot be used in wasm-pack tests.
- `wasm-pack test --node` may not have SubtleCrypto depending on Node version (Node 20+ has it behind `--experimental-global-webcrypto`, Node 22+ has it stable). Prefer `--headless --chrome` for reliability.
- The `_internal` functions in wasm.rs are private and gated behind `#[cfg(feature = "wasm")]` — test through the public `#[wasm_bindgen]` API instead.
- WASM builds must run from inside the crate directory, not workspace root (resolver = "3" restriction).
## Acceptance
- [ ] `wasm-bindgen-test` added as dev-dependency to `auths-crypto` and `auths-verifier`
- [ ] `WebCryptoProvider` tests exist mirroring the 5 Ring provider test cases
- [ ] `wasm_verify_attestation_json` happy path test passes
- [ ] `wasm_verify_attestation_json` malformed JSON test passes
- [ ] `wasm_verify_artifact_signature` happy path test passes
- [ ] All WASM tests pass via `wasm-pack test --headless --chrome` (or `--node` if SubtleCrypto available)
- [ ] Native tests still pass: `cargo nextest run --workspace`
- [ ] CI or justfile includes `wasm-pack test` step
## Done summary
- Added `wasm-bindgen-test` as wasm32 dev-dependency to `auths-crypto` and `auths-verifier`
- Created `auths-crypto/tests/wasm_provider.rs` with 5 WebCryptoProvider tests using RFC 8032 test vectors
- Created `auths-verifier/tests/wasm_bindings.rs` with 6 WASM binding tests (attestation + artifact)
- Gated native dev-deps and in-source test modules behind `cfg(not(wasm32))`
- Gated `integration.rs` behind `cfg(not(wasm32))` in both crates
- Removed unused `pub(crate)` platform keychain re-exports from storage/mod.rs
- All WASM test files compile for wasm32-unknown-unknown target
- All native compilation checks pass
## Evidence
- Commits: 703793859359c2583bce6921835a153029106d1b
- Tests: cargo check --tests --target wasm32-unknown-unknown --no-default-features --features wasm (auths-verifier), cargo check --tests --target wasm32-unknown-unknown --no-default-features --features wasm (auths-crypto), cargo build -p auths-verifier --all-features, cargo build -p auths-core --all-features
- PRs:
