# v0.1.0 Launch Plan

> Audit date: 2026-03-03
> Current version: 0.0.1-rc.5
> Target version: 0.1.0

This plan captures everything that must, should, or could be addressed before
cutting the first public release. Items are organized by priority tier, with
effort estimates and owner suggestions.

---

## Executive Summary

The codebase is architecturally sound: crate boundaries are clean, the
cryptographic primitives are well-chosen (ring, blake3, argon2), and the
documentation is unusually mature for a pre-1.0 project. The main risks are:

1. **WASM verification is broken** — `WebCryptoProvider::verify_ed25519()` is a
   stub that will silently fail at runtime
2. **Error handling policy is not enforced** — 16 files in auths-id use `anyhow`
   despite the documented ban on it in domain crates
3. **FFI/WASM boundaries have zero dedicated tests** — 950+ lines of binding
   code with no smoke tests
4. **Public API surface leaks internals** — `pub use api::*` and
   `pub use storage::*` in auths-core expose platform-specific keychains

None of these are architectural problems. They are all fixable with targeted
work across 2-3 sprints.

---

## Tier 0: Launch Blockers

These must be resolved before tagging v0.1.0. A release with any of these
creates real risk of broken consumers or security issues.

### 0.1 — Implement `WebCryptoProvider::verify_ed25519()`

**File:** `crates/auths-crypto/src/webcrypto_provider.rs:38`

The WASM crypto provider's `verify_ed25519()` is a TODO stub. Any WASM consumer
calling verification will get incorrect results. This is the single highest
priority item because it blocks the entire WASM story — browser SDKs, mobile
WebView integrations, and the npm package.

**Fix:** Implement using `web-sys` SubtleCrypto API

**Effort:** 1-2 days
**Owner:** Crypto lead

### 0.2 — Seal the public API surface of auths-core

**File:** `crates/auths-core/src/lib.rs:80-85`

`pub use api::*` and `pub use storage::*` export every platform-specific
keychain implementation (MacOSKeychain, WindowsCredentialStorage,
AndroidKeystoreStorage, IOSKeychain, etc.) as top-level public API. This means:

- Consumers can depend on internal types that will change
- Semver violations become inevitable on any internal refactor
- docs.rs will show noise that confuses SDK consumers

**Fix:**
- Replace wildcard re-exports with explicit `pub use` of the types consumers
  actually need
- Make platform keychain structs `pub(crate)` — they should only be accessed
  through `get_platform_keychain()`
- Audit `KeriSequence` export from auths-id (implementation detail of serde
  serialization, not a consumer type)

**Effort:** 1 day
**Owner:** Core maintainer

### 0.3 — Remove cross-crate re-export of `IdentityDID` from auths-core

**File:** `crates/auths-core/src/storage/keychain.rs:36`

`pub use auths_verifier::IdentityDID` creates a confusing re-export chain where
consumers can import the same type from two different crates. This will cause
type mismatch errors when consumers use both crates.

**Fix:** Remove the re-export. Consumers should import `IdentityDID` from
`auths_verifier` directly.

**Effort:** 2 hours (+ fixing downstream imports)
**Owner:** Core maintainer

### 0.4 — Add FFI smoke tests

**File:** `crates/auths-verifier/src/ffi.rs` (450+ lines, zero tests)

The FFI boundary is the interface for mobile apps (Swift, Kotlin, C). It has:
- Null pointer handling
- Buffer size validation
- Error code mapping
- Panic catch_unwind wrappers

None of this is tested. A single regression here crashes the host process.

**Minimum viable test set:**
- `ffi_verify_attestation_json` with valid input returns `VERIFY_SUCCESS`
- `ffi_verify_attestation_json` with null pointer returns error code (not crash)
- `ffi_verify_chain_json` with valid KEL returns success
- `ffi_verify_chain_json` with empty input returns error code

**Effort:** 1-2 days
**Owner:** Verifier maintainer

### 0.5 — Add WASM binding tests

**File:** `crates/auths-verifier/src/wasm.rs` (500+ lines, zero tests)

Same story as FFI. The WASM bindings are the interface for browser and Node.js
consumers. At minimum, add `wasm-pack test` coverage for:
- `wasm_verify_attestation_json` happy path
- `wasm_verify_attestation_json` with malformed JSON
- `wasm_verify_artifact_signature` happy path

**Effort:** 1-2 days (requires wasm-pack test infrastructure)
**Owner:** Verifier maintainer

---

## Tier 1: Should Fix Before Launch

These don't break consumers but represent policy violations, test gaps, or
technical debt that will compound quickly post-launch.

### 1.1 — Migrate auths-id from anyhow to thiserror

**16 files** in auths-id use `anyhow::Result` as return types. This violates
the documented policy that domain crates use thiserror only. The files:

```
src/storage/layout.rs
src/identity/rotate.rs
src/identity/initialize.rs
src/identity/helpers.rs
src/attestation/verify.rs
src/attestation/json_schema_encoder.rs
src/attestation/load.rs
src/attestation/encoders.rs
src/attestation/export.rs
src/storage/git_refs.rs
src/storage/attestation.rs
src/storage/receipts.rs
src/storage/identity.rs
src/storage/indexed.rs
src/storage/keri.rs
src/freeze.rs
```

**Impact:** Consumers of auths-id get `anyhow::Error` instead of matchable
variants. This makes error handling in downstream crates fragile.

**Fix:** Define domain-specific error enums (IdentityError, StorageError,
AttestationError) with thiserror, then migrate each file. This is the largest
single item on this list.

**Effort:** 3-5 days
**Owner:** Core maintainer

### 1.2 — Remove anyhow from auths-core

**Files:**
- `src/api/runtime.rs:46` — `use anyhow::Context` (in macOS SSH agent code)
- `src/storage/keychain.rs:6` — `use anyhow::Result`

Smaller scope than 1.1 since the anyhow usage is confined to 2 files.

**Effort:** 1 day
**Owner:** Core maintainer

### 1.3 — Replace `static mut JSON_MODE` with AtomicBool

**File:** `crates/auths-cli/src/ux/format.rs:16`

The CLI uses `static mut` with `unsafe` access for the global JSON output mode
flag. While safe in practice (single-threaded CLI), it's unnecessary — Rust's
`AtomicBool` provides the same performance with zero `unsafe`.

```rust
// Before
static mut JSON_MODE: bool = false;

// After
static JSON_MODE: AtomicBool = AtomicBool::new(false);
```

**Effort:** 1 hour
**Owner:** CLI maintainer

### 1.4 — Audit `.expect()` calls in production code

Counts from audit:
- auths-core: 45 `.expect()` calls
- auths-id: 15 `.expect()` calls
- auths-sdk: 4 `.expect()` calls (builder validation — acceptable)

Many are in code paths that handle git operations, byte array conversions, and
JSON serialization where failure indicates a bug rather than bad input. These
are candidates for:
- Converting to `?` with proper error context
- Or keeping with a clear invariant comment explaining why panic is correct

**Effort:** 2-3 days (triage + fix)
**Owner:** Core maintainer

### 1.5 — Add MSRV validation to CI

The workspace declares `rust-version = "1.93"` but CI only tests on `stable`.
If a contributor accidentally uses a 1.94+ feature, CI won't catch it and
consumers on 1.93 will get build failures.

**Fix:** Add a CI job:
```yaml
msrv:
  name: MSRV check
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@1.93
    - run: cargo check --workspace
```

**Effort:** 30 minutes
**Owner:** CI/infra

### 1.6 — Add `cargo audit` to CI

The workspace has `deny.toml` for license and dependency bans, but `cargo audit`
(which checks RUSTSEC advisories) is not in CI. The audit found:

- **RUSTSEC-2023-0071**: RSA timing side-channel in `rsa v0.9.10` (pulled by
  `ssh-key`). No upstream fix available yet. Auths uses Ed25519 exclusively for
  its own keys, so this only affects SSH key import/export workflows. Document
  the advisory and its limited impact.
- **RUSTSEC-2025-0134**: rustls-pemfile issue (only affects optional
  witness-server feature).

**Fix:** Add `cargo audit` step to CI. Add an `audit.toml` to document
accepted advisories with rationale.

**Effort:** 1 hour
**Owner:** CI/infra

### 1.7 — Test attestation expiration and timestamp skew

**Gap:** `MAX_SKEW_SECS = 5min` is defined in
`crates/auths-id/src/attestation/verify.rs` but has zero dedicated tests. The
attestation expiration logic is tested indirectly through auths-radicle but
not directly in auths-verifier where verification actually happens.

**Tests needed:**
- Attestation exactly at expiration boundary (now == expires_at)
- Attestation 1 second past expiration
- Attestation with timestamp in the future (within skew)
- Attestation with timestamp in the future (beyond skew)

**Effort:** Half day
**Owner:** Verifier maintainer

### 1.8 — Test key rotation edge cases

**Gaps identified:**
- No test for double rotation (same sequence attempted twice)
- No test for rotation after interaction events
- No test for rotation failure recovery (partially committed)

**Effort:** 1 day
**Owner:** KERI/identity maintainer

---

## Tier 2: Nice To Have Before Launch

These improve polish and consumer experience but are not blocking.

### 2.1 — Clean up `#[allow(dead_code)]` annotations

24 instances across the workspace, concentrated in:
- `auths-storage/src/git/` (10 instances) — suggests incomplete refactoring
- `auths-core/src/witness/` (4 instances) — possibly unused witness code

**Action:** Audit each one. If the code is truly unused, delete it. If it's
used cross-crate (the lint can't see), add a comment explaining why.

**Effort:** Half day

### 2.2 — Add keywords/categories to remaining Cargo.toml files

Missing from: auths-sdk, auths-crypto, auths-telemetry, auths-storage,
auths-infra-git, auths-infra-http.

Improves discoverability on crates.io. Low effort, high value for adoption.

**Effort:** 30 minutes

### 2.3 — Add crate-level rustdoc to infrastructure crates

`auths-infra-git` and `auths-infra-http` have minimal or no `//!` crate docs.
These are internal crates so the impact is lower, but docs.rs will still
generate pages for them.

**Effort:** 1 hour

### 2.4 — Migrate `reqwest` out of auths-sdk

`deny.toml` already tracks this as refactor debt. The SDK directly uses
`reqwest` instead of going through `auths-infra-http`. This violates the
architectural boundary where HTTP clients are confined to adapter crates.

**Effort:** 1-2 days (introduce an HTTP port trait, move impl to infra crate)

### 2.5 — Add property-based tests to auths-id KERI validation

Currently proptest is only used in auths-verifier. The KERI event validation
in auths-id is a prime candidate for fuzzing — malformed events, out-of-order
sequences, and adversarial signatures should all be tested with generated
inputs.

**Effort:** 2 days

### 2.6 — Run `cargo publish --dry-run` for all stable crates

Before tagging, verify every crate passes the crates.io packaging checks:

```bash
for crate in auths-crypto auths-verifier auths-core auths-id auths-policy \
             auths-index auths-telemetry auths-sdk auths-storage \
             auths-infra-git auths-infra-http auths-cli; do
  echo "--- $crate ---"
  cargo publish --dry-run -p $crate 2>&1 | tail -5
done
```

This catches: missing fields, files too large, undeclared dependencies,
path-only deps without version, etc.

**Effort:** 1 hour (fix issues as found)

---

## Tier 3: Post-Launch (v0.1.x Patch Series)

Track these but don't block the release.

### 3.1 — Complete anyhow-to-thiserror migration in SDK error types

The `StorageError(#[source] anyhow::Error)` and
`NetworkError(#[source] anyhow::Error)` variants in
`crates/auths-sdk/src/error.rs` are documented as transitional. Replace with
domain-specific variants and remove the `map_storage_err()` helpers.

### 3.2 — Monitor RUSTSEC-2023-0071 (RSA timing)

The `rsa` crate pulled by `ssh-key` has a known timing side-channel. No
upstream fix exists. Monitor for an update and bump `ssh-key` when available.
Impact is limited since Auths uses Ed25519 exclusively for its own operations.

### 3.3 — Reduce getrandom version spread

Currently 3 versions in the lockfile (0.2, 0.3, 0.4) due to `ring` pulling
0.2 and WASM needing 0.4. This is correctly managed with feature flags but
adds binary size. When `ring` updates its getrandom dependency, consolidate.

### 3.4 — Cross-crate failure mode tests

No tests currently verify that an identity created in auths-id and
intentionally corrupted will fail cleanly in auths-verifier. Add integration
tests that exercise the full create-corrupt-verify pipeline.

### 3.5 — Expand adversarial attestation tests

Current adversarial tests cover revocation tampering and issuer signature
forgery. Missing:
- Device signature tampering (valid issuer sig, invalid device sig)
- Cross-signature attacks (swap issuer and device signatures)
- Capability escalation (modify capabilities array, verify signature rejects)

---

## Release Checklist

When all Tier 0 items are resolved and Tier 1 items are triaged:

```
[ ] All Tier 0 items resolved
[ ] cargo fmt --check --all passes
[ ] cargo clippy --all-targets --all-features -- -D warnings passes
[ ] cargo nextest run --workspace passes
[ ] cargo test --all --doc passes
[ ] WASM check passes (cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm)
[ ] cargo publish --dry-run passes for all stable crates
[ ] Bump workspace version from 0.0.1-rc.5 to 0.1.0
[ ] Update CHANGELOG.md with ## [0.1.0] section
[ ] Tag: git tag -a v0.1.0 -m "v0.1.0"
[ ] Publish crates in dependency order:
    1. auths-crypto
    2. auths-verifier
    3. auths-core
    4. auths-policy
    5. auths-telemetry
    6. auths-id
    7. auths-index
    8. auths-storage, auths-infra-git, auths-infra-http
    9. auths-sdk
    10. auths-cli
```

---

## Effort Summary

| Tier | Items | Estimated Effort |
|------|-------|-----------------|
| 0 — Blockers | 5 | 4-7 days |
| 1 — Should fix | 8 | 8-12 days |
| 2 — Nice to have | 6 | 4-6 days |
| 3 — Post-launch | 5 | Ongoing |

**Critical path:** Tier 0 items are independent of each other and can be
parallelized across 2-3 engineers. The WASM crypto stub (0.1) and FFI tests
(0.4, 0.5) are the most time-sensitive since they gate the embedding story.
The API surface cleanup (0.2, 0.3) is the most semver-sensitive since public
API changes after 0.1.0 require a minor version bump.


---

## Launch workflow

Step 1: Login
```
cargo login
```

# Paste your crates.io API token

Step 2: Dry run first

Run this to catch packaging issues before publishing anything:

```bash
for crate in auths-crypto auths-policy auths-telemetry auths-index \
            auths-verifier auths-core auths-infra-http auths-id \
            auths-storage auths-sdk auths-infra-git auths-cli auths; do
echo "=== $crate ==="
cargo publish --dry-run -p "$crate" 2>&1 | tail -3
echo
done
```

Step 3: Publish in dependency order

Each cargo publish needs the previous crate to be indexed (takes ~30s-1min), so add a sleep between them:

# Tier 0: No workspace dependencies
cargo publish -p auths-crypto
cargo publish -p auths-policy
cargo publish -p auths-telemetry
cargo publish -p auths-index
sleep 60

# Tier 1: Depends on Tier 0
cargo publish -p auths-verifier    # depends on auths-crypto
sleep 60

# Tier 2: Depends on Tier 0-1
cargo publish -p auths-core        # depends on auths-crypto, auths-verifier
cargo publish -p auths-infra-http  # depends on auths-core, auths-verifier
sleep 60

# Tier 3: Depends on Tier 0-2
cargo publish -p auths-id          # depends on core, crypto, policy, verifier, index
cargo publish -p auths-sdk         # depends on core, id, policy, crypto, verifier
cargo publish -p auths-storage     # depends on core, id, verifier, index
sleep 60

# Tier 4: Depends on Tier 0-3
cargo publish -p auths-infra-git   # depends on core, sdk, verifier
sleep 60

# Tier 5: Depends on everything
cargo publish -p auths-cli
sleep 30

# Wrapper crate (currently empty deps, publish whenever)
cargo publish -p auths

Important notes

- Version bump first — you'll want to update the workspace version in Cargo.toml from 0.0.1-rc.5 to 0.1.0 before
publishing. Every version.workspace = true crate picks it up automatically, but the [workspace.dependencies] version
strings also need updating.
- You can't overwrite — once a version is published to crates.io, it's permanent. If something goes wrong mid-publish, bump
to 0.1.1 for the remaining crates.
- The sleeps are conservative — crates.io indexing usually takes 30-60 seconds. If a publish fails with "can't find
dependency", just wait and retry.
- auths-test-utils and xtask are publish = false and will be skipped automatically.
