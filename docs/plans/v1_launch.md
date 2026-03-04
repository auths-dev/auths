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

### 0.3 — Remove cross-crate re-export of `IdentityDID` from auths-core

**File:** `crates/auths-core/src/storage/keychain.rs:36`

`pub use auths_verifier::IdentityDID` creates a confusing re-export chain where
consumers can import the same type from two different crates. This will cause
type mismatch errors when consumers use both crates.

**Fix:** Remove the re-export. Consumers should import `IdentityDID` from
`auths_verifier` directly.

**Effort:** 2 hours (+ fixing downstream imports)
**Owner:** Core maintainer

---

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
