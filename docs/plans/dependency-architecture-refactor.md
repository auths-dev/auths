# Dependency Architecture Refactor

**Status**: Draft
**Scope**: Workspace-wide restructuring of crate dependencies, test utilities, and publish pipeline
**Breaking changes**: Yes (pre-launch, acceptable)

---

## Problem Statement

Publishing any crate to crates.io requires manually removing dev-dependencies, inlining test helpers, and publishing with `--no-verify` or `--allow-dirty`. This is because:

1. **`auths-test-utils` is a monolith** that depends on 7 workspace crates (`auths-core`, `auths-crypto`, `auths-id`, `auths-storage`, `auths-sdk`, `auths-telemetry`, `auths-verifier`). Any crate that dev-depends on it cannot publish until it's on crates.io — but it can't be published until all its dependencies are.

2. **`auths-id` ↔ `auths-storage` circular dev-dependency**: `auths-storage` depends on `auths-id` (for traits), `auths-id` dev-depends on `auths-storage` (for testing with real Git backend). Neither can publish first.

3. **`auths-id` has a `git-storage` feature** that pulls in `git2`, `dirs`, `tempfile`, `tokio` — mixing domain logic with infrastructure concerns. Storage implementation code is split between `auths-id` and `auths-storage`.

4. **No automated publish ordering** — manual `sleep 60` between publishes, fragile and error-prone.

---

## Principles

1. **Dependency flow is strictly downward.** Foundation → Domain → Infrastructure → Orchestration → Presentation. No reverse dependencies, not even dev-deps pointing upward.
2. **Each crate owns its own test helpers.** Feature-gated `test-utils` modules replace the monolithic test-utils crate. This is the pattern used by reth (150+ crates), alloy, and tokio.
3. **Traits live with their domain, implementations live in infrastructure.** `auths-id` defines what storage looks like; `auths-storage` provides the implementations. Tests in `auths-id` use in-memory fakes, not real backends.
4. **Contract tests live with the trait they verify.** Exported as macros so implementations can pull them in.

---

## Target Architecture

```
Layer 0 — Foundation (no workspace deps)
┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  ┌─────────────┐
│ auths-crypto│  │ auths-policy │  │ auths-telemetry │  │ auths-index │
└─────────────┘  └──────────────┘  └─────────────────┘  └─────────────┘

Layer 1 — Domain (depends only on Layer 0)
┌──────────────────┐  ┌──────────┐
│ auths-verifier   │  │ auths-id │
│ (crypto)         │  │ (crypto, policy, verifier)
└──────────────────┘  └──────────┘

Layer 2 — Infrastructure (depends on Layer 0 + 1)
┌────────────────┐  ┌────────────────┐  ┌──────────────────┐
│ auths-storage  │  │ auths-infra-git│  │ auths-infra-http │
│ (id, core,     │  │ (core, sdk,    │  │ (core, verifier) │
│  verifier)     │  │  verifier)     │  │                  │
└────────────────┘  └────────────────┘  └──────────────────┘

Layer 3 — Orchestration (depends on all above)
┌───────────┐
│ auths-sdk │
│ (core, id, policy, crypto, verifier)
└───────────┘

Layer 4 — Presentation (depends on all above)
┌───────────┐
│ auths-cli │
└───────────┘
```

**Key change**: No arrows point upward. No dev-dependencies cross layer boundaries upward.

---

## Phase 1: Distribute test utilities into per-crate `test-utils` features

This is the highest-impact change. It eliminates the `auths-test-utils` monolith and all circular dev-dependency issues.

### 1a. `auths-crypto` — add `test-utils` feature

Move from `auths-test-utils/src/crypto.rs`:
- `create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32])`
- `get_shared_keypair() -> &'static [u8]`
- `gen_keypair() -> Ed25519KeyPair`

```toml
# auths-crypto/Cargo.toml
[features]
test-utils = ["dep:ring"]  # ring is already an optional dep
```

```rust
// auths-crypto/src/testing.rs
#[cfg(feature = "test-utils")]
pub mod testing {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::OnceLock;

    pub fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
        (keypair, public_key)
    }

    pub fn get_shared_keypair() -> &'static [u8] { /* OnceLock pattern */ }
    pub fn gen_keypair() -> Ed25519KeyPair { /* random seed */ }
}
```

**Consumers**: Every crate that currently imports `auths_test_utils::crypto::*` switches to:
```toml
[dev-dependencies]
auths-crypto = { workspace = true, features = ["test-utils"] }
```

### 1b. `auths-id` — add `test-utils` feature

Move from `auths-test-utils/src/fakes/`, `contracts/`, `fixtures/`, `mocks/`, `storage_fakes.rs`:

**Fakes** (implement traits defined in `auths-id` itself — no cross-crate dependency needed):
- `FakeRegistryBackend` (implements `RegistryBackend`)
- `FakeAttestationSink` / `FakeAttestationSource` (implements `AttestationSink` / `AttestationSource`)
- `FakeIdentityStorage` (implements `IdentityStorage`)
- `InMemoryStorage` (implements `BlobReader`, `BlobWriter`, `RefReader`, `RefWriter`, `EventLogReader`, `EventLogWriter`)
- `MockClock` (implements `ClockProvider`)
- `MockCryptoProvider` (implements `CryptoProvider`)
- `DeterministicUuidProvider` (implements `UuidProvider`)
- `FakeGitDiagnosticProvider`, `FakeCryptoDiagnosticProvider`
- `FakeGitLogProvider` (implements `GitLogProvider`)

**Contract test macros**:
- `registry_backend_contract_tests!`
- `git_log_provider_contract_tests!`
- `session_store_contract_tests!`
- `event_sink_contract_tests!`

**Fixtures**:
- `test_inception_event(key_seed: &str) -> Event`
- `test_attestation(device_did, issuer) -> Attestation`

**Mockall mocks**:
- `MockIdentityStorage`
- `MockAttestationSource`

```toml
# auths-id/Cargo.toml
[features]
test-utils = [
    "auths-crypto/test-utils",  # chain the feature
    "dep:mockall",
    "dep:rand",
    "dep:tempfile",
]
```

```rust
// auths-id/src/testing/mod.rs
#[cfg(feature = "test-utils")]
pub mod testing {
    pub mod fakes;      // FakeRegistryBackend, FakeAttestationSource, etc.
    pub mod contracts;  // contract test macros
    pub mod fixtures;   // test_inception_event, test_attestation
    pub mod mocks;      // MockIdentityStorage, MockAttestationSource
}
```

**Why this works**: All the fakes implement traits defined in `auths-id` itself. The mock implementations use only types from `auths-id` and its dependencies (Layer 0). No upward dependency on `auths-storage` or `auths-sdk`.

### 1c. `auths-telemetry` — add `test-utils` feature

Move from `auths-test-utils/src/fakes/telemetry.rs`:
- `MemoryEventSink` (implements `EventSink`)

```toml
# auths-telemetry/Cargo.toml
[features]
test-utils = []
```

### 1d. `auths-core` — expand existing `test-utils` feature

`auths-core` already declares `test-utils = []` as a feature. Populate it with any test helpers specific to core (if any exist beyond what's in `auths-crypto`).

### 1e. Git test helpers — move to `auths-infra-git`

Move from `auths-test-utils/src/git.rs`:
- `init_test_repo() -> (TempDir, git2::Repository)`
- `get_cloned_test_repo() -> TempDir`
- `copy_directory(src, dst)`

```toml
# auths-infra-git/Cargo.toml
[features]
test-utils = ["dep:tempfile"]
```

These are only needed by crates that test against real Git repositories.

### 1f. Delete `auths-test-utils`

After all helpers are distributed, remove `crates/auths-test-utils/` entirely:
- Remove from workspace `members` in root `Cargo.toml`
- Remove from `[workspace.dependencies]`
- Remove all `auths-test-utils.workspace = true` lines from every crate

---

## Phase 2: Clean up `auths-id` — remove infrastructure dependencies

Currently `auths-id` has a `git-storage` feature that brings in `git2`, `dirs`, `tempfile`, `tokio`. This mixes domain logic with infrastructure.

### 2a. Audit what `git-storage` feature provides in `auths-id`

Identify all code gated behind `#[cfg(feature = "git-storage")]` in `auths-id/src/`. This likely includes:
- Git-based `IdentityStorage` implementation
- Local `~/.auths` directory management
- Git ref reading/writing for identity data

### 2b. Move git-storage code from `auths-id` to `auths-storage`

All Git-based storage implementations should live in `auths-storage`:
- Move the git-gated code to `auths-storage/src/git/`
- `auths-storage` already depends on `auths-id` — it can implement the traits
- Remove `git-storage` feature from `auths-id`
- Remove `git2`, `dirs`, `tempfile` from `auths-id`'s dependencies

### 2c. Remove `auths-storage` dev-dependency from `auths-id`

After Phase 1, `auths-id` tests use in-memory fakes (from its own `test-utils` feature) instead of `GitRegistryBackend`. The real Git backend is tested in `auths-storage` using the contract test macros exported by `auths-id/test-utils`.

```rust
// auths-storage/tests/cases/registry_contract.rs
// Import the contract test macro from auths-id
auths_id::testing::contracts::registry_backend_contract_tests!(
    git_backend,
    { /* construct GitRegistryBackend */ },
);
```

This is how reth does it: the trait crate exports contract tests, the implementation crate runs them.

### 2d. Result — `auths-id` becomes a pure domain crate

After this phase, `auths-id`'s dependencies are:
```toml
[dependencies]
auths-core.workspace = true
auths-crypto.workspace = true
auths-policy.workspace = true
auths-verifier.workspace = true
# ... plus pure Rust deps (chrono, serde, etc.)
# NO git2, NO dirs, NO tempfile, NO tokio
```

No dev-dependencies on infrastructure crates. Clean Layer 1 crate.

---

## Phase 3: Consolidate `auths-core` role

`auths-core` currently depends on `auths-crypto` and `auths-verifier`. It provides:
- Platform keychains (macOS, Linux, Windows)
- Agent/passphrase management
- Encryption primitives
- Config management

### 3a. Evaluate whether `auths-core` should depend on `auths-verifier`

`auths-verifier` is designed as a minimal, embeddable crate. If `auths-core` pulls it in as a dependency, that adds `auths-core` to `auths-verifier`'s reverse dependency tree, which complicates the layer model.

If the dependency is only used in a few places, consider:
- Making it optional: `auths-verifier = { workspace = true, optional = true }`
- Or duplicating the minimal verification logic needed

### 3b. Ensure `auths-core` stays at Layer 0

`auths-core` should only depend on `auths-crypto` (Layer 0). If it needs types from `auths-id`, that's a sign those types should be in a lower layer.

---

## Phase 4: Automate publishing

### 4a. Adopt `cargo publish --workspace` (Rust 1.90+)

Since Rust 1.90 (September 2025), Cargo natively supports workspace publishing:
```bash
cargo publish --workspace
```

This topologically sorts crates and publishes in dependency order. After Phases 1-3 eliminate all circular dev-deps, this works out of the box.

### 4b. Consider `release-plz` for CI

For automated releases via GitHub PRs:
- Auto-generates changelogs from conventional commits
- Integrates `cargo-semver-checks` for breaking change detection
- Opens a Release PR, publishes on merge
- Handles `sleep` between publishes automatically

### 4c. Define publish order explicitly

After the refactor, the publish order is deterministic:
```
Tier 0 (parallel): auths-crypto, auths-policy, auths-telemetry, auths-index
Tier 1 (parallel): auths-verifier, auths-core
Tier 2 (sequential): auths-id (after verifier, core)
Tier 3 (parallel): auths-storage, auths-infra-git, auths-infra-http
Tier 4: auths-sdk
Tier 5: auths-cli
```

No tier depends on a crate in the same or later tier. No circular dependencies.

---

## Phase 5: Cleanup and verification

### 5a. Remove all temporary inlined helpers

Remove the `create_test_keypair` functions that were inlined in:
- `auths-crypto/tests/cases/provider.rs`
- `auths-verifier/src/verify.rs`
- `auths-verifier/src/witness.rs`
- `auths-verifier/tests/cases/expiration_skew.rs`
- `auths-verifier/tests/cases/revocation_adversarial.rs`

Replace with:
```rust
use auths_crypto::testing::create_test_keypair;
```

### 5b. Re-add dev-dependencies that were removed for publishing

Restore any dev-deps that were stripped purely for the initial publish (e.g., `auths-storage` in `auths-id` — though after Phase 2, this should no longer be needed).

### 5c. Full workspace verification

```bash
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --all --doc
cargo publish --workspace --dry-run
```

### 5d. WASM verification

```bash
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

---

## Migration Map

| Current location | Target location | What |
|---|---|---|
| `auths-test-utils/src/crypto.rs` | `auths-crypto/src/testing.rs` | `create_test_keypair`, `get_shared_keypair`, `gen_keypair` |
| `auths-test-utils/src/git.rs` | `auths-infra-git/src/testing.rs` | `init_test_repo`, `get_cloned_test_repo` |
| `auths-test-utils/src/fakes/*.rs` | `auths-id/src/testing/fakes/*.rs` | All fake trait implementations |
| `auths-test-utils/src/contracts/*.rs` | `auths-id/src/testing/contracts/*.rs` | All contract test macros |
| `auths-test-utils/src/fixtures/*.rs` | `auths-id/src/testing/fixtures/*.rs` | `test_inception_event`, `test_attestation` |
| `auths-test-utils/src/mocks/*.rs` | `auths-id/src/testing/mocks/*.rs` | `MockIdentityStorage`, `MockAttestationSource` |
| `auths-test-utils/src/storage_fakes.rs` | `auths-id/src/testing/fakes/storage.rs` | `InMemoryStorage` |
| `auths-test-utils/src/fakes/telemetry.rs` | `auths-telemetry/src/testing.rs` | `MemoryEventSink` |
| `auths-id` git-storage code | `auths-storage/src/git/` | Git-based identity storage |
| `crates/auths-test-utils/` | **deleted** | — |

---

## Consumer Migration

Every crate that currently has `auths-test-utils.workspace = true` in dev-dependencies gets replaced:

```toml
# Before
[dev-dependencies]
auths-test-utils.workspace = true

# After — only enable the features you actually use
[dev-dependencies]
auths-crypto = { workspace = true, features = ["test-utils"] }
auths-id = { workspace = true, features = ["test-utils"] }
```

The `test-utils` features chain transitively — `auths-id/test-utils` enables `auths-crypto/test-utils` automatically.

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Large diff touching many files | Execute in phases; each phase is independently shippable |
| Contract test macros may have complex dependencies | Audit macro expansions before moving; may need to simplify |
| `auths-id` git-storage removal may break `auths-cli` | `auths-cli` already depends on `auths-storage`; rewire imports |
| Feature flag proliferation | Only two feature flags per crate max (`test-utils` + one domain feature) |
| `mockall` and `rand` become regular deps (optional) of published crates | Gated behind `test-utils` feature; not compiled by default consumers |

---

## Success Criteria

1. `cargo publish --workspace --dry-run` passes with zero manual intervention
2. `auths-test-utils` crate no longer exists
3. No crate has dev-dependencies on crates in the same or higher layer
4. All 1395+ tests pass
5. WASM build passes
6. Each crate's dependency list fits its architectural layer
