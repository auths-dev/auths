# Testing Strategy

This document describes the test architecture adopted in fn-10 to reduce
compilation overhead and eliminate slow test helpers.

## Goals

- One integration-test binary per crate (not one per file)
- Shared crypto and git helpers via `auths-test-utils`
- Fast Argon2 parameters under `#[cfg(test)]`

## Crate Layout

```
crates/<crate>/
  tests/
    integration.rs       # entry point: `mod cases;`
    cases/
      mod.rs             # re-exports each submodule
      <topic>.rs         # one file per logical concern
```

Each file in `tests/` is compiled as a separate Cargo binary. By using a
single `integration.rs` that `mod`-includes submodules under `cases/`,
we get **one binary per crate** instead of one per file. This eliminates
redundant linking of heavy dependencies (`ring`, `git2`, `tokio`).

## Shared Helpers — `auths-test-utils`

Add to a crate's `Cargo.toml`:
```toml
[dev-dependencies]
auths-test-utils.workspace = true
```

### Crypto helpers (`auths_test_utils::crypto`)

| Function | Description |
|---|---|
| `get_shared_keypair()` | Returns a `'static` Ed25519 key pair, generated once per binary via `OnceLock`. |
| `create_test_keypair()` | Generates a fresh Ed25519 key pair for tests that need their own keys. |

Use `get_shared_keypair()` whenever the test only needs _a_ valid key and
does not care about uniqueness. Use `create_test_keypair()` when the test
explicitly requires a key that has not been seen before.

### Git helpers (`auths_test_utils::git`)

| Function | Description |
|---|---|
| `init_test_repo()` | Creates a fresh `TempDir` with an initialised git repo and user config. |
| `get_cloned_test_repo()` | Returns a copy of a lazily-initialised template repo (`OnceLock`). Each call gets its own `TempDir`. |
| `copy_directory(src, dst)` | Recursive directory copy (no symlinks). |

Use `get_cloned_test_repo()` when the test needs a git repo but does not
care about its initial state. Use `init_test_repo()` when the test needs
to control the initial state from scratch.

## `OnceLock` Pattern

```rust
use std::sync::OnceLock;

static SHARED_KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn get_shared_keypair() -> &'static ring::signature::Ed25519KeyPair {
    // ...
}
```

`OnceLock` is:
- **std-only** — no extra dependencies
- **thread-safe** — safe for parallel test runners
- **`'static`** — the value lives for the lifetime of the test binary

The template `TempDir` held by `OnceLock` will not be dropped until the
process exits, so there is no risk of the directory disappearing while
tests are still running.

## Argon2 Parameters

`auths-core/src/crypto/encryption.rs` exposes a single `get_kdf_params()`
getter that switches between OWASP-recommended parameters (production) and
minimal parameters (test):

```rust
pub fn get_kdf_params() -> Result<Params, AgentError> {
    #[cfg(not(test))]
    let params = Params::new(65536, 3, 1, Some(SYMMETRIC_KEY_LEN)); // 64 MiB, 3 iterations
    #[cfg(test)]
    let params = Params::new(8, 1, 1, Some(SYMMETRIC_KEY_LEN));     // 8 KiB, 1 iteration
    params.map_err(|e| AgentError::CryptoError(format!("Invalid Argon2 params: {}", e)))
}
```

Decryption always reads parameters from the encrypted blob header, so
production-encrypted data is not affected by the test-time parameter
reduction.

## Git Trailer Folding

`auths-id/src/trailer.rs` folds long trailer values per RFC 822
(continuation lines start with a single space). Receiver code in
`Receipt::from_trailer_value` strips all whitespace before base64url
decoding to tolerate the spaces introduced during unfolding.

## Contract Tests

Contract test suites live in `crates/auths-test-utils/src/contracts/` and prove
fake-to-real behavioural parity for key trait implementations.

### Why Contract Tests?

Fakes risk silently drifting from real adapter behaviour ("mock drift"). A single
set of tests parameterised over a trait, run against **both** the fake and the
real adapter, guarantees parity.

### Available Contract Suites

| Macro | Trait | Located in |
|---|---|---|
| `registry_backend_contract_tests!` | `RegistryBackend` | `contracts/registry.rs` |
| `git_log_provider_contract_tests!` | `GitLogProvider` | `contracts/git_log.rs` |
| `event_sink_contract_tests!` | `EventSink` (MemoryEventSink) | `contracts/event_sink.rs` |
| `session_store_contract_tests!` | `SessionStore` | `contracts/session.rs` |

### Invocation Pattern

Each macro wraps its tests in a named `mod` to avoid name collisions when
multiple implementations are tested in the same file.

```rust
// In crates/auths-id/tests/cases/registry_contract.rs

// Fake (no disk I/O — fast):
auths_test_utils::registry_backend_contract_tests!(
    fake,
    (FakeRegistryBackend::new(), ()),
);

// Real (TempDir guard keeps the directory alive):
auths_test_utils::registry_backend_contract_tests!(
    packed,
    {
        let dir = tempfile::tempdir().unwrap();
        let backend = PackedRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(dir.path()),
        );
        backend.init_if_needed().unwrap();
        (backend, dir)   // dir kept alive until _guard drops at end of test
    },
);
```

### TempDir Guard Pattern

The `$setup` expression for disk-backed backends **must** return a tuple
`(backend, guard)`. The guard (e.g. `TempDir`) lives until the end of the test
function. Returning only the backend lets the guard drop immediately, deleting
the directory before the test runs.

```rust
// WRONG — TempDir dropped at end of block, directory gone before test body:
let store = {
    let dir = tempfile::tempdir().unwrap();
    PackedRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()))
};

// CORRECT — dir kept alive by _guard variable:
let (store, _guard) = {
    let dir = tempfile::tempdir().unwrap();
    let backend = PackedRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (backend, dir)
};
```

### Naming Convention

All generated test function names include the `contract_` prefix, making them
easy to identify in test output:

```
cargo nextest run -E 'test(contract_)'
```

## Running Tests

```bash
# All tests (recommended)
cargo nextest run --workspace

# Doc tests (nextest does not run these)
cargo test --all --doc

# Single crate
cargo nextest run -p auths-id

# Single test by name
cargo nextest run -E 'test(full_keri_lifecycle)'

# Lint
cargo clippy --all-targets --all-features -- -D warnings
```
