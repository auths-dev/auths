# Testing Guide

## Running tests

```bash
# Run all tests (except doc tests)
cargo nextest run --workspace

# Run doc tests separately (nextest does not support doc tests)
cargo test --all --doc

# Test a specific crate
cargo nextest run -p auths_verifier

# Run a single test by name
cargo nextest run -E 'test(verify_chain)'
```

## Test structure

Each crate uses a single integration-test binary with the following layout:

```
crates/<crate-name>/
└── tests/
    ├── integration.rs       # Entry point: `mod cases;`
    └── cases/
        ├── mod.rs            # Re-exports: `mod topic_a; mod topic_b;`
        ├── topic_a.rs
        └── topic_b.rs
```

To add a new test:

1. Create `tests/cases/<topic>.rs` with your test functions.
2. Add `mod <topic>;` to `tests/cases/mod.rs`.
3. Run `cargo nextest run -p <crate_name>` to verify.

This single-binary pattern reduces link time compared to having many separate test files in `tests/`.

## Shared test helpers

The `auths-test-utils` crate provides shared helpers. Add it to your crate's `[dev-dependencies]`:

```toml
[dev-dependencies]
auths-test-utils.workspace = true
```

### Modules overview

| Module | Purpose |
|--------|---------|
| `crypto` | Ed25519 keypair generation and sharing |
| `git` | Temporary Git repository creation |
| `fakes` | In-memory trait implementations for deterministic testing |
| `mocks` | `mockall`-generated mocks for targeted unit tests |
| `fixtures` | Pre-built KERI events and attestations |
| `contracts` | Contract test helpers for storage ports |
| `storage_fakes` | `InMemoryStorage` implementing all 6 storage port traits |

### Crypto helpers

```rust
use auths_test_utils::crypto;

// Shared keypair (default choice -- fast, reused across tests via OnceLock)
let pkcs8_bytes = crypto::get_shared_keypair();
let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();

// Deterministic keypair from seed (when you need reproducible output)
let (keypair, public_key) = crypto::create_test_keypair(&[1u8; 32]);

// Fresh random keypair (when uniqueness matters)
let keypair = crypto::gen_keypair();
```

Use `get_shared_keypair()` by default. It generates one keypair on first call and reuses it for the entire test binary via `OnceLock`, eliminating key generation overhead.

Use `create_test_keypair()` when you need multiple distinct keypairs with deterministic output.

Use `gen_keypair()` when you need a unique keypair but do not care about reproducibility.

### Git helpers

```rust
use auths_test_utils::git;

// New temporary Git repository (fresh TempDir + git init + user config)
let (temp_dir, repo) = git::init_test_repo();

// Cloned copy of a shared template repo (faster for read-only setup)
let temp_dir = git::get_cloned_test_repo();
let repo = git2::Repository::open(temp_dir.path()).unwrap();
```

`init_test_repo()` creates a new `TempDir`, initializes a Git repository, and configures `user.name` and `user.email` so commits work immediately.

`get_cloned_test_repo()` creates a template repository once (via `OnceLock`) and returns a fresh copy on each call. Use this when tests only need to read from a repository -- it avoids repeated `git init` overhead.

### Fakes

Fakes are full in-memory implementations of domain traits. Use them for integration-boundary tests that exercise multiple behaviors.

```rust
use auths_test_utils::fakes::clock::MockClock;
use auths_test_utils::fakes::crypto::MockCryptoProvider;
use auths_test_utils::fakes::attestation::{FakeAttestationSink, FakeAttestationSource};
use auths_test_utils::fakes::identity_storage::FakeIdentityStorage;
```

| Fake | Trait implemented | Description |
|------|-------------------|-------------|
| `MockClock` | `ClockProvider` | Returns a fixed `DateTime<Utc>` on every call |
| `MockCryptoProvider` | `CryptoProvider` | Configurable accept/reject with call counting |
| `FakeAttestationSink` | `AttestationSink` | In-memory attestation storage |
| `FakeAttestationSource` | `AttestationSource` | In-memory attestation retrieval |
| `FakeIdentityStorage` | `IdentityStorage` | In-memory identity create/load |

Example using `MockCryptoProvider`:

```rust
use std::sync::Arc;
use auths_test_utils::fakes::crypto::MockCryptoProvider;

let provider = Arc::new(MockCryptoProvider::accepting());
// ... pass Arc::clone(&provider) to the system under test ...
assert_eq!(provider.call_count(), 1);

// Switch to rejecting mode mid-test
provider.set_should_verify(false);
```

### InMemoryStorage

`InMemoryStorage` implements all six storage port traits (`BlobReader`, `BlobWriter`, `RefReader`, `RefWriter`, `EventLogReader`, `EventLogWriter`). Use it for testing domain logic without a Git repository:

```rust
use auths_test_utils::storage_fakes::InMemoryStorage;
use auths_core::ports::storage::BlobWriter;

let store = InMemoryStorage::new();
store.put_blob("test/path", b"data").unwrap();
```

### Mocks

Mocks are `mockall`-generated and suited for targeted unit tests that need only one or two behaviors configured:

```rust
use auths_test_utils::mocks::MockIdentityStorage;

let mut mock = MockIdentityStorage::new();
mock.expect_load_identity()
    .returning(|| Ok(ManagedIdentity { .. }));
```

Use fakes for integration-boundary contract tests. Use mocks for isolated unit tests.

### Fixtures

Pre-built KERI events and attestations for tests that need structurally valid domain objects:

```rust
use auths_test_utils::fixtures::{test_inception_event, test_attestation};
use auths_verifier::types::DeviceDID;

// Minimal signed inception event
let event = test_inception_event("seed-1");
let prefix = event.prefix().to_string();

// Minimal attestation
let did = DeviceDID::new("did:key:zTest");
let att = test_attestation(&did, "did:keri:ETestOrg");
```

## Git configuration for CI

Tests that create Git repositories require a configured identity. CI sets this up automatically:

```bash
git config --global user.name "Test User"
git config --global user.email "test@example.com"
```

If tests fail locally with "please tell me who you are" errors, run these commands.
