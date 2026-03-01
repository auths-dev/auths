# Coding Standards

## Code comments

Do not add code comments that explain processes. The code should be self-evident. If you find yourself writing a comment to explain what a block of code does, that is a signal to break the function into modular components and name them clearly.

Only leave comments where a particular decision was made -- opinionated code that would not be obvious from the structure alone.

```rust
// BAD: explaining process
// Loop through attestations and check if any are expired
for att in &attestations {
    if att.expires_at < now { ... }
}

// GOOD: no comment needed -- the function name is the documentation
let active = filter_unexpired_attestations(&attestations, now);
```

## Docstrings

All public functions and public API functions must be documented. Private functions do not require docstrings unless they represent important logic.

Docstrings follow this format with description, `Args:`, and `Usage:` blocks:

```rust
/// Verifies a GitHub Actions OIDC token and extracts its claims.
///
/// Args:
/// * `token`: The raw JWT string provided by the GitHub Actions environment.
/// * `jwks_client`: The client used to fetch GitHub's public keys.
///
/// Usage:
/// ```ignore
/// let claims = verify_github_token(&raw_token, &jwks_client).await?;
/// ```
```

Use `/// ```ignore` when doc tests would require complex setup or external dependencies.

## Clock injection

`Utc::now()` is banned in `auths-core/src/` and `auths-id/src/` outside `#[cfg(test)]` blocks.

All time-sensitive functions accept `now: DateTime<Utc>` as their first parameter. The call chain works as follows:

1. The **CLI** calls `Utc::now()` at the presentation boundary.
2. The **SDK layer** calls `clock.now()` and passes the value down.
3. **Core and ID** crates receive `now` as a parameter -- they never obtain the current time themselves.

This enables deterministic testing with the `MockClock` fake from `auths-test-utils`:

```rust
use auths_test_utils::fakes::clock::MockClock;
use chrono::Utc;

let fixed = Utc::now();
let clock = MockClock(fixed);
assert_eq!(clock.now(), fixed); // always returns the same time
```

## Error handling: `thiserror` not `anyhow`

Core and SDK crates use `thiserror` enums exclusively. `anyhow::Error` and `Box<dyn Error>` are banned in `auths-core`, `auths-id`, `auths-crypto`, `auths-sdk`, and `auths-verifier`.

```rust
// GOOD: domain-specific error
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("key not found: {0}")]
    KeyNotFound(String),
}
```

### Translation boundary

The CLI and server crates (`auths-cli`, `auths-registry-server`) define a clear translation boundary where domain errors are wrapped with operational context using `anyhow::Context`:

```rust
// auths-cli/src/commands/sign.rs (Presentation Layer)
let signature = sign_artifact(&config, data)
    .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
```

The rule: always wrap the typed `thiserror` error cleanly -- never discard the typed error.

## DRY and separation of concerns

Business workflows must be entirely separated from I/O. No monolithic functions that mix domain logic with file reads, network calls, or user prompts.

## No reverse dependencies

Core and SDK must never reference presentation layer crates. The dependency direction is strictly:

```
auths-core  ->  auths-id  ->  auths-sdk  ->  auths-cli
```

Never in the reverse direction.

## Test structure

Each crate uses a single integration-test binary: `tests/integration.rs` as the entry point, with submodules under `tests/cases/`:

```
crates/auths-verifier/
├── src/
│   └── ...
└── tests/
    ├── integration.rs      # mod cases;
    └── cases/
        ├── mod.rs           # mod capability_fromstr; mod proptest_core; ...
        ├── capability_fromstr.rs
        ├── proptest_core.rs
        └── revocation_adversarial.rs
```

Add new test cases as `tests/cases/<topic>.rs` and re-export from `tests/cases/mod.rs`. This compiles all integration tests into a single binary, reducing link time.

## Formatting and linting

All code must pass:

```bash
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
```

CI enforces both. Run them locally before pushing.
