# Contributing

## Getting Started

```bash
# Build
cargo build

# Run all tests
cargo nextest run --workspace

# Run doc tests
cargo test --all --doc

# Lint
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Security audit
cargo audit

# License and ban check
cargo deny check
```

## Documentation Standards

Every public function, struct, trait, and enum **must** have a rustdoc comment. Follow the format from `CLAUDE.md`:

```rust
/// Short description.
///
/// Args:
/// * `param_name`: What this parameter represents and its constraints.
///
/// Usage:
/// ```ignore
/// let result = my_function("example", 42)?;
/// ```
pub fn my_function(param_name: &str, count: usize) -> Result<Output, MyError> {
    // implementation
}
```

Rules:
- Private functions do not require doc comments unless the logic is non-obvious.
- Do not add comments that explain *what* the code does — name the function and its parts clearly instead.
- Do add comments that explain *why* a particular decision was made (opinionated choices, non-obvious tradeoffs).
- Broken intra-doc links are a compile error (`#![deny(rustdoc::broken_intra_doc_links)]`).

## Code Style

- No `println!` or `eprintln!` in library crates (`#![deny(clippy::print_stdout, clippy::print_stderr)]`).
- No `Utc::now()` or `SystemTime::now()` in domain logic — inject `ClockProvider` (see ARCHITECTURE.md).
- No `std::env::var()` in domain logic — use `EnvironmentConfig` abstraction.
- Domain errors use `thiserror` enums. `anyhow` is only for CLI and server crates.
- All new port traits live in `src/ports/` with a fake in `auths-test-utils/src/fakes/` and a mock in `auths-test-utils/src/mocks/`.

## SemVer Policy

See `RELEASES.md`. For changes to `auths-verifier`, `auths-core`, or `auths-sdk`:

- **Additive changes** (new public items, new optional fields): minor version bump.
- **Breaking changes** (removed/renamed items, changed signatures): major version bump (or `0.(x+1).0` while in pre-release).
- CI enforces this via `cargo-semver-checks` on all pull requests.

## Testing

Follow the test pyramid (see ARCHITECTURE.md):

1. **Unit tests** — use `auths-test-utils::mocks` (mockall). No I/O.
2. **Integration boundary tests** — use `auths-test-utils::fakes` + contract macros. No disk or network.
3. **E2E tests** — use `auths-test-utils::git::init_test_repo()` for real Git I/O.

All unit tests must pass with network blocked (`cargo test --lib --workspace` behind iptables in CI).

## Pull Request Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo nextest run --workspace` green
- [ ] `cargo test --all --doc` green
- [ ] Public API changes documented with `Args:` and `Usage:` blocks
- [ ] New port traits have a fake and/or mock in `auths-test-utils`
- [ ] Breaking changes bumped version per `RELEASES.md`
