# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Auths is a decentralized identity system for developers. It enables cryptographic commit signing with Git-native storage using KERI-inspired identity principles. No central server or blockchain—just Git and cryptography.

## Build & Test Commands

```bash
# Build
cargo build                              # Debug build
cargo build --release                    # Release build
cargo build --package auths_cli         # Build specific crate

# Test
cargo nextest run --workspace            # Run all tests (except doc tests)
cargo test --all --doc                   # Run doc tests (nextest doesn't support these)
cargo nextest run -p auths_verifier     # Test specific crate
cargo nextest run -E 'test(verify_chain)' # Run single test by name

# Lint & Format
cargo fmt --all                          # Format code
cargo fmt --check --all                  # Check formatting (CI uses this)
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# WASM verification (auths-verifier only)
# Must cd into the crate — resolver = "3" rejects --features from workspace root
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

## Code Comments

You SHOULD NOT add code comments that explain processes - the code should be self-evident

Only leave comments where a particular decision was made - i.e. opinionated code
Or in places where

If you are leaving comments to explain processes, it is a sign to break the function into modular components and name them clearly.

## Docstrings

Doc strings should look like this, including description, Args, and Usage code block
```
/// Verifies a GitHub Actions OIDC token and extracts its claims.
///
/// Args:
/// * `token`: The raw JWT string provided by the GitHub Actions environment.
/// * `jwks_client`: The client used to fetch GitHub's public keys.
///
/// Usage:
/// ```ignore (add ignore where necessary like doc tests)
/// let claims = verify_github_token(&raw_token, &jwks_client).await?;
/// ```
```
All public functions, and public API functions should be documented
Private functions don't need to be documented - but you can if it seems like an important function

## Crate Architecture

```
Layer 0: auths-crypto     (cryptographic primitives, DID:key encoding)
Layer 1: auths-verifier   (standalone verification, FFI/WASM)
Layer 2: auths-core       (keychains, signing, policy, ports)
Layer 3: auths-id         (identity, attestation, KERI, traits)
         auths-policy     (policy expression engine)
Layer 4: auths-storage    (Git/SQL storage adapters)
         auths-sdk        (application services)
Layer 5: auths-infra-git  (Git client adapter)
         auths-infra-http (HTTP client adapter)
Layer 6: auths-cli        (user commands)
```

**auths-crypto**: Layer 0 cryptographic primitives — Ed25519, KERI key parsing, DID:key encoding.

**auths-verifier**: Minimal-dependency verification library for FFI/WASM embedding. Depends only on auths-crypto.

**auths-core**: Foundation layer with platform keychains (macOS Security Framework, Linux Secret Service, Windows Credential Manager), signing, policy, and port abstractions.

**auths-id**: Identity and attestation domain logic. Defines key traits: `IdentityStorage`, `AttestationSource`, `AttestationSink`. KERI identity management. Refs stored under `refs/auths/` and `refs/keri/`.

**auths-storage**: Storage backend implementations — `GitAttestationStorage`, `GitIdentityStorage`, `GitRefSink`, `GitRegistryBackend`.

**auths-cli**: Command-line interface with three binaries: `auths`, `auths-sign`, `auths-verify`. Uses clap for argument parsing.

**auths-verifier**: Minimal-dependency verification library designed for embedding. Supports FFI (feature: `ffi`), WASM (feature: `wasm`). Does NOT depend on git2 or heavy deps. Core functions: `verify_chain()`, `verify_with_keys()`, `did_key_to_ed25519()`.

## Key Patterns

**Git as Storage**: All identity data and attestations are stored as Git refs. The `~/.auths` directory is a Git repository.

**DID Types**:
- `did:keri:...` - Primary identity (derived from Ed25519 key)
- `did:key:z...` - Device identifiers (Ed25519 multicodec format)

**Attestation Structure**: JSON-serialized, canonicalized with `json-canon`, dual-signed (issuer + device). Fields include: version, rid, issuer, subject, device_public_key, identity_signature, device_signature, capabilities, expires_at.

**Trait Abstractions**: Platform-specific code uses traits (`Storage`, `DidResolver`) with conditional compilation for cross-platform support.

**Clock Injection**: `Utc::now()` is banned in `auths-core/src/` and `auths-id/src/` outside `#[cfg(test)]`. All time-sensitive functions accept `now: DateTime<Utc>` as their first parameter. The `auths-sdk` layer calls `clock.now()` and passes the value down. The CLI calls `Utc::now()` at the presentation boundary. Never add `Utc::now()` to domain or core logic — inject it instead.

## Feature Flags

- `auths-core`: `keychain-file-fallback`, `keychain-windows`, `crypto-secp256k1`, `test-utils`
- `auths-id`: `auths-radicle`, `indexed-storage`
- `auths-verifier`: `ffi` (enables libc, FFI module), `wasm` (enables wasm-bindgen)

## Writing Tests

Each crate uses a single integration-test binary: `tests/integration.rs` (entry point) with submodules under `tests/cases/`. Add new test cases as `tests/cases/<topic>.rs` and re-export from `tests/cases/mod.rs`.

Use `crates/auths-test-utils` for shared helpers — add `auths-test-utils.workspace = true` under `[dev-dependencies]`:
- `auths_test_utils::crypto::get_shared_keypair()` — shared Ed25519 key via `OnceLock` (fast, use by default)
- `auths_test_utils::crypto::create_test_keypair()` — fresh key per call (use only when uniqueness matters)
- `auths_test_utils::git::init_test_repo()` — new `TempDir` + initialised git repo
- `auths_test_utils::git::get_cloned_test_repo()` — cloned copy of a shared template repo (faster for read-only setup)

See `TESTING_STRATEGY.md` for full details.

## CI Requirements

Tests require Git configuration, ask the user for this and help them find it:
```bash
git config --global user.name "{user_current_name}"
git config --global user.email "{user_current_email}"
```

CI runs on: Ubuntu (x86_64), macOS (aarch64), Windows (x86_64). Rust 1.93 with clippy and rustfmt.

When the user is getting errors locally, don't forget to remind them to reinstall any local changes (e.g. `cargo install --path crates/auths-cli`)

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK. Example: `DomainError::InvalidSignature`, `StorageError::ConcurrentModification`.
5. **`thiserror`/`anyhow` Translation Boundary**: The ban on `anyhow` in Core/SDK is strict, but the CLI and API servers (`auths-auth-server`, `auths-registry-server`) **must** define a clear translation boundary where domain errors are wrapped with operational context. The CLI and server crates continue using `anyhow::Context` to collect system-level information (paths, environment, subprocess output), but always wrap the domain `thiserror` errors cleanly — never discard the typed error:
    ```rust
    // auths-cli/src/commands/sign.rs (Presentation Layer)
    // Converts the strict thiserror SigningError into a contextualized anyhow::Error
    let signature = sign_artifact(&config, data)
        .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
    ```
    The existing SDK error types (`SetupError`, `DeviceError`, `RegistrationError` in `crates/auths-sdk/src/error.rs`) currently wrap `anyhow::Error` in their `StorageError` and `NetworkError` variants (e.g., `StorageError(#[source] anyhow::Error)`). These must be migrated to domain-specific `thiserror` variants during Epic 1/2 execution — the `anyhow` wrapping is a transitional pattern, not a permanent design. The `map_storage_err()` and `map_device_storage_err()` helper functions should be replaced with direct `From` impls on the domain storage errors.
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
7. **`unwrap()` / `expect()` Policy**: The workspace denies `clippy::unwrap_used` and `clippy::expect_used` globally. `clippy.toml` sets `allow-unwrap-in-tests = true`, so test code is exempt. For production code:
   - **Default**: Use `?` (in functions returning `Result`), `.ok_or_else(|| ...)`, `.unwrap_or_default()`, or `match` instead of `.unwrap()` / `.expect()`.
   - **Provably safe unwraps**: When an unwrap is provably infallible (e.g., `try_into()` after a length check, `ProgressStyle::with_template()` on a compile-time constant, `Regex::new()` on a literal), use an inline `#[allow]` with an `INVARIANT:` comment explaining why it cannot fail:
     ```rust
     #[allow(clippy::expect_used)] // INVARIANT: length validated to be 32 bytes on line N
     let arr: [u8; 32] = vec.try_into().expect("validated above");
     ```
   - **FFI boundaries**: `expect()` is acceptable in FFI/WASM `extern "C"` functions where panicking is the only option (no `Result` return). Annotate with `#[allow]`.
   - **Mutex/RwLock poisoning**: `lock().expect()` / `write().expect()` on stdlib mutexes is acceptable — a poisoned mutex means another thread panicked, which is unrecoverable. Annotate with `#[allow]` and an INVARIANT comment.
   - **Never** add blanket `#![allow(clippy::unwrap_used, clippy::expect_used)]` to crate roots. Fix each site individually.
