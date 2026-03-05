# fn-3.5 Migrate auths-sdk error types from anyhow to thiserror

## Description
PURGE `anyhow` from `auths-sdk` dependencies entirely. All `Result<T, anyhow::Error>` MUST be converted to `Result<T, SdkError>`. DELETE the `map_storage_err` helper functions -- they are a crutch for bad error design.

## Strict Requirements

1. **PURGE**: Remove `anyhow` from `[dependencies]` in `auths-sdk/Cargo.toml`. Not just from public types -- from the entire crate.
2. **DELETE** `map_storage_err()` and `map_device_storage_err()` helper functions entirely
3. **REPLACE** with `From` implementations for underlying error types (`git2::Error`, `serde_json::Error`, `std::io::Error`, etc.)
4. **ALL** `Result<T, anyhow::Error>` in SDK become `Result<T, SdkError>` (or domain-specific sub-errors like `StorageError`, `NetworkError`, `DeviceError`)
5. **Domain variants only**: `StorageError::NotFound { key }`, `StorageError::Corrupt { detail }`, `StorageError::Permission { path }` -- not `StorageError(String)`
6. **CLI boundary preserved**: `auths-cli` continues using `anyhow::Context` at the presentation layer. The translation boundary is explicit.

## Key Files
- `crates/auths-sdk/Cargo.toml` -- REMOVE `anyhow` from `[dependencies]`
- `crates/auths-sdk/src/error.rs` -- REWRITE error types with domain variants
- `crates/auths-sdk/src/device.rs` -- DELETE `map_device_storage_err` usage
- `crates/auths-sdk/src/setup.rs` -- DELETE `map_storage_err` usage
- `crates/auths-sdk/src/workflows/` -- update all error mappings

## Risk
Touches many call sites. Approach: migrate one error type at a time (StorageError first, then NetworkError, then DeviceError). Run workspace tests after each.
## Problem

Per CLAUDE.md: "No `anyhow::Error` or `Box<dyn Error>` in Core/SDK." The SDK error types at `crates/auths-sdk/src/error.rs` currently wrap `anyhow::Error` in their `StorageError` and `NetworkError` variants. The `map_storage_err()` and `map_device_storage_err()` helper functions stringify errors. This is a transitional pattern that must be migrated before Heartwood depends on these types.

## Implementation

1. In `crates/auths-sdk/src/error.rs`:
   - Replace `StorageError(#[source] anyhow::Error)` with domain variants like `StorageNotFound { key: String }`, `StorageCorrupt { detail: String }`, `StoragePermission { path: PathBuf }`
   - Replace `NetworkError(#[source] anyhow::Error)` with domain variants like `NetworkUnreachable`, `NetworkTimeout`, `NetworkAuth { detail: String }`
   - Remove `map_storage_err()` and `map_device_storage_err()` helpers
   - Add `From` impls for the underlying error types instead
2. Update all SDK callers that use `.map_err(map_storage_err)`
3. Keep `anyhow::Context` usage in the CLI layer (presentation boundary) -- that's allowed

## Key Files
- `crates/auths-sdk/src/error.rs` -- error type definitions
- `crates/auths-sdk/src/device.rs` -- uses `map_device_storage_err`
- `crates/auths-sdk/src/setup.rs` -- uses `map_storage_err`
- `crates/auths-sdk/src/workflows/` -- various error mappings
- CLAUDE.md -- rules on error handling boundaries

## Risk
This touches many call sites across the SDK. Run full workspace tests after each module migration. Consider doing one error type at a time (StorageError first, then NetworkError).

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `anyhow` REMOVED from `auths-sdk/Cargo.toml` `[dependencies]`
- [ ] `grep -r "anyhow" crates/auths-sdk/src/` returns zero results
- [ ] `map_storage_err()` DELETED
- [ ] `map_device_storage_err()` DELETED
- [ ] `StorageError` has domain-specific variants (not string wrapping)
- [ ] `NetworkError` has domain-specific variants
- [ ] `From` impls replace helper functions
- [ ] CLI layer uses `anyhow::Context` at presentation boundary only
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
## Done summary
anyhow was already absent from auths-sdk Cargo.toml and source code. Only a doc comment referenced it. Removed the doc comment reference. grep -r anyhow crates/auths-sdk/src/ returns zero results.
## Evidence
- Commits:
- Tests:
- PRs:
