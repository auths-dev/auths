# Release Policy

## SemVer-Stable Crates

The following crates are semver-stable and subject to API compatibility guarantees:

| Crate | Stability |
|---|---|
| `auths-verifier` | Stable — public API is versioned |
| `auths-core` | Stable — public API is versioned |
| `auths-sdk` | Stable — public API is versioned |

The following crates are **not** semver-checked (binaries or internal):

| Crate | Reason |
|---|---|
| `auths-cli` | Binary crate — no public library API |
| `auths-registry-server` | Binary crate — no stable public API |
| `auths-auth-server` | Binary crate — no stable public API |
| `auths-test-utils` | Internal test utility — `publish = false` |

## What Constitutes a Breaking Change

Per [Rust API Compatibility Guidelines](https://doc.rust-lang.org/cargo/reference/semver.html):

- Removing or renaming a public type, trait, function, or constant
- Changing a public function signature (parameters, return type)
- Removing a trait implementation
- Adding a required method to a public trait
- Narrowing trait bounds on a public item
- Changing a public enum to add or remove variants (in a `#[non_exhaustive]` context)

Non-breaking changes include:

- Adding optional fields with `#[serde(default)]`
- Adding new variants to `#[non_exhaustive]` enums
- Adding new inherent methods to public types
- Adding new public items (functions, types, traits)

## MSRV Policy

Minimum Supported Rust Version (MSRV): **1.93**

Declared in `Cargo.toml` under `[workspace.package]`. A MSRV bump requires a minor version increment.

## Pre-Release Exception (`0.x`)

While the workspace version is `0.x.y`, breaking changes may be shipped without a major bump, but must be documented in the changelog and noted clearly in the release tag (`0.x.y` → `0.(x+1).0` for breaking changes).

## Release Process

1. Bump version in workspace `Cargo.toml` (`[workspace.package].version`).
2. Update `CHANGELOG.md` (if present) with breaking changes, new features, and fixes.
3. Open a release PR. CI must pass including `cargo-semver-checks` for stable crates.
4. Tag: `git tag v<version>` and push.
5. Publish stable crates: `cargo publish -p auths-verifier && cargo publish -p auths-core && cargo publish -p auths-sdk`.

## CI Enforcement

Pull requests are automatically checked by `cargo-semver-checks` for `auths-verifier`, `auths-core`, and `auths-sdk`. A PR that introduces a breaking change without a major version bump will fail CI.
