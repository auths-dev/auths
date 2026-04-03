# Release Process

## Versioning

Auths follows Semantic Versioning (SemVer). The project is currently pre-1.0 (`0.x.y`).

| Increment | Meaning |
|-----------|---------|
| `0.y.z` to `0.y.(z+1)` | Bug fixes, minor additions |
| `0.y.z` to `0.(y+1).0` | Breaking changes, significant features |

All pre-1.0 versions are unstable. The public API may change at any time.

The current workspace version is defined in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.0.1-rc.5"
```

## Release steps

### Using the release scripts

The `justfile` at the repo root automates all release steps:

GitHub Release:
```bash
just github-release
```
This handles pre-flight checks (clean working tree, branch, remote sync), creates and pushes the annotated tag, and opens the GitHub Actions run in your browser. GitHub Actions then builds binaries, creates the release, and triggers the Homebrew formula update.

> Note: GitHub releases should succeed before moving onto crate.io release.

[crates.io](https://crates.io/crates/auths-cli) release:
```bash
just crates-release
```
This makes similar checks as the github release. It also includes properly ordering runs based on dependency ordering, as well as a sleep timer to help crates.io fully upload crates with preceeding dependency.

### One-time CI signing setup

Before the first release, GitHub Actions needs a device key and identity bundle for artifact signing:

```bash
just ci-setup
```

This creates a limited-capability CI device key, exports it as an encrypted keychain, and sets three GitHub secrets: `AUTHS_CI_PASSPHRASE`, `AUTHS_CI_KEYCHAIN`, and `AUTHS_CI_IDENTITY_BUNDLE`. Artifact signing is skipped gracefully if these secrets are missing.

Re-run `ci-setup` only if the CI device key is revoked or the identity repo changes significantly.

### Manual steps (if needed)

#### 1. Ensure main is stable

```bash
cargo build
cargo nextest run --workspace
cargo test --all --doc
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
```

#### 2. Update version numbers

```bash
# If using cargo-edit:
cargo set-version 0.x.y
cargo check  # updates Cargo.lock

git add .
git commit -m "Bump version to v0.x.y"
git push origin main
```

#### 3. Create Git tag

```bash
git tag -a v0.x.y -m "Release v0.x.y"
git push origin v0.x.y
```

GitHub Actions picks up the `v*` tag and runs `.github/workflows/release.yml`.

#### 4. Publish Rust crates

```bash
cargo publish -p auths
cargo publish -p auths-crypto
cargo publish -p auths-index
cargo publish -p auths-policy
cargo publish -p auths-telemetry
sleep 60
cargo publish -p auths-verifier
cargo publish -p auths-keri
cargo publish -p auths-core
sleep 60
cargo publish -p auths-infra-http
sleep 60
cargo publish -p auths-id
sleep 60
cargo publish -p auths-storage
cargo publish -p auths-sdk
sleep 60
cargo publish -p auths-infra-git
sleep 60
cargo publish -p auths-cli
```

#### 5. Publish SDK packages (optional)

```bash
# Python
cd packages/auths-verifier-python
maturin build --release
twine upload target/wheels/*

# JavaScript
cd packages/auths-verifier-ts
npm run build
npm publish

# Go
# Tag the module: git tag packages/auths-verifier-go/v0.x.y
```

## SDK versioning

SDK packages (Python, TypeScript, Go, Swift) have independent version numbers from the Rust crates.

| Component | Registry |
|-----------|----------|
| Rust crates (`auths-core`, `auths-verifier`, ...) | crates.io |
| Python SDK (`auths-verifier`) | PyPI |
| TypeScript SDK (`@auths/verifier`) | npm |

SDK versions track their own binding API stability. A breaking change in the Python wrapper bumps the Python version even if the underlying Rust API did not change. An internal Rust refactor that does not affect the binding surface does not require an SDK version bump.

### Automated SDK publishing

SDK publishing is automated via GitHub Actions triggered by `v*` tags:

- **Python**: `.github/workflows/publish-python.yml` -- builds platform wheels with maturin and publishes to PyPI using Trusted Publisher.
- **TypeScript**: `.github/workflows/publish-typescript.yml` -- builds WASM + TypeScript and publishes to npm.

## CI matrix

| Platform | Architecture |
|----------|-------------|
| Ubuntu | x86_64 |
| macOS | aarch64 |
| Windows | x86_64 |

Rust version: 1.93+ (check `rust-toolchain.toml`).

## What CI does on a release tag

When a `v*` tag is pushed:

1. Runs the full test suite across all three platforms.
2. Builds release binaries for each platform.
3. Creates a GitHub Release with the binaries attached.
4. Signs artifacts with the CI device key (if secrets are configured).
5. Triggers the Homebrew formula update.
6. Triggers SDK publishing workflows (Python, TypeScript).
