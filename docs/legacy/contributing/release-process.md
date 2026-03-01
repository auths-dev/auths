# Release Process

Auths follows Semantic Versioning (SemVer). The project is currently pre-1.0 (`0.x.y`).

## Versioning (pre-1.0)

| Increment | Meaning |
|-----------|---------|
| `0.y.z` → `0.y.(z+1)` | Bug fixes, minor additions |
| `0.y.z` → `0.(y+1).0` | Breaking changes, significant features |

All pre-1.0 versions are unstable. The public API may change at any time.

## Release steps

> **Use the justfile.** The [`justfile`](../../justfile) at the repo root automates all release steps.
> Read it to understand the manual steps behind each recipe.

### Step 0 — One-time CI signing setup (required before first release)

Before `just release` can sign artifacts, GitHub Actions needs a device key and identity bundle. Run this once from your local machine (requires an existing `auths` identity — run `auths init` first if needed):

```bash
just ci-setup
```

This creates a limited-capability CI device key, exports it as an encrypted keychain, and sets three GitHub secrets automatically: `AUTHS_CI_PASSPHRASE`, `AUTHS_CI_KEYCHAIN`, and `AUTHS_CI_IDENTITY_BUNDLE`. Artifact signing in the release workflow is skipped gracefully if these secrets are missing, so releases still work — but artifacts won't be signed.

You only need to re-run `ci-setup` if the CI device key is revoked or the identity repo changes significantly.

### Step 1 — Release

```bash
# Bump version in all Cargo.toml files, commit, then:
just release 0.x.y
```

`just release` handles the pre-flight checks (clean working tree, branch, remote sync), creates and pushes the annotated tag, and opens the GitHub Actions run in your browser. GitHub Actions then builds binaries, creates the release, and triggers the Homebrew formula update automatically.

See [`justfile`](../../justfile) for what each recipe does step by step.

---

### Manual steps (if needed)

The justfile recipes are thin wrappers around standard commands. If you need to run steps individually:

#### 1. Ensure main is stable

```bash
cargo build
cargo test --all
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

#### 4. Publish crates (optional)

```bash
cargo publish -p auths_core
cargo publish -p auths_id
cargo publish -p auths_verifier
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

SDK packages (Python, TypeScript, Go, Swift) have **independent version numbers** from the Rust crates.

| Component | Current version | Registry |
|-----------|----------------|----------|
| Rust crates (`auths-core`, `auths-verifier`, ...) | `0.0.1-rc.9` | crates.io |
| Python SDK (`auths-verifier`) | `0.1.0` | PyPI |
| TypeScript SDK (`@auths/verifier`) | `0.1.0` | npm |

SDK versions track their own binding API stability. A breaking change in the Python wrapper (e.g. renaming a function) bumps the Python minor version even if the underlying Rust API didn't change. Conversely, an internal Rust refactor that doesn't affect the binding surface doesn't require an SDK version bump.

### Publishing SDKs

SDK publishing is automated via GitHub Actions workflows triggered by `v*` tags:

- **Python**: `.github/workflows/publish-python.yml` -- builds platform wheels with maturin and publishes to PyPI using Trusted Publisher.
- **TypeScript**: `.github/workflows/publish-typescript.yml` -- builds WASM + TypeScript and publishes to npm.

To publish, create and push a version tag:

```bash
git tag -a v0.1.1 -m "SDK release v0.1.1"
git push origin v0.1.1
```

## CI matrix

CI runs on:

| Platform | Architecture |
|----------|-------------|
| Ubuntu | x86_64 |
| macOS | aarch64 |
| Windows | x86_64 |

Rust version: 1.93+ (check `rust-toolchain.toml`)
