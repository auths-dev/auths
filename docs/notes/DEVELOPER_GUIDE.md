# Auths Developer Guide

Welcome, developer! This guide provides instructions on how to set up your environment, build, test, and contribute to the Auths project.

## Prerequisites

* **Rust Toolchain:** Ensure you have Rust and Cargo installed. If not, get them from [https://rustup.rs/](https://rustup.rs/). We recommend using the latest stable version unless specific nightly features are required (check `rust-toolchain.toml` if present).
* **Git:** Required for cloning the repository and managing versions.
* **(macOS):** Xcode Command Line Tools (for Keychain access FFI).
* **(Linux):** `libclang-dev`, `pkg-config`, `libssl-dev` (dependencies for `ring` and potentially other crates). `libsecret-1-dev` and `libdbus-1-dev` might be needed for Linux keyring support if added later.
* **(Optional):** `jq` for easier parsing of JSON output during testing/debugging.

---

## Getting Started

1.  **Clone the Repository:**
    ```bash
    git clone git@github.com:bordumb/mobile-ssh-agent.git
    cd mobile-ssh-agent
    ```

---

2.  **Fetch Dependencies:** Cargo will handle this automatically during the build step.

## Building the Project

Auths is structured as a Cargo workspace.

1.  **Build All Crates (Debug):** For development and testing, use a debug build.
    ```bash
    cargo build
    ```
    This compiles all crates in the workspace. Binaries will be located in `./target/debug/`.

2.  **Build Specific Crate (e.g., `auths-cli`):**
    ```bash
    cargo build --package auths_cli
    ```

3.  **Build for Release:** For optimized binaries suitable for distribution (though not recommended until stable).
    ```bash
    cargo build --release
    ```
    Binaries will be in `./target/release/`.

### Project Structure

This repository is a Cargo workspace containing several key crates:
```
auths/ (repository root)
├── crates/
│   ├── auths-core/      # Foundational crypto, FFI, secure storage (Keychain)
│   ├── auths-id/        # Multi-device identity logic, attestations, Git storage
│   ├── auths-cli/       # Command-line interface application (auths)
├── docs/
│   ├── DEVELOPER_GUIDE.md # Guide for contributors
│   └── ...               # Other documentation
├── scripts/              # Build/test scripts
├── target/               # Build artifacts (ignored by git)
├── Cargo.toml            # Workspace manifest
└── README.md             # This file
```
### Crate Overview

* **`auths-core`:** The foundation. Provides cryptographic primitives, the `Storage` trait with Keychain implementations (macOS, iOS) for secure key storage, encryption utilities, and the FFI layer for potential integration with other languages (like Swift).
* **`auths-id`:** Implements the logic for multi-device identities. It handles DID creation/resolution (KERI, Key), creation and verification of device link attestations, and interaction with Git repositories for storing identity and attestation data according to the defined layout.
* **`auths-cli`:** The user-facing command-line tool (`auths`). It uses `auths-core` and `auths-id` to provide commands for initializing identities (`id init-did`), linking devices (`device link`), viewing status (`id show`, `id show-devices`), and potentially other key management tasks.

---

## Running Tests

Ensure code quality and prevent regressions by running the test suite.

1.  **Run All Tests:** Execute tests across all crates in the workspace.
    ```bash
    cargo test --all
    ```

2.  **Run Tests for Specific Crate:**
    ```bash
    cargo test --package auths_id
    ```

3.  **Run Specific Test Function:**
    ```bash
    cargo test --package auths_id --test test_attestation test_verification_logic -- --exact
    ```
    (Replace `test_attestation` with the test file name and `test_verification_logic` with the test function name).

## Code Formatting and Linting

We use standard Rust tooling for code quality.

1.  **Formatting:** Ensure your code adheres to the standard Rust style.
    ```bash
    cargo fmt --all -- --check # Check formatting
    cargo fmt --all           # Apply formatting
    ```
    *(Ensure your local `rustfmt` version matches the one used in CI - see `.github/workflows/`)*

2.  **Linting:** Check for common mistakes and style issues using Clippy.
    ```bash
    cargo clippy --all -- -D warnings
    ```

3. **Further Fixes**: To automatically apply suggested fixes for lints and warnings (like prefixing unused variables) directly in your code, even with uncommitted/staged changes, run the below.
    ```bash
    cargo fix --allow-dirty --allow-staged
    ```

## Creating a Release (Alpha Stage)

As an early-stage project (0.0.x), releases indicate tested milestones but do not guarantee API stability. We follow Semantic Versioning (SemVer).

### Semantic Versioning (SemVer) Basics (Pre-1.0.0)

* **Format:** `0.MAJOR.MINOR` (or `0.MINOR.PATCH` depending on interpretation for 0.x)
* **`0.y.z` Stage:** Indicates initial development. Anything MAY change at any time. The public API should not be considered stable.
* **Incrementing `y` (MINOR for 0.x):** Typically signifies potentially breaking changes or significant new features within the unstable 0.x series.
* **Incrementing `z` (PATCH for 0.x):** Typically signifies backward-compatible bug fixes or minor feature additions within the current `0.y` series.

For `v0.0.1`: This is the very first experimental/alpha release.

### Release Steps

1.  **Ensure `main`/`master` is Stable:** Merge all features and fixes intended for the release into the main branch. Ensure all CI checks (build, test, format, lint) are passing.
2.  **Update Version Numbers:**
    * Check `Cargo.toml` files in the workspace (root and individual crates).
    * Update the `version = "..."` field to the target release version (e.g., `0.0.1`). Use `cargo set-version 0.0.1` if using `cargo-edit`.
    * Update `Cargo.lock`: Run `cargo check` or `cargo build` to update the lock file based on new version numbers.
    * Commit these version bumps:
        ```bash
        git add .
        git commit -m "Bump version to v0.0.1"
        git push origin main # Or your main branch name
        ```
3.  **Create Git Tag:** Tag the commit you just created. Use annotated tags (`-a`).
    ```bash
    # Example for v0.0.1
    git tag -a v0.0.1 -m "Release v0.0.1 (Alpha)"
    ```
4.  **Push Git Tag:** Push the tag to the remote repository (e.g., GitHub).
    ```bash
    git push origin v0.0.1
    ```
5.  **(Optional) Create GitHub Release:**
    * Go to your repository on GitHub.
    * Click on "Releases" (usually under the "Code" tab).
    * Click "Draft a new release".
    * Choose the tag you just pushed (e.g., `v0.0.1`).
    * Write release notes summarizing the changes since the last release (or since the beginning for v0.0.1). Mention it's an **alpha release** and subject to change.
    * *(Optional)* Build release binaries (`cargo build --release`) for different targets (macOS x86_64, macOS aarch64, Linux x86_64 etc.), archive them (e.g., `.tar.gz`, `.zip`), and attach them to the GitHub release.
    * Mark it as a "pre-release" if it's alpha/beta.
    * Publish the release.
6.  **(Optional) Publish to Crates.io:**
    * For libraries (`auths-core`, `auths-id`), you might publish them using `cargo publish -p <crate_name>`.
    * For binaries (`auths-cli`), publishing is less common unless it's intended as a library or installed via `cargo install`. Usually, users download binaries from GitHub Releases for CLIs.
    * **Note:** Publishing `0.x.y` versions is fine, but clearly mark them as unstable. Once published, a specific version cannot be overwritten.

Happy coding!
