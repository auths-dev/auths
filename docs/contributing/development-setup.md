# Development Setup

This guide walks through setting up a local development environment for Auths.

## Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust | 1.93+ | Check `rust-toolchain.toml` at repo root |
| Git | 2.34+ | Required for SHA-256 object format support |
| cargo-nextest | latest | Test runner used by CI |
| cargo-audit | latest | Security audit tool |

### Optional

| Tool | Purpose |
|------|---------|
| `wasm-pack` / `wasm32-unknown-unknown` target | Building the WASM verifier |
| `maturin` | Building Python bindings |
| `just` | Running release automation recipes |

## Clone and build

```bash
git clone https://github.com/auths-dev/auths.git
cd auths
cargo build
```

## Install cargo-nextest

Auths uses [cargo-nextest](https://nexte.st) as its test runner. Install it once:

```bash
cargo install cargo-nextest
```

## Run tests

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

## Git configuration for tests

Many tests create temporary Git repositories. They require a global Git identity:

```bash
git config --global user.name "Test User"
git config --global user.email "test@example.com"
```

CI configures this automatically. If you see "please tell me who you are" errors locally, this is the fix.

## Lint and format

```bash
# Format code
cargo fmt --all

# Check formatting (CI uses this)
cargo fmt --check --all

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit
```

## WASM verification

The `auths-verifier` crate compiles to WASM. To verify locally:

```bash
# Must cd into the crate — resolver = "3" rejects --features from workspace root
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

## Installing the CLI locally

After making changes to the CLI, reinstall it to test:

```bash
cargo install --path crates/auths-cli
```

This is a common source of confusion: if your local `auths` binary does not reflect your code changes, you likely need to reinstall.

## Editor setup

### VS Code

Recommended extensions:

- **rust-analyzer** -- provides inline type hints, completions, and diagnostics
- **Even Better TOML** -- syntax highlighting for `Cargo.toml`
- **CodeLLDB** -- debugger integration for Rust

Add to `.vscode/settings.json`:

```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.extraArgs": ["--all-targets", "--all-features"]
}
```

### JetBrains (RustRover / IntelliJ)

Install the Rust plugin. Set the toolchain to match the version in `rust-toolchain.toml`.

### Neovim

Use `nvim-lspconfig` with the `rust_analyzer` server. Ensure `clippy` is configured as the check command.

## CI matrix

CI runs on three platforms. If you only have access to one, CI will catch platform-specific failures:

| Platform | Architecture |
|----------|-------------|
| Ubuntu | x86_64 |
| macOS | aarch64 |
| Windows | x86_64 |
