# E2E Tests

Black-box tests that exercise the Auths CLI binaries (`auths`, `auths-sign`, `auths-verify`) as a real user would. Each test spawns subprocesses in isolated temp directories — no Rust internals are imported.

Covers: identity lifecycle, device attestation, git signing, key rotation, policy engine, and OIDC bridge.

## Quick start

```bash
# 1. Build the CLI binaries
cargo build --package auths-cli

# 2. Run the tests (uv installs deps automatically)
cd tests/e2e
uv run pytest -v
```

To point at a specific build:

```bash
AUTHS_BIN=../../target/release/auths uv run pytest -v
```

Run a single file or skip slow tests:

```bash
uv run pytest test_git_signing.py -v
uv run pytest -m "not slow" -v
```
