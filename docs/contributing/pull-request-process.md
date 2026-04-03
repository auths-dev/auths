# Pull Request Process

## Branch naming

Use descriptive branch names with a category prefix:

| Prefix | Use |
|--------|-----|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `refactor/` | Code restructuring without behavior change |
| `docs/` | Documentation changes |
| `chore/` | Maintenance, dependency updates, CI changes |

Alternatively, ticket-based naming (`fn-43`, `fix-127`) is used when branches map to tracked issues.

## Commit messages

Write commit messages in present tense using an imperative verb:

```
feat: add support for key rotation in CLI
fix: attestation expiry check off-by-one
refactor: storage trait to use thiserror
```

Not:

```
Added support for key rotation
Fixed the attestation expiry check
Refactored storage trait
```

Keep the first line under 72 characters. Use the body for additional context when the change is not self-explanatory.

## Before opening a PR

### Pre-commit hooks

The repo uses [pre-commit](https://pre-commit.com/) to run checks automatically on every commit and push. Install the hooks once after cloning:

```bash
pip install pre-commit   # or: brew install pre-commit
pre-commit install
pre-commit install --hook-type pre-push
```

**On commit**, the hooks run fast checks: `cargo fmt`, `cargo clippy`, YAML/TOML validation, actionlint, clippy config sync, and `cargo deny` (licenses + bans).

**On push**, slower checks run: the full test suite (`cargo nextest run`), Python bindings check, WASM compilation, and cross-platform `cargo check` for Linux, Windows, and aarch64.

If you need to bypass hooks temporarily (e.g. WIP commits), use `git commit --no-verify`, but make sure all checks pass before opening a PR.

### Manual checks

You can also run the checks manually:

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Test
cargo nextest run --workspace

# Doc tests
cargo test --all --doc
```

If you changed `auths-verifier`, also verify WASM compilation:

```bash
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

## Opening a PR

1. Push your branch to the remote.
2. Open a pull request against `main`.
3. Fill in the PR description with:
    - A summary of what changed and why.
    - Any breaking changes or migration steps.
    - How to test the change manually (if applicable).

## CI checks

CI runs the following on every PR across Ubuntu (x86_64), macOS (aarch64), and Windows (x86_64):

| Check | Command |
|-------|---------|
| Format | `cargo fmt --check --all` |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| Tests | `cargo nextest run --workspace` |
| Doc tests | `cargo test --all --doc` |
| Security audit | `cargo audit` |

All checks must pass before merging.

## Code review

- Every PR requires at least one approving review.
- Reviewers check for adherence to the [coding standards](coding-standards.md): no process comments, clock injection, `thiserror` in domain crates, proper docstrings on public APIs.
- If a reviewer requests changes, address them and push new commits. Do not force-push over review comments.

## Merging

PRs are merged via squash merge to keep `main` history linear. The squash commit message should follow the same conventions as individual commits: present tense, imperative verb, under 72 characters.

## After merging

If you made changes to the CLI, remember to reinstall locally:

```bash
cargo install --path crates/auths-cli
```
