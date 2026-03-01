# Contributing

Thank you for contributing to Auths.

| Guide | Description |
|-------|-------------|
| [Repo Layout](repo-layout.md) | Crate structure and what goes where |
| [Adding a Binding](adding-a-binding.md) | How to add a new language binding |
| [Release Process](release-process.md) | Versioning and release steps |
| [Security Notes](security-notes.md) | Security-sensitive areas and practices |

## Quick start for contributors

```bash
git clone https://github.com/auths-dev/auths.git
cd auths
cargo build
cargo test --all
```

## Code quality

```bash
cargo fmt --all                                          # Format
cargo fmt --check --all                                  # Check formatting
cargo clippy --all-targets --all-features -- -D warnings # Lint
cargo audit                                              # Security audit
```

## Pull request process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Run `cargo fmt --all` and `cargo clippy --all -- -D warnings`
4. Run `cargo test --all`
5. Commit with a clear message (present tense: "Add support for..." not "Added support for...")
6. Open a PR against `main`

## CI requirements

Tests require Git configuration:

```bash
git config --global user.name "Test User"
git config --global user.email "test@example.com"
```

CI runs on: Ubuntu (x86_64), macOS (aarch64), Windows (x86_64). Rust 1.93+.
