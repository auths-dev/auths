# auths

Cryptographic identity for developers. One command to set up, Git-native storage, no central server.

## Getting Started (10 seconds)

```bash
auths init
auths doctor
git commit -m "first signed commit"
auths verify HEAD
```

That's it. `auths init` generates keys, creates your identity, and configures Git signing.

### Link another device

```bash
auths pair                         # On existing device — shows QR/code
auths pair --join ABC123           # On new device — enter the code
```

## The Basics

### `auths sign` — Sign a commit or artifact

```bash
auths sign HEAD                    # Sign latest commit
auths sign main..HEAD              # Sign a range
auths sign ./release.tar.gz       # Sign a file
```

### `auths verify` — Verify signatures

```bash
auths verify                       # Verify HEAD
auths verify HEAD~3..HEAD          # Verify a range
auths verify abc1234               # Verify specific commit
auths verify path/to/attestation   # Verify attestation file
```

### `auths status` — See your identity at a glance

```bash
auths status
```

### `auths whoami` — Show the current identity

```bash
auths whoami
```

### `auths doctor` — Health checks

```bash
auths doctor
# Exit code 0 = all checks pass, 1 = something needs attention
```

### `auths tutorial` — Interactive walkthrough

```bash
auths tutorial
```

## Artifact Signing

Sign, verify, and publish arbitrary files — binaries, packages, container images — with the same identity used for commits.

### Sign an artifact

```bash
auths artifact sign ./release.tar.gz
auths artifact sign ./my-app.whl --note "v2.1.0 release"
auths artifact sign ./build.zip --expires-in 90   # expires in 90 days
```

### Verify an artifact

```bash
auths artifact verify ./release.tar.gz
```

### Batch sign multiple artifacts

```bash
auths artifact batch-sign ./dist/
```

### Publish an attestation to a registry

```bash
auths artifact publish ./release.tar.gz.auths.json --registry https://registry.example.com
```

The `auths sign` shorthand also supports artifact files — if the target is a file on disk, it signs the artifact instead of a commit:

```bash
auths sign ./release.tar.gz   # equivalent to: auths artifact sign ./release.tar.gz
```

## Advanced Commands

Run `auths --help-all` to see the full command list:

| Group | What it does |
|---|---|
| `id` | Create, rotate, export, and register identities |
| `device` | Link, revoke, and manage device authorizations |
| `key` | List, import, export, and delete keys |
| `approval` | Manage approval workflows |
| `artifact` | Sign, verify, and publish arbitrary files |
| `policy` | Lint, compile, test, and diff authorization policies |
| `git` | Generate allowed-signers files, install hooks |
| `trust` | Pin identity-to-key bindings (TOFU) |
| `org` | Manage organizations, members, and attestations |
| `audit` | Generate signing audit reports |
| `agent` | Start/stop the SSH agent daemon |
| `witness` | Run or manage KERI witness servers |
| `scim` | SCIM provisioning integration |
| `config` | View and modify configuration |
| `emergency` | Key compromise response (revoke, rotate, freeze) |
| `completions` | Generate shell completions |

Run `auths <group> --help` for details on any group.

## CI Setup (GitHub Actions)

`auths init --profile ci` creates an ephemeral in-memory identity scoped to the current run — no platform keychain required, no secrets to rotate.

### Signing commits in CI

```yaml
name: Signed Commits
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      AUTHS_KEYCHAIN_BACKEND: memory
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install Auths
        run: cargo install --path crates/auths-cli --force
      - name: Set up Auths (CI profile)
        run: auths init --profile ci --non-interactive
      - name: Run doctor (verify setup)
        run: auths doctor
      - name: Your build step
        run: cargo build --release
```

### Verifying commit signatures in CI

```yaml
name: Verify Commit Signatures
on: [pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@stable
      - name: Install Auths
        run: cargo install --path crates/auths-cli --force
      - name: Verify commits on this PR
        run: auths verify HEAD
```

## Installation

```bash
cargo install --path crates/auths-cli --force
```

This installs three binaries: `auths`, `auths-sign`, and `auths-verify`. Ensure `~/.cargo/bin` is in your PATH.
