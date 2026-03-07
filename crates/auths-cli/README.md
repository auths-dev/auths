# Auths CLI

Cryptographic identity for developers. Sign commits, link devices, verify signatures — all stored in Git, no central server.

## Installation

```bash
cargo install --path crates/auths-cli --force
```

This installs three binaries to `~/.cargo/bin`:

- `auths` — main CLI
- `auths-sign` — standalone signing (for git hooks)
- `auths-verify` — standalone verification

Ensure `~/.cargo/bin` is in your PATH:

```bash
echo $PATH | grep -q ".cargo/bin" || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
```

### Run without installing

```bash
cargo run -p auths-cli -- <arguments...>
```

### Global flags

These flags apply to all commands:

```
--repo <PATH>       Override storage directory (default: ~/.auths)
--format <FORMAT>   Output format: text or json
--json              Shorthand for --format json
-q, --quiet         Suppress non-essential output
```

---

## Quick Start

Three commands to go from zero to signed commits:

```bash
# 1. Create your identity
auths init

# 2. Verify everything is wired up
auths doctor

# 3. Sign and verify a commit
git commit -m "first signed commit"
auths verify HEAD
```

`auths init` handles everything: generates keys, creates your identity, links your device, and configures Git for automatic commit signing.

---

## Getting Started

### `auths init`

Interactive setup that creates your identity and configures Git signing.

```bash
auths init                              # Interactive developer setup
auths init --profile developer          # Same as above, explicit
auths init --profile ci                 # Ephemeral identity for CI/CD
auths init --profile agent              # Scoped identity for AI agents
auths init --non-interactive            # Skip prompts, use defaults
```

| Flag | Description |
|---|---|
| `--profile <PROFILE>` | `developer`, `ci`, or `agent` |
| `--key-alias <ALIAS>` | Key alias (default: `main`) |
| `--non-interactive` | Skip interactive prompts |
| `--force` | Overwrite existing identity |
| `--dry-run` | Preview without creating files |
| `--registry <URL>` | Registry URL for identity publication |
| `--skip-registration` | Skip automatic registry registration |

### `auths status`

Show current identity, agent, and device status at a glance.

```bash
auths status
```

### `auths doctor`

Run health checks on your setup: Git config, keychain access, identity state, allowed signers file.

```bash
auths doctor
# Exit code 0 = all checks pass, 1 = something needs attention
```

### `auths tutorial`

Interactive walkthrough covering identities, signing, verification, devices, and revocation.

```bash
auths tutorial                # Start from beginning
auths tutorial --list         # List all sections
auths tutorial --skip 3       # Jump to section 3
auths tutorial --reset        # Reset progress
```

---

## Verification & Signing

### `auths verify`

Verify commit signatures or attestation files. Accepts git refs, commit ranges, file paths, or stdin.

```bash
auths verify                            # Verify HEAD
auths verify HEAD~3..HEAD               # Verify a range
auths verify abc1234                    # Verify specific commit
auths verify path/to/attestation.json   # Verify attestation file
cat attestation.json | auths verify -   # Verify from stdin
```

| Flag | Description |
|---|---|
| `--allowed-signers <PATH>` | Signers file (default: `.auths/allowed_signers`) |
| `--identity-bundle <PATH>` | Identity bundle JSON for stateless CI verification |
| `--issuer-did <DID>` | Issuer identity for trust-based key resolution |
| `--witness-receipts <PATH>` | Witness receipts JSON file |
| `--witness-threshold <N>` | Witness quorum threshold (default: 1) |
| `--witness-keys <KEYS>...` | Witness public keys as DID:hex pairs |

### `auths sign`

Sign a commit or artifact file.

```bash
auths sign HEAD                         # Sign latest commit
auths sign main..HEAD                   # Sign a range
auths sign ./release.tar.gz             # Sign a file
```

| Flag | Description |
|---|---|
| `--device-key-alias <ALIAS>` | Device key for signing |
| `--identity-key-alias <ALIAS>` | Identity key (for dual-signing) |
| `--sig-output <PATH>` | Output path for signature file |
| `--expires-in-days <N>` | Signature expiration |
| `--note <NOTE>` | Embed a note in the attestation |

---

## Devices

Link multiple machines to your identity. Each device has its own key; the identity key authorizes them.

### `auths device list`

```bash
auths device list
auths device list --include-revoked
```

### `auths device link`

Authorize a new device by creating a signed attestation.

```bash
auths device link \
  --identity-key-alias main \
  --device-key-alias laptop \
  --device-did "did:key:z6Mk..." \
  --note "Work laptop" \
  --expires-in-days 90
```

| Flag | Description |
|---|---|
| `--identity-key-alias <ALIAS>` | Identity key for signing (required) |
| `--device-key-alias <ALIAS>` | Device key to authorize (required) |
| `--device-did <DID>` | Device DID (required) |
| `--capabilities <CAPS>` | Comma-separated permissions |
| `--expires-in-days <N>` | Authorization expiration |
| `--note <NOTE>` | Description |
| `--payload <PATH>` | JSON payload file |
| `--schema <PATH>` | JSON schema for payload validation |

### `auths device revoke`

```bash
auths device revoke \
  --identity-key-alias main \
  --device-did "did:key:z6Mk..." \
  --note "Laptop retired"
```

### `auths device extend`

Extend a device authorization's expiration.

```bash
auths device extend \
  --device-did "did:key:z6Mk..." \
  --days 90 \
  --identity-key-alias main \
  --device-key-alias laptop
```

### `auths device resolve`

Look up a device by DID.

```bash
auths device resolve --device-did "did:key:z6Mk..."
```

### `auths device pair`

Link a device via QR code or short code (for cross-device pairing).

### `auths device verify-attestation`

Verify a device authorization's signatures directly.

---

## Identity Management

### `auths id create`

Create a new identity manually (most users should use `auths init` instead).

```bash
auths id create \
  --local-key-alias main \
  --metadata-file ~/metadata.json \
  --preset default
```

| Flag | Description |
|---|---|
| `--local-key-alias <ALIAS>` | Alias for generated key |
| `--metadata-file <PATH>` | JSON metadata to embed |
| `--preset <PRESET>` | Storage layout: `default`, `radicle`, or `gitoxide` |

### `auths id show`

Display identity DID and metadata.

```bash
auths id show
```

### `auths id rotate`

Rotate identity keys using KERI pre-rotation. Your `did:keri:E...` stays the same; only the active signing key changes.

```bash
auths id rotate --alias main
auths id rotate --current-key-alias main --next-key-alias main_v2
```

| Flag | Description |
|---|---|
| `--alias <ALIAS>` | Key to rotate |
| `--current-key-alias <ALIAS>` | Alternative to `--alias` |
| `--next-key-alias <ALIAS>` | Alias for the new key |
| `--add-witness <PREFIX>` | Add a witness server (repeatable) |
| `--remove-witness <PREFIX>` | Remove a witness server (repeatable) |
| `--witness-threshold <N>` | New witness quorum threshold |

### `auths id export-bundle`

Export an identity bundle for stateless verification (useful for CI).

```bash
auths id export-bundle --alias main -o bundle.json
```

### `auths id register`

Publish your identity to a registry.

```bash
auths id register --registry https://auths-registry.fly.dev
```

### `auths id claim`

Add a platform claim to your identity (e.g., GitHub, email).

### `auths id migrate`

Import existing GPG or SSH keys into an Auths identity.

---

## Key Management

### `auths key list`

List all key aliases in secure storage.

### `auths key import`

Import a 32-byte Ed25519 seed file.

```bash
auths key import \
  --alias my_device \
  --seed-file ~/device.seed \
  --controller-did "did:keri:E..."
```

### `auths key export`

Export a key in different formats.

```bash
auths key export --alias main --passphrase "..." --format pub   # Public key
auths key export --alias main --passphrase "..." --format pem   # Private key (PEM)
auths key export --alias main --passphrase "..." --format enc   # Encrypted
```

### `auths key delete`

Remove a key from secure storage.

```bash
auths key delete --alias old_key
```

### `auths key copy-backend`

Copy a key to a different storage backend (e.g., file keychain for CI).

```bash
auths key copy-backend --alias main --dst-backend file --dst-file ./keys.json
```

---

## Organizations

Manage organizations with member roles and authorization policies.

### `auths org init`

Create an organization identity.

```bash
auths org init --name "My Org"
auths org init --name "My Org" --local-key-alias org_key --metadata-file org.json
```

### `auths org add-member`

```bash
auths org add-member \
  --org "did:keri:E..." \
  --member "did:keri:E..." \
  --role admin \
  --signer-alias org_key
```

Roles: `admin`, `member`, `readonly`.

### `auths org revoke-member`

```bash
auths org revoke-member \
  --org "did:keri:E..." \
  --member "did:keri:E..." \
  --signer-alias org_key \
  --note "Access removed"
```

### `auths org list-members`

```bash
auths org list-members --org "did:keri:E..."
auths org list-members --org "did:keri:E..." --include-revoked
```

### `auths org attest`

Issue an organizational attestation for a subject.

```bash
auths org attest \
  --subject "did:keri:E..." \
  --payload-file claim.json \
  --signer-alias org_key \
  --expires-at "2025-12-31T00:00:00Z"
```

### `auths org revoke`

Revoke an organizational attestation.

```bash
auths org revoke --subject "did:keri:E..." --signer-alias org_key
```

### `auths org show`

Show attestations for a subject.

```bash
auths org show --subject "did:keri:E..."
auths org show --subject "did:keri:E..." --include-revoked
```

### `auths org list`

List all organizational attestations.

### `auths policy`

Validate, test, and compare authorization policies.

| Subcommand | Description |
|---|---|
| `auths policy lint <file>` | Validate policy JSON syntax and structure |
| `auths policy compile <file>` | Compile a policy to its canonical form |
| `auths policy explain <file> -c context.json` | Explain how a policy evaluates against a context |
| `auths policy test <file> -t tests.json` | Run a policy test suite |
| `auths policy diff <old> <new>` | Show differences between two policy versions |

---

## Artifacts

Sign, verify, and publish arbitrary files (binaries, packages, configs).

### `auths artifact sign`

```bash
auths artifact sign release.tar.gz \
  --device-key-alias laptop \
  --identity-key-alias main \
  --expires-in-days 365
```

### `auths artifact verify`

```bash
auths artifact verify release.tar.gz
auths artifact verify release.tar.gz --signature release.tar.gz.auths.json
```

### `auths artifact publish`

Publish a signature to a registry.

```bash
auths artifact publish \
  --signature release.tar.gz.auths.json \
  --package "npm:my-package@1.0.0" \
  --registry https://auths-registry.fly.dev
```

---

## Trust & Witnesses

### `auths trust`

Pin identity-to-key bindings locally (trust-on-first-use).

| Subcommand | Description |
|---|---|
| `auths trust list` | Show all pinned identities |
| `auths trust show <DID>` | Show details for a pinned identity |
| `auths trust pin --did <DID> --key <HEX>` | Pin an identity's public key |
| `auths trust remove <DID>` | Remove a pinned identity |

### `auths witness`

Run or manage KERI witness servers for independent event verification.

| Subcommand | Description |
|---|---|
| `auths witness serve` | Run a witness server (`--bind`, `--db-path`) |
| `auths witness add --url <URL>` | Register a witness |
| `auths witness remove --url <URL>` | Unregister a witness |
| `auths witness list` | Show configured witnesses |

---

## Git Integration

### `auths git allowed-signers`

Generate an `allowed_signers` file from your identity's device keys.

```bash
auths git allowed-signers -o .auths/allowed_signers
```

### `auths git install-hooks`

Install Git hooks for automatic signature verification.

```bash
auths git install-hooks --repo .
auths git install-hooks --repo . --force   # Overwrite existing hooks
```

---

## Security & Compliance

### `auths audit`

Generate signing audit reports for compliance.

```bash
auths audit --since 2025-Q1 --format table
auths audit --since 2025-01-01 --until 2025-03-31 --format csv -o report.csv
auths audit --require-all-signed --exit-code   # Fail if unsigned commits found
```

| Flag | Description |
|---|---|
| `--since <DATE>` | Start date (YYYY-MM-DD or YYYY-QN) |
| `--until <DATE>` | End date |
| `--format <FMT>` | `table`, `csv`, `json`, or `html` |
| `--author <EMAIL>` | Filter by author |
| `--signer <DID>` | Filter by signing identity |
| `-n, --count <N>` | Max commits (default: 100) |
| `--require-all-signed` | Require all commits to be signed |
| `--exit-code` | Exit 1 if unsigned commits found |
| `-o, --output-file <PATH>` | Output file |

### `auths emergency`

Emergency response commands for key compromise or security incidents. Running without a subcommand starts an interactive flow.

| Subcommand | Description |
|---|---|
| `auths emergency revoke-device` | Emergency device revocation (`--device`, `--dry-run`, `-y`) |
| `auths emergency rotate-now` | Immediate key rotation (`--current-alias`, `--next-alias`, `--reason`) |
| `auths emergency freeze` | Temporarily freeze identity operations (`--duration`, default 24h) |
| `auths emergency unfreeze` | Resume operations after a freeze |
| `auths emergency report` | Generate incident report (`--events <N>`, `-o <PATH>`) |

---

## SSH Agent

The Auths agent daemon manages keys in memory and provides SSH agent protocol support.

| Subcommand | Description |
|---|---|
| `auths agent start` | Start the daemon (`--socket`, `--foreground`, `--timeout`) |
| `auths agent stop` | Stop the daemon |
| `auths agent status` | Show daemon status |
| `auths agent env` | Print shell environment variables (`--shell bash\|zsh\|fish`) |
| `auths agent lock` | Clear keys from memory |
| `auths agent unlock` | Load a key into the agent (`--key <ALIAS>`) |
| `auths agent install-service` | Install as system service (launchd/systemd) |
| `auths agent uninstall-service` | Remove system service |

---

## Utilities

### `auths completions`

Generate shell completions.

```bash
auths completions bash > ~/.bash_completion.d/auths
auths completions zsh > ~/.zfunc/_auths
auths completions fish > ~/.config/fish/completions/auths.fish
```

### `auths util derive-did`

Derive a `did:key` from an Ed25519 seed.

```bash
auths util derive-did --seed-hex $(xxd -p -c 256 my_seed.raw)
```

### `auths util pubkey-to-did`

Convert an OpenSSH Ed25519 public key to a DID.

```bash
auths util pubkey-to-did "ssh-ed25519 AAAA..."
```

### `auths util verify-attestation`

Verify an attestation file directly with a known issuer public key.

```bash
auths util verify-attestation \
  --attestation-file auth.json \
  --issuer-pubkey <64-char-hex>
```

---

## CI Setup (GitHub Actions)

`auths init --profile ci` creates an ephemeral in-memory identity scoped to the
current run — no platform keychain required, no secrets to rotate, no state left
behind after the job ends.

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

### Troubleshooting CI

Run `auths doctor` as the first step in any failing job.
Exit code 0 = all checks pass. Exit code 1 = at least one check failed.

---

## Advanced: Layout Overrides

Several commands accept layout override flags under the "Advanced Setup" heading. These are per-command flags (not global) for working with non-default Git ref layouts:

```
--identity-ref <GIT_REF>               Git ref for identity (e.g., refs/rad/id)
--identity-blob <FILENAME>             Blob name for identity data
--attestation-prefix <GIT_REF_PREFIX>  Base ref prefix for device attestations
--attestation-blob <FILENAME>          Blob name for attestation data
```

For most users, the `--preset` flag on `auths id create` is simpler:

```bash
auths id create --preset default    # refs/rad/id, refs/keys (RIP-X layout)
auths id create --preset radicle    # Same as default
auths id create --preset gitoxide   # refs/auths/id, refs/auths/devices
```
