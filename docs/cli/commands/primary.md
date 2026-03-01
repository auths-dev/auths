# Primary commands

These are the four commands you use day-to-day. Run `auths --help` to see them.

---

## auths init

Guided setup for initializing an Auths identity. One command takes you from zero to signed commits.

```bash
auths init [--profile <PROFILE>] [--key-alias <ALIAS>] [--non-interactive] [--force]
```

<!-- BEGIN GENERATED: auths init -->
| Flag | Default | Description |
|------|---------|-------------|
| `--profile <PROFILE>` | (prompted) | Setup profile: `developer`, `ci`, or `agent` |
| `--key-alias <ALIAS>` | `main` | Alias for the identity key in the keychain |
| `--non-interactive` | `false` | Skip all prompts, use defaults |
| `--force` | `false` | Proceed even if an identity already exists |
<!-- END GENERATED: auths init -->

### Profiles

#### Developer

Full local development setup. This is the profile most individual developers should use.

```bash
auths init --profile developer
```

What it does (5 steps):

1. **Check prerequisites** — verifies keychain access and Git >= 2.34
2. **Set up identity** — creates a new `did:keri` identity at `~/.auths` (or reuses an existing one)
3. **Link device** — links the current machine via the identity key
4. **Configure Git** — sets `gpg.format=ssh`, `gpg.ssh.program=auths-sign`, and `commit.gpgSign=true`; you choose `--global` or `--local` scope interactively
5. **Health check** — runs `auths doctor` to verify everything works

After setup, your next commit will be signed automatically.

#### CI

Ephemeral identity for CI/CD pipelines.

```bash
auths init --profile ci --non-interactive
```

What it does:

1. **Detect CI environment** — recognizes GitHub Actions, GitLab CI, CircleCI, Jenkins, Buildkite, Travis
2. **Create ephemeral identity** — uses a memory-backed keychain (`AUTHS_KEYCHAIN_BACKEND=memory`) and a `.auths-ci/` directory in the workspace
3. **Generate configuration** — outputs environment variables to add to your CI secrets

Example GitHub Actions snippet:

```yaml
env:
  AUTHS_KEYCHAIN_BACKEND: memory
  AUTHS_KEY_ALIAS: ci-key

steps:
  - uses: actions/checkout@v4
  - name: Setup Auths
    run: auths init --profile ci --non-interactive
```

#### Agent

Scoped identity for AI agents with capability restrictions.

```bash
auths init --profile agent
```

What it does:

1. **Create agent identity** — initializes a separate identity at `~/.auths-agent`
2. **Select capabilities** — interactively choose what the agent is allowed to do: `sign_commit`, `sign_release`, `manage_members`, `rotate_keys`
3. **Generate configuration** — writes `auths-agent.toml` with the identity DID, key alias, capabilities, and socket path

Non-interactive mode defaults to `sign_commit` only:

```bash
auths init --profile agent --non-interactive
```

### Shell completions

During interactive developer setup you'll be offered shell completions for Bash, Zsh, or Fish. To install manually:

```bash
auths completions zsh  > ~/.zfunc/_auths
auths completions bash > ~/.local/share/bash-completion/completions/auths
auths completions fish > ~/.config/fish/completions/auths.fish
```

### Examples

```bash
# Quick non-interactive developer setup
auths init --profile developer --non-interactive

# Custom key alias
auths init --profile developer --key-alias work-laptop

# Re-run on a machine that already has an identity
auths init --force
```

---

## auths sign

!!! note "You should almost never call `auths sign` directly"
    This binary exists to satisfy Git's `gpg.ssh.program` interface. Git calls it automatically when you run `git commit`. If you want to sign something, just commit normally with signing enabled.

`auths-sign` is a standalone binary that implements the SSH signing protocol expected by Git. It is not called directly — Git invokes it during `git commit -S`.

### How it works

1. Git passes the commit data to `auths-sign` via stdin
2. `auths-sign` reads the signing key alias from `user.signingKey` (format: `auths:<alias>`)
3. It loads the key from the platform keychain
4. It prompts for the passphrase via `/dev/tty`
5. It signs the data and returns the SSH signature to Git

### Git configuration

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:my-key"
```

`auths init` sets all of this automatically. Use these commands only if you need to reconfigure manually.

### Troubleshooting

**"auths-sign: command not found"**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

**No passphrase prompt** — `auths-sign` reads passphrases from `/dev/tty`. Run Git from an interactive terminal.

**"Key not found"** — verify the alias matches `user.signingKey` (without the `auths:` prefix):

```bash
auths key list
```

---

## auths verify

Verify attestations and commit signatures.

### `auths verify`

Verify a standalone attestation file.

```bash
auths verify <attestation.json>
```

Reads the attestation JSON, resolves the issuer's public key, and verifies both signatures.

```
Attestation is valid
  Issuer: did:keri:E...
  Subject: did:key:z6Mk...
  Status: VALID
```

### `auths verify-commit`

Verify a Git commit signature. **This is the most common verification command.**

```bash
auths verify-commit [<REF>] [--json]
```

<!-- BEGIN GENERATED: auths verify -->
| Argument/Flag | Default | Description |
|---------------|---------|-------------|
| `<REF>` | `HEAD` | Git ref or commit hash to verify |
| `--json` | | Output as JSON |
<!-- END GENERATED: auths verify -->

Text output:

```
Commit abc1234 is valid
  Signed by: did:keri:E...
  Device: did:key:z6Mk...
  Status: VALID
```

JSON output:

```json
{
  "valid": true,
  "commit": "abc1234...",
  "signer_did": "did:keri:E...",
  "signed_at": "2024-01-15T10:30:00Z"
}
```

### `auths git setup`

Configure Git to use Auths for commit signing (also done automatically by `auths init`).

```bash
auths git setup
```

Sets `gpg.format`, `gpg.ssh.program`, `user.signingKey`, and `commit.gpgSign`.

### `auths git allowed-signers`

Generate an `allowed_signers` file for `git log --show-signature`.

```bash
auths git allowed-signers [--output <PATH>]
```

```bash
auths git allowed-signers --output ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

---

## auths status

Show the current state of your identity, linked devices, and Git signing configuration.

```bash
auths status [--json]
```

<!-- BEGIN GENERATED: auths status -->
| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
<!-- END GENERATED: auths status -->

Example output:

```
Identity:  did:keri:EAbcd...
Key alias: main
Devices:   2 active, 0 revoked
Git:       signing enabled (gpg.format=ssh)
Health:    ok
```

Use `auths doctor` for a more detailed diagnostic report.

---

## auths pair

Link a new device to your identity using a QR code or short code. This is the easiest way to add a second device (laptop, phone, CI machine) without manually copying keys.

!!! tip "Prefer `auths pair` for most use cases"
    `auths pair` handles key exchange, DID derivation, and attestation signing automatically in one step — no copying keys or DIDs between devices. [`auths device link`](advanced.md#auths-device-link) gives you the same result but requires you to supply the device DID manually, making it better suited for scripting, automation, or situations where the two devices can't communicate directly.

```bash
auths pair                        # Show QR code (LAN mode)
auths pair --join <CODE>          # Join an existing session
auths pair --registry <URL>       # Use a relay server instead of LAN
```

| Flag | Default | Description |
|------|---------|-------------|
| `--join <CODE>` | — | Join an existing session by short code |
| `--registry <URL>` | (LAN) | Relay server URL for online pairing |
| `--capabilities` | `sign_commit` | Comma-separated capabilities to grant |
| `--expiry <SECONDS>` | `300` | Session expiry time |
| `--no-qr` | `false` | Print short code only, no QR |

### How it works

The initiating device starts a session and displays a QR code or short code. The joining device scans or enters the code, completes an X25519 key exchange, and the initiating device writes a signed device attestation — identical to what `auths device link` produces.

### Examples

```bash
# On the new device you want to add — scan the QR from your existing device
auths pair --join AB3DEF

# Add a CI machine via a relay server
auths pair --registry https://relay.example.com --capabilities sign_commit,sign_release
```
