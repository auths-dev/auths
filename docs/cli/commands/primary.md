# Primary Commands

## auths init

```bash
auths init
```

<!-- BEGIN GENERATED: auths init -->
Set up your cryptographic identity and Git signing

| Flag | Default | Description |
|------|---------|-------------|
| `--interactive` | — | Force interactive prompts (errors if not a TTY) |
| `--non-interactive` | — | Skip interactive prompts and use sensible defaults |
| `--profile <PROFILE>` | — | Preset profile: developer, ci, or agent |
| `--key-alias <KEY_ALIAS>` | `main` | Key alias for the identity key (default: main) |
| `--force` | — | Force overwrite if identity already exists |
| `--dry-run` | — | Preview agent configuration without creating files or identities |
| `--registry <REGISTRY>` | `https://auths-registry.fly.dev` | Registry URL for automatic identity registration |
| `--skip-registration` | — | Skip automatic registry registration during setup |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths init -->

---

## auths sign

```bash
auths sign <TARGET>
```

<!-- BEGIN GENERATED: auths sign -->
Sign a Git commit or artifact file.

| Flag | Default | Description |
|------|---------|-------------|
| `<TARGET>` | — | Commit ref, range, or artifact file path |
| `--sig-output <PATH>` | — | Output path for the signature file. Defaults to <FILE>.auths.json |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the identity key (for artifact signing) |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — | Local alias of the device key (for artifact signing, required for files) |
| `--expires-in-days <N>` | — | Number of days until the signature expires (for artifact signing) [aliases: --days] |
| `--note <NOTE>` | — | Optional note to embed in the attestation (for artifact signing) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths sign -->

---

## auths verify

```bash
auths verify
```

<!-- BEGIN GENERATED: auths verify -->
Verify a signed commit or attestation.

| Flag | Default | Description |
|------|---------|-------------|
| `--allowed-signers <ALLOWED_SIGNERS>` | `.auths/allowed_signers` | Path to allowed signers file (commit verification) |
| `--identity-bundle <IDENTITY_BUNDLE>` | — | Path to identity bundle JSON (for CI/CD stateless commit verification) |
| `--issuer-pk <ISSUER_PK>` | — | Issuer public key in hex format (attestation verification) |
| `--issuer-did <ISSUER_DID>` | — | Issuer identity ID for attestation trust-based key resolution [aliases: --issuer] |
| `--witness-receipts <WITNESS_RECEIPTS>` | — | Path to witness receipts JSON file |
| `--witness-threshold <WITNESS_THRESHOLD>` | `1` | Witness quorum threshold |
| `--witness-keys <WITNESS_KEYS>...` | — | Witness public keys as DID:hex pairs |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths verify -->

---

## auths status

```bash
auths status
```

<!-- BEGIN GENERATED: auths status -->
Show identity and agent status overview

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths status -->

---

## auths whoami

```bash
auths whoami
```

<!-- BEGIN GENERATED: auths whoami -->
Show the current identity on this machine

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths whoami -->

---

## auths tutorial

```bash
auths tutorial
```

<!-- BEGIN GENERATED: auths tutorial -->
Interactive tutorial for learning Auths concepts

| Flag | Default | Description |
|------|---------|-------------|
| `-s, --skip <SECTION>` | — | Skip to a specific section (1-6) |
| `--reset` | — | Reset progress and start from the beginning |
| `--list` | — | List all tutorial sections |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tutorial -->

---

## auths doctor

```bash
auths doctor
```

<!-- BEGIN GENERATED: auths doctor -->
Run comprehensive health checks

| Flag | Default | Description |
|------|---------|-------------|
| `--fix` | — | Auto-fix issues where possible |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths doctor -->

---

## auths pair

```bash
auths pair
```

<!-- BEGIN GENERATED: auths pair -->
Link devices to your identity

| Flag | Default | Description |
|------|---------|-------------|
| `--join <CODE>` | — | Join an existing pairing session using a short code |
| `--registry <URL>` | — | Registry URL for pairing relay (omit for LAN mode) |
| `--timeout <SECONDS>` | `300` | Custom timeout in seconds for the pairing session (default: 300 = 5 minutes)  [aliases: --expiry] |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths pair -->
