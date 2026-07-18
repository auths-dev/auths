# Primary Commands

## Primary

### auths init

```bash
auths init
```

<!-- BEGIN GENERATED: auths init -->
Create your signing identity and configure Git

| Flag | Default | Description |
|------|---------|-------------|
| `--interactive` | — | Force interactive prompts (errors if not a TTY) |
| `--non-interactive` | — | Skip interactive prompts and use sensible defaults |
| `--profile <PROFILE>` | — | Preset profile: developer, ci, or agent |
| `--key-alias <KEY_ALIAS>` | `main` | Key alias for the identity key (default: main) |
| `--force` | — | Force overwrite if identity already exists |
| `--dry-run` | — | Preview agent configuration without creating files or identities |
| `--registry <REGISTRY>` | `https://registry.auths.dev` | Registry URL for identity registration [env: AUTHS_REGISTRY_URL=] |
| `--register` | — | Register identity with the Auths Registry after creation |
| `--github-action` | — | Scaffold a GitHub Actions workflow using the auths attest-action |
| `--device-count <DEVICE_COUNT>` | `1` | Number of device slots for a multi-key KEL (default 1) |
| `--signing-threshold <SIGNING_THRESHOLD>` | — | Signing threshold: scalar integer (e.g. `"2"`) or fraction list (e.g. `"1/2,1/2,1/2"`). Required when `--device-count > 1` |
| `--rotation-threshold <ROTATION_THRESHOLD>` | — | Rotation (next) threshold, same format as `--signing-threshold` |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths init -->

### auths sign

```bash
auths sign
```

<!-- BEGIN GENERATED: auths sign -->
Sign a Git commit or artifact file.

| Flag | Default | Description |
|------|---------|-------------|
| `<TARGET>` | — | Commit ref, range, or artifact file path |
| `--sig-output <PATH>` | — | Output path for the signature file. Defaults to <FILE>.auths.json |
| `--key <KEY>` | — | Local alias of the identity key (for artifact signing) |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key (for artifact signing, required for files) |
| `--expires-in <N>` | — | Duration in seconds until expiration (per RFC 6749) |
| `--note <NOTE>` | — | Optional note to embed in the attestation (for artifact signing) |
| `--scope <SCOPE>` | — | Capabilities this commit claims it exercises (comma-separated), e.g. `--scope sign_commit`. Emitted as an `Auths-Scope` trailer so a verifier can reject a claim outside the signer's delegator-anchored grant. Commit-only |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths sign -->

### auths verify

```bash
auths verify
```

<!-- BEGIN GENERATED: auths verify -->
Verify a signed commit or attestation.

| Flag | Default | Description |
|------|---------|-------------|
| `--identity-bundle <IDENTITY_BUNDLE>` | — | Path to identity bundle JSON (for CI/CD stateless commit verification) |
| `--signer-key <ISSUER_PK>` | — | Signer public key in hex format (attestation verification) |
| `--signer <ISSUER_DID>` | — | Signer identity ID for attestation trust-based key resolution [aliases: --issuer-did] |
| `--witness-signatures <WITNESS_RECEIPTS>` | — | Path to witness signatures JSON file |
| `--witnesses-required <WITNESS_THRESHOLD>` | `1` | Number of witnesses required |
| `--witness-keys <WITNESS_KEYS>...` | — | Witness public keys as DID:hex pairs |
| `--signature <PATH>` | — | Path to signature file. Only used when verifying an artifact file (not a commit). Defaults to <FILE>.auths.json |
| `--require-witnesses` | — | Fail verification when the signer's root KEL has not reached witness quorum (fail-closed). Default: warn and continue |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths verify -->

### auths status

```bash
auths status
```

<!-- BEGIN GENERATED: auths status -->
Show identity and agent status overview

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths status -->

### auths whoami

```bash
auths whoami
```

<!-- BEGIN GENERATED: auths whoami -->
Show the current identity on this machine

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths whoami -->

## Setup & Troubleshooting

### auths pair

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
| `--verify` | — | Prompt to manually verify the short-authentication-string (SAS) codes match between devices before completing the pair |
| `--recover <OLD_DID>` | — | Lost/stolen-device recovery: pair a replacement delegated device, then revoke the old device's delegation (by `did:keri:`). The replacement is authorized before the old one is revoked, so the identity is never left with zero usable devices. Supported over the relay path (with `--registry`) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths pair -->

### auths trust list

```bash
auths trust list
```

<!-- BEGIN GENERATED: auths trust list -->
List all pinned identities

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust list -->

### auths trust pin

```bash
auths trust pin
```

<!-- BEGIN GENERATED: auths trust pin -->
Manually pin an identity as trusted

| Flag | Default | Description |
|------|---------|-------------|
| `--did <DID>` | — | The DID of the identity to pin (e.g., did:keri:E...) |
| `--key <KEY>` | — | The public key in hex format (64 chars for Ed25519) |
| `--kel-tip <KEL_TIP>` | — | Identity log checkpoint for tracking key changes (optional, advanced) |
| `--note <NOTE>` | — | Optional note about this identity |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust pin -->

### auths trust remove

```bash
auths trust remove
```

<!-- BEGIN GENERATED: auths trust remove -->
Remove a pinned identity

| Flag | Default | Description |
|------|---------|-------------|
| `<DID>` | — | The DID of the identity to remove |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust remove -->

### auths trust show

```bash
auths trust show
```

<!-- BEGIN GENERATED: auths trust show -->
Show details of a pinned identity

| Flag | Default | Description |
|------|---------|-------------|
| `<DID>` | — | The DID of the identity to show |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust show -->

### auths doctor

```bash
auths doctor
```

<!-- BEGIN GENERATED: auths doctor -->
Run comprehensive health checks

| Flag | Default | Description |
|------|---------|-------------|
| `--fix` | — | Auto-fix issues where possible |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths doctor -->

### auths tutorial

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tutorial -->

### auths demo

```bash
auths demo
```

<!-- BEGIN GENERATED: auths demo -->
Sign and verify a demo artifact — works offline, no setup or registry needed

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths demo -->

## Utilities

### auths config set

```bash
auths config set
```

<!-- BEGIN GENERATED: auths config set -->
Set a configuration value (e.g. `auths config set passphrase.cache always`)

| Flag | Default | Description |
|------|---------|-------------|
| `<KEY>` | — | Dotted key path (e.g. `passphrase.cache`, `passphrase.duration`) |
| `<VALUE>` | — | Value to assign |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config set -->

### auths config get

```bash
auths config get
```

<!-- BEGIN GENERATED: auths config get -->
Get a configuration value (e.g. `auths config get passphrase.cache`)

| Flag | Default | Description |
|------|---------|-------------|
| `<KEY>` | — | Dotted key path |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config get -->

### auths config show

```bash
auths config show
```

<!-- BEGIN GENERATED: auths config show -->
Show the full configuration

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config show -->

### auths completions

```bash
auths completions
```

<!-- BEGIN GENERATED: auths completions -->
Generate shell completions

| Flag | Default | Description |
|------|---------|-------------|
| `<SHELL>` | — | The shell to generate completions for |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths completions -->
