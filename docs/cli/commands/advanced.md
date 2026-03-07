# Advanced Commands

## Device

### auths device link

```bash
auths device link
```

<!-- BEGIN GENERATED: auths device link -->
| Flag | Default | Description |
|------|---------|-------------|
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — |  |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — |  |
| `--device-did <DEVICE_DID>` | — |  |
| `--payload <PAYLOAD_PATH>` | — |  |
| `--schema <SCHEMA_PATH>` | — |  |
| `--expires-in-days <DAYS>` | — |  |
| `--note <NOTE>` | — |  |
| `--capabilities <CAPABILITIES>` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths device link -->

---

### auths device revoke

```bash
auths device revoke
```

<!-- BEGIN GENERATED: auths device revoke -->
| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — |  |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — |  |
| `--note <NOTE>` | — |  |
| `--dry-run` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths device revoke -->

---

### auths device extend

```bash
auths device extend
```

<!-- BEGIN GENERATED: auths device extend -->
| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — |  |
| `--expires-in-days <DAYS>` | — |  |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — |  |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths device extend -->

---

## Identity

### auths id init-did

```bash
auths id init-did
```

<!-- BEGIN GENERATED: auths id init-did -->
_No options._
<!-- END GENERATED: auths id init-did -->

---

### auths id rotate

```bash
auths id rotate
```

<!-- BEGIN GENERATED: auths id rotate -->
| Flag | Default | Description |
|------|---------|-------------|
| `--alias <ALIAS>` | — |  |
| `--current-key-alias <CURRENT_KEY_ALIAS>` | — |  |
| `--next-key-alias <NEXT_KEY_ALIAS>` | — |  |
| `--add-witness <ADD_WITNESS>` | — |  |
| `--remove-witness <REMOVE_WITNESS>` | — |  |
| `--witness-threshold <WITNESS_THRESHOLD>` | — |  |
| `--dry-run` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths id rotate -->

---

## Key Management

### auths key import

```bash
auths key import
```

<!-- BEGIN GENERATED: auths key import -->
| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — |  |
| `--seed-file <SEED_FILE>` | — |  |
| `--controller-did <CONTROLLER_DID>` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
| `--repo <REPO>` | — |  |
<!-- END GENERATED: auths key import -->

---

### auths key export

```bash
auths key export
```

<!-- BEGIN GENERATED: auths key export -->
| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — | Local alias of the key to export. [aliases: --alias] |
| `--passphrase <PASSPHRASE>` | — | Passphrase to decrypt the key (needed for 'pem'/'pub' formats). |
| `--format <FORMAT>` | — | Export format: pem (OpenSSH private), pub (OpenSSH public), enc (raw encrypted bytes). |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key export -->

---

### auths key delete

```bash
auths key delete
```

<!-- BEGIN GENERATED: auths key delete -->
| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — | Local alias of the key to remove. [aliases: --alias] |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key delete -->

---

## Policy

### auths policy explain

```bash
auths policy explain
```

<!-- BEGIN GENERATED: auths policy explain -->
| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the policy file (JSON) |
| `-c, --context <CONTEXT>` | — | Path to the context file (JSON) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy explain -->

---

### auths policy test

```bash
auths policy test
```

<!-- BEGIN GENERATED: auths policy test -->
| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the policy file (JSON) |
| `-t, --tests <TESTS>` | — | Path to the test suite file (JSON) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy test -->

---

### auths policy diff

```bash
auths policy diff
```

<!-- BEGIN GENERATED: auths policy diff -->
| Flag | Default | Description |
|------|---------|-------------|
| `<OLD>` | — | Path to the old policy file (JSON) |
| `<NEW>` | — | Path to the new policy file (JSON) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy diff -->

---

## Emergency

### auths emergency revoke-device

```bash
auths emergency revoke-device
```

<!-- BEGIN GENERATED: auths emergency revoke-device -->
| Flag | Default | Description |
|------|---------|-------------|
| `--device <DEVICE>` | — |  |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — |  |
| `--note <NOTE>` | — |  |
| `-y, --yes` | — |  |
| `--dry-run` | — |  |
| `--repo <REPO>` | — |  |
| `--json` | — |  |
| `-q, --quiet` | — |  |
<!-- END GENERATED: auths emergency revoke-device -->

---

### auths emergency rotate-now

```bash
auths emergency rotate-now
```

<!-- BEGIN GENERATED: auths emergency rotate-now -->
| Flag | Default | Description |
|------|---------|-------------|
| `--current-alias <CURRENT_ALIAS>` | — | Local alias of the current signing key |
| `--next-alias <NEXT_ALIAS>` | — | Local alias for the new signing key after rotation |
| `-y, --yes` | — | Skip confirmation prompt (requires typing ROTATE) |
| `--dry-run` | — | Preview actions without making changes |
| `--reason <REASON>` | — | Reason for rotation |
| `--repo <REPO>` | — | Path to the Auths repository |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency rotate-now -->

---

### auths emergency freeze

```bash
auths emergency freeze
```

<!-- BEGIN GENERATED: auths emergency freeze -->
| Flag | Default | Description |
|------|---------|-------------|
| `--duration <DURATION>` | `24h` | Duration to freeze (e.g., "24h", "7d") |
| `-y, --yes` | — | Skip confirmation prompt (requires typing identity name) |
| `--dry-run` | — | Preview actions without making changes |
| `--repo <REPO>` | — | Path to the Auths repository |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency freeze -->

---

### auths emergency report

```bash
auths emergency report
```

<!-- BEGIN GENERATED: auths emergency report -->
| Flag | Default | Description |
|------|---------|-------------|
| `--events <EVENTS>` | `100` | Include last N events in report |
| `-o, --output <OUTPUT_FILE>` | — | Output file path (defaults to stdout) [aliases: --file] |
| `--repo <REPO>` | — | Path to the Auths repository |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency report -->
