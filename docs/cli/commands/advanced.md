# Advanced Commands

## Device

### auths device link

```bash
auths device link
```

<!-- BEGIN GENERATED: auths device link -->
Authorize a new device to act on behalf of the identity

| Flag | Default | Description |
|------|---------|-------------|
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the *identity's* key (used for signing). [aliases: --ika] |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — | Local alias of the *new device's* key (must be imported first). [aliases: --dka] |
| `--device-did <DEVICE_DID>` | — | Identity ID of the new device being authorized (must match device-key-alias). [aliases: --device] |
| `--payload <PAYLOAD_PATH>` | — | Optional path to a JSON file containing arbitrary payload data for the authorization. |
| `--schema <SCHEMA_PATH>` | — | Optional path to a JSON schema for validating the payload (experimental). |
| `--expires-in-days <DAYS>` | — | Optional number of days until this device authorization expires. [aliases: --days] |
| `--note <NOTE>` | — | Optional description/note for this device authorization. |
| `--capabilities <CAPABILITIES>` | — | Permissions to grant this device (comma-separated) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device link -->

---

### auths device revoke

```bash
auths device revoke
```

<!-- BEGIN GENERATED: auths device revoke -->
Revoke an existing device authorization using the identity key

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | Identity ID of the device authorization to revoke. [aliases: --device] |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the *identity's* key (required to authorize revocation). |
| `--note <NOTE>` | — | Optional note explaining the revocation. |
| `--dry-run` | — | Preview actions without making changes. |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device revoke -->

---

### auths device extend

```bash
auths device extend
```

<!-- BEGIN GENERATED: auths device extend -->
Extend the expiration date of an existing device authorization

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | Identity ID of the device authorization to extend. [aliases: --device] |
| `--expires-in-days <DAYS>` | — | Number of days to extend the expiration by (from now). [aliases: --days] |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the *identity's* key (required for re-signing). [aliases: --ika] |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — | Local alias of the *device's* key (required for re-signing). [aliases: --dka] |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device extend -->

---

## Identity

### auths id init-did

```bash
auths id init-did
```

<!-- BEGIN GENERATED: auths id init-did -->
error: unrecognized subcommand 'init-did'

_No options._
<!-- END GENERATED: auths id init-did -->

---

### auths id rotate

```bash
auths id rotate
```

<!-- BEGIN GENERATED: auths id rotate -->
Rotate identity keys. Stores the new key under a new alias

| Flag | Default | Description |
|------|---------|-------------|
| `--alias <ALIAS>` | — | Alias of the identity key to rotate. |
| `--current-key-alias <CURRENT_KEY_ALIAS>` | — | Alias of the CURRENT private key controlling the identity. |
| `--next-key-alias <NEXT_KEY_ALIAS>` | — | Alias to store the NEWLY generated private key under. |
| `--add-witness <ADD_WITNESS>` | — | Verification server prefix to add (e.g., B...). Can be specified multiple times. |
| `--remove-witness <REMOVE_WITNESS>` | — | Verification server prefix to remove (e.g., B...). Can be specified multiple times. |
| `--witness-threshold <WITNESS_THRESHOLD>` | — | New simple verification threshold count (e.g., 1 for 1-of-N). |
| `--dry-run` | — | Preview actions without making changes |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id rotate -->

---

## Key Management

### auths key import

```bash
auths key import
```

<!-- BEGIN GENERATED: auths key import -->
Import an Ed25519 key from a 32-byte seed file and store it encrypted

| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — | Local alias to assign to the imported key. [aliases: --alias] |
| `--seed-file <SEED_FILE>` | — | Path to the file containing the raw 32-byte Ed25519 seed. |
| `--controller-did <CONTROLLER_DID>` | — | Controller DID (e.g., did:key:...) to associate with the imported key. |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key import -->

---

### auths key export

```bash
auths key export
```

<!-- BEGIN GENERATED: auths key export -->
Export a stored key in various formats (requires passphrase for some formats)

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
Remove a key from the platform's secure storage by alias

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
Evaluate a policy against a context and show the decision

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
Run a policy against a test suite

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
Compare two policies and show semantic differences

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
Revoke a compromised device immediately

| Flag | Default | Description |
|------|---------|-------------|
| `--device <DEVICE>` | — | Device DID to revoke |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the identity's key (used for signing the revocation) |
| `--note <NOTE>` | — | Optional note explaining the revocation |
| `-y, --yes` | — | Skip confirmation prompt |
| `--dry-run` | — | Preview actions without making changes |
| `--repo <REPO>` | — | Path to the Auths repository |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency revoke-device -->

---

### auths emergency rotate-now

```bash
auths emergency rotate-now
```

<!-- BEGIN GENERATED: auths emergency rotate-now -->
Force immediate key rotation

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
Freeze all signing operations

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
Generate an incident report

| Flag | Default | Description |
|------|---------|-------------|
| `--events <EVENTS>` | `100` | Include last N events in report |
| `-o, --output <OUTPUT_FILE>` | — | Output file path (defaults to stdout) [aliases: --file] |
| `--repo <REPO>` | — | Path to the Auths repository |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency report -->

---

## Git

### auths signers sync

```bash
auths signers sync
```

<!-- BEGIN GENERATED: auths signers sync -->
Sync attestation entries from the auths registry

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <REPO>` | `~/.auths` | Path to the Auths identity repository |
| `-o, --output <OUTPUT_FILE>` | — | Output file path. Overrides the default location |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths signers sync -->

---

### auths git install-hooks

```bash
auths git install-hooks
```

<!-- BEGIN GENERATED: auths git install-hooks -->
Install Git hooks for automatic allowed_signers regeneration

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <REPO>` | `.` | Path to the Git repository where hooks should be installed. Defaults to the current directory |
| `--auths-repo <AUTHS_REPO>` | `~/.auths` | Path to the Auths identity repository |
| `--allowed-signers-path <ALLOWED_SIGNERS_PATH>` | `.auths/allowed_signers` | Path where allowed_signers file should be written |
| `--force` | — | Overwrite existing hook without prompting |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths git install-hooks -->

---

## Trust

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
| `--kel-tip <KEL_TIP>` | — | Optional KEL tip SAID for rotation tracking |
| `--note <NOTE>` | — | Optional note about this identity |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust pin -->

---

### auths trust list

```bash
auths trust list
```

<!-- BEGIN GENERATED: auths trust list -->
List all pinned identities

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust list -->

---

### auths trust remove

```bash
auths trust remove
```

<!-- BEGIN GENERATED: auths trust remove -->
Remove a pinned identity

| Flag | Default | Description |
|------|---------|-------------|
| `<DID>` | — | The DID of the identity to remove |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust remove -->

---

### auths trust show

```bash
auths trust show
```

<!-- BEGIN GENERATED: auths trust show -->
Show details of a pinned identity

| Flag | Default | Description |
|------|---------|-------------|
| `<DID>` | — | The DID of the identity to show |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths trust show -->

---

## Organization

### auths org create

```bash
auths org create
```

<!-- BEGIN GENERATED: auths org create -->
Create a new organization identity

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Organization name |
| `--local-key-alias <LOCAL_KEY_ALIAS>` | — | Alias for the local signing key (auto-generated if not provided) |
| `--metadata-file <METADATA_FILE>` | — | Optional metadata file (if provided, merged with org metadata) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org create -->

---

### auths org add-member

```bash
auths org add-member
```

<!-- BEGIN GENERATED: auths org add-member -->
Add a member to an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--member-did <MEMBER_DID>` | — | Member identity ID to add [aliases: --member] |
| `--role <ROLE>` | — | Role to assign (admin, member, readonly) |
| `--capabilities <CAPABILITIES>` | — | Override default capabilities (comma-separated) |
| `--signer-alias <SIGNER_ALIAS>` | — | Alias of the signing key in keychain |
| `--note <NOTE>` | — | Optional note for the authorization |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org add-member -->

---

### auths org revoke-member

```bash
auths org revoke-member
```

<!-- BEGIN GENERATED: auths org revoke-member -->
Revoke a member from an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--member-did <MEMBER_DID>` | — | Member identity ID to revoke [aliases: --member] |
| `--note <NOTE>` | — | Reason for revocation |
| `--signer-alias <SIGNER_ALIAS>` | — | Alias of the signing key in keychain |
| `--dry-run` | — | Preview actions without making changes |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org revoke-member -->

---

### auths org list-members

```bash
auths org list-members
```

<!-- BEGIN GENERATED: auths org list-members -->
List members of an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--include-revoked` | — | Include revoked members |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org list-members -->

---

## Audit

### auths audit

```bash
auths audit
```

<!-- BEGIN GENERATED: auths audit -->
Generate signing audit reports for compliance

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <REPO>` | `.` | Path to the Git repository to audit (defaults to current directory) |
| `--since <SINCE>` | — | Start date for audit period (YYYY-MM-DD or YYYY-QN for quarter) |
| `--until <UNTIL>` | — | End date for audit period (YYYY-MM-DD) |
| `--format <FORMAT>` | `table` | Output format |
| `--require-all-signed` | — | Require all commits to be signed (for CI exit codes) |
| `--exit-code` | — | Return exit code 1 if any unsigned commits found |
| `--author <AUTHOR>` | — | Filter by author email |
| `--signer <SIGNER>` | — | Filter by signing identity/device DID |
| `-n, --count <COUNT>` | `100` | Maximum number of commits to include |
| `-o, --output-file <OUTPUT_FILE>` | — | Output file path (defaults to stdout) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths audit -->

---

## Agent

### auths agent start

```bash
auths agent start
```

<!-- BEGIN GENERATED: auths agent start -->
Start the SSH agent daemon

| Flag | Default | Description |
|------|---------|-------------|
| `--socket <SOCKET>` | — | Custom Unix socket path |
| `--foreground` | — | Run in foreground instead of daemonizing |
| `--timeout <TIMEOUT>` | `30m` | Idle timeout before auto-lock |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent start -->

---

### auths agent stop

```bash
auths agent stop
```

<!-- BEGIN GENERATED: auths agent stop -->
Stop the SSH agent daemon

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent stop -->

---

### auths agent status

```bash
auths agent status
```

<!-- BEGIN GENERATED: auths agent status -->
Show agent status

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent status -->

---

### auths agent env

```bash
auths agent env
```

<!-- BEGIN GENERATED: auths agent env -->
Output shell environment for SSH_AUTH_SOCK (use with eval)

| Flag | Default | Description |
|------|---------|-------------|
| `--shell <SHELL>` | `bash` | Shell format |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent env -->

---

### auths agent lock

```bash
auths agent lock
```

<!-- BEGIN GENERATED: auths agent lock -->
Lock the agent (clear keys from memory)

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent lock -->

---

### auths agent unlock

```bash
auths agent unlock
```

<!-- BEGIN GENERATED: auths agent unlock -->
Unlock the agent (re-load keys)

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-key-alias <AGENT_KEY_ALIAS>` | `default` | Key alias to unlock  [aliases: --key] |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent unlock -->

---

### auths agent install-service

```bash
auths agent install-service
```

<!-- BEGIN GENERATED: auths agent install-service -->
Install as a system service (launchd on macOS, systemd on Linux)

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | — | Print service file without installing |
| `--force` | — | Overwrite existing service file |
| `--manager <MANAGER>` | — | Service manager (auto-detect by default) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent install-service -->

---

### auths agent uninstall-service

```bash
auths agent uninstall-service
```

<!-- BEGIN GENERATED: auths agent uninstall-service -->
Uninstall the system service

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent uninstall-service -->

---

## Witness

### auths witness start

```bash
auths witness start
```

<!-- BEGIN GENERATED: auths witness start -->
Start the witness HTTP server

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `127.0.0.1:3333` | Address to bind to (e.g., "127.0.0.1:3333") |
| `--db-path <DB_PATH>` | `witness.db` | Path to the SQLite database for witness storage |
| `--witness-did <WITNESS_DID>` | — | Witness DID (auto-generated if not provided) [aliases: --witness] |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness start -->

---

### auths witness add

```bash
auths witness add
```

<!-- BEGIN GENERATED: auths witness add -->
Add a witness URL to the identity configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | — | Witness server URL (e.g., "http://127.0.0.1:3333") |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness add -->

---

### auths witness remove

```bash
auths witness remove
```

<!-- BEGIN GENERATED: auths witness remove -->
Remove a witness URL from the identity configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | — | Witness server URL to remove |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness remove -->

---

### auths witness list

```bash
auths witness list
```

<!-- BEGIN GENERATED: auths witness list -->
List configured witnesses for the current identity

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness list -->

---

## SCIM

### auths scim serve

```bash
auths scim serve
```

<!-- BEGIN GENERATED: auths scim serve -->
Start the SCIM provisioning server

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `0.0.0.0:3301` | Listen address |
| `--database-url <DATABASE_URL>` | — | PostgreSQL connection URL |
| `--registry-path <REGISTRY_PATH>` | — | Path to the Auths registry Git repository |
| `--log-level <LOG_LEVEL>` | `info` | Log level |
| `--test-mode` | — | Enable test mode (auto-tenant, relaxed TLS) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim serve -->

---

### auths scim quickstart

```bash
auths scim quickstart
```

<!-- BEGIN GENERATED: auths scim quickstart -->
Zero-config quickstart: temp DB + test tenant + running server

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `0.0.0.0:3301` | Listen address |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim quickstart -->

---

### auths scim test-connection

```bash
auths scim test-connection
```

<!-- BEGIN GENERATED: auths scim test-connection -->
Validate the full SCIM pipeline: create -> get -> patch -> delete

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | `http://localhost:3301` | Server URL |
| `--token <TOKEN>` | — | Bearer token |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim test-connection -->

---

### auths scim tenants

```bash
auths scim tenants
```

<!-- BEGIN GENERATED: auths scim tenants -->
List SCIM tenants

| Flag | Default | Description |
|------|---------|-------------|
| `--database-url <DATABASE_URL>` | — | PostgreSQL connection URL |
| `--json` | — | Output as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim tenants -->

---

### auths scim add-tenant

```bash
auths scim add-tenant
```

<!-- BEGIN GENERATED: auths scim add-tenant -->
Generate a new bearer token for an IdP tenant

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Tenant name |
| `--database-url <DATABASE_URL>` | — | PostgreSQL connection URL |
| `--expires-in <EXPIRES_IN>` | — | Token expiry duration (e.g., 90d, 365d). Omit for no expiry |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim add-tenant -->

---

### auths scim rotate-token

```bash
auths scim rotate-token
```

<!-- BEGIN GENERATED: auths scim rotate-token -->
Rotate bearer token for an existing tenant

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Tenant name |
| `--database-url <DATABASE_URL>` | — | PostgreSQL connection URL |
| `--expires-in <EXPIRES_IN>` | — | Token expiry duration (e.g., 90d, 365d) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim rotate-token -->

---

### auths scim status

```bash
auths scim status
```

<!-- BEGIN GENERATED: auths scim status -->
Show SCIM sync state for debugging

| Flag | Default | Description |
|------|---------|-------------|
| `--database-url <DATABASE_URL>` | — | PostgreSQL connection URL |
| `--json` | — | Output as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim status -->

---

## Configuration

### auths config set

```bash
auths config set <KEY> <VALUE>
```

<!-- BEGIN GENERATED: auths config set -->
Set a configuration value (e.g. `auths config set passphrase.cache always`)

| Flag | Default | Description |
|------|---------|-------------|
| `<KEY>` | — | Dotted key path (e.g. `passphrase.cache`, `passphrase.duration`) |
| `<VALUE>` | — | Value to assign |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config set -->

---

### auths config get

```bash
auths config get <KEY>
```

<!-- BEGIN GENERATED: auths config get -->
Get a configuration value (e.g. `auths config get passphrase.cache`)

| Flag | Default | Description |
|------|---------|-------------|
| `<KEY>` | — | Dotted key path |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config get -->

---

### auths config show

```bash
auths config show
```

<!-- BEGIN GENERATED: auths config show -->
Show the full configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths config show -->

---

## Approval

### auths approval list

```bash
auths approval list
```

<!-- BEGIN GENERATED: auths approval list -->
List pending approval requests

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths approval list -->

---

### auths approval grant

```bash
auths approval grant
```

<!-- BEGIN GENERATED: auths approval grant -->
Grant approval for a pending request

| Flag | Default | Description |
|------|---------|-------------|
| `--request <REQUEST>` | — | The request hash to approve (hex-encoded) |
| `--note <NOTE>` | — | Optional note for the approval |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths approval grant -->

---

## Artifact

### auths artifact sign

```bash
auths artifact sign <FILE>
```

<!-- BEGIN GENERATED: auths artifact sign -->
Sign an artifact file with your Auths identity

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the artifact file to sign. |
| `--sig-output <PATH>` | — | Output path for the signature file. Defaults to <FILE>.auths.json |
| `--identity-key-alias <IDENTITY_KEY_ALIAS>` | — | Local alias of the identity key. Omit for device-only CI signing. [aliases: --ika] |
| `--device-key-alias <DEVICE_KEY_ALIAS>` | — | Local alias of the device key (used for dual-signing). [aliases: --dka] |
| `--expires-in-days <N>` | — | Number of days until the signature expires [aliases: --days] |
| `--note <NOTE>` | — | Optional note to embed in the attestation |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact sign -->

---

### auths artifact verify

```bash
auths artifact verify <FILE>
```

<!-- BEGIN GENERATED: auths artifact verify -->
Verify an artifact's signature against an Auths identity

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the artifact file to verify. |
| `--signature <PATH>` | — | Path to the signature file. Defaults to <FILE>.auths.json |
| `--identity-bundle <IDENTITY_BUNDLE>` | — | Path to identity bundle JSON (for CI/CD stateless verification) |
| `--witness-receipts <WITNESS_RECEIPTS>` | — | Path to witness receipts JSON file |
| `--witness-keys <WITNESS_KEYS>...` | — | Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...") |
| `--witness-threshold <WITNESS_THRESHOLD>` | `1` | Witness quorum threshold (default: 1) |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact verify -->

---

### auths artifact publish

```bash
auths artifact publish
```

<!-- BEGIN GENERATED: auths artifact publish -->
Publish a signed artifact attestation to a registry

| Flag | Default | Description |
|------|---------|-------------|
| `--signature <SIGNATURE>` | — | Path to the .auths.json signature file created by `auths artifact sign` |
| `--package <PACKAGE>` | — | Package identifier for registry indexing (e.g., npm:react@18.3.0) |
| `--registry <REGISTRY>` | `https://auths-registry.fly.dev` | Registry URL to publish to |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact publish -->

---

## Completions

### auths completions

```bash
auths completions <SHELL>
```

<!-- BEGIN GENERATED: auths completions -->
Generate shell completions

| Flag | Default | Description |
|------|---------|-------------|
| `<SHELL>` | — | The shell to generate completions for |
| `--json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths completions -->
