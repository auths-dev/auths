# Advanced Commands

## Advanced

### auths reset

```bash
auths reset
```

<!-- BEGIN GENERATED: auths reset -->
Remove Auths identity and git signing configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | — | Skip confirmation prompt |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths reset -->

### auths signcommit

```bash
auths signcommit
```

<!-- BEGIN GENERATED: auths signcommit -->
Sign a Git commit with machine identity.

| Flag | Default | Description |
|------|---------|-------------|
| `<COMMIT>` | — | Git commit SHA or reference (e.g., HEAD, main..HEAD) |
| `--json` | — | Output format (json or human-readable) |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths signcommit -->

### auths signers list

```bash
auths signers list
```

<!-- BEGIN GENERATED: auths signers list -->
List all entries in the allowed_signers file

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Output as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths signers list -->

### auths signers add

```bash
auths signers add
```

<!-- BEGIN GENERATED: auths signers add -->
Add a manual signer entry

| Flag | Default | Description |
|------|---------|-------------|
| `<EMAIL>` | — | Email address of the signer |
| `<PUBKEY>` | — | SSH public key (ssh-ed25519 AAAA...) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths signers add -->

### auths signers remove

```bash
auths signers remove
```

<!-- BEGIN GENERATED: auths signers remove -->
Remove a manual signer entry

| Flag | Default | Description |
|------|---------|-------------|
| `<EMAIL>` | — | Email address of the signer to remove |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths signers remove -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths signers sync -->

### auths signers add-from-github

```bash
auths signers add-from-github
```

<!-- BEGIN GENERATED: auths signers add-from-github -->
Add a signer from a GitHub user's SSH keys

| Flag | Default | Description |
|------|---------|-------------|
| `<USERNAME>` | — | GitHub username whose SSH keys to add |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths signers add-from-github -->

### auths error list

```bash
auths error list
```

<!-- BEGIN GENERATED: auths error list -->
List all known error codes

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths error list -->

### auths error show

```bash
auths error show
```

<!-- BEGIN GENERATED: auths error show -->
Show explanation for an error code

| Flag | Default | Description |
|------|---------|-------------|
| `<CODE>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths error show -->

### auths id create

```bash
auths id create
```

<!-- BEGIN GENERATED: auths id create -->
Create a new cryptographic identity with secure key storage

| Flag | Default | Description |
|------|---------|-------------|
| `--metadata-file <METADATA_FILE>` | — | Path to JSON file with arbitrary identity metadata. |
| `--local-key-alias <LOCAL_KEY_ALIAS>` | — | Alias for storing the NEWLY generated private key in the secure keychain. |
| `--preset <PRESET>` | `default` | Storage layout preset (default, radicle, gitoxide) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id create -->

### auths id show

```bash
auths id show
```

<!-- BEGIN GENERATED: auths id show -->
Show primary identity details (identity ID, metadata) from the Git repository

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id show -->

### auths id list

```bash
auths id list
```

<!-- BEGIN GENERATED: auths id list -->
List identities (currently same as show, forward-compatible for future multi-identity support)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id list -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id rotate -->

### auths id export-bundle

```bash
auths id export-bundle
```

<!-- BEGIN GENERATED: auths id export-bundle -->
Export an identity bundle for stateless CI/CD verification

| Flag | Default | Description |
|------|---------|-------------|
| `--alias <ALIAS>` | — | Key alias to include in bundle |
| `-o, --output <OUTPUT_FILE>` | — | Output file path for the JSON bundle |
| `--max-age-secs <MAX_AGE_SECS>` | — | Maximum bundle age in seconds before it is considered stale |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id export-bundle -->

### auths id register

```bash
auths id register
```

<!-- BEGIN GENERATED: auths id register -->
Publish this identity to a public registry for discovery

| Flag | Default | Description |
|------|---------|-------------|
| `--registry <REGISTRY>` | `https://auths-registry.fly.dev` | Registry URL to publish to |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id register -->

### auths id claim

```bash
auths id claim
```

<!-- BEGIN GENERATED: auths id claim -->
Add a platform claim to an already-registered identity

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id claim -->

### auths id migrate

```bash
auths id migrate
```

<!-- BEGIN GENERATED: auths id migrate -->
Import existing GPG or SSH keys into Auths

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id migrate -->

### auths id bind-idp

```bash
auths id bind-idp
```

<!-- BEGIN GENERATED: auths id bind-idp -->
Bind this identity to an enterprise IdP (Okta, Entra ID, Google Workspace, SAML)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id bind-idp -->

### auths id update-scope

```bash
auths id update-scope
```

<!-- BEGIN GENERATED: auths id update-scope -->
Re-authorize with a platform and optionally upload SSH signing key

| Flag | Default | Description |
|------|---------|-------------|
| `<PLATFORM>` | — | Platform name (currently supports 'github') |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id update-scope -->

### auths device list

```bash
auths device list
```

<!-- BEGIN GENERATED: auths device list -->
List all authorized devices for the current identity

| Flag | Default | Description |
|------|---------|-------------|
| `--include-revoked` | — | Include devices with revoked or expired authorizations in the output. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device list -->

### auths device link

```bash
auths device link
```

<!-- BEGIN GENERATED: auths device link -->
Authorize a new device to act on behalf of the identity

| Flag | Default | Description |
|------|---------|-------------|
| `--key <KEY>` | — | Local alias of the *identity's* key (used for signing). |
| `--device-key <DEVICE_KEY>` | — | Local alias of the *new device's* key (must be imported first). |
| `--device-did <DEVICE_DID>` | — | Identity ID of the new device being authorized (must match --device-key). [aliases: --device] |
| `--payload <PAYLOAD_PATH>` | — | Optional path to a JSON file containing arbitrary payload data for the authorization. |
| `--schema <SCHEMA_PATH>` | — | Optional path to a JSON schema for validating the payload (experimental). |
| `--expires-in <SECS>` | — | Optional number of seconds until this device authorization expires. |
| `--note <NOTE>` | — | Optional description/note for this device authorization. |
| `--capabilities <CAPABILITIES>` | — | Permissions to grant this device (comma-separated) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device link -->

### auths device revoke

```bash
auths device revoke
```

<!-- BEGIN GENERATED: auths device revoke -->
Revoke an existing device authorization using the identity key

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | Identity ID of the device authorization to revoke. [aliases: --device] |
| `--key <KEY>` | — | Local alias of the *identity's* key (required to authorize revocation). |
| `--note <NOTE>` | — | Optional note explaining the revocation. |
| `--dry-run` | — | Preview actions without making changes. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device revoke -->

### auths device resolve

```bash
auths device resolve
```

<!-- BEGIN GENERATED: auths device resolve -->
Resolve a device DID to its controller identity DID

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | The device DID to resolve (e.g. did:key:z6Mk...). [aliases: --device] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device resolve -->

### auths device pair

```bash
auths device pair
```

<!-- BEGIN GENERATED: auths device pair -->
Link devices to your identity via QR code or short code

| Flag | Default | Description |
|------|---------|-------------|
| `--join <CODE>` | — | Join an existing pairing session using a short code |
| `--registry <URL>` | — | Registry URL for pairing relay (omit for LAN mode) |
| `--timeout <SECONDS>` | `300` | Custom timeout in seconds for the pairing session (default: 300 = 5 minutes)  [aliases: --expiry] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device pair -->

### auths device verify

```bash
auths device verify
```

<!-- BEGIN GENERATED: auths device verify -->
Verify device authorization signatures (attestation)

| Flag | Default | Description |
|------|---------|-------------|
| `--attestation <ATTESTATION>` | — | Path to authorization JSON file, or "-" to read from stdin |
| `--issuer-pk <ISSUER_PK>` | — | Issuer public key in hex format (64 hex chars = 32 bytes) |
| `--issuer-did <ISSUER_DID>` | — | Issuer identity ID for trust-based key resolution [aliases: --issuer] |
| `--trust <TRUST>` | — | Trust policy for unknown identities |
| `--roots-file <ROOTS_FILE>` | — | Path to roots.json file for explicit trust |
| `--require-capability <REQUIRE_CAPABILITY>` | — | Require attestation to have a specific capability (sign-commit, sign-release, manage-members, rotate-keys) |
| `--witness-receipts <WITNESS_RECEIPTS>` | — | Path to witness receipts JSON file |
| `--witness-threshold <WITNESS_THRESHOLD>` | `1` | Witness quorum threshold (default: 1) |
| `--witness-keys <WITNESS_KEYS>...` | — | Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...") |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device verify -->

### auths device extend

```bash
auths device extend
```

<!-- BEGIN GENERATED: auths device extend -->
Extend the expiration date of an existing device authorization

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | Identity ID of the device authorization to extend. [aliases: --device] |
| `--expires-in <SECS>` | — | Number of seconds to extend the expiration by (from now). |
| `--key <KEY>` | — | Local alias of the *identity's* key (required for re-signing). |
| `--device-key <DEVICE_KEY>` | — | Local alias of the *device's* key (required for re-signing). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device extend -->

### auths key list

```bash
auths key list
```

<!-- BEGIN GENERATED: auths key list -->
List aliases of all keys stored in the platform's secure storage

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key list -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key export -->

### auths key delete

```bash
auths key delete
```

<!-- BEGIN GENERATED: auths key delete -->
Remove a key from the platform's secure storage by alias

| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — | Local alias of the key to remove. [aliases: --alias] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key delete -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key import -->

### auths key copy-backend

```bash
auths key copy-backend
```

<!-- BEGIN GENERATED: auths key copy-backend -->
Copy a key from the current keychain backend to a different backend

| Flag | Default | Description |
|------|---------|-------------|
| `--key-alias <KEY_ALIAS>` | — | Alias of the key to copy from the current (source) keychain [aliases: --alias] |
| `--dst-backend <DST_BACKEND>` | — | Destination backend type. Currently supported: "file" |
| `--dst-file <DST_FILE>` | — | Path for the destination file keychain (required when --dst-backend is "file") |
| `--dst-passphrase <DST_PASSPHRASE>` | — | Passphrase for the destination file keychain. If omitted, the AUTHS_PASSPHRASE environment variable is used |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key copy-backend -->

### auths approval list

```bash
auths approval list
```

<!-- BEGIN GENERATED: auths approval list -->
List pending approval requests

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths approval list -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths approval grant -->

### auths artifact sign

```bash
auths artifact sign
```

<!-- BEGIN GENERATED: auths artifact sign -->
Sign an artifact file with your Auths identity

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the artifact file to sign. |
| `--sig-output <PATH>` | — | Output path for the signature file. Defaults to <FILE>.auths.json |
| `--key <KEY>` | — | Local alias of the identity key. Omit for device-only CI signing. |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key. Auto-detected when only one key exists. |
| `--expires-in <N>` | — | Duration in seconds until expiration (per RFC 6749) |
| `--note <NOTE>` | — | Optional note to embed in the attestation |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact sign -->

### auths artifact publish

```bash
auths artifact publish
```

<!-- BEGIN GENERATED: auths artifact publish -->
Sign and publish an artifact attestation to a registry

| Flag | Default | Description |
|------|---------|-------------|
| `--signature <PATH>` | — | Path to an existing .auths.json signature file. Defaults to <FILE>.auths.json |
| `--package <PACKAGE>` | — | Package identifier for registry indexing (e.g., npm:react@18.3.0) |
| `--registry <REGISTRY>` | `https://auths-registry.fly.dev` | Registry URL to publish to |
| `--key <KEY>` | — | Local alias of the identity key. Omit for device-only CI signing |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key. Auto-detected when only one key exists |
| `--expires-in <N>` | — | Duration in seconds until expiration |
| `--note <NOTE>` | — | Optional note to embed in the attestation |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact publish -->

### auths artifact batch-sign

```bash
auths artifact batch-sign
```

<!-- BEGIN GENERATED: auths artifact batch-sign -->
Sign multiple artifacts matching a glob pattern

| Flag | Default | Description |
|------|---------|-------------|
| `<PATTERN>` | — | Glob pattern matching artifact files to sign. |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key |
| `--key <KEY>` | — | Local alias of the identity key. Omit for device-only CI signing |
| `--attestation-dir <DIR>` | — | Directory to collect attestation files into |
| `--expires-in <N>` | — | Duration in seconds until expiration |
| `--note <NOTE>` | — | Optional note to embed in each attestation |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact batch-sign -->

### auths artifact verify

```bash
auths artifact verify
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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact verify -->

### auths policy lint

```bash
auths policy lint
```

<!-- BEGIN GENERATED: auths policy lint -->
Validate policy JSON syntax without full compilation

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the policy file (JSON) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy lint -->

### auths policy compile

```bash
auths policy compile
```

<!-- BEGIN GENERATED: auths policy compile -->
Compile a policy file with full validation

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | — | Path to the policy file (JSON) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy compile -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy explain -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy test -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths policy diff -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths git install-hooks -->

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
| `--kel-tip <KEL_TIP>` | — | Optional KEL tip SAID for rotation tracking |
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

### auths namespace claim

```bash
auths namespace claim
```

<!-- BEGIN GENERATED: auths namespace claim -->
Claim a namespace in a package ecosystem

| Flag | Default | Description |
|------|---------|-------------|
| `--ecosystem <ECOSYSTEM>` | — | Package ecosystem (e.g. npm, crates.io, pypi) |
| `--package-name <PACKAGE_NAME>` | — | Package name to claim |
| `--registry-url <REGISTRY_URL>` | — | Registry URL (defaults to the public registry) |
| `--key <KEY>` | — | Alias of the signing key in keychain |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths namespace claim -->

### auths namespace delegate

```bash
auths namespace delegate
```

<!-- BEGIN GENERATED: auths namespace delegate -->
Delegate namespace authority to another identity

| Flag | Default | Description |
|------|---------|-------------|
| `--ecosystem <ECOSYSTEM>` | — | Package ecosystem (e.g. npm, crates.io, pypi) |
| `--package-name <PACKAGE_NAME>` | — | Package name |
| `--delegate-did <DELEGATE_DID>` | — | DID of the identity to delegate to |
| `--registry-url <REGISTRY_URL>` | — | Registry URL (defaults to the public registry) |
| `--key <KEY>` | — | Alias of the signing key in keychain |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths namespace delegate -->

### auths namespace transfer

```bash
auths namespace transfer
```

<!-- BEGIN GENERATED: auths namespace transfer -->
Transfer namespace ownership to another identity

| Flag | Default | Description |
|------|---------|-------------|
| `--ecosystem <ECOSYSTEM>` | — | Package ecosystem (e.g. npm, crates.io, pypi) |
| `--package-name <PACKAGE_NAME>` | — | Package name |
| `--new-owner-did <NEW_OWNER_DID>` | — | DID of the new owner |
| `--registry-url <REGISTRY_URL>` | — | Registry URL (defaults to the public registry) |
| `--key <KEY>` | — | Alias of the signing key in keychain |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths namespace transfer -->

### auths namespace lookup

```bash
auths namespace lookup
```

<!-- BEGIN GENERATED: auths namespace lookup -->
Look up namespace information

| Flag | Default | Description |
|------|---------|-------------|
| `--ecosystem <ECOSYSTEM>` | — | Package ecosystem (e.g. npm, crates.io, pypi) |
| `--package-name <PACKAGE_NAME>` | — | Package name |
| `--registry-url <REGISTRY_URL>` | — | Registry URL (defaults to the public registry) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths namespace lookup -->

### auths org create

```bash
auths org create
```

<!-- BEGIN GENERATED: auths org create -->
Create a new organization identity

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Organization name |
| `--key <KEY>` | — | Alias for the local signing key (auto-generated if not provided) |
| `--metadata-file <METADATA_FILE>` | — | Optional metadata file (if provided, merged with org metadata) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org create -->

### auths org attest

```bash
auths org attest
```

<!-- BEGIN GENERATED: auths org attest -->
| Flag | Default | Description |
|------|---------|-------------|
| `--subject-did <SUBJECT_DID>` | — | [aliases: --subject] |
| `--payload-file <PAYLOAD_FILE>` | — |  |
| `--note <NOTE>` | — |  |
| `--expires-at <EXPIRES_AT>` | — |  |
| `--key <KEY>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org attest -->

### auths org revoke

```bash
auths org revoke
```

<!-- BEGIN GENERATED: auths org revoke -->
| Flag | Default | Description |
|------|---------|-------------|
| `--subject-did <SUBJECT_DID>` | — | [aliases: --subject] |
| `--note <NOTE>` | — |  |
| `--key <KEY>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org revoke -->

### auths org show

```bash
auths org show
```

<!-- BEGIN GENERATED: auths org show -->
| Flag | Default | Description |
|------|---------|-------------|
| `--subject-did <SUBJECT_DID>` | — | [aliases: --subject] |
| `--include-revoked` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org show -->

### auths org list

```bash
auths org list
```

<!-- BEGIN GENERATED: auths org list -->
| Flag | Default | Description |
|------|---------|-------------|
| `--include-revoked` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org list -->

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
| `--key <KEY>` | — | Alias of the signing key in keychain |
| `--note <NOTE>` | — | Optional note for the authorization |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org add-member -->

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
| `--key <KEY>` | — | Alias of the signing key in keychain |
| `--dry-run` | — | Preview actions without making changes |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org revoke-member -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org list-members -->

### auths org join

```bash
auths org join
```

<!-- BEGIN GENERATED: auths org join -->
Join an organization using an invite code

| Flag | Default | Description |
|------|---------|-------------|
| `--code <CODE>` | — | Invite code (e.g. from `auths org join --code C23BD59F`) |
| `--registry <REGISTRY>` | `https://auths-registry.fly.dev` | Registry URL to contact |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org join -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths audit -->

### auths auth challenge

```bash
auths auth challenge
```

<!-- BEGIN GENERATED: auths auth challenge -->
Sign an authentication challenge for DID-based login

| Flag | Default | Description |
|------|---------|-------------|
| `--nonce <NONCE>` | — | The challenge nonce from the authentication server |
| `--domain <DOMAIN>` | `auths.dev` | The domain requesting authentication |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths auth challenge -->

## Internal

### auths emergency revoke-device

```bash
auths emergency revoke-device
```

<!-- BEGIN GENERATED: auths emergency revoke-device -->
Revoke a compromised device immediately

| Flag | Default | Description |
|------|---------|-------------|
| `--device <DEVICE>` | — | Device DID to revoke |
| `--key <KEY>` | — | Local alias of the identity's key (used for signing the revocation) |
| `--note <NOTE>` | — | Optional note explaining the revocation |
| `-y, --yes` | — | Skip confirmation prompt |
| `--dry-run` | — | Preview actions without making changes |
| `--repo <REPO>` | — | Path to the Auths repository |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency revoke-device -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency rotate-now -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency freeze -->

### auths emergency unfreeze

```bash
auths emergency unfreeze
```

<!-- BEGIN GENERATED: auths emergency unfreeze -->
Unfreeze (cancel an active freeze early)

| Flag | Default | Description |
|------|---------|-------------|
| `-y, --yes` | — | Skip confirmation prompt |
| `--repo <REPO>` | — | Path to the Auths repository |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency unfreeze -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
<!-- END GENERATED: auths emergency report -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent start -->

### auths agent stop

```bash
auths agent stop
```

<!-- BEGIN GENERATED: auths agent stop -->
Stop the SSH agent daemon

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent stop -->

### auths agent status

```bash
auths agent status
```

<!-- BEGIN GENERATED: auths agent status -->
Show agent status

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent status -->

### auths agent env

```bash
auths agent env
```

<!-- BEGIN GENERATED: auths agent env -->
Output shell environment for SSH_AUTH_SOCK (use with eval)

| Flag | Default | Description |
|------|---------|-------------|
| `--shell <SHELL>` | `bash` | Shell format |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent env -->

### auths agent lock

```bash
auths agent lock
```

<!-- BEGIN GENERATED: auths agent lock -->
Lock the agent (clear keys from memory)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent lock -->

### auths agent unlock

```bash
auths agent unlock
```

<!-- BEGIN GENERATED: auths agent unlock -->
Unlock the agent (re-load keys)

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-key-alias <AGENT_KEY_ALIAS>` | `default` | Key alias to unlock  [aliases: --key] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent unlock -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent install-service -->

### auths agent uninstall-service

```bash
auths agent uninstall-service
```

<!-- BEGIN GENERATED: auths agent uninstall-service -->
Uninstall the system service

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths agent uninstall-service -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness start -->

### auths witness add

```bash
auths witness add
```

<!-- BEGIN GENERATED: auths witness add -->
Add a witness URL to the identity configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | — | Witness server URL (e.g., "http://127.0.0.1:3333") |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness add -->

### auths witness remove

```bash
auths witness remove
```

<!-- BEGIN GENERATED: auths witness remove -->
Remove a witness URL from the identity configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | — | Witness server URL to remove |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness remove -->

### auths witness list

```bash
auths witness list
```

<!-- BEGIN GENERATED: auths witness list -->
List configured witnesses for the current identity

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness list -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim serve -->

### auths scim quickstart

```bash
auths scim quickstart
```

<!-- BEGIN GENERATED: auths scim quickstart -->
Zero-config quickstart: temp DB + test tenant + running server

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `0.0.0.0:3301` | Listen address |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim quickstart -->

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
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim test-connection -->

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
| `--expires-in <EXPIRES_IN>` | — | Duration in seconds until expiration (per RFC 6749) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim add-tenant -->

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
| `--expires-in <EXPIRES_IN>` | — | Duration in seconds until expiration (per RFC 6749) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim rotate-token -->

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
