# Advanced Commands

## Advanced

### auths publish

```bash
auths publish
```

<!-- BEGIN GENERATED: auths publish -->
Publish a signed artifact attestation to the Auths registry.

| Flag | Default | Description |
|------|---------|-------------|
| `--signature <PATH>` | — | Path to an existing .auths.json signature file. Defaults to <FILE>.auths.json |
| `--package <PACKAGE>` | — | Package identifier for registry indexing (e.g., npm:react@18.3.0) |
| `--registry <REGISTRY>` | — | Registry URL to publish to [env: AUTHS_REGISTRY_URL=] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths publish -->

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
| `--force` | — | Overwrite the --sig-output file if it already exists |
| `--key <KEY>` | — | Local alias of the identity key. Omit for device-only CI signing. |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key. Auto-detected when only one key exists. |
| `--expires-in <N>` | — | Duration in seconds until expiration (per RFC 6749) |
| `--note <NOTE>` | — | Optional note to embed in the attestation |
| `--commit <COMMIT>` | — | Git commit SHA to embed in the attestation (provenance binding; embedded only when given, never inferred from git state) |
| `--no-commit` | — | Do not embed any commit SHA in the attestation |
| `--ci` | — | Use ephemeral CI signing (no keychain needed). Requires --commit |
| `--curve <CURVE>` | — | Curve for the ephemeral CI key (`p256` or `ed25519`). Only meaningful with --ci; defaults to p256 |
| `--ci-platform <CI_PLATFORM>` | — | CI platform override when --ci is used outside a detected CI environment |
| `--oidc-token <TOKEN-FILE>` | — | Path to the runner's OIDC token (the keyless exchange: the token is validated against the issuer's JWKS and the verified claims are embedded in the signed attestation as an OIDC binding) |
| `--oidc-audience <AUD>` | — | Expected OIDC token audience (exact match). Required with --oidc-token |
| `--oidc-issuer <URL>` | `https://token.actions.githubusercontent.com` | Expected OIDC token issuer (exact match) |
| `--oidc-jwks <JWKS-FILE>` | — | Pinned JWKS file for offline/air-gapped token validation (default: fetch the issuer's published JWKS over HTTPS) |
| `--log <LOG_ID>` | — | Transparency log to submit to (overrides default from trust config) |
| `--allow-unlogged` | — | Skip transparency log submission (local testing only). Produces an unlogged attestation that verifiers reject by default |
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
| `--registry <REGISTRY>` | — | Registry URL to publish to [env: AUTHS_REGISTRY_URL=] |
| `--key <KEY>` | — | Local alias of the identity key. Omit for device-only CI signing |
| `--device-key <DEVICE_KEY>` | — | Local alias of the device key. Auto-detected when only one key exists |
| `--expires-in <N>` | — | Duration in seconds until expiration |
| `--note <NOTE>` | — | Optional note to embed in the attestation |
| `--commit <COMMIT>` | — | Git commit SHA to embed in the attestation (provenance binding; embedded only when given, never inferred from git state) |
| `--no-commit` | — | Do not embed any commit SHA in the attestation |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact publish -->

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
| `--witness-signatures <WITNESS_RECEIPTS>` | — | Path to witness signatures JSON file |
| `--witness-keys <WITNESS_KEYS>...` | — | Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...") |
| `--witnesses-required <WITNESS_THRESHOLD>` | `1` | Number of witnesses required (default: 1) |
| `--verify-commit` | — | Also verify the source commit's signing attestation |
| `--signature-only` | — | For an ephemeral (`did:key:`) attestation, confirm the signature over the artifact digest WITHOUT chasing the commit-anchor leg. This is the runner's self-check: it has no maintainer repo/roots, but it can prove it signed what it emitted. A pass means "digest matches, ephemeral key signed it", not "the signer trust-chains to a maintainer" |
| `--offline` | — | Verify an air-gapped org bundle entirely offline (no network access) |
| `--roots <PATH>` | — | Override the pinned trust roots path (default: `.auths/roots`) |
| `--member <MEMBER>` | — | (offline) Member `did:keri` to classify authority for [aliases: --member-did] |
| `--signed-at <SIGNED_AT>` | — | (offline) The artifact's in-band signing KEL position |
| `--json` | — | (offline) Emit the typed verdict as JSON |
| `--oidc-policy <POLICY-FILE>` | — | OIDC-subject policy file to JOIN against the attestation's signed OIDC binding (issuer + repository [+ workflow_ref] the org trusts). Fail-closed: a missing binding or any mismatch fails verification |
| `--oidc-policy-did <ORG-DID>` | — | Resolve the OIDC-subject policy from the org's KEL instead of a pinned file: reads the latest policy digest the org anchored (`auths org anchor-oidc-policy`) from the local registry and refuses a digest mismatch — the witnessed log is the source of truth |
| `--log-evidence <EVIDENCE-FILE>` | — | Offline transparency-log inclusion evidence for this artifact (`auths log prove --out`). Verified fully offline; the verdict's `anchored` field reports the outcome. Requires --log-key — an inclusion proof without a pinned operator proves nothing |
| `--log-key <HEX>` | — | The log operator's Ed25519 public key (64 hex chars), pinned out of band — never trusted from the evidence file itself |
| `--expect-signer <DID>` | — | Require the verified signer to be exactly this identity (e.g. a release signer). Fails closed on a signer mismatch — an allowlist applied after verification, it can only narrow a valid verdict, never widen it |
| `--require-rooted-signer` | — | Require the verified signer to be a rooted did:keri identity (a rotatable, revocable key-state log), rejecting a bare did:key self-attestation. Fails closed; applied after verification, it can only narrow a valid verdict, never widen it |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths artifact verify -->

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
Create a new signing identity

| Flag | Default | Description |
|------|---------|-------------|
| `--metadata-file <METADATA_FILE>` | — | Path to JSON file with arbitrary identity metadata. |
| `--local-key-alias <LOCAL_KEY_ALIAS>` | — | Name for the new signing key in secure storage. |
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
| `--alias <ALIAS>` | — | Name of the key to rotate. |
| `--current-key-alias <CURRENT_KEY_ALIAS>` | — | Current signing key name (alternative to --alias). |
| `--next-key-alias <NEXT_KEY_ALIAS>` | — | Name for the new signing key after rotation. |
| `--add-witness <ADD_WITNESS>` | — | Add a witness server address (repeatable). |
| `--remove-witness <REMOVE_WITNESS>` | — | Remove a witness server address (repeatable). |
| `--witness-threshold <WITNESS_THRESHOLD>` | — | Number of witnesses required to accept this rotation (e.g., 1). |
| `--dry-run` | — | Preview actions without making changes |
| `--add-device <CURVE>` | — | Add a device slot on this rotation (repeatable). Value is the curve for the new slot (`P256` or `Ed25519`) |
| `--remove-device <INDEX>` | — | Remove a device slot by index on this rotation (repeatable). Currently rejected — requires CESR indexed-signature support |
| `--signing-threshold <SIGNING_THRESHOLD>` | — | New signing threshold (scalar like `"2"` or fractions like `"1/2,1/2,1/2"`). Omit to keep the prior `kt` |
| `--rotation-threshold <ROTATION_THRESHOLD>` | — | New rotation (next) threshold, same format as `--signing-threshold`. Omit to keep the prior `nt` |
| `--from-device` | — | Receive the rotation from a paired device over LAN instead of authoring it locally. The device builds and co-signs the shared-KEL rotation; this host only validates it against the registry's prior key state and appends it. No local key material is touched |
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

### auths id allowed-signers

```bash
auths id allowed-signers
```

<!-- BEGIN GENERATED: auths id allowed-signers -->
Export a KEL-derived `allowed_signers` file so plain `git` / `ssh` can verify this identity's signatures on machines without auths installed

| Flag | Default | Description |
|------|---------|-------------|
| `--alias <ALIAS>` | — | Key alias to export the signing key for |
| `--principal <PRINCIPAL>` | — | Principal for the allowed_signers line (default: identity DID) |
| `-o, --output <OUTPUT_FILE>` | — | Output file (default: stdout) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id allowed-signers -->

### auths id register

```bash
auths id register
```

<!-- BEGIN GENERATED: auths id register -->
Publish this identity to a public registry for discovery

| Flag | Default | Description |
|------|---------|-------------|
| `--registry <REGISTRY>` | — | Registry URL to publish to [env: AUTHS_REGISTRY_URL=] |
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

### auths id agent

```bash
auths id agent
```

<!-- BEGIN GENERATED: auths id agent -->
Manage AI agents delegated by this identity (KERI delegated identifiers)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths id agent -->

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

### auths device add

```bash
auths device add
```

<!-- BEGIN GENERATED: auths device add -->
Add a device as a delegated identifier of the identity

| Flag | Default | Description |
|------|---------|-------------|
| `--key <KEY>` | — | Your identity's signing key name. |
| `--device-key <DEVICE_KEY>` | — | Keychain alias to store the new device's key under. |
| `--curve <CURVE>` | `p256` | Curve for the new device key (p256 or ed25519). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device add -->

### auths device link

```bash
auths device link
```

<!-- BEGIN GENERATED: auths device link -->
Authorize a new device to act on behalf of the identity (legacy attestation)

| Flag | Default | Description |
|------|---------|-------------|
| `--key <KEY>` | — | Your identity's key name. |
| `--device-key <DEVICE_KEY>` | — | The new device's key name (import first with: auths key import). |
| `--device-did <DEVICE_DID>` | — | The device's ID (must match --device-key). [aliases: --device] |
| `--payload <PAYLOAD_PATH>` | — | Optional path to a JSON file containing arbitrary payload data for the authorization. |
| `--schema <SCHEMA_PATH>` | — | Optional path to a JSON schema for validating the payload (experimental). |
| `--expires-in <SECS>` | — | Optional number of seconds until this device authorization expires. |
| `--note <NOTE>` | — | Optional description/note for this device authorization. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device link -->

### auths device remove

```bash
auths device remove
```

<!-- BEGIN GENERATED: auths device remove -->
Remove a device from the shared identity's controller set by signing a rotation on the shared KEL

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | The controller DID to remove. [aliases: --device] |
| `--key <KEY>` | — | Your identity's signing key name. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths device remove -->

### auths device revoke

```bash
auths device revoke
```

<!-- BEGIN GENERATED: auths device revoke -->
Revoke an existing device authorization using the identity key

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | The device's ID to revoke. [aliases: --device] |
| `--key <KEY>` | — | Your identity's key name. |
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
Resolve a device to its owner identity

| Flag | Default | Description |
|------|---------|-------------|
| `--device-did <DEVICE_DID>` | — | The device ID to resolve (e.g. did:key:z6Mk...). [aliases: --device] |
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
| `--verify` | — | Prompt to manually verify the short-authentication-string (SAS) codes match between devices before completing the pair |
| `--recover <OLD_DID>` | — | Lost/stolen-device recovery: pair a replacement delegated device, then revoke the old device's delegation (by `did:keri:`). The replacement is authorized before the old one is revoked, so the identity is never left with zero usable devices. Supported over the relay path (with `--registry`) |
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
| `--signer-key <ISSUER_PK>` | — | Signer public key in hex format (64 hex chars = 32 bytes) |
| `--signer <ISSUER_DID>` | — | Signer identity ID for trust-based key resolution [aliases: --issuer-did] |
| `--trust <TRUST>` | — | Trust policy for unknown identities |
| `--roots-file <ROOTS_FILE>` | — | Path to roots.json file for explicit trust |
| `--witness-signatures <WITNESS_RECEIPTS>` | — | Path to witness signatures JSON file |
| `--witnesses-required <WITNESS_THRESHOLD>` | `1` | Number of witnesses required (default: 1) |
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
| `--device-did <DEVICE_DID>` | — | The device's ID to extend. [aliases: --device] |
| `--expires-in <SECS>` | — | Number of seconds to extend the expiration by (from now). |
| `--key <KEY>` | — | Your identity's key name. |
| `--device-key <DEVICE_KEY>` | — | The device's key name. |
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
| `--passphrase <PASSPHRASE>` | — | Passphrase to decrypt the key (omit to be prompted securely). |
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
| `--controller-did <CONTROLLER_DID>` | — | Your identity to associate with this key (e.g., did:keri:E...). |
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

### auths kel validate

```bash
auths kel validate
```

<!-- BEGIN GENERATED: auths kel validate -->
Structurally validate a KEL: SAID encodings and chain linkage

| Flag | Default | Description |
|------|---------|-------------|
| `--kel <KEL.json>` | — | Validate this KEL JSON file instead of a stored identity's KEL |
| `--did <did:keri:...>` | — | Validate this identity's local KEL (defaults to your own identity) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths kel validate -->

### auths key-state

```bash
auths key-state
```

<!-- BEGIN GENERATED: auths key-state -->
Emit or ingest a KERI key-state notice (ksn) — interoperable with keripy/keriox

| Flag | Default | Description |
|------|---------|-------------|
| `--from-kel <KEL.json>` | — | Replay this KEL file and emit its current key-state as a KERI `ksn` record (the shape a keripy/keriox peer can read) |
| `--ingest <KSN.json>` | — | Ingest a KERI `ksn` record from this file (the shape a keripy/keriox peer publishes) and print the resolved key-state |
| `--reject-stale-below <HEX_SEQ>` | — | Reject an ingested notice whose sequence is below this (lowercase-hex) value — a verifier already holding a newer state refuses a stale or replayed view. Fails closed with a distinct reason; only valid with `--ingest` |
| `--dt <DT>` | `1970-01-01T00:00:00+00:00` | Timestamp (RFC 3339) to stamp an emitted notice with. Defaults to the epoch so emission stays deterministic; pass the real `now` to publish |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths key-state -->

### auths did-webs

```bash
auths did-webs
```

<!-- BEGIN GENERATED: auths did-webs -->
Emit a did:webs DID document for an AID — resolvable under a standard did:webs resolver

| Flag | Default | Description |
|------|---------|-------------|
| `--from-kel <KEL.json>` | — | Replay this KEL file and project its current key-state into a `did:webs` DID document (the shape a did:webs/DID-core resolver reads) |
| `--domain <DOMAIN>` | — | The web domain the `did:webs` is anchored at — the host (optionally `host%3Aport` and path segments) before the AID in `did:webs:<domain>:<aid>` |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths did-webs -->

### auths keri-emit dip

```bash
auths keri-emit dip
```

<!-- BEGIN GENERATED: auths keri-emit dip -->
Delegated inception (`dip`): the delegate self-signs; `di` names the delegator

| Flag | Default | Description |
|------|---------|-------------|
| `--key <CESR>` | — | The delegate's current signing key, CESR-encoded (qb64) — the same form keripy's `verfer.qb64` |
| `--delegator <PREFIX>` | — | The delegator's AID prefix (becomes the dip's `di`) |
| `--next <SAID>` | — | Optional next-key commitment (pre-rotation digest). Absent → `nt=0`, `n=[]` |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths keri-emit dip -->

### auths keri-emit ixn

```bash
auths keri-emit ixn
```

<!-- BEGIN GENERATED: auths keri-emit ixn -->
Interaction (`ixn`): anchors one seal in the KEL (e.g. a delegator-side revocation)

| Flag | Default | Description |
|------|---------|-------------|
| `--pre <PREFIX>` | — | The AID prefix authoring the interaction (the delegator, for a revocation) |
| `--sn <SN>` | — | Sequence number of this interaction |
| `--prev <SAID>` | — | Prior event SAID (`p`) |
| `--seal-digest <SAID>` | — | A digest seal `{d}` to anchor (auths's delegator-side revocation marker: the device prefix) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths keri-emit ixn -->

### auths tls-cert issue

```bash
auths tls-cert issue
```

<!-- BEGIN GENERATED: auths tls-cert issue -->
Issue a KEL-rooted leaf certificate for an AID (us → peer)

| Flag | Default | Description |
|------|---------|-------------|
| `--from-kel <KEL.json>` | — | Replay this KEL file and project its current key-state into the leaf's `did:keri` SAN + binding extension. The KEL is the root of trust |
| `--san <HOST>` | — | Extra Subject-Alternative-Name host the leaf must serve (DNS name or IP literal). Repeatable. Typically `localhost`, `127.0.0.1`, the LAN host |
| `--tls-key <KEY.pem>` | — | Use this PKCS#8-PEM TLS keypair as the leaf's subject key instead of a fresh ephemeral one (e.g. to reuse a key the acceptor already holds) |
| `--sign-key <AID-KEY.pem>` | — | The AID's current signing key (PKCS#8 PEM). When given, the leaf carries an AID authorization over its TLS key (a KERI signature over the leaf SPKI), so `verify` can reject a forged binding minted over an attacker's TLS key. Without it the leaf only chains to the key-state (the discovery surface) and is rejected by the adversarial verifier |
| `--sign-key-index <N>` | `0` | Which current key (index into the KEL's current key-state) `--sign-key` corresponds to. Defaults to 0 (single-sig AIDs) |
| `--out <PREFIX>` | — | Write `<PREFIX>.cert.pem` + `<PREFIX>.key.pem` instead of printing to stdout. Without it, the cert PEM is printed (the key never is, to avoid leaking it into logs) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tls-cert issue -->

### auths tls-cert identity

```bash
auths tls-cert identity
```

<!-- BEGIN GENERATED: auths tls-cert identity -->
Read the did:keri AID out of a leaf's subjectAltName (X.509-SVID identity)

| Flag | Default | Description |
|------|---------|-------------|
| `--cert <CERT.pem>` | — | The leaf certificate, PEM-encoded. Its `did:keri` subjectAltName names the auths identity — the AID a verifier looks up before replaying its KEL |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tls-cert identity -->

### auths tls-cert verify

```bash
auths tls-cert verify
```

<!-- BEGIN GENERATED: auths tls-cert verify -->
Verify a peer's leaf binds to the KEL we hold (peer → us)

| Flag | Default | Description |
|------|---------|-------------|
| `--cert <CERT.pem>` | — | The peer's leaf certificate, PEM-encoded |
| `--from-kel <KEL.json>` | — | Replay this KEL (the one we hold for the cert's AID) and require the cert to bind to its replayed key-state |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tls-cert verify -->

### auths tls-cert quic

```bash
auths tls-cert quic
```

<!-- BEGIN GENERATED: auths tls-cert quic -->
Carry the KEL-rooted leaf + channel binding over a QUIC/HTTP3 transport

| Flag | Default | Description |
|------|---------|-------------|
| `--from-kel <KEL.json>` | — | Replay this KEL and serve its KEL-rooted leaf over the QUIC handshake. The KEL is the root of trust the client re-derives by replay — over QUIC exactly as over TCP |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths tls-cert quic -->

### auths oobi resolve

```bash
auths oobi resolve
```

<!-- BEGIN GENERATED: auths oobi resolve -->
Resolve a peer's OOBI URL → fetch + replay its KEL → print the key-state

| Flag | Default | Description |
|------|---------|-------------|
| `--url <OOBI_URL>` | — | The peer's OOBI URL: `<scheme>://<authority>/oobi/<cid>/<role>[/<eid>]` |
| `--from-file <STREAM.json>` | — | Resolve an already-fetched stream from this file instead of an HTTP fetch — the offline/hermetic path (the bytes a live endpoint would return). The KEL is still replayed and verified |
| `--timeout <TIMEOUT>` | `30` | HTTP fetch timeout in seconds (live resolve only) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths oobi resolve -->

### auths oobi endpoint

```bash
auths oobi endpoint
```

<!-- BEGIN GENERATED: auths oobi endpoint -->
Serve an AID: emit its OOBI URL + the `rpy` reply stream a peer fetches

| Flag | Default | Description |
|------|---------|-------------|
| `--from-kel <KEL.json>` | — | Replay this KEL and serve its controller as a discoverable AID |
| `--scheme <SCHEME>` | `http` | URL scheme to publish the endpoint under (`http`/`https`/`tcp`) |
| `--authority <HOST:PORT>` | — | Network authority (`host[:port]`) hosting the endpoint — the part of the OOBI URL before `/oobi` |
| `--url <URL>` | — | Absolute endpoint URL embedded in the `/loc/scheme` reply. Defaults to `<scheme>://<authority>/` when omitted |
| `--dt <DT>` | `1970-01-01T00:00:00.000000+00:00` | Timestamp (RFC 3339) to stamp the `rpy` replies with. Defaults to the epoch so output stays deterministic; pass the real `now` to publish |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths oobi endpoint -->

### auths ipex grant

```bash
auths ipex grant
```

<!-- BEGIN GENERATED: auths ipex grant -->
Grant (disclose) a credential: embed an ACDC in a `/ipex/grant` `exn`

| Flag | Default | Description |
|------|---------|-------------|
| `--acdc <ACDC.json>` | — | The saidified ACDC credential to disclose (its JSON body, `{v,d,i,ri,s,a}`) |
| `--sender <AID>` | — | The discloser (sender) AID granting the credential |
| `--recipient <AID>` | — | The recipient (holder) AID the credential is granted to |
| `--message <MESSAGE>` | `""` | Optional human-readable disclosure message (`a.m`) |
| `--dt <DT>` | `1970-01-01T00:00:00.000000+00:00` | Timestamp (RFC 3339) to stamp the `exn` with. Defaults to the epoch so output stays deterministic; pass the real `now` to send |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths ipex grant -->

### auths ipex admit

```bash
auths ipex admit
```

<!-- BEGIN GENERATED: auths ipex admit -->
Admit (accept) a received grant: emit an `/ipex/admit` `exn` for it

| Flag | Default | Description |
|------|---------|-------------|
| `--grant <GRANT.json>` | — | The peer's grant `exn` to admit (its JSON body) |
| `--sender <AID>` | — | The holder (sender) AID admitting the disclosure |
| `--message <MESSAGE>` | `""` | Optional human-readable admission message (`a.m`) |
| `--dt <DT>` | `1970-01-01T00:00:00.000000+00:00` | Timestamp (RFC 3339) to stamp the `exn` with. Defaults to the epoch so output stays deterministic; pass the real `now` to send |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths ipex admit -->

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
| `--registry-url <REGISTRY_URL>` | — | Registry URL (no default) |
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
| `--registry-url <REGISTRY_URL>` | — | Registry URL (no default) |
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
| `--registry-url <REGISTRY_URL>` | — | Registry URL (no default) |
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
| `--registry-url <REGISTRY_URL>` | — | Registry URL (no default) |
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
| `--subject <SUBJECT_DID>` | — | [aliases: --subject-did] |
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
| `--subject <SUBJECT_DID>` | — | [aliases: --subject-did] |
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
| `--subject <SUBJECT_DID>` | — | [aliases: --subject-did] |
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
| `--member <MEMBER_DID>` | — | Member identity ID to add [aliases: --member-did] |
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
| `--member <MEMBER_DID>` | — | Member identity ID to revoke [aliases: --member-did] |
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

### auths org audit

```bash
auths org audit
```

<!-- BEGIN GENERATED: auths org audit -->
Classify a member's authority at an artifact's signing position (by KEL position)

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--member <MEMBER_DID>` | — | Member identity ID to classify [aliases: --member-did] |
| `--artifact <ARTIFACT>` | — | Artifact path (shown in the report for context) |
| `--signed-at <SIGNED_AT>` | — | The artifact's in-band signing KEL position (e.g. a commit's `Auths-Anchor-Seq`) |
| `--json` | — | Emit the typed verdict as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org audit -->

### auths org offboarding-log

```bash
auths org offboarding-log
```

<!-- BEGIN GENERATED: auths org offboarding-log -->
List durable off-boarding records for an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--member <MEMBER_DID>` | — | Restrict to a single member [aliases: --member-did] |
| `--json` | — | Emit the records as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org offboarding-log -->

### auths org bundle

```bash
auths org bundle
```

<!-- BEGIN GENERATED: auths org bundle -->
Produce a self-contained, air-gapped provenance bundle for an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--out <OUT>` | — | Output path for the bundle file |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org bundle -->

### auths org join

```bash
auths org join
```

<!-- BEGIN GENERATED: auths org join -->
Join an organization using an invite code

| Flag | Default | Description |
|------|---------|-------------|
| `--code <CODE>` | — | Invite code (e.g. from `auths org join --code C23BD59F`) |
| `--registry <REGISTRY>` | — | Registry URL to contact [env: AUTHS_REGISTRY_URL=] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org join -->

### auths org policy

```bash
auths org policy
```

<!-- BEGIN GENERATED: auths org policy -->
Manage the org-wide authorization policy (anchored on the org KEL)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org policy -->

### auths org anchor-oidc-policy

```bash
auths org anchor-oidc-policy
```

<!-- BEGIN GENERATED: auths org anchor-oidc-policy -->
Anchor the org's OIDC-subject policy on its KEL (who may sign keylessly). Verifiers resolve it with `auths artifact verify --oidc-policy-did <org-did>` — the witnessed log is the policy's source of truth, not a pinned file

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--file <FILE>` | — | Path to the OIDC-subject policy JSON (issuer + repository, optional workflow_ref) |
| `--key <KEY>` | — | Org signing key alias (defaults to the org slug alias) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org anchor-oidc-policy -->

### auths org metrics

```bash
auths org metrics
```

<!-- BEGIN GENERATED: auths org metrics -->
Show fleet governance metrics for an organization

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID |
| `--json` | — | Emit the metrics as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org metrics -->

### auths org trace

```bash
auths org trace
```

<!-- BEGIN GENERATED: auths org trace -->
Trace an agent's delegation chain to the authorizing root + live-at-signing

| Flag | Default | Description |
|------|---------|-------------|
| `--commit <COMMIT>` | — | A signed commit SHA — traces its signer (`Auths-Device`) at its anchor-seq |
| `--member <MEMBER>` | — | A member/agent identity ID to trace directly [aliases: --member-did] |
| `--signed-at <SIGNED_AT>` | — | The in-band signing KEL position (used with `--member`; `--commit` reads it from the commit's `Auths-Anchor-Seq` trailer) |
| `--json` | — | Emit the chain as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths org trace -->

### auths compliance attest

```bash
auths compliance attest
```

<!-- BEGIN GENERATED: auths compliance attest -->
Anchor a release attestation (artifact digest + signer) in the org KEL — the signing position becomes part of the tamper-evident log

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID (`did:keri:…`) or bare prefix |
| `--artifact <ARTIFACT>` | — | Artifact file to hash (sha256) and attest |
| `--digest <DIGEST>` | — | Pre-computed artifact digest (`sha256:<64 hex>`) |
| `--signer <SIGNER>` | — | The signing member's identity (`did:keri:…`) or bare prefix |
| `--key <KEY>` | — | Org signing key alias (defaults to the org slug alias) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths compliance attest -->

### auths compliance report

```bash
auths compliance report
```

<!-- BEGIN GENERATED: auths compliance report -->
Produce a compliance evidence pack for a reporting period

| Flag | Default | Description |
|------|---------|-------------|
| `--org <ORG>` | — | Organization identity ID (`did:keri:…`) or bare prefix |
| `--period <PERIOD>` | — | Reporting period label (free-form, e.g. `2026-Q3`) |
| `--framework <FRAMEWORK>` | `slsa` | Target framework (tags the pack; with `--predicate`, selects the rendered predicate: SLSA provenance+VSA / SPDX SBOM / CRA mapping / SOC 2 TSC mapping / ISO 27001 Annex-A mapping) |
| `--predicate` | — | Render the framework predicate (in-toto Statement) instead of the raw pack |
| `--verifier-id <VERIFIER_ID>` | `https://auths.dev/compliance` | Verifier id recorded in the SLSA VSA (with `--predicate --framework slsa`) |
| `--releases <RELEASES>` | — | JSON file: array of `{ artifact_digest, signer, signed_at?, transparency? }` — caller-asserted positions (alternative to `--discover`) |
| `--discover` | — | Derive the rows from the release attestations anchored in the org KEL (`compliance attest`); each row's `signed_at` IS its anchoring position |
| `--offline` | — | Embed the org KEL bundle so each row verifies offline (no network) |
| `--sign` | — | Org-sign the pack as a DSSE-wrapped in-toto statement |
| `--key <KEY>` | — | Org signing key alias (defaults to the org slug alias); used with `--sign` |
| `--witness-policy <WITNESS_POLICY>` | — | Pinned witness-policy path (default: `$AUTHS_WITNESS_POLICY_PATH`, else fail-closed) |
| `--out <OUT>` | — | Output file (default: stdout) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths compliance report -->

### auths compliance verify

```bash
auths compliance verify
```

<!-- BEGIN GENERATED: auths compliance verify -->
Verify a DSSE-signed evidence pack offline — no account, no network, no keychain

| Flag | Default | Description |
|------|---------|-------------|
| `--pack <PACK>` | — | The DSSE-signed pack file (from `compliance report --offline --sign`) |
| `--roots <ROOTS>` | — | Pinned trust-roots file (one `did:keri:…` per line) — the only trust input |
| `--log-key <LOG_KEY>` | — | Pinned log-operator key file (one hex Ed25519 key, `#` comments allowed). When given, every row's transparency checkpoint must be SIGNED by this operator — "in the log" becomes operator-attested non-repudiation, not bare Merkle membership |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths compliance verify -->

### auths credential issue

```bash
auths credential issue
```

<!-- BEGIN GENERATED: auths credential issue -->
Issue a capability credential to an issuee (its KEL must already exist)

| Flag | Default | Description |
|------|---------|-------------|
| `--issuer <ISSUER>` | — | The issuer's signing key name (your identity's key). |
| `--to <TO>` | — | The issuee/subject did:keri to credential. |
| `--cap <CAP>` | — | Capability to grant (repeatable). |
| `--role <ROLE>` | — | Informational role claim (e.g. deployer). |
| `--expires-in <EXPIRES_IN>` | — | Expire the credential after N seconds. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths credential issue -->

### auths credential revoke

```bash
auths credential revoke
```

<!-- BEGIN GENERATED: auths credential revoke -->
Revoke a credential (anchors a `rev` in the issuer's KEL). Idempotent

| Flag | Default | Description |
|------|---------|-------------|
| `<CREDENTIAL_SAID>` | — | The credential SAID to revoke. |
| `--issuer <ISSUER>` | — | The issuer's signing key name. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths credential revoke -->

### auths credential list

```bash
auths credential list
```

<!-- BEGIN GENERATED: auths credential list -->
List the issuer's live credentials (issued − revoked)

| Flag | Default | Description |
|------|---------|-------------|
| `--issuer <ISSUER>` | — | The issuer's signing key name. |
| `--include-revoked` | — | Include revoked credentials. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths credential list -->

### auths credential verify

```bash
auths credential verify
```

<!-- BEGIN GENERATED: auths credential verify -->
Verify a credential, resolving the issuer KEL/TEL + witness receipts

| Flag | Default | Description |
|------|---------|-------------|
| `<CREDENTIAL_SAID>` | — | The credential SAID to verify. |
| `--issuer <ISSUER>` | — | The issuer's signing key name. |
| `--require-witnesses` | — | Fail closed unless every lifecycle anchor reaches witness quorum. |
| `--usage-counter <FILE>` | — | Enforce a quantitative usage cap against an observed call count (JSON: {"said":…,"calls_used":N}). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths credential verify -->

### auths credential present

```bash
auths credential present
```

<!-- BEGIN GENERATED: auths credential present -->
Present a credential: prove control of the subject AID and emit an `Auths-Presentation` header

| Flag | Default | Description |
|------|---------|-------------|
| `--subject <SUBJECT>` | — | The subject (holder) keychain alias to sign with. |
| `--said <SAID>` | — | The credential SAID to present. |
| `--audience <AUDIENCE>` | — | The relying-party audience to bind to. |
| `--nonce <NONCE>` | — | The base64url challenge nonce from /v1/auth/challenge. |
| `--with-evidence` | — | Emit JSON with the header AND the verifiable evidence bundle (for relying parties that hold no replica of your KEL). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths credential present -->

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

### auths auth verify

```bash
auths auth verify
```

<!-- BEGIN GENERATED: auths auth verify -->
Verify a challenge response offline against the registry's current key

| Flag | Default | Description |
|------|---------|-------------|
| `--nonce <NONCE>` | — | The challenge nonce this verifier issued |
| `--domain <DOMAIN>` | `auths.dev` | The domain the challenge was bound to |
| `--did <DID>` | — | The responder's did:keri: controller DID (delegated device DIDs fail closed — their liveness needs the delegator's revocation verdict) |
| `--signature <SIGNATURE>` | — | Hex-encoded signature from the challenge response |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths auth verify -->

### auths treasury open

```bash
auths treasury open
```

<!-- BEGIN GENERATED: auths treasury open -->
Establish a manager's aggregate cap

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — | Manager keychain alias (the ledger key). |
| `--cap <CAP>` | — | Aggregate cap (calls:<N> or a plain integer). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury open -->

### auths treasury allot

```bash
auths treasury allot
```

<!-- BEGIN GENERATED: auths treasury allot -->
Commit a slice of the cap to a sub-agent (refused if Σ + amount > cap)

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — |  |
| `--to <TO>` | — | Sub-agent did:keri: to allot to. |
| `--amount <AMOUNT>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury allot -->

### auths treasury reallocate

```bash
auths treasury reallocate
```

<!-- BEGIN GENERATED: auths treasury reallocate -->
Move a slice from one sub-agent to another (constant-sum; refused on underflow)

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — |  |
| `--from <FROM>` | — | Source sub-agent did:keri:. |
| `--to <TO>` | — | Target sub-agent did:keri:. |
| `--amount <AMOUNT>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury reallocate -->

### auths treasury status

```bash
auths treasury status
```

<!-- BEGIN GENERATED: auths treasury status -->
Report parent cap, committed, free pool, slices, and the aggregate invariant

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury status -->

### auths treasury credit

```bash
auths treasury credit
```

<!-- BEGIN GENERATED: auths treasury credit -->
Credit a recorded x402 inbound settlement to a sub-agent's verifiable P&L

| Flag | Default | Description |
|------|---------|-------------|
| `--to <TO>` | — | Sub-agent did:keri: to credit. |
| `--settlement <SETTLEMENT>` | — | Path to a recorded x402 SettlementResponse JSON. |
| `--claim-cents <CLAIM_CENTS>` | — | Assert the credited amount (rejected if ≠ the recorded settlement). |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury credit -->

### auths treasury subdelegate

```bash
auths treasury subdelegate
```

<!-- BEGIN GENERATED: auths treasury subdelegate -->
Sub-delegate a child slice from a sub-agent (Σ children ≤ the parent's slice)

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — |  |
| `--parent <PARENT>` | — | The sub-agent (parent) did:keri: doing the sub-delegation. |
| `--child <CHILD>` | — | The child worker did:keri:. |
| `--amount <AMOUNT>` | — |  |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury subdelegate -->

### auths treasury reclaim

```bash
auths treasury reclaim
```

<!-- BEGIN GENERATED: auths treasury reclaim -->
Reclaim a revoked sub-agent's slice back to the free pool (idempotent)

| Flag | Default | Description |
|------|---------|-------------|
| `--manager <MANAGER>` | — |  |
| `--agent <AGENT>` | — | The revoked sub-agent did:keri: to reclaim. |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths treasury reclaim -->

### auths anchor verify

```bash
auths anchor verify
```

<!-- BEGIN GENERATED: auths anchor verify -->
Verify a duplicity proof offline — no witness contacted, no registry

| Flag | Default | Description |
|------|---------|-------------|
| `--proof <PROOF>` | — | Path to the duplicity-proof JSON (`-` reads stdin) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths anchor verify -->

### auths witness-set declare

```bash
auths witness-set declare
```

<!-- BEGIN GENERATED: auths witness-set declare -->
Anchor the set's content SAID in your KEL via one `ixn`, so verifiers hold your anchors to exactly this set

| Flag | Default | Description |
|------|---------|-------------|
| `--member <NAME=KEY>` | — | A declared member as `NAME=KEY` (repeatable) |
| `--threshold <T>` | — | The finalization threshold `t` of the `t`-of-`N` set |
| `--key <ALIAS>` | — | Keychain alias of your identity signing key (defaults to the identity's primary key) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness-set declare -->

### auths witness-set said

```bash
auths witness-set said
```

<!-- BEGIN GENERATED: auths witness-set said -->
Print the set's content SAID without touching the KEL (deterministic)

| Flag | Default | Description |
|------|---------|-------------|
| `--member <NAME=KEY>` | — | A declared member as `NAME=KEY` (repeatable) |
| `--threshold <T>` | — | The finalization threshold `t` of the `t`-of-`N` set |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness-set said -->

### auths multi-sig begin

```bash
auths multi-sig begin
```

<!-- BEGIN GENERATED: auths multi-sig begin -->
Create an unsigned-event bundle for distribution to signers

| Flag | Default | Description |
|------|---------|-------------|
| `--event <EVENT>` | — | Path to the JSON-encoded finalized `SignedEvent` (signatures empty) |
| `--signers <SIGNERS>` | — | Comma-separated signer aliases, in slot order |
| `--output <OUTPUT>` | — | Output path for the unsigned bundle |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths multi-sig begin -->

### auths multi-sig sign

```bash
auths multi-sig sign
```

<!-- BEGIN GENERATED: auths multi-sig sign -->
Sign an unsigned bundle with a single device key

| Flag | Default | Description |
|------|---------|-------------|
| `--unsigned <UNSIGNED>` | — | Path to the unsigned-event bundle |
| `--keyalias <KEY_ALIAS>` | — | Keychain alias of the signing key |
| `--index <INDEX>` | — | Slot index for the indexed signature (0-based) |
| `--output <OUTPUT>` | — | Output path for the partial signature |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths multi-sig sign -->

### auths multi-sig combine

```bash
auths multi-sig combine
```

<!-- BEGIN GENERATED: auths multi-sig combine -->
Combine partial signatures into a SignedEvent, enforcing the threshold

| Flag | Default | Description |
|------|---------|-------------|
| `--unsigned <UNSIGNED>` | — | Path to the unsigned-event bundle |
| `--partials <PARTIALS>` | — | Comma-separated paths to partial signature files |
| `--threshold <THRESHOLD>` | — | Expected threshold (scalar `"2"` or fractions `"1/2,1/2,1/2"`) |
| `--keycount <KEY_COUNT>` | — | Number of signer slots expected (device_count) |
| `--output <OUTPUT>` | — | Output path for the combined SignedEvent JSON |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths multi-sig combine -->

## Internal

### auths emergency revoke-device

```bash
auths emergency revoke-device
```

<!-- BEGIN GENERATED: auths emergency revoke-device -->
Revoke a compromised device immediately

| Flag | Default | Description |
|------|---------|-------------|
| `--device <DEVICE>` | — | Device ID to revoke |
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

### auths daemon start

```bash
auths daemon start
```

<!-- BEGIN GENERATED: auths daemon start -->
Start the SSH agent daemon

| Flag | Default | Description |
|------|---------|-------------|
| `--socket <SOCKET>` | — | Custom Unix socket path |
| `--foreground` | — | Run in foreground instead of daemonizing |
| `--timeout <TIMEOUT>` | `30m` | Idle timeout before auto-lock |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon start -->

### auths daemon stop

```bash
auths daemon stop
```

<!-- BEGIN GENERATED: auths daemon stop -->
Stop the SSH agent daemon

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon stop -->

### auths daemon status

```bash
auths daemon status
```

<!-- BEGIN GENERATED: auths daemon status -->
Show agent status

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon status -->

### auths daemon env

```bash
auths daemon env
```

<!-- BEGIN GENERATED: auths daemon env -->
Output shell environment for SSH_AUTH_SOCK (use with eval)

| Flag | Default | Description |
|------|---------|-------------|
| `--shell <SHELL>` | `bash` | Shell format |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon env -->

### auths daemon lock

```bash
auths daemon lock
```

<!-- BEGIN GENERATED: auths daemon lock -->
Lock the agent (clear keys from memory)

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon lock -->

### auths daemon unlock

```bash
auths daemon unlock
```

<!-- BEGIN GENERATED: auths daemon unlock -->
Unlock the agent (re-load keys)

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-key-alias <AGENT_KEY_ALIAS>` | `default` | Key alias to unlock  [aliases: --key] |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon unlock -->

### auths daemon install-service

```bash
auths daemon install-service
```

<!-- BEGIN GENERATED: auths daemon install-service -->
Install as a system service (launchd on macOS, systemd on Linux)

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | — | Print service file without installing |
| `--force` | — | Overwrite existing service file |
| `--manager <MANAGER>` | — | Service manager (auto-detect by default) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon install-service -->

### auths daemon uninstall-service

```bash
auths daemon uninstall-service
```

<!-- BEGIN GENERATED: auths daemon uninstall-service -->
Uninstall the system service

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths daemon uninstall-service -->

### auths witness up

```bash
auths witness up
```

<!-- BEGIN GENERATED: auths witness up -->
Stand up a witness node (and its monitor) from a clean box, one command

| Flag | Default | Description |
|------|---------|-------------|
| `--port <PORT>` | `3333` | Host port to publish the node's endpoint on |
| `--data-dir <DATA_DIR>` | `./witness-data` | Host directory for the node's persistent data volume |
| `--accept-file-key` | — | Acknowledge file-backed key custody when no managed key store (KMS/enclave) is available. Without this, a node refuses to fall back to a file key rather than silently weaken custody |
| `--image <IMAGE>` | — | Override the node image to run. Defaults to the released, attested image the platform ships. Use this only to pin a specific released tag or to run an image already present on an air-gapped host |
| `--build-attestation <BUILD_ATTESTATION>` | — | Path to the released image's signed build attestation (`auths artifact sign` output). When supplied, the node serves a proof of which binary it runs, and `status` verifies it. Operators pin the attestation that ships with the released image |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness up -->

### auths witness down

```bash
auths witness down
```

<!-- BEGIN GENERATED: auths witness down -->
Tear a stood-up witness node down

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir <DATA_DIR>` | `./witness-data` | Host directory of the node to tear down |
| `--port <PORT>` | `3333` | Host port the node to tear down was published on |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness down -->

### auths witness status

```bash
auths witness status
```

<!-- BEGIN GENERATED: auths witness status -->
Report a stood-up node's health, identity, receipts, and peers

| Flag | Default | Description |
|------|---------|-------------|
| `--port <PORT>` | `3333` | Host port the node publishes its endpoint on |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness status -->

### auths witness verify-receipt

```bash
auths witness verify-receipt
```

<!-- BEGIN GENERATED: auths witness verify-receipt -->
Verify a witness receipt offline, on this machine alone

| Flag | Default | Description |
|------|---------|-------------|
| `--receipt <RECEIPT>` | — | Path to the receipt bundle JSON file (`-` reads from stdin) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness verify-receipt -->

### auths witness register

```bash
auths witness register
```

<!-- BEGIN GENERATED: auths witness register -->
Open a signed candidate entry to register this node in the directory

| Flag | Default | Description |
|------|---------|-------------|
| `--endpoint <ENDPOINT>` | — | Public base URL operators will reach this node at |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness register -->

### auths witness logs

```bash
auths witness logs
```

<!-- BEGIN GENERATED: auths witness logs -->
Stream a stood-up node's logs

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir <DATA_DIR>` | `./witness-data` | Host directory of the node whose logs to show |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness logs -->

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
| `--identity <IDENTITY>` | — | Path to the persisted witness signing-key keystore. The advertised AID derives from this key and is stable across restarts. Without it the witness runs with an EPHEMERAL (unpinnable) identity. The `AUTHS_WITNESS_SEED` env var (hex seed) takes precedence for containers [aliases: --id] |
| `--generate` | — | Create the keystore at `--identity` if it does not exist. Without this, a missing keystore fails closed (never silently mints a fresh key) |
| `--curve <CURVE>` | `p256` | Signing curve for a newly generated identity: "p256" (default) or "ed25519" |
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

### auths witness publish

```bash
auths witness publish
```

<!-- BEGIN GENERATED: auths witness publish -->
Publish this identity's full KEL to its configured witnesses, collecting receipts for every event

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths witness publish -->

### auths scim serve

```bash
auths scim serve
```

<!-- BEGIN GENERATED: auths scim serve -->
Start the SCIM provisioning server (in-process, KERI-authoritative)

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `0.0.0.0:8787` | Listen address |
| `--tenant <TENANT>` | — | Tenant id for the single-tenant bootstrap (matches the IdP's tenant) |
| `--org-prefix <ORG_PREFIX>` | — | Auths org prefix this tenant provisions into |
| `--token <TOKEN>` | — | Bearer token authenticating the provisioning channel |
| `--org-key <ORG_KEY>` | — | Org signing-key alias (default: derived `org-<slug>`) |
| `--base-url <BASE_URL>` | — | Base URL used for SCIM `meta.location` |
| `--allowed-capability <ALLOWED_CAPABILITY>` | — | Capability this tenant may grant (repeatable). Empty = deny all (RT-006); pass --allow-all-capabilities to opt into permit-all |
| `--allow-all-capabilities` | — | Let this tenant grant ANY capability, bypassing the allowlist (opt-in) |
| `--passphrase <PASSPHRASE>` | — | Passphrase for the org signing key (single-host custody) |
| `--registry-path <REGISTRY_PATH>` | — | Path to the Auths registry Git repository (default: `~/.auths`) |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim serve -->

### auths scim quickstart

```bash
auths scim quickstart
```

<!-- BEGIN GENERATED: auths scim quickstart -->
Zero-config quickstart: generate a token and run a single-tenant server

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <BIND>` | `0.0.0.0:8787` | Listen address |
| `--org-prefix <ORG_PREFIX>` | — | Auths org prefix to provision into (must already exist on this host) |
| `--tenant <TENANT>` | `quickstart` | Tenant id (defaults to `quickstart`) |
| `--passphrase <PASSPHRASE>` | — | Passphrase for the org signing key (single-host custody) |
| `--registry-path <REGISTRY_PATH>` | — | Path to the Auths registry Git repository (default: `~/.auths`) |
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
| `--url <URL>` | `http://localhost:8787` | Server URL |
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
List SCIM tenants (process-configured in this model)

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | — | Output as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim tenants -->

### auths scim add-tenant

```bash
auths scim add-tenant
```

<!-- BEGIN GENERATED: auths scim add-tenant -->
Mint a bearer token for an IdP provisioning channel

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Tenant name |
| `--org-prefix <ORG_PREFIX>` | — | Auths org prefix this tenant provisions into |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim add-tenant -->

### auths scim rotate-token

```bash
auths scim rotate-token
```

<!-- BEGIN GENERATED: auths scim rotate-token -->
Mint a replacement bearer token to rotate a tenant's channel

| Flag | Default | Description |
|------|---------|-------------|
| `--name <NAME>` | — | Tenant name |
| `-j, --json` | — | Emit machine-readable JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim rotate-token -->

### auths scim status

```bash
auths scim status
```

<!-- BEGIN GENERATED: auths scim status -->
Probe a running SCIM server's health and discovery surface

| Flag | Default | Description |
|------|---------|-------------|
| `--url <URL>` | `http://localhost:8787` | Server URL |
| `--json` | — | Output as JSON |
| `-q, --quiet` | — | Suppress non-essential output |
| `--repo <REPO>` | — | Override the local storage directory (default: ~/.auths) |
<!-- END GENERATED: auths scim status -->
