# Advanced commands

These commands are available directly as `auths device`, `auths key`, etc. — no `advanced` prefix needed. Run `auths <command> --help` to see options for any command.

Most users only need these for key management, onboarding additional devices, policy work, or incident response.

---

## auths device

Manage device links to your identity.

### `auths device link`

Link a device to your identity by creating a signed attestation.

!!! tip "When to use this"
    - Adding a new laptop, phone, or CI agent to your identity
    - **Not** for key rotation — use [`auths id rotate`](#auths-advanced-id) instead
    - **Not** for creating a new identity — use [`auths init`](primary.md#auths-init) instead

```bash
auths device link \
  --identity-key-alias <ALIAS> \
  --device-key-alias <ALIAS> \
  --device-did <DID> \
  [--note <TEXT>] \
  [--expires-in-days <N>]
```

<!-- BEGIN GENERATED: auths device link -->
| Flag | Required | Description |
|------|----------|-------------|
| `--identity-key-alias` | Yes | Alias of the identity key |
| `--device-key-alias` | Yes | Alias of the device key |
| `--device-did` | Yes | Device `did:key:z6Mk...` |
| `--note` | No | Human-readable description |
| `--expires-in-days` | No | Attestation expiration (days from now) |
<!-- END GENERATED: auths device link -->

You will be prompted for passphrases three times: device key, identity key, then device key again (for the dual signature).

!!! warning "Common mistakes"
    - **Wrong passphrase order** — device → identity → device. It's easy to enter the wrong one at the wrong prompt.
    - **Device DID mismatch** — the `--device-did` must match the key you imported. Derive it with `auths util derive-did` if unsure.

### `auths device revoke`

Revoke a device, disabling its attestation.

!!! tip "When to use this"
    - Device is lost or stolen
    - Retiring a machine you no longer use

```bash
auths device revoke \
  --identity-key-alias <ALIAS> \
  --device-did <DID> \
  [--note <TEXT>]
```

<!-- BEGIN GENERATED: auths device revoke -->
<!-- END GENERATED: auths device revoke -->

After revocation the device no longer appears in `auths id show-devices` (unless `--include-revoked` is used), but existing signatures remain verifiable with revocation noted.

### `auths device extend`

Renew a device attestation before it expires.

```bash
auths device extend \
  --identity-key-alias <ALIAS> \
  --device-did <DID> \
  --expires-in-days <N>
```

<!-- BEGIN GENERATED: auths device extend -->
<!-- END GENERATED: auths device extend -->

---

## auths id

Manage your cryptographic identity.

### `auths id init-did`

Create a new identity with a controller DID.

!!! tip "When to use this"
    - First-time setup on any machine (prefer `auths init --profile developer` for guided setup)
    - Starting a completely fresh identity
    - **Not** for adding a second device — use [`auths device link`](#auths-advanced-device) instead

```bash
auths id init-did \
  --local-key-alias <ALIAS> \
  --metadata-file <PATH>
```

<!-- BEGIN GENERATED: auths id init-did -->
| Flag | Required | Description |
|------|----------|-------------|
| `--local-key-alias` | Yes | Alias for the key in the keychain |
| `--metadata-file` | Yes | Path to JSON metadata file |
| `--seed-hex` | No | Provide a hex seed (testing only) |
<!-- END GENERATED: auths id init-did -->

!!! warning "Common mistakes"
    - **Forgetting your passphrase** — there's no recovery. Use a password manager.
    - **Running `init-did` twice** — creates a second identity, not a second device. If you already have an identity, use `auths device link` instead.

### `auths id show`

Display identity details.

```bash
auths id show [--show-pk-bytes]
```

```
Controller DID: did:keri:E...
Metadata:
  name: ...
  email: ...
Key Alias: ...
```

### `auths id show-devices`

List all devices linked to the identity.

```bash
auths id show-devices [--include-revoked]
```

### `auths id rotate`

Rotate the identity key using KERI pre-rotation.

!!! tip "When to use this"
    - Scheduled key hygiene (e.g., annual rotation)
    - Suspected compromise of the current key
    - **Not** for revoking a device — use [`auths device revoke`](#auths-advanced-device) instead

```bash
auths id rotate --alias <ALIAS> [--next-key-alias <ALIAS>]
```

<!-- BEGIN GENERATED: auths id rotate -->
<!-- END GENERATED: auths id rotate -->

After rotation the `did:keri:E...` identity remains the same; the new key becomes the active signing key and the Key Event Log records the rotation. Historical signatures verify against the key state at signing time.

---

## auths key

Manage keys stored in your platform keychain.

!!! note "You can ignore this for now"
    Most users never need `auths key` directly. Identity creation and device linking handle key operations automatically. These commands are for debugging, migration, and advanced workflows.

### `auths key list`

List all stored key aliases.

```bash
auths key list
```

### `auths key import`

Import a key from a seed file.

```bash
auths key import \
  --alias <ALIAS> \
  --seed-file <PATH> \
  --controller-did <DID>
```

<!-- BEGIN GENERATED: auths key import -->
<!-- END GENERATED: auths key import -->

### `auths key export`

Export a key in the specified format.

```bash
auths key export --alias <ALIAS> --format <FORMAT>
```

<!-- BEGIN GENERATED: auths key export -->
| Flag | Required | Description |
|------|----------|-------------|
| `--alias` | Yes | Key alias to export |
| `--format` | Yes | `pub` (public key) or `pem` (private key PEM) |
<!-- END GENERATED: auths key export -->

!!! warning
    `--format pem` outputs the **private key**. Handle with care.

### `auths key delete`

Permanently remove a key from the keychain.

```bash
auths key delete --alias <ALIAS>
```

<!-- BEGIN GENERATED: auths key delete -->
<!-- END GENERATED: auths key delete -->

!!! warning "Common mistakes"
    - **Deleting before revoking** — if the device is still linked, revoke it first with `auths device revoke`.
    - There is no undo.

---

## auths policy

Manage authorization policies — lint, compile, test, explain, and diff policy files.

Policies are JSON documents that define what actions are allowed. See [Policy concepts](../../concepts/policy.md) for background.

### `auths policy lint`

Validate policy JSON syntax without full compilation.

```bash
auths policy lint <FILE>
```

### `auths policy compile`

Compile a policy with full validation, checking node limits and depth constraints.

```bash
auths policy compile <FILE>
```

The output includes a content-addressable hash useful for pinning and auditing.

### `auths policy explain`

Evaluate a policy against a context and show the decision with reasoning.

```bash
auths policy explain <POLICY_FILE> --context <CONTEXT_FILE>
```

<!-- BEGIN GENERATED: auths policy explain -->
<!-- END GENERATED: auths policy explain -->

Context file format:

```json
{
  "issuer": "did:keri:EOrg...",
  "subject": "did:key:z6MkDev...",
  "capabilities": ["sign_commit"],
  "role": "member",
  "repo": "org/my-repo",
  "environment": "production"
}
```

### `auths policy test`

Run a policy against a test suite.

```bash
auths policy test <POLICY_FILE> --tests <TEST_FILE>
```

<!-- BEGIN GENERATED: auths policy test -->
<!-- END GENERATED: auths policy test -->

Test suite format — an array of `{ name, context, expect }` objects where `expect` is `"Allow"` or `"Deny"`. Exits non-zero if any test fails.

### `auths policy diff`

Compare two policies and show semantic differences with risk assessment.

```bash
auths policy diff <OLD_FILE> <NEW_FILE>
```

<!-- BEGIN GENERATED: auths policy diff -->
| Risk level | Meaning |
|------------|---------|
| **HIGH** | Removing safety checks (`NotRevoked`, `NotExpired`) or changing `And` to `Or` at root |
| **MEDIUM** | Removing scope constraints (`IssuerIs`, `RepoIs`, `EnvIs`) |
| **LOW** | Adding constraints (narrows scope) |
<!-- END GENERATED: auths policy diff -->

All subcommands support `--json` output via `AUTHS_OUTPUT=json`.

---

## auths emergency

Incident response commands for compromised devices, exposed keys, and emergency freezes.

Running `auths emergency` without a subcommand starts an interactive flow:

```bash
auths emergency
```

```
What happened?
> Device lost or stolen
  Key may have been exposed
  Freeze everything immediately
  Generate incident report
  Cancel
```

### `auths emergency revoke-device`

Immediately revoke a compromised device.

```bash
auths emergency revoke-device \
  [--device <DID>] \
  [--yes] \
  [--dry-run]
```

<!-- BEGIN GENERATED: auths emergency revoke-device -->
<!-- END GENERATED: auths emergency revoke-device -->

In interactive mode (no `--device`), you'll see a list of linked devices and select the one to revoke.

### `auths emergency rotate-now`

Force immediate key rotation when a key may have been exposed.

!!! warning "All devices will need to re-authorize"
    After rotation, re-link each device with `auths device link` and update any CI/CD secrets.

```bash
auths emergency rotate-now \
  [--reason <TEXT>] \
  [--yes] \
  [--dry-run]
```

<!-- BEGIN GENERATED: auths emergency rotate-now -->
<!-- END GENERATED: auths emergency rotate-now -->

Without `--yes`, this requires typing `ROTATE` to confirm.

After rotation:

```bash
auths device link  # Re-authorize devices
auths doctor        # Verify everything is healthy
```

### `auths emergency freeze`

Temporarily disable all signing operations across all devices.

```bash
auths emergency freeze \
  [--duration <DURATION>] \
  [--yes] \
  [--dry-run]
```

<!-- BEGIN GENERATED: auths emergency freeze -->
<!-- END GENERATED: auths emergency freeze -->

`--duration` accepts values like `24h` or `7d` (default: `24h`). To unfreeze early:

```bash
auths emergency unfreeze
```

### `auths emergency report`

Generate an incident report with device status, recent events, and recommendations.

```bash
auths emergency report \
  [--events <N>] \
  [--file <PATH>] \
  [--json]
```

<!-- BEGIN GENERATED: auths emergency report -->
<!-- END GENERATED: auths emergency report -->
