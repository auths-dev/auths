# Advanced Commands

## Device

### auths device link

```bash
auths device link
```

<!-- BEGIN GENERATED: auths device link -->
Authorize a new device to act on behalf of the identity

<div class="flags-container">
<input type="checkbox" id="flags---identity-key-aliasIDENTITYKEYALIAS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the *identity's* key (used for signing). [aliases: --ika]</td></tr>
<tr><td><code>--device-key-alias &lt;DEVICE_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the *new device's* key (must be imported first). [aliases: --dka]</td></tr>
<tr><td><code>--device-did &lt;DEVICE_DID&gt;</code></td><td>—</td><td>Identity ID of the new device being authorized (must match device-key-alias). [aliases: --device]</td></tr>
<tr><td><code>--payload &lt;PAYLOAD_PATH&gt;</code></td><td>—</td><td>Optional path to a JSON file containing arbitrary payload data for the authorization.</td></tr>
<tr><td><code>--schema &lt;SCHEMA_PATH&gt;</code></td><td>—</td><td>Optional path to a JSON schema for validating the payload (experimental).</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--expires-in-days &lt;DAYS&gt;</code></td><td>—</td><td>Optional number of days until this device authorization expires. [aliases: --days]</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional description/note for this device authorization.</td></tr>
<tr><td><code>--capabilities &lt;CAPABILITIES&gt;</code></td><td>—</td><td>Permissions to grant this device (comma-separated)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---identity-key-aliasIDENTITYKEYALIAS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths device link -->

---

### auths device revoke

```bash
auths device revoke
```

<!-- BEGIN GENERATED: auths device revoke -->
Revoke an existing device authorization using the identity key

<div class="flags-container">
<input type="checkbox" id="flags---device-didDEVICEDID" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--device-did &lt;DEVICE_DID&gt;</code></td><td>—</td><td>Identity ID of the device authorization to revoke. [aliases: --device]</td></tr>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the *identity's* key (required to authorize revocation).</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note explaining the revocation.</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes.</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---device-didDEVICEDID" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths device revoke -->

---

### auths device extend

```bash
auths device extend
```

<!-- BEGIN GENERATED: auths device extend -->
Extend the expiration date of an existing device authorization

<div class="flags-container">
<input type="checkbox" id="flags---device-didDEVICEDID" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--device-did &lt;DEVICE_DID&gt;</code></td><td>—</td><td>Identity ID of the device authorization to extend. [aliases: --device]</td></tr>
<tr><td><code>--expires-in-days &lt;DAYS&gt;</code></td><td>—</td><td>Number of days to extend the expiration by (from now). [aliases: --days]</td></tr>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the *identity's* key (required for re-signing). [aliases: --ika]</td></tr>
<tr><td><code>--device-key-alias &lt;DEVICE_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the *device's* key (required for re-signing). [aliases: --dka]</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---device-didDEVICEDID" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
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

<div class="flags-container">
<input type="checkbox" id="flags---aliasALIAS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--alias &lt;ALIAS&gt;</code></td><td>—</td><td>Alias of the identity key to rotate.</td></tr>
<tr><td><code>--current-key-alias &lt;CURRENT_KEY_ALIAS&gt;</code></td><td>—</td><td>Alias of the CURRENT private key controlling the identity.</td></tr>
<tr><td><code>--next-key-alias &lt;NEXT_KEY_ALIAS&gt;</code></td><td>—</td><td>Alias to store the NEWLY generated private key under.</td></tr>
<tr><td><code>--add-witness &lt;ADD_WITNESS&gt;</code></td><td>—</td><td>Verification server prefix to add (e.g., B...). Can be specified multiple times.</td></tr>
<tr><td><code>--remove-witness &lt;REMOVE_WITNESS&gt;</code></td><td>—</td><td>Verification server prefix to remove (e.g., B...). Can be specified multiple times.</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--witness-threshold &lt;WITNESS_THRESHOLD&gt;</code></td><td>—</td><td>New simple verification threshold count (e.g., 1 for 1-of-N).</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---aliasALIAS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths id rotate -->

---

## Key Management

### auths key import

```bash
auths key import
```

<!-- BEGIN GENERATED: auths key import -->
Import an Ed25519 key from a 32-byte seed file and store it encrypted

<div class="flags-container">
<input type="checkbox" id="flags---key-aliasKEYALIAS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--key-alias &lt;KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias to assign to the imported key. [aliases: --alias]</td></tr>
<tr><td><code>--seed-file &lt;SEED_FILE&gt;</code></td><td>—</td><td>Path to the file containing the raw 32-byte Ed25519 seed.</td></tr>
<tr><td><code>--controller-did &lt;CONTROLLER_DID&gt;</code></td><td>—</td><td>Controller DID (e.g., did:key:...) to associate with the imported key.</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---key-aliasKEYALIAS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths key import -->

---

### auths key export

```bash
auths key export
```

<!-- BEGIN GENERATED: auths key export -->
Export a stored key in various formats (requires passphrase for some formats)

<div class="flags-container">
<input type="checkbox" id="flags---key-aliasKEYALIAS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--key-alias &lt;KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the key to export. [aliases: --alias]</td></tr>
<tr><td><code>--passphrase &lt;PASSPHRASE&gt;</code></td><td>—</td><td>Passphrase to decrypt the key (needed for 'pem'/'pub' formats).</td></tr>
<tr><td><code>--format &lt;FORMAT&gt;</code></td><td>—</td><td>Export format: pem (OpenSSH private), pub (OpenSSH public), enc (raw encrypted bytes).</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---key-aliasKEYALIAS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths key export -->

---

### auths key delete

```bash
auths key delete
```

<!-- BEGIN GENERATED: auths key delete -->
Remove a key from the platform's secure storage by alias

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--key-alias &lt;KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the key to remove. [aliases: --alias]</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths key delete -->

---

## Policy

### auths policy explain

```bash
auths policy explain
```

<!-- BEGIN GENERATED: auths policy explain -->
Evaluate a policy against a context and show the decision

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;FILE&gt;</code></td><td>—</td><td>Path to the policy file (JSON)</td></tr>
<tr><td><code>-c, --context &lt;CONTEXT&gt;</code></td><td>—</td><td>Path to the context file (JSON)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths policy explain -->

---

### auths policy test

```bash
auths policy test
```

<!-- BEGIN GENERATED: auths policy test -->
Run a policy against a test suite

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;FILE&gt;</code></td><td>—</td><td>Path to the policy file (JSON)</td></tr>
<tr><td><code>-t, --tests &lt;TESTS&gt;</code></td><td>—</td><td>Path to the test suite file (JSON)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths policy test -->

---

### auths policy diff

```bash
auths policy diff
```

<!-- BEGIN GENERATED: auths policy diff -->
Compare two policies and show semantic differences

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;OLD&gt;</code></td><td>—</td><td>Path to the old policy file (JSON)</td></tr>
<tr><td><code>&lt;NEW&gt;</code></td><td>—</td><td>Path to the new policy file (JSON)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths policy diff -->

---

## Emergency

### auths emergency revoke-device

```bash
auths emergency revoke-device
```

<!-- BEGIN GENERATED: auths emergency revoke-device -->
Revoke a compromised device immediately

<div class="flags-container">
<input type="checkbox" id="flags---deviceDEVICE" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--device &lt;DEVICE&gt;</code></td><td>—</td><td>Device DID to revoke</td></tr>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the identity's key (used for signing the revocation)</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note explaining the revocation</td></tr>
<tr><td><code>-y, --yes</code></td><td>—</td><td>Skip confirmation prompt</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Path to the Auths repository</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<label for="flags---deviceDEVICE" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths emergency revoke-device -->

---

### auths emergency rotate-now

```bash
auths emergency rotate-now
```

<!-- BEGIN GENERATED: auths emergency rotate-now -->
Force immediate key rotation

<div class="flags-container">
<input type="checkbox" id="flags---current-aliasCURRENTALIAS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--current-alias &lt;CURRENT_ALIAS&gt;</code></td><td>—</td><td>Local alias of the current signing key</td></tr>
<tr><td><code>--next-alias &lt;NEXT_ALIAS&gt;</code></td><td>—</td><td>Local alias for the new signing key after rotation</td></tr>
<tr><td><code>-y, --yes</code></td><td>—</td><td>Skip confirmation prompt (requires typing ROTATE)</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes</td></tr>
<tr><td><code>--reason &lt;REASON&gt;</code></td><td>—</td><td>Reason for rotation</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Path to the Auths repository</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<label for="flags---current-aliasCURRENTALIAS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths emergency rotate-now -->

---

### auths emergency freeze

```bash
auths emergency freeze
```

<!-- BEGIN GENERATED: auths emergency freeze -->
Freeze all signing operations

<div class="flags-container">
<input type="checkbox" id="flags---durationDURATION" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--duration &lt;DURATION&gt;</code></td><td><code>24h</code></td><td>Duration to freeze (e.g., &quot;24h&quot;, &quot;7d&quot;)</td></tr>
<tr><td><code>-y, --yes</code></td><td>—</td><td>Skip confirmation prompt (requires typing identity name)</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Path to the Auths repository</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<label for="flags---durationDURATION" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths emergency freeze -->

---

### auths emergency report

```bash
auths emergency report
```

<!-- BEGIN GENERATED: auths emergency report -->
Generate an incident report

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--events &lt;EVENTS&gt;</code></td><td><code>100</code></td><td>Include last N events in report</td></tr>
<tr><td><code>-o, --output &lt;OUTPUT_FILE&gt;</code></td><td>—</td><td>Output file path (defaults to stdout) [aliases: --file]</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Path to the Auths repository</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths emergency report -->

---

## Git

### auths git allowed-signers

```bash
auths git allowed-signers
```

<!-- BEGIN GENERATED: auths git allowed-signers -->
Generate allowed_signers file from Auths device authorizations

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td><code>~/.auths</code></td><td>Path to the Auths identity repository</td></tr>
<tr><td><code>-o, --output &lt;OUTPUT_FILE&gt;</code></td><td>—</td><td>Output file path. If not specified, outputs to stdout</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths git allowed-signers -->

---

### auths git install-hooks

```bash
auths git install-hooks
```

<!-- BEGIN GENERATED: auths git install-hooks -->
Install Git hooks for automatic allowed_signers regeneration

<div class="flags-container">
<input type="checkbox" id="flags---repoREPO" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td><code>.</code></td><td>Path to the Git repository where hooks should be installed. Defaults to the current directory</td></tr>
<tr><td><code>--auths-repo &lt;AUTHS_REPO&gt;</code></td><td><code>~/.auths</code></td><td>Path to the Auths identity repository</td></tr>
<tr><td><code>--allowed-signers-path &lt;ALLOWED_SIGNERS_PATH&gt;</code></td><td><code>.auths/allowed_signers</code></td><td>Path where allowed_signers file should be written</td></tr>
<tr><td><code>--force</code></td><td>—</td><td>Overwrite existing hook without prompting</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<label for="flags---repoREPO" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths git install-hooks -->

---

## Trust

### auths trust pin

```bash
auths trust pin
```

<!-- BEGIN GENERATED: auths trust pin -->
Manually pin an identity as trusted

<div class="flags-container">
<input type="checkbox" id="flags---didDID" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--did &lt;DID&gt;</code></td><td>—</td><td>The DID of the identity to pin (e.g., did:keri:E...)</td></tr>
<tr><td><code>--key &lt;KEY&gt;</code></td><td>—</td><td>The public key in hex format (64 chars for Ed25519)</td></tr>
<tr><td><code>--kel-tip &lt;KEL_TIP&gt;</code></td><td>—</td><td>Optional KEL tip SAID for rotation tracking</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note about this identity</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---didDID" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths trust pin -->

---

### auths trust list

```bash
auths trust list
```

<!-- BEGIN GENERATED: auths trust list -->
List all pinned identities

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths trust list -->

---

### auths trust remove

```bash
auths trust remove
```

<!-- BEGIN GENERATED: auths trust remove -->
Remove a pinned identity

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;DID&gt;</code></td><td>—</td><td>The DID of the identity to remove</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths trust remove -->

---

### auths trust show

```bash
auths trust show
```

<!-- BEGIN GENERATED: auths trust show -->
Show details of a pinned identity

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;DID&gt;</code></td><td>—</td><td>The DID of the identity to show</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths trust show -->

---

## Organization

### auths org create

```bash
auths org create
```

<!-- BEGIN GENERATED: auths org create -->
Create a new organization identity

<div class="flags-container">
<input type="checkbox" id="flags---nameNAME" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--name &lt;NAME&gt;</code></td><td>—</td><td>Organization name</td></tr>
<tr><td><code>--local-key-alias &lt;LOCAL_KEY_ALIAS&gt;</code></td><td>—</td><td>Alias for the local signing key (auto-generated if not provided)</td></tr>
<tr><td><code>--metadata-file &lt;METADATA_FILE&gt;</code></td><td>—</td><td>Optional metadata file (if provided, merged with org metadata)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---nameNAME" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths org create -->

---

### auths org add-member

```bash
auths org add-member
```

<!-- BEGIN GENERATED: auths org add-member -->
Add a member to an organization

<div class="flags-container">
<input type="checkbox" id="flags---orgORG" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--org &lt;ORG&gt;</code></td><td>—</td><td>Organization identity ID</td></tr>
<tr><td><code>--member-did &lt;MEMBER_DID&gt;</code></td><td>—</td><td>Member identity ID to add [aliases: --member]</td></tr>
<tr><td><code>--role &lt;ROLE&gt;</code></td><td>—</td><td>Role to assign (admin, member, readonly)</td></tr>
<tr><td><code>--capabilities &lt;CAPABILITIES&gt;</code></td><td>—</td><td>Override default capabilities (comma-separated)</td></tr>
<tr><td><code>--signer-alias &lt;SIGNER_ALIAS&gt;</code></td><td>—</td><td>Alias of the signing key in keychain</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note for the authorization</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---orgORG" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths org add-member -->

---

### auths org revoke-member

```bash
auths org revoke-member
```

<!-- BEGIN GENERATED: auths org revoke-member -->
Revoke a member from an organization

<div class="flags-container">
<input type="checkbox" id="flags---orgORG" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--org &lt;ORG&gt;</code></td><td>—</td><td>Organization identity ID</td></tr>
<tr><td><code>--member-did &lt;MEMBER_DID&gt;</code></td><td>—</td><td>Member identity ID to revoke [aliases: --member]</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Reason for revocation</td></tr>
<tr><td><code>--signer-alias &lt;SIGNER_ALIAS&gt;</code></td><td>—</td><td>Alias of the signing key in keychain</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview actions without making changes</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---orgORG" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths org revoke-member -->

---

### auths org list-members

```bash
auths org list-members
```

<!-- BEGIN GENERATED: auths org list-members -->
List members of an organization

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--org &lt;ORG&gt;</code></td><td>—</td><td>Organization identity ID</td></tr>
<tr><td><code>--include-revoked</code></td><td>—</td><td>Include revoked members</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths org list-members -->

---

## Audit

### auths audit

```bash
auths audit
```

<!-- BEGIN GENERATED: auths audit -->
Generate signing audit reports for compliance

<div class="flags-container">
<input type="checkbox" id="flags---repoREPO" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td><code>.</code></td><td>Path to the Git repository to audit (defaults to current directory)</td></tr>
<tr><td><code>--since &lt;SINCE&gt;</code></td><td>—</td><td>Start date for audit period (YYYY-MM-DD or YYYY-QN for quarter)</td></tr>
<tr><td><code>--until &lt;UNTIL&gt;</code></td><td>—</td><td>End date for audit period (YYYY-MM-DD)</td></tr>
<tr><td><code>--format &lt;FORMAT&gt;</code></td><td><code>table</code></td><td>Output format</td></tr>
<tr><td><code>--require-all-signed</code></td><td>—</td><td>Require all commits to be signed (for CI exit codes)</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--exit-code</code></td><td>—</td><td>Return exit code 1 if any unsigned commits found</td></tr>
<tr><td><code>--author &lt;AUTHOR&gt;</code></td><td>—</td><td>Filter by author email</td></tr>
<tr><td><code>--signer &lt;SIGNER&gt;</code></td><td>—</td><td>Filter by signing identity/device DID</td></tr>
<tr><td><code>-n, --count &lt;COUNT&gt;</code></td><td><code>100</code></td><td>Maximum number of commits to include</td></tr>
<tr><td><code>-o, --output-file &lt;OUTPUT_FILE&gt;</code></td><td>—</td><td>Output file path (defaults to stdout)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
</table>
<label for="flags---repoREPO" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths audit -->

---

## Agent

### auths agent start

```bash
auths agent start
```

<!-- BEGIN GENERATED: auths agent start -->
Start the SSH agent daemon

<div class="flags-container">
<input type="checkbox" id="flags---socketSOCKET" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--socket &lt;SOCKET&gt;</code></td><td>—</td><td>Custom Unix socket path</td></tr>
<tr><td><code>--foreground</code></td><td>—</td><td>Run in foreground instead of daemonizing</td></tr>
<tr><td><code>--timeout &lt;TIMEOUT&gt;</code></td><td><code>30m</code></td><td>Idle timeout before auto-lock</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---socketSOCKET" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths agent start -->

---

### auths agent stop

```bash
auths agent stop
```

<!-- BEGIN GENERATED: auths agent stop -->
Stop the SSH agent daemon

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent stop -->

---

### auths agent status

```bash
auths agent status
```

<!-- BEGIN GENERATED: auths agent status -->
Show agent status

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent status -->

---

### auths agent env

```bash
auths agent env
```

<!-- BEGIN GENERATED: auths agent env -->
Output shell environment for SSH_AUTH_SOCK (use with eval)

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--shell &lt;SHELL&gt;</code></td><td><code>bash</code></td><td>Shell format</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent env -->

---

### auths agent lock

```bash
auths agent lock
```

<!-- BEGIN GENERATED: auths agent lock -->
Lock the agent (clear keys from memory)

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent lock -->

---

### auths agent unlock

```bash
auths agent unlock
```

<!-- BEGIN GENERATED: auths agent unlock -->
Unlock the agent (re-load keys)

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--agent-key-alias &lt;AGENT_KEY_ALIAS&gt;</code></td><td><code>default</code></td><td>Key alias to unlock  [aliases: --key]</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent unlock -->

---

### auths agent install-service

```bash
auths agent install-service
```

<!-- BEGIN GENERATED: auths agent install-service -->
Install as a system service (launchd on macOS, systemd on Linux)

<div class="flags-container">
<input type="checkbox" id="flags---dry-run" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--dry-run</code></td><td>—</td><td>Print service file without installing</td></tr>
<tr><td><code>--force</code></td><td>—</td><td>Overwrite existing service file</td></tr>
<tr><td><code>--manager &lt;MANAGER&gt;</code></td><td>—</td><td>Service manager (auto-detect by default)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---dry-run" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths agent install-service -->

---

### auths agent uninstall-service

```bash
auths agent uninstall-service
```

<!-- BEGIN GENERATED: auths agent uninstall-service -->
Uninstall the system service

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths agent uninstall-service -->

---

## Witness

### auths witness start

```bash
auths witness start
```

<!-- BEGIN GENERATED: auths witness start -->
Start the witness HTTP server

<div class="flags-container">
<input type="checkbox" id="flags---bindBIND" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--bind &lt;BIND&gt;</code></td><td><code>127.0.0.1:3333</code></td><td>Address to bind to (e.g., &quot;127.0.0.1:3333&quot;)</td></tr>
<tr><td><code>--db-path &lt;DB_PATH&gt;</code></td><td><code>witness.db</code></td><td>Path to the SQLite database for witness storage</td></tr>
<tr><td><code>--witness-did &lt;WITNESS_DID&gt;</code></td><td>—</td><td>Witness DID (auto-generated if not provided) [aliases: --witness]</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---bindBIND" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths witness start -->

---

### auths witness add

```bash
auths witness add
```

<!-- BEGIN GENERATED: auths witness add -->
Add a witness URL to the identity configuration

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--url &lt;URL&gt;</code></td><td>—</td><td>Witness server URL (e.g., &quot;http://127.0.0.1:3333&quot;)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths witness add -->

---

### auths witness remove

```bash
auths witness remove
```

<!-- BEGIN GENERATED: auths witness remove -->
Remove a witness URL from the identity configuration

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--url &lt;URL&gt;</code></td><td>—</td><td>Witness server URL to remove</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths witness remove -->

---

### auths witness list

```bash
auths witness list
```

<!-- BEGIN GENERATED: auths witness list -->
List configured witnesses for the current identity

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths witness list -->

---

## SCIM

### auths scim serve

```bash
auths scim serve
```

<!-- BEGIN GENERATED: auths scim serve -->
Start the SCIM provisioning server

<div class="flags-container">
<input type="checkbox" id="flags---bindBIND" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--bind &lt;BIND&gt;</code></td><td><code>0.0.0.0:3301</code></td><td>Listen address</td></tr>
<tr><td><code>--database-url &lt;DATABASE_URL&gt;</code></td><td>—</td><td>PostgreSQL connection URL</td></tr>
<tr><td><code>--registry-path &lt;REGISTRY_PATH&gt;</code></td><td>—</td><td>Path to the Auths registry Git repository</td></tr>
<tr><td><code>--log-level &lt;LOG_LEVEL&gt;</code></td><td><code>info</code></td><td>Log level</td></tr>
<tr><td><code>--test-mode</code></td><td>—</td><td>Enable test mode (auto-tenant, relaxed TLS)</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---bindBIND" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths scim serve -->

---

### auths scim quickstart

```bash
auths scim quickstart
```

<!-- BEGIN GENERATED: auths scim quickstart -->
Zero-config quickstart: temp DB + test tenant + running server

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--bind &lt;BIND&gt;</code></td><td><code>0.0.0.0:3301</code></td><td>Listen address</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths scim quickstart -->

---

### auths scim test-connection

```bash
auths scim test-connection
```

<!-- BEGIN GENERATED: auths scim test-connection -->
Validate the full SCIM pipeline: create -> get -> patch -> delete

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--url &lt;URL&gt;</code></td><td><code>http://localhost:3301</code></td><td>Server URL</td></tr>
<tr><td><code>--token &lt;TOKEN&gt;</code></td><td>—</td><td>Bearer token</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths scim test-connection -->

---

### auths scim tenants

```bash
auths scim tenants
```

<!-- BEGIN GENERATED: auths scim tenants -->
List SCIM tenants

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--database-url &lt;DATABASE_URL&gt;</code></td><td>—</td><td>PostgreSQL connection URL</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Output as JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths scim tenants -->

---

### auths scim add-tenant

```bash
auths scim add-tenant
```

<!-- BEGIN GENERATED: auths scim add-tenant -->
Generate a new bearer token for an IdP tenant

<div class="flags-container">
<input type="checkbox" id="flags---nameNAME" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--name &lt;NAME&gt;</code></td><td>—</td><td>Tenant name</td></tr>
<tr><td><code>--database-url &lt;DATABASE_URL&gt;</code></td><td>—</td><td>PostgreSQL connection URL</td></tr>
<tr><td><code>--expires-in &lt;EXPIRES_IN&gt;</code></td><td>—</td><td>Token expiry duration (e.g., 90d, 365d). Omit for no expiry</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---nameNAME" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths scim add-tenant -->

---

### auths scim rotate-token

```bash
auths scim rotate-token
```

<!-- BEGIN GENERATED: auths scim rotate-token -->
Rotate bearer token for an existing tenant

<div class="flags-container">
<input type="checkbox" id="flags---nameNAME" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--name &lt;NAME&gt;</code></td><td>—</td><td>Tenant name</td></tr>
<tr><td><code>--database-url &lt;DATABASE_URL&gt;</code></td><td>—</td><td>PostgreSQL connection URL</td></tr>
<tr><td><code>--expires-in &lt;EXPIRES_IN&gt;</code></td><td>—</td><td>Token expiry duration (e.g., 90d, 365d)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---nameNAME" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths scim rotate-token -->

---

### auths scim status

```bash
auths scim status
```

<!-- BEGIN GENERATED: auths scim status -->
Show SCIM sync state for debugging

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--database-url &lt;DATABASE_URL&gt;</code></td><td>—</td><td>PostgreSQL connection URL</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Output as JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths scim status -->

---

## Configuration

### auths config set

```bash
auths config set <KEY> <VALUE>
```

<!-- BEGIN GENERATED: auths config set -->
Set a configuration value (e.g. `auths config set passphrase.cache always`)

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;KEY&gt;</code></td><td>—</td><td>Dotted key path (e.g. `passphrase.cache`, `passphrase.duration`)</td></tr>
<tr><td><code>&lt;VALUE&gt;</code></td><td>—</td><td>Value to assign</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths config set -->

---

### auths config get

```bash
auths config get <KEY>
```

<!-- BEGIN GENERATED: auths config get -->
Get a configuration value (e.g. `auths config get passphrase.cache`)

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;KEY&gt;</code></td><td>—</td><td>Dotted key path</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths config get -->

---

### auths config show

```bash
auths config show
```

<!-- BEGIN GENERATED: auths config show -->
Show the full configuration

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths config show -->

---

## Approval

### auths approval list

```bash
auths approval list
```

<!-- BEGIN GENERATED: auths approval list -->
List pending approval requests

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths approval list -->

---

### auths approval grant

```bash
auths approval grant
```

<!-- BEGIN GENERATED: auths approval grant -->
Grant approval for a pending request

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--request &lt;REQUEST&gt;</code></td><td>—</td><td>The request hash to approve (hex-encoded)</td></tr>
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note for the approval</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths approval grant -->

---

## Artifact

### auths artifact sign

```bash
auths artifact sign <FILE>
```

<!-- BEGIN GENERATED: auths artifact sign -->
Sign an artifact file with your Auths identity

<div class="flags-container">
<input type="checkbox" id="flags-FILE" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;FILE&gt;</code></td><td>—</td><td>Path to the artifact file to sign.</td></tr>
<tr><td><code>--sig-output &lt;PATH&gt;</code></td><td>—</td><td>Output path for the signature file. Defaults to &lt;FILE&gt;.auths.json</td></tr>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the identity key. Omit for device-only CI signing. [aliases: --ika]</td></tr>
<tr><td><code>--device-key-alias &lt;DEVICE_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the device key (used for dual-signing). [aliases: --dka]</td></tr>
<tr><td><code>--expires-in-days &lt;N&gt;</code></td><td>—</td><td>Number of days until the signature expires [aliases: --days]</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note to embed in the attestation</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags-FILE" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths artifact sign -->

---

### auths artifact verify

```bash
auths artifact verify <FILE>
```

<!-- BEGIN GENERATED: auths artifact verify -->
Verify an artifact's signature against an Auths identity

<div class="flags-container">
<input type="checkbox" id="flags-FILE" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;FILE&gt;</code></td><td>—</td><td>Path to the artifact file to verify.</td></tr>
<tr><td><code>--signature &lt;PATH&gt;</code></td><td>—</td><td>Path to the signature file. Defaults to &lt;FILE&gt;.auths.json</td></tr>
<tr><td><code>--identity-bundle &lt;IDENTITY_BUNDLE&gt;</code></td><td>—</td><td>Path to identity bundle JSON (for CI/CD stateless verification)</td></tr>
<tr><td><code>--witness-receipts &lt;WITNESS_RECEIPTS&gt;</code></td><td>—</td><td>Path to witness receipts JSON file</td></tr>
<tr><td><code>--witness-keys &lt;WITNESS_KEYS&gt;...</code></td><td>—</td><td>Witness public keys as DID:hex pairs (e.g., &quot;did:key:z6Mk...:abcd1234...&quot;)</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--witness-threshold &lt;WITNESS_THRESHOLD&gt;</code></td><td><code>1</code></td><td>Witness quorum threshold (default: 1)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags-FILE" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths artifact verify -->

---

### auths artifact publish

```bash
auths artifact publish
```

<!-- BEGIN GENERATED: auths artifact publish -->
Publish a signed artifact attestation to a registry

<div class="flags-container">
<input type="checkbox" id="flags---signatureSIGNATURE" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--signature &lt;SIGNATURE&gt;</code></td><td>—</td><td>Path to the .auths.json signature file created by `auths artifact sign`</td></tr>
<tr><td><code>--package &lt;PACKAGE&gt;</code></td><td>—</td><td>Package identifier for registry indexing (e.g., npm:react@18.3.0)</td></tr>
<tr><td><code>--registry &lt;REGISTRY&gt;</code></td><td><code>https://auths-registry.fly.dev</code></td><td>Registry URL to publish to</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---signatureSIGNATURE" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths artifact publish -->

---

## Completions

### auths completions

```bash
auths completions <SHELL>
```

<!-- BEGIN GENERATED: auths completions -->
Generate shell completions

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;SHELL&gt;</code></td><td>—</td><td>The shell to generate completions for</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths completions -->
