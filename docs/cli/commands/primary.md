# Primary Commands

## auths init

```bash
auths init
```

<!-- BEGIN GENERATED: auths init -->
Set up your cryptographic identity and Git signing

<div class="flags-container">
<input type="checkbox" id="flags---non-interactive" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--non-interactive</code></td><td>—</td><td>Skip interactive prompts and use sensible defaults</td></tr>
<tr><td><code>--profile &lt;PROFILE&gt;</code></td><td>—</td><td>Preset profile: developer, ci, or agent</td></tr>
<tr><td><code>--key-alias &lt;KEY_ALIAS&gt;</code></td><td><code>main</code></td><td>Key alias for the identity key (default: main)</td></tr>
<tr><td><code>--force</code></td><td>—</td><td>Force overwrite if identity already exists</td></tr>
<tr><td><code>--dry-run</code></td><td>—</td><td>Preview agent configuration without creating files or identities</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--registry &lt;REGISTRY&gt;</code></td><td><code>https://auths-registry.fly.dev</code></td><td>Registry URL for automatic identity registration</td></tr>
<tr><td><code>--skip-registration</code></td><td>—</td><td>Skip automatic registry registration during setup</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---non-interactive" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths init -->

---

## auths sign

```bash
auths sign <TARGET>
```

<!-- BEGIN GENERATED: auths sign -->
Sign a Git commit or artifact file.

<div class="flags-container">
<input type="checkbox" id="flags-TARGET" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>&lt;TARGET&gt;</code></td><td>—</td><td>Commit ref, range, or artifact file path</td></tr>
<tr><td><code>--sig-output &lt;PATH&gt;</code></td><td>—</td><td>Output path for the signature file. Defaults to &lt;FILE&gt;.auths.json</td></tr>
<tr><td><code>--identity-key-alias &lt;IDENTITY_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the identity key (for artifact signing)</td></tr>
<tr><td><code>--device-key-alias &lt;DEVICE_KEY_ALIAS&gt;</code></td><td>—</td><td>Local alias of the device key (for artifact signing, required for files)</td></tr>
<tr><td><code>--expires-in-days &lt;N&gt;</code></td><td>—</td><td>Number of days until the signature expires (for artifact signing) [aliases: --days]</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--note &lt;NOTE&gt;</code></td><td>—</td><td>Optional note to embed in the attestation (for artifact signing)</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags-TARGET" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths sign -->

---

## auths verify

```bash
auths verify
```

<!-- BEGIN GENERATED: auths verify -->
Verify a signed commit or attestation.

<div class="flags-container">
<input type="checkbox" id="flags---allowed-signersALLOWEDSIGNERS" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--allowed-signers &lt;ALLOWED_SIGNERS&gt;</code></td><td><code>.auths/allowed_signers</code></td><td>Path to allowed signers file (commit verification)</td></tr>
<tr><td><code>--identity-bundle &lt;IDENTITY_BUNDLE&gt;</code></td><td>—</td><td>Path to identity bundle JSON (for CI/CD stateless commit verification)</td></tr>
<tr><td><code>--issuer-pk &lt;ISSUER_PK&gt;</code></td><td>—</td><td>Issuer public key in hex format (attestation verification)</td></tr>
<tr><td><code>--issuer-did &lt;ISSUER_DID&gt;</code></td><td>—</td><td>Issuer identity ID for attestation trust-based key resolution [aliases: --issuer]</td></tr>
<tr><td><code>--witness-receipts &lt;WITNESS_RECEIPTS&gt;</code></td><td>—</td><td>Path to witness receipts JSON file</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--witness-threshold &lt;WITNESS_THRESHOLD&gt;</code></td><td><code>1</code></td><td>Witness quorum threshold</td></tr>
<tr><td><code>--witness-keys &lt;WITNESS_KEYS&gt;...</code></td><td>—</td><td>Witness public keys as DID:hex pairs</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---allowed-signersALLOWEDSIGNERS" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths verify -->

---

## auths status

```bash
auths status
```

<!-- BEGIN GENERATED: auths status -->
Show identity and agent status overview

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths status -->

---

## auths whoami

```bash
auths whoami
```

<!-- BEGIN GENERATED: auths whoami -->
Show the current identity on this machine

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths whoami -->

---

## auths tutorial

```bash
auths tutorial
```

<!-- BEGIN GENERATED: auths tutorial -->
Interactive tutorial for learning Auths concepts

<div class="flags-container">
<input type="checkbox" id="flags--s--skipSECTION" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>-s, --skip &lt;SECTION&gt;</code></td><td>—</td><td>Skip to a specific section (1-6)</td></tr>
<tr><td><code>--reset</code></td><td>—</td><td>Reset progress and start from the beginning</td></tr>
<tr><td><code>--list</code></td><td>—</td><td>List all tutorial sections</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags--s--skipSECTION" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths tutorial -->

---

## auths doctor

```bash
auths doctor
```

<!-- BEGIN GENERATED: auths doctor -->
Run comprehensive health checks

<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<!-- END GENERATED: auths doctor -->

---

## auths pair

```bash
auths pair
```

<!-- BEGIN GENERATED: auths pair -->
Link devices to your identity

<div class="flags-container">
<input type="checkbox" id="flags---joinCODE" class="flags-state">
<table>
<thead><tr><th>Flag</th><th>Default</th><th>Description</th></tr></thead>
<tbody>
<tr><td><code>--join &lt;CODE&gt;</code></td><td>—</td><td>Join an existing pairing session using a short code</td></tr>
<tr><td><code>--registry &lt;URL&gt;</code></td><td>—</td><td>Registry URL for pairing relay (omit for LAN mode)</td></tr>
<tr><td><code>--timeout &lt;SECONDS&gt;</code></td><td><code>300</code></td><td>Custom timeout in seconds for the pairing session (default: 300 = 5 minutes)  [aliases: --expiry]</td></tr>
<tr><td><code>--json</code></td><td>—</td><td>Emit machine-readable JSON</td></tr>
<tr><td><code>-q, --quiet</code></td><td>—</td><td>Suppress non-essential output</td></tr>
</tbody>
<tbody class="flags-overflow">
<tr><td><code>--repo &lt;REPO&gt;</code></td><td>—</td><td>Override the local storage directory (default: ~/.auths)</td></tr>
</tbody>
</table>
<label for="flags---joinCODE" class="flags-toggle"><span class="flags-show">Show all flags</span><span class="flags-hide">Show less</span></label>
</div>
<!-- END GENERATED: auths pair -->
