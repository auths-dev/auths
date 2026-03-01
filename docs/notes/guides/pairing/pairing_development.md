# Pairing: Local Development & Testing

A step-by-step walkthrough for contributors to test the cross-device pairing flow on a single machine using three terminals.

## Prerequisites

1. **An initialized identity at `~/.auths`**:
   ```bash
   auths init
   ```
   If you already have one, verify with `auths status`.

2. **A key in your keychain**:
   ```bash
   auths key list
   # Should show at least one alias (e.g., "macbook", "main")
   ```

3. **The project built**:
   ```bash
   cargo build --package auths-cli --package auths-registry-server
   ```

## The Three-Terminal Setup

You need three terminals open, all in the `auths/` workspace root.

### Terminal 1: Registry Server

Start the pairing relay server. It stores sessions in-memory and uses `~/.auths` as its identity repo by default.

```bash
cargo run --package auths-registry-server
```

Expected output:
```
2026-02-10T20:40:16Z  INFO auths_registry_server: Auths Registry Server v0.0.1-rc.9
2026-02-10T20:40:16Z  INFO auths_registry_server: Repository: "/Users/<you>/.auths"
2026-02-10T20:40:16Z  INFO auths_registry_server: Bind address: 0.0.0.0:3000
2026-02-10T20:40:16Z  INFO auths_registry_server: CORS: disabled
2026-02-10T20:40:16Z  INFO auths_registry_server: Starting registry server on 0.0.0.0:3000
```

Leave this running.

### Terminal 2: Host (Initiates Pairing)

This simulates the existing device that wants to authorize a new device.

```bash
auths pair --registry http://localhost:3000
```

Expected output:
```
Device Pairing Mode
===================================================================

Registry:   http://localhost:3000
Controller: did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM

Registering pairing session... OK

    [QR code rendered here]

Scan the QR code above, or enter this code manually:

    QDB-BEV

Capabilities: sign_commit
Expires: 20:45:18 (300s remaining)

Waiting for response from mobile device...
(Press Ctrl+C to cancel)
```

Note the **short code** (e.g., `QDB-BEV`). You have 5 minutes before it expires.

### Terminal 3: Joiner (Joins the Session)

This simulates the new device being paired. Use the short code from Terminal 2 (dashes are optional):

```bash
auths pair --join QDBBEV --registry http://localhost:3000
```

Expected output:
```
Joining pairing session...

Short code: QDB-BEV
Registry:   http://localhost:3000

Looking up session... OK

Controller: did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM
Session ID: QDBBEV

Loading local device key... Enter passphrase for key 'macbook':
OK
Device DID: did:key:z6MkrXGyrDjNKaedh9Xc3d2ZwHgvFedHq26qEu1a44AQPiGf

Creating pairing response... OK
Submitting response... OK

===================================================================
Pairing response submitted successfully!
===================================================================

The initiating device will verify the response and create
a device attestation for this device.
```

### Back to Terminal 2: Host Completes

After the joiner submits, Terminal 2 picks up the response:

```
Response received!

===================================================================
Pairing Response Received
===================================================================

Device Name: unknown-device
Device DID:  did:key:z6MkrXGyrDjNKaedh9Xc3d2ZwHgvFedHq26qEu1a44AQPiGf

Verifying signature... OK
Completing key exchange... OK

Identity: did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM (RID: .auths)
Creating device attestation...
Enter passphrase for key 'macbook' to sign:
Enter passphrase:

Pairing complete! Device attestation created.
```

## Verifying the Result

After pairing completes, confirm the device attestation was stored:

```bash
auths status
auths id show-devices
```

## Testing Variations

### Custom capabilities

```bash
auths pair --capabilities sign_commit,sign_tag --registry http://localhost:3000
```

### Shorter expiry window

```bash
auths pair --expiry 60 --registry http://localhost:3000
```

### Text-only mode (no QR code)

```bash
auths pair --no-qr --registry http://localhost:3000
```

### Offline mode (no registry, for testing QR rendering)

```bash
auths pair --offline
```

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Short code not found` | Joiner ran before host, code expired, or typo | Run host first, use code within 5 minutes |
| `Key not found` | No identity initialized | Run `auths init` |
| `No signing key found for identity` | Keychain has no key for the loaded identity | Run `auths key list` to check, re-init if needed |
| `Connection refused` | Registry server not running | Start Terminal 1 first |
| `Session has expired` | More than 5 minutes elapsed | Host runs `auths pair` again for a fresh code |

## Architecture Notes

For contributors working on the pairing code:

- **CLI logic**: `crates/auths-cli/src/commands/pair.rs` — host initiation, joiner flow, attestation creation
- **Crypto protocol**: `crates/auths-core/src/pairing/` — X25519 ECDH, short code generation, Ed25519 binding signatures
- **Key loading**: `crates/auths-core/src/crypto/signer.rs` — `load_ed25519_keypair()` handles all PKCS#8 format variations
- **Server relay**: `crates/auths-registry-server/src/routes/pairing.rs` — in-memory session store, REST endpoints
- **API paths**: `crates/auths-registry-server/src/paths.rs` — endpoint constants

Sessions are stored in-memory on the registry server (not persisted). Restarting the server clears all active sessions.

## See Also

- [Pairing Devices](pairing_devices.md) — end-user guide
- [Git Signing](../git-signing.md) — set up commit signing after pairing
