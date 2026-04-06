# Multi-Device Setup

Use multiple devices -- laptops, desktops, CI runners -- under a single `did:keri` identity. Each device gets its own Ed25519 keypair and a signed device attestation that delegates trust from the identity key.

## Prerequisites

- An initialized identity on the host device (`auths init`)
- Auths CLI installed on both devices
- Both devices on the same Wi-Fi network (for LAN mode), or a running registry server (for online mode)

## Adding a second device

There are two paths: **pairing** (automated, recommended) and **manual linking** (full control over key material).

| Approach | Command | When to use |
|----------|---------|-------------|
| Pairing | `auths device pair` | Default for most setups. Handles key exchange and attestation automatically. |
| Manual linking | `auths device link` | When you need explicit control over key material, or no network is available. |

## Pairing flow

Pairing uses X25519 ECDH key agreement with Ed25519 signature binding. The binding signature covers `short_code || initiator_x25519_pubkey || device_x25519_pubkey`, preventing replay and MITM attacks.

### LAN mode (default -- no server required)

#### 1. Host device initiates pairing

```bash
auths device pair
```

The CLI starts an ephemeral HTTP server on your LAN IP and displays a QR code with a 6-character short code:

```
━━━ Auths Device Pairing (LAN) ━━━

  Registry:  http://192.168.8.183:54688
  Identity:  did:keri:EnXNx...

  [QR CODE]

  Scan the QR code above, or enter this code manually:

    Z43-8JR

  Capabilities: sign_commit
  Expires: 20:23:07 (300s remaining)

  (Press Ctrl+C to cancel)
```

#### 2. Joining device enters the code

From another terminal or device:

```bash
auths device pair --join Z43-8JR
```

The joiner discovers the host via mDNS, performs the ECDH key exchange, and the host creates a device attestation in `~/.auths`.

!!! tip "Code formatting is flexible"
    Dashes and spaces in the code are ignored. `Z43-8JR`, `Z438JR`, and `z43 8jr` all resolve to the same session.

### Online mode (with relay server)

Use online mode when devices are not on the same network.

#### 1. Start the registry server (if self-hosting)

```bash
cargo run --package auths-registry-server -- --cors
```

The server binds to `0.0.0.0:3000` by default.

#### 2. Host initiates pairing

```bash
auths device pair --registry http://localhost:3000
```

#### 3. Joiner enters the code

```bash
auths device pair --join Z43-8JR --registry http://localhost:3000
```

!!! note "Both sides must use the same `--registry` URL"
    When pairing with a mobile device, use your machine's LAN IP rather than `localhost`.

### Pairing command reference

| Flag | Default | Description |
|------|---------|-------------|
| `--registry <URL>` | *(omit for LAN mode)* | Registry server URL; omit to use LAN mode |
| `--join <CODE>` | | Join an existing session using the short code |
| `--no-qr` | `false` | Only show the short code, skip QR |
| `--expiry <SECONDS>` | `300` | Session TTL (5 minutes max) |
| `--capabilities <LIST>` | `sign_commit` | Comma-separated capabilities to grant |
| `--offline` | `false` | Render QR only, no network (testing only) |

### Mode dispatch

| Command | Mode |
|---------|------|
| `auths device pair` | LAN: local HTTP server + mDNS |
| `auths device pair --registry URL` | Online: registry relay |
| `auths device pair --join CODE` | LAN join: mDNS discovery |
| `auths device pair --join CODE --registry URL` | Online join: registry relay |
| `auths device pair --offline` | Offline: QR only, no server |

## Manual linking

Use manual linking when you need full control over key material or cannot run a network service.

### 1. Import the device key on the new device

```bash
IDENTITY=$(auths id show | grep 'Identity:' | awk '{print $NF}')

auths key import \
  --alias laptop-key \
  --seed-file ~/device_key.seed \
  --identity "$IDENTITY"
```

The seed file must contain exactly 32 bytes of raw Ed25519 key material. You will be prompted for a passphrase to encrypt the key before storing it in the platform keychain.

### 2. Link the device

```bash
auths device link \
  --key my-key \
  --device-key laptop-key \
  --device "$DEVICE_DID" \
  --note "Work Laptop" \
  --expires-in 7776000
```

You will be prompted for passphrases for both the identity key and the device key, as the attestation requires dual signatures.

Optional flags for `device link`:

| Flag | Description |
|------|-------------|
| `--payload <PATH>` | Path to a JSON file with arbitrary payload data |
| `--schema <PATH>` | JSON schema to validate the payload (experimental) |
| `--expires-in <SECONDS>` | Attestation expiry |
| `--note <TEXT>` | Description for this device authorization |
| `--capabilities <LIST>` | Comma-separated permissions to grant |

### 3. Configure Git on the new device

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:laptop-key"
git config --global commit.gpgSign true
```

Commits from this device will now be signed by the same identity.

## How attestations delegate trust

When a device is linked, Auths creates a **device attestation** -- a JSON document dual-signed by both the identity key and the device key. The attestation contains:

- The identity DID (`did:keri:...`) as the issuer
- The device DID (`did:key:z...`) as the subject
- The device's Ed25519 public key
- Granted capabilities (e.g., `sign_commit`)
- Optional expiration timestamp
- Both signatures (identity and device)

The attestation is canonicalized with `json-canon` before signing, stored as a Git ref under `refs/auths/`, and can be verified by any party with access to the identity's Key Event Log.

## Managing linked devices

### List devices

```bash
auths device list
auths device list --include-revoked
```

### Extend an expiring attestation

```bash
auths device extend \
  --device "$DEVICE_DID" \
  --expires-in 7776000 \
  --key my-key \
  --device-key laptop-key
```

### Revoke a device

```bash
auths device revoke \
  --device "$DEVICE_DID" \
  --key my-key \
  --note "Laptop retired"
```

After revoking, remove the local keys:

```bash
auths key delete --alias laptop-key
```

### Verify an attestation

```bash
auths device verify --attestation path/to/attestation.json
```

The `--attestation` flag accepts a path to a device authorization JSON file, or `-` to read from stdin. You can optionally pass `--signer` or `--signer-key` to specify the expected signer.

## Troubleshooting

### "Short code not found"

The host has not initiated a session, the session expired (>5 minutes), or the code was entered incorrectly. Run `auths device pair` on the host first, then enter the code on the joining device within the expiry window.

### "Could not connect" in LAN mode

1. Verify both devices are on the same Wi-Fi network and subnet.
2. Check firewall settings: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` on macOS.
3. Test connectivity with the curl command printed by the CLI.
4. Check router AP isolation settings.

### "No signing key found for identity"

The keychain has no key associated with the loaded identity DID:

```bash
auths key list
auths init --force   # Re-initialize if needed
```

### Session expired

More than 5 minutes passed between initiation and joining. Run `auths device pair` again for a fresh code. Adjust the window with `--expiry <SECONDS>`.
