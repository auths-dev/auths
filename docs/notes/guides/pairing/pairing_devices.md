# Pairing Devices with Auths

This guide explains how to link a second device (laptop, phone, CI runner) to your Auths identity using the `auths pair` command.

## Overview

Auths identities live at `~/.auths` on your primary device. Pairing lets you authorize additional devices to sign commits or perform other actions on behalf of the same identity. The protocol uses:

- **X25519 ECDH** for key agreement between devices
- **Ed25519 signatures** to cryptographically bind the exchange
- A **registry server** as a short-lived relay (no secrets are stored server-side)

## Prerequisites

1. **An initialized identity** on the host device:
   ```bash
   auths init
   # Identity is stored at ~/.auths
   ```

2. **Auths CLI installed** on both devices:
   ```bash
   cargo install auths_cli
   ```

3. **A running registry server** (for relaying the pairing handshake):
   ```bash
   cargo run --package auths-registry-server
   ```
   The server binds to `0.0.0.0:3000` by default and uses `~/.auths` as its repository. No flags are required for local use.

## Quick Start

### Terminal 1: Start the registry server

```bash
cargo run --package auths-registry-server
```

### Terminal 2: Host device initiates pairing

```bash
auths pair --registry http://localhost:3000
```

This displays a QR code and a 6-character short code:

```
Scan the QR code above, or enter this code manually:

    Z43-8JR

Capabilities: sign_commit
Expires: 20:23:07 (300s remaining)

Waiting for response from mobile device...
```

### Terminal 3: Joining device enters the code

```bash
auths pair --join Z43-8JR --registry http://localhost:3000
```

The joiner looks up the session, performs the key exchange, and the host creates a device attestation granting the specified capabilities.

## How It Works

```
Host Device                    Registry Server                Joining Device
-----------                    ---------------                --------------
1. Generate X25519 keypair
   Generate short code
   POST /v1/pairing/sessions
   ──────────────────────────►  Store session (in-memory)
   Display QR + short code

                                                              2. Enter short code
                                GET /v1/pairing/sessions/
                                  by-code/{code}
                                ◄──────────────────────────────
                                Return session + token
                                ──────────────────────────────►

                                                              3. Generate X25519 keypair
                                                                 Perform ECDH
                                                                 Sign binding message
                                POST /v1/pairing/sessions/
                                  {id}/response
                                ◄──────────────────────────────

4. Poll for response
   GET /v1/pairing/sessions/{id}
   ──────────────────────────►  Return response
   ◄──────────────────────────

5. Verify Ed25519 signature
   Complete ECDH
   Create device attestation
   Store in ~/.auths
```

The binding signature covers `short_code || host_x25519_pubkey || device_x25519_pubkey`, preventing replay and man-in-the-middle attacks.

## Command Reference

### Host: Initiate Pairing

```bash
auths pair [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--registry <URL>` | `http://localhost:3000` | Registry server URL |
| `--no-qr` | `false` | Only show the short code, skip QR |
| `--expiry <SECONDS>` | `300` | Session TTL (max 5 minutes) |
| `--capabilities <LIST>` | `sign_commit` | Comma-separated capabilities to grant |
| `--offline` | `false` | Skip registry (testing only) |

### Joiner: Join a Session

```bash
auths pair --join <CODE> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--join <CODE>` | | The 6-character short code from the host |
| `--registry <URL>` | `http://localhost:3000` | Must match the host's registry |

Dashes and spaces in the code are ignored (`Z43-8JR` and `Z438JR` are equivalent).

### Registry Server

```bash
auths-registry-server [OPTIONS]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--bind <ADDR>` | `AUTHS_BIND_ADDR` | `0.0.0.0:3000` | Bind address |
| `--repo <PATH>` | `AUTHS_REPO_PATH` | `~/.auths` | Identity repository path |
| `--cors` | `AUTHS_CORS` | disabled | Enable CORS for browser clients |
| `--log-level <LEVEL>` | `AUTHS_LOG_LEVEL` | `info` | Log level |

Environment variables take precedence over CLI flags.

## Capabilities

Capabilities control what the paired device is allowed to do. Pass them as a comma-separated list:

```bash
auths pair --capabilities sign_commit,sign_tag
```

Available capabilities:
- `sign_commit` - Sign Git commits
- `sign_tag` - Sign Git tags

## Troubleshooting

### "Short code not found"

**Cause**: The host hasn't initiated a session yet, the session expired (>5 minutes), or the code was entered incorrectly.

**Solution**: Make sure the host runs `auths pair` first, then enter the code on the joining device within 5 minutes.

### "Key not found" on the joining device

**Cause**: The joining device doesn't have an Auths identity initialized.

**Solution**:
```bash
auths init
auths key list   # Verify a key exists
```

### "No signing key found for identity"

**Cause**: The keychain has no key associated with the loaded identity's DID.

**Solution**:
```bash
# Check which keys exist
auths key list

# Re-initialize if needed
auths init --force
```

### Host and joiner can't connect

**Cause**: They're pointing at different registry servers.

**Solution**: Both must use the same `--registry` URL. For local testing, both should use `http://localhost:3000`.

### Session expired

**Cause**: More than 5 minutes passed between the host initiating and the joiner entering the code.

**Solution**: The host should run `auths pair` again to get a fresh code. Use `--expiry` to increase the window if needed (max 300s).

## Verifying a Paired Device

After pairing, verify the device attestation was created:

```bash
auths status
auths id show-devices
```

The paired device can now sign commits using the granted capabilities.

## See Also

- [Git Signing and Verification](../git-signing.md) - Set up commit signing with Auths
- [Replacing GPG with Auths](../replacing-gpg-with-auths.md) - Migration guide from GPG
