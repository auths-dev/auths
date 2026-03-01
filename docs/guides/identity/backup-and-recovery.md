# Backup & Recovery

Your Auths identity consists of two things: encrypted private keys in the platform keychain, and the identity repository at `~/.auths` (a Git repo). Losing either one requires a recovery procedure.

## What to back up

| Component | Location | Contains |
|-----------|----------|----------|
| **Platform keychain** | macOS Keychain, Linux Secret Service, Windows Credential Manager, or `~/.auths/keys.enc` (file backend) | Encrypted Ed25519 private keys, key aliases, associated DIDs |
| **Identity repository** | `~/.auths` | Key Event Log (KEL), device attestations, identity metadata -- all stored as Git refs |

!!! warning "Never store raw private keys in plaintext"
    Keys in the Auths keychain are always encrypted with a passphrase before storage. The passphrase is the ultimate secret -- without it, the encrypted key material is useless.

## Exporting keys

### List stored keys

```bash
auths key list
```

Output includes the backend name and all stored aliases:

```
Using keychain backend: macOS Keychain
Stored keys:
- my-key
- my-key--next-0
```

### Export in OpenSSH format

Export the private key as an OpenSSH PEM:

```bash
auths key export --alias my-key --passphrase "<your-passphrase>" --format pem
```

Export the public key only:

```bash
auths key export --alias my-key --passphrase "<your-passphrase>" --format pub
```

### Export raw encrypted bytes

```bash
auths key export --alias my-key --passphrase "<your-passphrase>" --format enc
```

This outputs the hex-encoded encrypted key material. The output can be stored as a backup and later re-imported.

### Copy keys to a file-based keychain

For creating portable backups or provisioning headless CI environments:

```bash
auths key copy-backend \
  --alias my-key \
  --dst-backend file \
  --dst-file /path/to/backup-keychain.enc \
  --dst-passphrase "$BACKUP_PASSPHRASE"
```

The encrypted key bytes are transferred as-is -- no re-encryption occurs. The same passphrase used when the key was originally stored must be used when loading it from the destination.

!!! tip "Use `AUTHS_PASSPHRASE` for scripted backups"
    If `--dst-passphrase` is omitted, the command reads from the `AUTHS_PASSPHRASE` environment variable.

## Backing up the identity repository

The `~/.auths` directory is a standard Git repository. Back it up with any Git-compatible method:

```bash
# Clone to a backup location
git clone ~/.auths /path/to/backup/auths-identity

# Or create a bundle
cd ~/.auths && git bundle create ~/auths-backup.bundle --all
```

The repository contains:

- `refs/auths/registry` -- packed identity data and device attestations
- `refs/keri/kel` -- the Key Event Log
- `freeze.json` -- freeze state (if active)

## Recovery strategies

### Scenario 1: Lost device, identity key still available on another device

If you have another device linked to the same identity:

1. Revoke the lost device from your remaining device:

    ```bash
    auths device revoke \
      --device-did "did:key:z6Mk..." \
      --identity-key-alias my-key \
      --note "Device lost"
    ```

2. Delete the lost device's local keys (if they were also stored on this device):

    ```bash
    auths key delete --alias lost-device-key
    ```

3. Verify the revocation took effect:

    ```bash
    auths device list --include-revoked
    ```

### Scenario 2: Lost device, no other devices linked

If the lost device was your only device but you have a backup of the keychain and identity repository:

1. Restore the identity repository:

    ```bash
    git clone /path/to/backup/auths-identity ~/.auths
    ```

2. Import the backed-up key:

    ```bash
    auths key import \
      --alias my-key \
      --seed-file /path/to/backup/seed \
      --controller-did "did:keri:E..."
    ```

    Or, if you used `copy-backend` to create a file-based keychain backup, set the environment to use it:

    ```bash
    export AUTHS_KEYCHAIN_BACKEND=file
    export AUTHS_KEYCHAIN_FILE=/path/to/backup-keychain.enc
    export AUTHS_PASSPHRASE="$BACKUP_PASSPHRASE"
    ```

3. Verify the identity loads:

    ```bash
    auths id show
    auths status
    ```

### Scenario 3: Suspected key compromise

Use the emergency response flow:

```bash
auths emergency
```

This interactive wizard walks you through:

- **Device lost or stolen** -- revoke the compromised device
- **Key may have been exposed** -- force immediate key rotation
- **Freeze everything** -- temporarily disable all signing operations

Or use the subcommands directly:

```bash
# Freeze signing for 24 hours while you investigate
auths emergency freeze --duration 24h

# Rotate keys immediately
auths emergency rotate-now \
  --current-alias my-key \
  --next-alias my-key-v2 \
  --reason "Key exposure"

# Unfreeze when ready
auths emergency unfreeze
```

### Scenario 4: Passphrase forgotten

!!! warning "There is no passphrase recovery mechanism"
    Auths uses Argon2id key derivation and XChaCha20-Poly1305 encryption. If you forget the passphrase, the encrypted key material cannot be decrypted. This is by design.

If you still have access to a linked device, you can:

1. Create a new identity: `auths init --force`
2. Re-link your devices to the new identity

If this was your only device and you have no backup, the identity is irrecoverable. You will need to create a fresh identity.

## Freezing operations

The freeze mechanism temporarily disables all signing operations for your identity. This is useful during incident response when you need time to investigate before taking permanent action.

```bash
# Freeze for 24 hours
auths emergency freeze --duration 24h

# Freeze for 7 days
auths emergency freeze --duration 7d

# Unfreeze early
auths emergency unfreeze
```

While frozen, `auths-sign` refuses to produce signatures. The freeze state is stored in `~/.auths/freeze.json` and automatically expires after the specified duration.

## Generating an incident report

For post-incident analysis:

```bash
auths emergency report
```

This generates a summary of:

- Identity DID
- All devices (active, revoked, expired)
- Recent attestation events
- Actionable recommendations

Export to a file:

```bash
auths emergency report --file incident-report.json --events 200
```

## Recommended backup practice

1. After running `auths init`, immediately back up your key using `auths key copy-backend` to a separate encrypted file
2. Store the backup file and its passphrase in separate secure locations (e.g., password manager for passphrase, encrypted USB drive for the key file)
3. Periodically verify your backup by restoring to a test environment
4. After each key rotation, create a new backup of the rotated key
