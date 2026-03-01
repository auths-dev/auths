# Troubleshooting

Common issues and solutions when using the Auths CLI.

## "auths-sign: command not found"

`auths-sign` is not in your `PATH`.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add this to your shell profile (`~/.zshrc`, `~/.bashrc`) for persistence.

## "Key not found"

The key alias referenced in a command doesn't exist in the keychain. See [Key Management](../../concepts/identity/index.md) for how keys and aliases work.

```bash
# List available keys
auths key list

# Check your Git signing key config
git config user.signingKey
# Should be "auths:<alias>" where <alias> matches a key in the list
```

## No passphrase prompt

Auths reads passphrases from `/dev/tty`, which requires an interactive terminal.

**Won't work in:**

- Piped commands
- Some IDE terminals
- Non-interactive CI (use `AUTHS_PASSPHRASE` or `--passphrase` instead)

**Fix:** Run Git from a standard terminal emulator.

## Wrong passphrase

```
Error: AUTHS_INCORRECT_PASSPHRASE
```

Re-enter the correct passphrase. There's no recovery mechanism -- if you've forgotten the passphrase, you'll need to delete the key and create a new one. See [Key Rotation](../../concepts/key-rotation.md) for how to recover by rotating to a new key.

## Keychain not accessible

```
Error: AUTHS_BACKEND_UNAVAILABLE
```

| Platform | Check |
|----------|-------|
| macOS | Open Keychain Access, ensure the login keychain is unlocked |
| Linux | Verify the Secret Service daemon is running (`dbus-send --session --dest=org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Introspectable.Introspect`) |
| CI/headless | Set `AUTHS_KEYCHAIN_BACKEND=file` for encrypted file storage |

## Git layout mismatch

If you're using a custom layout (e.g., Radicle) and seeing "identity not found" errors, ensure you're passing the correct layout flags. See [Git Layouts](../../concepts/git-layouts.md) for how Auths stores data in Git refs and how custom layouts work.

```bash
auths id show \
  --repo <PATH> \
  --identity-ref <REF> \
  --identity-blob <FILENAME> \
  --attestation-prefix <PREFIX> \
  --attestation-blob <FILENAME>
```

See [Git Layouts](../../concepts/git-layouts.md) for details.

## Device link fails

Common causes:

- **Wrong passphrases**: `device link` prompts three times (device, identity, device). Ensure you're entering the right passphrase at each prompt.
- **Wrong device DID**: The `--device-did` must match the key imported with `--device-key-alias`. Derive it with `auths util derive-did`.
- **Expired identity key**: If key rotation occurred, use the current key alias.

## Attestation verification fails

```
Error: AUTHS_VERIFICATION_ERROR
```

- **Expired**: Check `expires_at` in the attestation
- **Revoked**: The attestation has been explicitly revoked
- **Wrong issuer key**: The public key provided doesn't match the attestation's issuer
- **Tampered data**: The attestation JSON has been modified after signing

See [Attestations](../../concepts/attestations.md) for how dual-signing works, and [Verification](../../concepts/verification.md) for the full list of statuses.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (see stderr for details) |

For structured errors, use `--output json`. See [Error Codes](../../reference/exit-codes.md) for the full list.
