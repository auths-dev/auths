# AUTHS-E5005: Device — Keychain Unavailable

The system keychain could not be accessed. This commonly happens in headless environments (CI, Docker, SSH sessions) where no GUI keychain daemon is running.

## Resolution

1. Switch to the file-based keychain backend:
   ```bash
   export AUTHS_KEYCHAIN_BACKEND=file
   export AUTHS_PASSPHRASE=<your-passphrase>
   ```
2. Or if on a desktop, ensure the keychain daemon is running:
   - macOS: Keychain Access should be available by default
   - Linux: Start the Secret Service daemon (`gnome-keyring-daemon` or `kwallet`)

## Related

- `AUTHS-E3014` — Backend unavailable
