# AUTHS-E3015: Backend Unavailable

The keychain backend is not available on this platform or configuration.

## Resolution

1. Run diagnostics:
   ```bash
   auths doctor
   ```
2. If running headless (CI/Docker), switch to the file backend:
   ```bash
   export AUTHS_KEYCHAIN_BACKEND=file
   export AUTHS_PASSPHRASE=<your-passphrase>
   ```

## Related

- `AUTHS-E3017` — Backend init failed
- `AUTHS-E3016` — Storage locked
