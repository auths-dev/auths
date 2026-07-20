# AUTHS-E4203

**Crate:** `auths-id`

**Type:** `InitError::Key`

## Message

key operation failed: {0}

## Suggestion

Check keychain access and passphrase. Headless/CI (no Touch ID): set AUTHS_KEYCHAIN_BACKEND=file AUTHS_KEYCHAIN_FILE=<path> AUTHS_PASSPHRASE=<pass>, or run `auths init --profile ci`.
