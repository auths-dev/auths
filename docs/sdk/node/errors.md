# Errors

All errors thrown by the Node SDK inherit from `AuthsError` and carry a machine-readable `code` and human-readable `message`.

## Error hierarchy

```text
AuthsError
├── VerificationError    — attestation or chain verification failures
├── CryptoError          — key or signing failures
├── KeychainError        — platform keychain inaccessible or locked
├── StorageError         — Git registry or storage failures
├── NetworkError         — witness or server communication failures
├── IdentityError        — identity or device operation failures
├── OrgError             — organization operation failures
└── PairingError         — device pairing failures or timeouts
```

## Catching errors

All SDK errors extend `AuthsError`, so a single catch handles everything:

```typescript
import { AuthsError } from '@auths-dev/sdk'

try {
  auths.signAs({ message: data, identityDid: did })
} catch (e) {
  if (e instanceof AuthsError) {
    console.log(e.code, e.message)
  }
}
```

For finer control, catch specific subclasses:

```typescript
import { CryptoError, KeychainError, NetworkError } from '@auths-dev/sdk'

try {
  auths.signAs({ message: data, identityDid: did })
} catch (e) {
  if (e instanceof KeychainError) {
    // Keychain locked — prompt user or switch to file backend
    console.log('Set AUTHS_KEYCHAIN_BACKEND=file for headless use')
  } else if (e instanceof CryptoError) {
    // Key not found, signing failed, etc.
    console.log(`Crypto error (${e.code}): ${e.message}`)
  }
}
```

## Error codes

### VerificationError

| Code | Description |
|------|-------------|
| `invalid_signature` | Attestation signature does not match the issuer key |
| `expired_attestation` | Attestation has passed its expiry date |
| `revoked_device` | Device has been revoked |
| `missing_capability` | Attestation does not grant the required capability |
| `future_timestamp` | Attestation timestamp is in the future |

### CryptoError

| Code | Description |
|------|-------------|
| `invalid_key` | Public or private key is malformed |
| `key_not_found` | No key found for the given identity or alias |
| `signing_failed` | Signing operation failed (e.g. incorrect passphrase) |

### KeychainError

| Code | Description |
|------|-------------|
| `keychain_locked` | Platform keychain is locked or unavailable |

### StorageError

| Code | Description |
|------|-------------|
| `repo_not_found` | Auths registry not found at the configured path |
| `trust_error` | Trust store operation failed |
| `witness_error` | Witness node operation failed |

### NetworkError

| Code | Description |
|------|-------------|
| `server_error` | Server communication failed |

`NetworkError` has a `shouldRetry` property (defaults to `true`) indicating whether the operation is safe to retry.

### IdentityError

| Code | Description |
|------|-------------|
| `identity_not_found` | Identity DID not found in registry |
| `unknown` | Unclassified identity or device error |

### OrgError

| Code | Description |
|------|-------------|
| `org_error` | Organization operation failed |

### PairingError

| Code | Description |
|------|-------------|
| `pairing_error` | Pairing operation failed |
| `timeout` | Pairing session timed out |

`PairingError` has a `shouldRetry` property (defaults to `true`) indicating whether the operation is safe to retry.
