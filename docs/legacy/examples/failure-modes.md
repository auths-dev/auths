# Failure Modes

What happens when verification fails, and what to do about it.

## Expired attestation

```
Status: Expired
  Expired at: 2024-12-01T00:00:00Z
```

**Cause**: The attestation's `expires_at` timestamp is in the past.

**Fix**: Renew the attestation:

```bash
auths device extend \
  --identity-key-alias my-key \
  --device-did "$DEVICE_DID" \
  --expires-in-days 90
```

## Revoked attestation

```
Status: Revoked
```

**Cause**: The attestation was explicitly revoked with `auths device revoke`.

**Fix**: This is intentional. If the revocation was a mistake, link the device again:

```bash
auths device link \
  --identity-key-alias my-key \
  --device-key-alias device-key \
  --device-did "$DEVICE_DID" \
  --note "Re-linked after accidental revocation"
```

## Invalid signature

```
Status: InvalidSignature
  At step: 0
```

**Cause**: The attestation JSON was modified after signing, or the wrong public key was provided for verification.

**Possible causes**:

- Attestation JSON was edited (even whitespace changes break canonical signatures)
- Wrong issuer public key passed to the verifier
- Data corruption in transit

**Fix**: Re-export the attestation from Git storage. Ensure you're using the correct issuer public key.

## Broken chain

```
Status: BrokenChain
  Missing link: did:key:z6Mk...
```

**Cause**: The chain of attestations has a gap. The `subject` of one attestation doesn't match the `issuer` of the next.

**Fix**: Ensure all attestations in the chain are present and ordered correctly.

## Key not found

```
Error: AUTHS_KEY_NOT_FOUND
```

**Cause**: The referenced key alias doesn't exist in the keychain.

**Fix**:

```bash
auths key list                  # See available keys
auths key import --alias ...    # Import a key
```

## Wrong passphrase

```
Error: AUTHS_INCORRECT_PASSPHRASE
```

**Cause**: The passphrase entered doesn't match the one used to encrypt the key.

**Fix**: Try again with the correct passphrase. If forgotten, the key must be recreated.

## Keychain unavailable

```
Error: AUTHS_BACKEND_UNAVAILABLE
```

**Cause**: The platform keychain is not accessible (locked, missing, or unsupported).

**Fix by platform**:

| Platform | Action |
|----------|--------|
| macOS | Open Keychain Access, unlock the login keychain |
| Linux | Start the Secret Service daemon |
| CI/headless | Set `AUTHS_KEYCHAIN_BACKEND=file` |

## Clock skew

Attestations may be rejected if the system clock is more than 5 minutes off. The verifier uses a tolerance of `MAX_SKEW_SECS = 300`.

**Fix**: Sync your system clock with NTP.
