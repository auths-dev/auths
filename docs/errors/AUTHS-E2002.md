# AUTHS-E2002: Device Signature Verification Failed

The device's Ed25519 signature on the attestation did not verify. The device key in the attestation does not match the key that produced the signature.

## Resolution

1. Verify the device key matches the attestation:
   ```bash
   auths id show --alias <ALIAS>
   ```
2. If the device key has changed, request a new attestation from the issuer.

## Related

- `AUTHS-E2001` — Issuer signature verification failed
