# AUTHS-E2001: Issuer Signature Verification Failed

The issuer's Ed25519 signature on the attestation did not verify against the signed payload. This means the attestation data was either tampered with or signed by a different key than claimed.

## Resolution

1. Verify the attestation was signed with the correct issuer key:
   ```bash
   auths id show --alias <ALIAS>
   ```
2. Re-issue the attestation if the issuer key has rotated.
3. If the identity has been compromised, rotate keys immediately:
   ```bash
   auths id rotate --alias <ALIAS>
   ```

## Related

- `AUTHS-E2002` — Device signature verification failed
- `AUTHS-E2003` — Attestation expired
