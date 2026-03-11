# AUTHS-E2003: Attestation Expired

The attestation's `expires_at` timestamp is in the past. Expired attestations are no longer valid for verification.

## Resolution

Request a new attestation from the issuer:
```bash
auths id attest --alias <ALIAS>
```

## Related

- `AUTHS-E2005` — Timestamp in the future (clock skew)
