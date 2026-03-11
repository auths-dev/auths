# AUTHS-E2016: Signature Invalid

The Ed25519 signature on the commit did not verify against the signed data. The commit may have been modified after signing, or the wrong key was used.

## Resolution

1. Check that the commit hasn't been amended or rebased since signing.
2. Re-sign the commit:
   ```bash
   git commit --amend -S --no-edit
   ```

## Related

- `AUTHS-E2010` — Unsigned commit
- `AUTHS-E2017` — Unknown signer
