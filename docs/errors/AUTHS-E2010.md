# AUTHS-E2010: Unsigned Commit

The commit does not contain any signature. Auths requires commits to be signed with an SSH key.

## Resolution

1. Configure Git for SSH signing:
   ```bash
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   ```
2. Sign commits with:
   ```bash
   git commit -S -m "your message"
   ```
3. Or enable automatic signing:
   ```bash
   git config commit.gpgsign true
   ```

## Related

- `AUTHS-E2011` — GPG signatures not supported
- `AUTHS-E2017` — Unknown signer
