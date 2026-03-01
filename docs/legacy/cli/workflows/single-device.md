# Single Device Workflow

The simplest Auths setup: one identity, one device, signed commits.

## 1. Initialize your identity

Create a metadata file:

```bash
cat > ~/auths-meta.json << 'EOF'
{
  "name": "Your Name",
  "email": "you@example.com"
}
EOF
```

Initialize:

```bash
auths id init-did \
  --local-key-alias my-key \
  --metadata-file ~/auths-meta.json
```

Enter a passphrase when prompted. This:

- Creates `~/.auths` as a bare Git repository
- Generates an Ed25519 keypair
- Stores the key in your platform keychain under alias `my-key`
- Creates the identity commit at `refs/auths/identity`
- Derives your `did:keri:E...` controller DID

## 2. Verify setup

```bash
auths id show
```

```
Controller DID: did:keri:E...
Metadata:
  name: Your Name
  email: you@example.com
```

```bash
auths key list
```

```
- my-key
```

## 3. Configure Git

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:my-key"
git config --global commit.gpgSign true
```

## 4. Sign commits

```bash
git commit -m "signed commit"
```

You'll be prompted for your passphrase. The commit is signed with your Auths identity.

## 5. Verify

```bash
auths verify-commit HEAD
```

## 6. Generate allowed-signers (for team verification)

```bash
auths git allowed-signers >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

This lets `git log --show-signature` verify your commits.

## Key management

```bash
# Export your public key
auths key export --alias my-key --format pub

# View key details
auths id show --show-pk-bytes
```

## When to move to multi-device

Consider [multi-device setup](multi-device/index.md) when:

- You work from more than one machine
- You want a backup key on another device
- You need to sign from CI
