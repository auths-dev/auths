# Local Development

Set up Auths for everyday development on a single machine.

## Setup

```bash
# Install
cargo install --git https://github.com/bordumb/auths.git auths_cli

# Create identity
cat > ~/auths-meta.json << 'EOF'
{"name": "Your Name", "email": "you@example.com"}
EOF

auths id init-did --local-key-alias dev-key --metadata-file ~/auths-meta.json

# Configure Git
auths git setup
```

## Daily workflow

Commits are signed automatically:

```bash
git commit -m "add feature"
# Prompted for passphrase → signed with did:keri:E...
```

Verify any commit:

```bash
auths verify-commit HEAD
auths verify-commit abc1234
```

## Team setup

Share your public key with teammates:

```bash
# Generate allowed-signers entry
auths git allowed-signers
```

Add all team members' entries to a shared `.auths/allowed_signers` file in the project repo:

```bash
# In the project repo
git config gpg.ssh.allowedSignersFile .auths/allowed_signers
```

Now `git log --show-signature` verifies all team members' commits.

## Per-project vs. global signing

**Global** (all repos):

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:dev-key"
git config --global commit.gpgSign true
```

**Per-project** (one repo only):

```bash
cd my-project
git config --local gpg.format ssh
git config --local gpg.ssh.program auths-sign
git config --local user.signingKey "auths:dev-key"
git config --local commit.gpgSign true
```

This is useful when migrating from GPG gradually.
