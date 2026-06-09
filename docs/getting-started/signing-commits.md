# Signing Commits

Make a signed commit and verify the signature. If you ran `auths init --profile developer`, Git is already configured -- your next commit will be signed automatically.

## How signing works

When you run `git commit`, Git calls the program specified in `gpg.ssh.program`. Auths sets this to `auths-sign`, a standalone binary that:

1. Reads the commit payload from stdin
2. Looks up the signing key alias from `user.signingKey` (format: `auths:<alias>`)
3. Loads and decrypts the key from the platform keychain
4. Returns an SSH signature to Git

You never call `auths-sign` directly. Git handles the integration transparently.

## Make a signed commit

```bash
cd your-project
echo "hello auths" > hello.txt
git add hello.txt
git commit -m "My first signed commit"
```

You will be prompted for your passphrase. After entering it, Git records the SSH signature inside the commit object.

!!! tip
    On macOS, the keychain may remember your passphrase for a configurable period, so you will not be prompted every time.

## Verify the signature

```bash
auths verify HEAD
```

```
Commit abc1234 verified: signed by did:keri:EAbcd1234...
```

The `verify` command accepts a Git ref, a commit SHA, or a range:

```bash
# Verify a specific commit
auths verify abc1234

# Verify the last 5 commits
auths verify HEAD~5..HEAD

# JSON output for scripting
auths verify HEAD --json
```

### What verification checks

For a local commit, `auths verify` performs SSH signature verification against the `allowed_signers` file at `.auths/allowed_signers`. The signer's public key must be present in that file.

When an identity bundle is provided (common in CI), verification also checks the attestation chain -- the cryptographic proof that the signing device was authorized by the identity controller.

## Manual Git configuration

`auths init` sets all of this automatically. Use these commands only if you need to reconfigure manually or understand what was set:

```bash
# Tell Git to use SSH-format signatures
git config --global gpg.format ssh

# Tell Git to use auths-sign as the signing program
git config --global gpg.ssh.program auths-sign

# Set the signing key alias (must match your auths key alias)
git config --global user.signingKey "auths:main"

# Sign all commits by default
git config --global commit.gpgSign true
```

To configure for the current repository only, replace `--global` with `--local`.

## Verify a signed commit

Verification is KEL-native — no allowed-signers file to generate or sync. `auths verify` resolves the signer's key state from their key event log:

```bash
auths verify HEAD
```

See the [Verifying Commits](../guides/git/verifying-commits.md) guide for ranges, CI, and teammate verification.

## Troubleshooting

**"auths-sign: command not found"**

Ensure `~/.cargo/bin` is on your `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

**No passphrase prompt appears**

`auths-sign` reads passphrases from `/dev/tty`. Run Git from an interactive terminal, not from an IDE's embedded terminal that may not support TTY prompts.

**"Key not found"**

The alias in `user.signingKey` must match a key in your keychain. Check with:

```bash
auths key list
```

**Full diagnostic**

```bash
auths doctor
```

Every failed check prints an exact command to fix it.

## Next: Sharing Your Identity

Your commits are signed. Continue to [Sharing Your Identity](sharing-your-identity.md) to register on a public registry and make your identity discoverable.
