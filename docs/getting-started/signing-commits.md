# Signing Commits

Make a signed commit and verify the signature. If you ran `auths init --profile developer`, Git is already configured -- your next commit will be signed automatically.

## How signing works

`auths init` wires two pieces into Git; together they make a plain `git commit` fully verifiable:

1. **The signature** -- Git calls the program specified in `gpg.ssh.program`. Auths sets this to `auths-sign`, a standalone binary that reads the commit payload from stdin, looks up the signing key alias from `user.signingKey` (format: `auths:<alias>`), loads the key from the platform keychain, and returns an SSH signature to Git.
2. **The identity trailers** -- Git runs the `prepare-commit-msg` hook init installed (via the global `core.hooksPath`, under `~/.auths/githooks/`). The hook appends the `Auths-Id` and `Auths-Device` trailers to the commit message -- the in-band pointers `auths verify` replays your key event log from. On your first commit in a repo it also pins your identity root into the repo's committed `.auths/roots`, the trust declaration teammates and CI inherit.

You never call `auths-sign` or the hook directly. Git handles both transparently.

!!! note
    Repositories that set their own `core.hooksPath` (hook managers like husky do this) bypass the auths hook, so commits there won't carry trailers. `auths doctor` detects this and explains how to chain the hook. Commits made before the hook existed can be backfilled with `auths sign <ref>` -- note that it amends, so the commit SHA changes.

!!! note "Key rotation and old commits"
    After `auths id rotate`, commits signed with the previous key verify as
    `SignedBySupersededKey` -- recognized legacy history, never confused with a
    forgery. Attestations and signed artifacts are unaffected. Details in
    [Key Rotation](../guides/identity/key-rotation.md).

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

Verification is KEL-native. `auths verify` reads the commit's `Auths-Id` and `Auths-Device` trailers, replays the signing device's key event log, confirms the device is delegated by the root identity in the repo's pinned trust roots (`.auths/roots`), and checks the signature against the device's current key. There is no allowed-signers file.

When an identity bundle is provided (common in CI), verification runs statelessly from the bundle -- the same KEL replay, without needing local identity storage.

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
