# First Success

Run one command to confirm everything is working:

```bash
auths doctor
```

Every check prints a pass or fail. Failed checks print the exact command to fix them. Exit code 0 means you're good.

---

If you'd rather check manually, here's what a healthy setup looks like:

## You have an identity

```bash
auths id show
```

```
Controller DID: did:keri:E...
Metadata:
  name: ...
  email: ...
Key Alias: ...
```

!!! failure "If this fails"
    Run: `auths init --profile developer`

## Git signing is configured

```bash
auths doctor
```

Look for `[✓] Git signing config: All 5 signing configs present`.

!!! failure "If this fails"
    `auths doctor` prints the exact `git config` commands to run.

## You can sign a commit

`auths init --profile developer` already ran a test commit during setup (Step 6/6). If that passed, you're ready.

To test again manually:

```bash
cd $(mktemp -d)
git init && git config user.email "test@test.com" && git config user.name "Test"
echo "test" > test.txt
git add test.txt
git commit -S -m "test commit"
```

!!! failure "If this fails"
    - `auths-sign: command not found` — add `~/.cargo/bin` to your `PATH`
    - `Key not found` — run `auths key list` and check your `user.signingKey` alias
    - No passphrase prompt — run from an interactive terminal

## You can verify a signature

```bash
auths verify-commit HEAD
```

```
Commit ... is valid
  Signed by: did:keri:E...
  Device: did:key:z6Mk...
  Status: VALID
```

## You're ready

Next: [Link another device](../cli/workflows/multi-device/index.md) or learn the [mental model](../concepts/mental-model.md).
