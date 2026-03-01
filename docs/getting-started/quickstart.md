# Quickstart

Get up and running with Auths in under 60 seconds. By the end, you'll have a cryptographic identity and a signed Git commit.

## Prerequisites

- **Rust 1.70+** with Cargo ([install](https://rustup.rs/))
- **Git 2.34+** for SSH signature support

## 1. Install

```bash
cargo install --git https://github.com/bordumb/auths.git auths_cli
```

## 2. Set up everything

```bash
auths init --profile developer
```

That's one command. It handles all of this for you:

- Creates your cryptographic identity in your platform keychain
- Links your current device
- Configures Git to sign commits automatically
- Verifies the signing pipeline with a test commit

You'll be prompted once for a passphrase to protect your key.

!!! warning "Remember your passphrase"
    There's no recovery mechanism. Write it down or use a password manager.

## 3. Sign a commit

```bash
cd your-project
echo "test" > test.txt
git add test.txt
git commit -m "My first signed commit"
```

Git calls `auths-sign` automatically. No extra flags needed.

## 4. Verify the signature

```bash
auths verify-commit HEAD
```

```
Commit abc1234 is valid
  Signed by: did:keri:E...
  Device: did:key:z6Mk...
  Status: VALID
```

If you see `Status: VALID`, you're done.

## Something not working?

```bash
auths doctor
```

Every failed check prints an exact command to fix it.

## Next steps

- [First Success](first-success.md) — confirm everything is working
- [Link a second device](../cli/workflows/multi-device/index.md) — use the same identity on another machine
- [CI setup](../cloud-ci/github-actions-oidc.md) — sign commits in GitHub Actions
