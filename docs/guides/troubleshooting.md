# Troubleshooting

Start here when something fails. First command, always:

```bash
auths doctor
```

Doctor checks every prerequisite (git, ssh-keygen, keychain, identity, the commit
hook, registry reachability) and prints an exact fix per failure.
Exit codes: `0` all pass · `1` a critical check failed (Auths is non-functional) ·
`2` only advisory checks failed (functional, environment could be better).

## "My binary behaves differently from the docs"

Check the version first:

```bash
auths --version
```

A stale install is the most common cause of "the docs are wrong" reports. If you build
from source, remember the installed binary does not update itself:

```bash
cargo install --path crates/auths-cli
```

## Verification failures

### "Commit carries no Auths-Id/Auths-Device trailer"

The commit message lacks identity trailers. Causes, in order of likelihood:

1. **The commit predates your auths setup.** Backfill with `auths sign <ref>` — note
   it amends the commit (the SHA changes), so never rewrite pushed history without
   coordinating.
2. **The repo uses a hook manager** (husky, lefthook) that sets a local
   `core.hooksPath`, bypassing the global auths hook. `auths doctor` detects this
   ("Repo hook override") and explains how to chain the auths hook from the manager's
   hook directory.
3. **The hook was never installed** — re-run `auths init` (it reinstalls the hook
   idempotently).

### "Root ... is not a pinned trusted root"

The signature is valid but you don't trust the signer's root identity yet:

```bash
auths trust pin --did did:keri:E...            # key resolves from their event log
auths trust pin --did did:keri:E... --bundle their-bundle.json
```

or add their DID to the repo's committed `.auths/roots`. Your *own* commits never
need this — self-trust is built in.

### Exit code confusion in CI

`auths verify` exits `0` verified, `1` verification failed, `2` could-not-attempt
(I/O, malformed input, missing repo). Gate CI on non-zero generally; distinguish 1
vs 2 if you want "untrusted" and "broken pipeline" handled differently.

## Setup failures

### `AUTHS-E5008` — passphrase too weak

The passphrase (often the `AUTHS_PASSPHRASE` environment variable, named in the
error) fails the strength policy: at least 12 characters and 3 of 4 character classes
(lowercase, uppercase, digit, symbol). Set a stronger value and re-run. A failed init
leaves **no partial state** — re-running is always safe.

### "Keychain not accessible"

On Linux ensure a Secret Service provider is running, or use the encrypted-file
backend: `AUTHS_KEYCHAIN_BACKEND=file` (with `AUTHS_PASSPHRASE` set). On macOS, the
first signing operation may prompt for keychain access — choose "Always Allow".

### Identity exists but you want a clean slate

```bash
auths reset --force
```

removes `~/.auths` and the git signing configuration. See
[Reset & Uninstall](../getting-started/uninstall.md).

## Signing failures

### Passphrase prompts on every commit

Start the agent (`auths agent start`) — it holds the unlocked key and signs without
re-prompting. `auths agent status` shows whether it's running.

### "No signing keys found for identity"

The identity record exists but the keychain has no matching key — typically a
restored `~/.auths` without the corresponding keychain entries, or a deleted key.
`auths key list` shows what the keychain holds; `auths reset --force` and re-init is
the clean recovery if the key is gone.

## Pairing failures

See the troubleshooting section of [Multi-Device Setup](identity/multi-device.md) —
short-code expiry, LAN/mDNS discovery, and firewall issues are covered there.

## Still stuck?

- Every Auths error carries a stable code — `auths error show AUTHS-E1234` explains
  any of them, and the [error index](../errors/index.md) lists all.
- File an issue: <https://github.com/auths-dev/auths/issues>
