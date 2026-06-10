# Verify & Trust Basics

Everything you need to know about verification, on one screen.

## Verify a commit

```bash
auths verify HEAD          # or any ref, SHA, or range like main..HEAD
```

```
Commit d4e7393e... verified: signed by did:keri:EDxfiyav...
```

## Verify a file

```bash
auths sign release.tar.gz          # creates release.tar.gz.auths.json
auths verify release.tar.gz        # finds the .auths.json sidecar automatically
```

## Who do you trust?

A signature being mathematically valid is only half the answer — the verifier also
decides whether the *identity* behind it is trusted. Three sources, in plain terms:

1. **Yourself.** Your own identity is always trusted on your own machine. Everything
   you sign verifies with zero setup.
2. **The repo's trust file.** `.auths/roots` is a committed file listing trusted root
   identities, one per line. Your first signed commit adds your own root
   automatically; teammates inherit the file by cloning. Review changes to it like
   code — a new line is a trust grant.
3. **Anyone you pin.** `auths trust pin --did did:keri:E...` trusts an identity for
   all your local verifications (the key resolves from their event log or a shared
   bundle — you never handle raw key bytes).

A valid signature from an identity in none of these fails verification with
"root is not a pinned trusted root" — valid math, unknown signer.

## Exit codes (for scripts and CI)

| Code | Meaning |
|------|---------|
| `0` | Verified |
| `1` | Verification failed (bad signature, missing trailers, untrusted signer) |
| `2` | Could not attempt (I/O error, malformed input, missing repository) |

## When verification fails

- **"Commit carries no Auths-Id/Auths-Device trailer"** — the commit predates your
  auths setup, or this repo's own hook configuration bypasses the auths commit hook.
  Run `auths doctor` to check; backfill old commits with `auths sign <ref>` (rewrites
  the commit — don't do it to pushed history).
- **"Root … is not a pinned trusted root"** — you don't trust the signer yet. Pin
  them (`auths trust pin --did <did>`) or add their DID to the repo's `.auths/roots`.
- **"Signed by a superseded device key"** — the commit predates a key rotation. The
  verifier recognized the old key as legitimately rotated away (not a forgery); if
  policy requires green, re-sign history with `auths sign <ref>` (rewrites SHAs).
- Anything else: `auths doctor` diagnoses the common environment problems and prints
  a fix for each.

## Going deeper

- [Verifying Commits](../guides/git/verifying-commits.md) — ranges, history audits, CI gates, identity bundles
- [Trust Model](trust-model.md) — the cryptography behind the trust decisions
- [Team Workflows](../guides/git/team-workflows.md) — trust across a team
