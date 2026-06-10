# Signing & Verifying Artifacts

Sign any file — a release tarball, a wheel, a binary — and let anyone verify who
signed it and that the bytes haven't changed.

## Sign a file

```bash
auths sign release.tar.gz
```

This writes a detached attestation next to the file: `release.tar.gz.auths.json`. It
contains the file's digest, your identity DID, and your signature — ship it alongside
the artifact.

Options:

```bash
auths sign release.tar.gz --sig-output sigs/release.json   # custom output path
auths sign release.tar.gz --note "v2.1.0 release build"    # embed a note
auths sign release.tar.gz --expires-in 31536000            # attestation expiry
```

## Verify a file

```bash
auths verify release.tar.gz          # finds release.tar.gz.auths.json automatically
auths verify path/to/sig.json        # or verify an attestation file directly
```

What's checked: the file digest matches the attestation, the signature is valid, and
the signer resolves to a trusted identity (yourself, a pinned identity, or a root in
`.auths/roots` — see [Verify & Trust Basics](../../getting-started/verify-and-trust.md)).

Exit codes: `0` verified · `1` verification failed · `2` could not attempt.

## Verifying as a third party

Consumers who have never seen your identity verify against an exported bundle:

```bash
# You publish alongside the release:
auths id export-bundle --alias main --output identity-bundle.json --max-age-secs 604800

# They verify statelessly — no local identity store needed:
auths verify release.tar.gz --identity-bundle identity-bundle.json
```

Or they pin you once (`auths trust pin --did <your-did> --bundle identity-bundle.json`)
and verify everything you ship from then on with no flags.

## Offline / air-gapped verification

For environments with no network and no `~/.auths`, the artifact tooling supports
fully offline verification against explicit trust roots:

```bash
auths artifact verify ./release.tar.gz --offline --roots .auths/roots
```

## CI: ephemeral signing

CI can sign artifacts without holding any long-lived secret — a throwaway key signs,
the commit signature anchors the trust chain, and the key is discarded:

```bash
auths artifact sign target/release/my-binary --ci --commit $GITHUB_SHA
```

The full pattern (verify gate → build → ephemeral sign → publish) is in
[CI/CD Integration](../platforms/ci-cd.md).

## Rotation and old signatures

Artifacts signed before a key rotation stay verifiable — verification resolves your
key state from the event log, not from a single static key.
