# CI/CD Integration: Ephemeral Artifact Signing

> Sigstore made artifact signing easy by making Linux Foundation infrastructure the trust root. Auths makes it sovereign by making the maintainer the trust root — your commit signature, rotated through KERI, anchors the whole chain. No CA, no OIDC dependency, no central transparency log required. Works offline, works air-gapped, works on your own CI.

See [how this compares to Sigstore](../../design/sigstore-comparison.md) for a detailed tradeoff analysis.

## How It Works

1. **You sign commits** with your device-bound Ed25519 key (hardware keychain, Touch ID). This happens automatically after `auths init`.
2. **CI verifies** the tagged commit is signed by a maintainer in `.auths/allowed_signers`.
3. **CI generates a throwaway key**, signs each artifact, and discards the key. No secrets needed.
4. **Consumers verify**: artifact hash → ephemeral signature → commit SHA → maintainer's commit signature.

Trust derives from your commit signature, not from a CI secret. The ephemeral key dies with the CI run.

## Setup

### Prerequisites

```bash
auths init          # creates your signing identity
auths git setup     # configures git to sign commits with your device key
```

### GitHub Actions

Add a verify gate and ephemeral signing to your release workflow:

```yaml
name: Release
on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: auths-dev/verify@v1

  build:
    needs: verify
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: cargo build --release

      - name: Sign artifact
        run: |
          auths artifact sign target/release/my-binary \
            --ci \
            --commit ${{ github.sha }}

      - name: Upload
        uses: actions/upload-artifact@v4
        with:
          path: |
            target/release/my-binary
            target/release/my-binary.auths.json
```

No `AUTHS_CI_TOKEN`. No secrets for signing. The `--ci` flag generates a throwaway key, signs, and discards it.

## Verification

```bash
# Clone the repo (needed for commit signature verification)
git clone https://github.com/owner/repo
cd repo

# Verify an artifact
auths artifact verify ./my-binary
```

The verify command:
1. Checks the artifact hash against the attestation
2. Verifies the ephemeral signature
3. Checks that the commit referenced in the attestation is signed by a trusted maintainer

## Security Model

See [Ephemeral Signing Threat Model](../../design/ephemeral-signing-threat-model.md) for the full analysis.

**What's protected:** If a CI runner is compromised, the attacker cannot forge the maintainer's commit signature. If they use a real signed commit SHA but build different code, the maintainer can detect unexpected attestations.

**What's not protected:** A fully compromised CI runner can build malicious artifacts from legitimate source. This is true of all CI-based signing (including Sigstore). Only reproducible builds can close this gap.
