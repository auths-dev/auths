# GitHub Actions

Automate release artifact signing and verification with GitHub Actions.

## Overview

| Workflow | Purpose |
|----------|---------|
| **Sign artifacts in a release job** | Maintainer signs artifacts as part of the release pipeline |
| **Verify downloads in CI** | Downstream projects verify artifacts before using them |

## Sign artifacts in a release job

### Prerequisites

| Secret | Purpose |
|--------|---------|
| `AUTHS_IDENTITY_REPO` | Base64-encoded `~/.auths` directory (contains identity and keys) |
| `AUTHS_PASSPHRASE` | Passphrase for the signing key |

!!! warning "CI environments have no platform keychain"
    Set `AUTHS_KEYCHAIN_BACKEND=file` so Auths uses the file-based keychain fallback instead of macOS Keychain / Linux Secret Service.

### Option A: Sign in the release job

Full workflow that builds, signs, and uploads artifacts:

```yaml
name: Release with Signed Artifacts
on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: stable

      - name: Install Auths CLI
        run: cargo install --path crates/auths-cli

      - name: Restore Auths identity
        run: |
          mkdir -p ~/.auths
          echo '${{ secrets.AUTHS_IDENTITY_REPO }}' | base64 -d | tar -xz -C ~/.auths

      - name: Build release binaries
        run: cargo build --release

      - name: Package tarball
        run: |
          tar -czf auths-linux-x86_64.tar.gz \
            -C target/release auths auths-sign auths-verify

      - name: Sign artifact
        env:
          AUTHS_KEYCHAIN_BACKEND: file
          AUTHS_PASSPHRASE: ${{ secrets.AUTHS_PASSPHRASE }}
        run: |
          auths artifact sign auths-linux-x86_64.tar.gz \
            --identity-key-alias main \
            --device-key-alias main

      - name: Verify signature
        env:
          AUTHS_KEYCHAIN_BACKEND: file
          AUTHS_PASSPHRASE: ${{ secrets.AUTHS_PASSPHRASE }}
        run: auths artifact verify auths-linux-x86_64.tar.gz

      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            auths-linux-x86_64.tar.gz
            auths-linux-x86_64.tar.gz.auths.json
          generate_release_notes: true
```

### Preparing the identity secret

On your local machine, archive and upload your identity:

```bash
# Archive ~/.auths as base64
tar -czf - -C ~/.auths . | base64 > /tmp/auths-identity.b64

# Add secrets to your repository
gh secret set AUTHS_IDENTITY_REPO < /tmp/auths-identity.b64
gh secret set AUTHS_PASSPHRASE

# Clean up
rm /tmp/auths-identity.b64
```

!!! note "Secret size limits"
    GitHub Actions secrets have a 48KB limit. A fresh `~/.auths` repo is typically under 10KB. If yours is larger (many attestations), use Option B instead.

### Option B: Sign locally, verify in CI

A simpler approach: sign artifacts on your local machine and use CI only for verification. This avoids storing identity secrets in GitHub.

```yaml
name: Verify Release Artifacts
on:
  release:
    types: [published]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Auths CLI
        run: cargo install --path crates/auths-cli

      - name: Download release assets
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download ${{ github.event.release.tag_name }} \
            --pattern "*.tar.gz" --pattern "*.auths.json"

      - name: Verify all artifacts
        run: |
          for tarball in *.tar.gz; do
            echo "Verifying $tarball..."
            auths artifact verify "$tarball" \
              --identity-bundle .auths/identity-bundle.json
          done
```

This requires an identity bundle committed to the repository (see [below](#identity-bundles-for-stateless-verification)).

## Verify downloads in downstream CI

Other projects can verify Auths artifacts they depend on:

```yaml
- name: Download and verify upstream artifact
  run: |
    gh release download v1.0.0 \
      --repo your-org/your-project \
      --pattern "your-artifact.tar.gz" \
      --pattern "your-artifact.tar.gz.auths.json"

    auths artifact verify your-artifact.tar.gz \
      --identity-bundle .auths/identity-bundle.json \
      --json
```

## Identity bundles for stateless verification

Identity bundles let CI verify signatures without `~/.auths`. The bundle contains only public data: the signer's DID, public key, and attestation chain.

### Creating the bundle

```bash
auths id export-bundle \
  --alias main \
  --output .auths/identity-bundle.json
```

### Storage options

| Method | Pros | Cons |
|--------|------|------|
| **Commit to repo** | Simple, version-controlled, always available | Must update on key rotation |
| GitHub Actions secret | Not publicly visible | 48KB limit, harder to update |
| Release asset | Ships with the release | Must download separately |

!!! tip "Recommended: commit to the repository"
    The identity bundle contains only public data (DID, public key, attestation chain). Committing it to `.auths/identity-bundle.json` is the simplest approach.

### Updating after key rotation

After rotating keys with `auths id rotate`, re-export the bundle:

```bash
auths id export-bundle --alias main --output .auths/identity-bundle.json
git add .auths/identity-bundle.json
git commit -m "Update identity bundle after key rotation"
git push
```

## Exit codes

Use exit codes for CI pass/fail decisions:

| Code | Meaning | CI action |
|------|---------|-----------|
| `0` | Valid signature, digest matches | Continue |
| `1` | Invalid signature or digest mismatch | Fail the build |
| `2` | Error (missing files, parse failure) | Fail the build |

## Troubleshooting

### "Key not found" in CI

CI environments don't have a platform keychain. Set the environment variable:

```bash
export AUTHS_KEYCHAIN_BACKEND=file
```

### "Failed to resolve public key from issuer DID"

The verifier is trying to resolve the DID from `~/.auths`, which doesn't exist in CI. Pass `--identity-bundle` for stateless verification.

### Secret too large for GitHub Actions

If the base64-encoded `~/.auths` exceeds 48KB, use Option B (sign locally, verify in CI) instead.

## Next steps

- [Signing Tarballs](signing-tarballs.md) -- manual signing workflow
- [Verification concepts](../../../concepts/verification.md) -- how chain verification works
