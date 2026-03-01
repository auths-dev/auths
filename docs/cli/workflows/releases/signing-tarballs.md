# Signing Tarballs

Sign release tarballs with `auths artifact sign` and publish them alongside your GitHub releases.

## Prerequisites

!!! note "Already have an identity?"
    If `auths id show` works, skip to [step 1](#1-build-release-binaries). If not, follow the [Single Device](../single-device.md) workflow first.

| Requirement | Check | Setup |
|-------------|-------|-------|
| Auths identity | `auths id show` | `auths init` or [Single Device](../single-device.md) |
| Key alias | `auths key list` | Created during `auths init` |
| GitHub CLI | `gh --version` | `brew install gh` or [cli.github.com](https://cli.github.com/) |

## 1. Build release binaries

```bash
cargo build --release
```

## 2. Package the tarball

```bash
tar -czf auths-aarch64-apple-darwin.tar.gz \
  -C target/release auths auths-sign auths-verify
```

!!! tip "Naming convention"
    Use `<project>-<arch>-<os>.tar.gz` to match common release conventions. Adjust the architecture and OS to match your build machine.

## 3. Sign the tarball

```bash
auths artifact sign auths-aarch64-apple-darwin.tar.gz \
  --identity-key-alias main \
  --device-key-alias main
```

You'll be prompted for your passphrase. On success:

```
Signed "auths-aarch64-apple-darwin.tar.gz" -> "auths-aarch64-apple-darwin.tar.gz.auths.json"
  RID:    .auths
  Digest: sha256:5fdd356e...
  Issuer: did:keri:EU4Zp5...
```

This creates `auths-aarch64-apple-darwin.tar.gz.auths.json` alongside the tarball.

### What's in the signature file

The `.auths.json` file is a standard Auths [attestation](../../../concepts/attestations.md):

| Field | Value |
|-------|-------|
| `rid` | `sha256:<hex>` -- content-addressed identifier |
| `capabilities` | `["sign_release"]` |
| `payload` | Artifact metadata (type, digest, name, size) |
| `identity_signature` | Ed25519 signature from your identity key |
| `device_signature` | Ed25519 signature from your device key |

### Optional flags

| Flag | Description |
|------|-------------|
| `--sig-output <PATH>` | Custom output path (default: `<file>.auths.json`) |
| `--expires-in-days <N>` | Signature expiration (e.g., `365` for one year) |
| `--note <TEXT>` | Embed a note (e.g., `"Official release v1.0.0"`) |

## 4. Verify before publishing

!!! warning "Always verify locally before uploading"
    Catch signing errors before they reach users.

```bash
auths artifact verify auths-aarch64-apple-darwin.tar.gz
```

For JSON output:

```bash
auths artifact verify auths-aarch64-apple-darwin.tar.gz --json
```

## 5. Upload to GitHub Release

```bash
# Create the release
gh release create v1.0.0 \
  --title "v1.0.0" \
  --notes "Release with signed artifacts" \
  --prerelease

# Upload tarball and signature
gh release upload v1.0.0 \
  auths-aarch64-apple-darwin.tar.gz \
  auths-aarch64-apple-darwin.tar.gz.auths.json
```

Verify the release page:

```bash
gh release view v1.0.0
```

You should see both the `.tar.gz` and the `.auths.json` listed as assets.

## 6. How end-users verify downloads

After downloading both the tarball and its `.auths.json` from the release page:

### With local identity

If the user has the signer's identity in their `~/.auths`:

```bash
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json
```

### Stateless verification (no ~/.auths needed)

For users who don't have the signer's identity locally, provide an identity bundle:

```bash
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json \
  --identity-bundle identity-bundle.json
```

### JSON output for scripting

```bash
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json \
  --json
```

Exit codes: `0` = valid, `1` = invalid, `2` = error.

## 7. Export an identity bundle

An identity bundle is a portable JSON file containing the signer's public key and attestation chain. It enables stateless verification without `~/.auths`.

```bash
auths id export-bundle \
  --alias main \
  --output identity-bundle.json
```

The bundle contains only public data and is safe to publish.

### Where to store the bundle

| Option | When to use |
|--------|-------------|
| Committed to repo (e.g., `.auths/identity-bundle.json`) | Open source projects, public verification |
| GitHub Release asset | Ship alongside each release |
| GitHub Actions secret | CI-only verification (see [GitHub Actions](github-actions.md)) |

## Signing multiple artifacts

Sign each artifact in a loop. The signature file is always `<file>.auths.json`:

```bash
for artifact in auths-linux-x86_64.tar.gz auths-macos-aarch64.tar.gz auths-windows-x86_64.zip; do
  [ -f "$artifact" ] || continue
  echo "Signing $artifact..."
  auths artifact sign "$artifact" \
    --identity-key-alias main \
    --device-key-alias main \
    --expires-in-days 365
done
```

Then upload all signatures:

```bash
gh release upload v1.0.0 *.auths.json
```

## Troubleshooting

### "Failed to load identity"

Run `auths init` first. See the [Single Device](../single-device.md) workflow.

### "Failed to load device key 'main'"

Your key alias doesn't match. Check with `auths key list` and use the correct alias for `--identity-key-alias` and `--device-key-alias`.

### "unrecognized subcommand 'artifact'"

Your `auths` binary is outdated. Reinstall:

```bash
cargo install --path crates/auths-cli
```

## Next steps

- [GitHub Actions](github-actions.md) -- automate signing and verification in CI/CD
- [Verification concepts](../../../concepts/verification.md) -- how chain verification works
