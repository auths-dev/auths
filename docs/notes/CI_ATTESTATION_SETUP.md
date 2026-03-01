# CI Attestation Setup

This document explains how to complete the release attestation setup for automated `.auths.json` generation in CI.

## Current State

The release workflow (`.github/workflows/release.yml`) has been updated to:
- ✅ Build binaries for multiple platforms
- ✅ Trigger Homebrew formula updates via `repository_dispatch`
- ⚠️ **Placeholder** steps for attestation generation (needs configuration)

The Homebrew formula scripts have been updated to:
- ✅ Extract SHA256 from `.auths.json` attestations (if available)
- ✅ Fall back to legacy `.sha256` files (for backward compatibility)

## What Needs to Be Done

### 1. Create a Release Signing Identity

Create a dedicated identity for signing release artifacts:

```bash
# Create release signing identity
auths init

# Note the key alias (e.g., "release-identity")
auths status
```

### 2. Export Keys for CI

Export the encrypted keys for use in GitHub Actions:

```bash
# Export identity key
auths key export --alias release-identity --output identity.key

# Export device key
auths key export --alias release-device --output device.key

# Base64 encode for GitHub secrets
base64 -i identity.key > identity.key.b64
base64 -i device.key > device.key.b64
```

### 3. Configure GitHub Secrets

Add these secrets to your GitHub repository (`Settings` → `Secrets and variables` → `Actions`):

| Secret Name | Value | Description |
|-------------|-------|-------------|
| `AUTHS_RELEASE_IDENTITY_KEY` | Contents of `identity.key.b64` | Encrypted identity key |
| `AUTHS_RELEASE_DEVICE_KEY` | Contents of `device.key.b64` | Encrypted device key |
| `AUTHS_RELEASE_PASSPHRASE` | Your key passphrase | Passphrase to decrypt keys |
| `HOMEBREW_TAP_TOKEN` | GitHub PAT | Token with repo access to `homebrew-auths-cli` |

### 4. Complete the Release Workflow

Update `.github/workflows/release.yml` to replace the TODO sections with actual implementation:

#### 4a. Key Import (Unix)

Replace the "Setup auths identity for release signing (Unix)" step:

```yaml
- name: Setup auths identity for release signing (Unix)
  if: runner.os != 'Windows'
  env:
    AUTHS_IDENTITY_KEY: ${{ secrets.AUTHS_RELEASE_IDENTITY_KEY }}
    AUTHS_DEVICE_KEY: ${{ secrets.AUTHS_RELEASE_DEVICE_KEY }}
  run: |
    # Initialize auths repo
    mkdir -p ~/.auths
    git init --bare ~/.auths

    # Decode and import keys
    echo "$AUTHS_IDENTITY_KEY" | base64 -d > /tmp/identity.key
    echo "$AUTHS_DEVICE_KEY" | base64 -d > /tmp/device.key

    # Import into auths keychain
    auths key import --alias release-identity < /tmp/identity.key
    auths key import --alias release-device < /tmp/device.key

    # Clean up temporary files
    rm /tmp/identity.key /tmp/device.key
```

#### 4b. Artifact Signing (Unix)

Replace the "Sign artifact with auths attestation (Unix)" step:

```yaml
- name: Sign artifact with auths attestation (Unix)
  if: runner.os != 'Windows'
  env:
    AUTHS_PASSPHRASE: ${{ secrets.AUTHS_RELEASE_PASSPHRASE }}
  run: |
    # Sign artifact and generate .auths.json attestation
    echo "$AUTHS_PASSPHRASE" | auths artifact sign \
      ${{ matrix.asset_name }}${{ matrix.ext }} \
      --identity-key-alias release-identity \
      --device-key-alias release-device \
      --note "Official release build via GitHub Actions" \
      --expires-in-days 365
```

#### 4c. Windows Support

Implement similar steps for Windows (adjust paths and commands for PowerShell).

### 5. Test the Workflow

1. Create a test tag:
   ```bash
   git tag -a v0.0.1-rc.9 -m "Test release with attestations"
   git push origin v0.0.1-rc.9
   ```

2. Watch the GitHub Actions workflow run

3. Verify the release includes `.auths.json` files:
   ```bash
   curl -sL https://github.com/auths-dev/auths/releases/download/v0.0.1-rc.9/auths-macos-aarch64.tar.gz.auths.json | jq
   ```

4. Verify the Homebrew formula update was triggered:
   - Check `homebrew-auths-cli` repo for a new PR or commit

### 6. Verify End-to-End

1. Wait for Homebrew formula to update
2. Test installation:
   ```bash
   brew tap bordumb/auths-cli
   brew install auths
   auths --version
   ```

## Alternative: Local Signing

If CI signing is too complex, you can sign releases locally:

### Local Signing Workflow

1. Download release artifacts:
   ```bash
   gh release download v0.0.1-rc.9 --repo bordumb/auths
   ```

2. Sign each artifact:
   ```bash
   for file in auths-*.tar.gz; do
     auths artifact sign "$file" \
       --identity-key-alias my-key \
       --device-key-alias my-device \
       --note "Official release"
   done
   ```

3. Upload attestations to release:
   ```bash
   gh release upload v0.0.1-rc.9 *.auths.json --repo bordumb/auths
   ```

4. Manually trigger Homebrew update:
   ```bash
   cd ../homebrew-auths-cli
   ./update-formula.sh 0.0.1-rc.9
   git commit -am "Update formula to v0.0.1-rc.9"
   git push
   ```

## Security Considerations

- **Passphrase Storage**: GitHub Secrets are encrypted at rest and only decrypted during workflow execution
- **Key Rotation**: Rotate release signing keys periodically (e.g., annually)
- **Audit**: Monitor release workflow runs for unauthorized changes
- **Backup**: Keep offline backups of release signing keys in a secure location

## Next Steps

Choose one approach:

1. **Full CI Automation** (recommended for frequent releases)
   - Complete steps 1-6 above
   - Releases are fully automated

2. **Local Signing** (simpler, manual)
   - Use the alternative local signing workflow
   - More control, less automation

Once attestations are being generated, the Homebrew formula will automatically use them for integrity verification!
