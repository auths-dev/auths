# Plan: Automate `.auths.json` Placement via GitHub Actions

## Context

Currently, when the `auths` CLI creates a release with signed artifacts, the `.auths.json` attestation files are only attached as release assets. However, the `@auths-dev/verify` widget needs these files to be **committed to the repository tree** so they can be accessed via the GitHub Contents API (which has CORS headers). Release asset downloads redirect to a CDN without CORS, causing the browser-based verifier to fail with `net::ERR_FAILED`.

## Problem

1. Users manually must (or forget to) place attestation files in the repo
2. Attestation files are not auditable in git history
3. The verifier can only work if `.auths.json` files are committed to the tree
4. Not scalable — creates friction for each release

## Solution

Automate via GitHub Actions:
1. On release creation (or as part of the release workflow), the CI job that signs artifacts also commits the `.auths.json` files to the repo
2. Place them in a standard location: `.auths/releases/{artifact-name}.auths.json`
3. Commit atomically with the release
4. No manual intervention needed

## Implementation

### Workflow Structure

**Trigger:** On release publish or as part of the release build pipeline

**Steps:**
1. Build and sign artifacts (existing `auths` CLI workflow)
2. For each artifact, the CLI outputs `{artifact-name}.auths.json`
3. Create/update `.auths/releases/` directory structure
4. Place each `.auths.json` in `.auths/releases/{artifact-name}.auths.json`
5. Commit to a release branch or directly to main
6. Push (or create a PR)
7. Create/update the release with the artifacts as assets

### GitHub Action Pseudocode

```yaml
name: Release with Auths Attestation

on:
  workflow_dispatch:  # Manual trigger
    inputs:
      version:
        description: 'Release version (e.g., v0.0.2)'
        required: true

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build and sign artifacts
        run: |
          # Build all release artifacts
          cargo build --release --target x86_64-unknown-linux-gnu
          cargo build --release --target aarch64-unknown-linux-gnu
          cargo build --release --target x86_64-apple-darwin
          cargo build --release --target aarch64-apple-darwin

          # Sign each with auths
          for artifact in dist/auths-*; do
            auths sign "$artifact" --output "${artifact}.auths.json"
          done

      - name: Commit attestations to repo
        run: |
          mkdir -p .auths/releases
          cp dist/*.auths.json .auths/releases/

          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .auths/releases/
          git commit -m "chore: add auths attestations for ${{ github.event.inputs.version }}"
          git push origin main

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          tag_name: ${{ github.event.inputs.version }}
          files: dist/auths-*
          draft: false
```

## What Needs to Change

### Files to Create/Modify:

1. **`.github/workflows/release-with-auths.yml`** (new)
   - GitHub Action that builds, signs, commits attestations, and creates release
   - Triggered manually or on tag push

2. **`.auths/releases/`** (new directory)
   - Holds all attestation files for all releases
   - Directory structure: `.auths/releases/{artifact-name}.auths.json`

3. **`.auths/.gitkeep`** (new, if needed)
   - Ensures `.auths/` directory is tracked

### Optional:

4. **`.auths/identity.json`** (future)
   - Identity metadata (issuer DID, etc.) for the repository

## Expected Outcome

After implementation:
1. Every release automatically has attestation files in `.auths/releases/`
2. The `@auths-dev/verify` widget can fetch via Contents API: `GET /repos/auths-dev/auths/contents/.auths/releases/{asset-name}.auths.json`
3. Attestations are auditable in git history
4. Users can verify any release by pointing the widget at the repo (no manual file placement needed)

## Verification

1. Create a test release via the GitHub Actions workflow
2. Confirm `.auths/releases/` files appear in the commit history
3. Verify the `@auths-dev/verify` widget can load and verify the attestation
4. Confirm the file is visible in GitHub UI under `.auths/releases/`

## Future Enhancements

- Add `.auths/identity.json` to declare the signing identity (issuer DID)
- Create a `.auths/releases/index.json` manifest listing all attestations
- Support signed identity proofs (tier 2 identity infrastructure)
