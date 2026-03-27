# CI/CD Integration

Sign release artifacts and verify commit signatures in CI pipelines. Auths uses a limited-capability device key model so your root identity never leaves your machine.

## Concepts

CI signing in Auths works through device delegation:

1. You create a **CI device key** on your local machine.
2. You **link** that device to your identity with restricted capabilities (e.g., `sign_release` only).
3. The device key and a snapshot of your identity repository are packaged as GitHub Secrets.
4. In CI, the runner restores the identity bundle and signs artifacts using the CI device key.
5. You can **revoke** the CI device at any time without affecting your root identity.

## One-time setup with `cargo xt ci-setup`

The `ci-setup` xtask automates the entire provisioning flow. Run it from the project root:

```bash
cargo xt ci-setup
```

This command will:

1. **Verify your identity exists** by running `auths status`.
2. **Read your identity DID** from `auths id show` and your key alias from `auths key list`.
3. **Generate a CI device key** (Ed25519, 32-byte seed) and import it into your platform keychain under the alias `ci-release-device`.
4. **Prompt for a passphrase** that will protect the CI device key. This passphrase will be stored as a GitHub Secret.
5. **Create an encrypted file keychain** by copying the key to a file-backed keychain using `auths key copy-backend --alias ci-release-device --dst-backend file`.
6. **Derive the device DID** using `auths key export --alias ci-release-device --format pub` and `auths debug util pubkey-to-did`.
7. **Link the CI device** to your identity with `auths device link --capabilities sign_release --note "GitHub Actions release signer"`.
8. **Package your `~/.auths` repository** as a base64-encoded tarball (excluding `.sock` files).
9. **Set three GitHub Secrets** via the `gh` CLI:
    - `AUTHS_CI_PASSPHRASE` -- The passphrase for the CI device key.
    - `AUTHS_CI_KEYCHAIN` -- The encrypted file keychain (base64).
    - `AUTHS_CI_IDENTITY_BUNDLE` -- The `~/.auths` repository snapshot (base64 tarball).

If the `gh` CLI is not authenticated, the command prints the secret values for you to add manually via **Repository > Settings > Secrets > Actions > New secret**.

### Re-running setup

If you already have a `ci-release-device` key, `cargo xt ci-setup` detects it and reuses the existing key while regenerating the file keychain and secrets.

## Signing artifacts in GitHub Actions

Once the secrets are set, add a signing step to your release workflow:

```yaml
name: Release
on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Auths
        run: cargo install auths-cli

      - name: Restore Auths identity
        env:
          AUTHS_CI_IDENTITY_BUNDLE: ${{ secrets.AUTHS_CI_IDENTITY_BUNDLE }}
          AUTHS_CI_KEYCHAIN: ${{ secrets.AUTHS_CI_KEYCHAIN }}
          AUTHS_CI_PASSPHRASE: ${{ secrets.AUTHS_CI_PASSPHRASE }}
        run: |
          # Restore the ~/.auths identity repository
          mkdir -p ~/.auths
          echo "$AUTHS_CI_IDENTITY_BUNDLE" | base64 -d | tar xz -C ~/.auths

          # Restore the file keychain
          echo "$AUTHS_CI_KEYCHAIN" | base64 -d > /tmp/ci-keychain.enc

          # Set environment for file-backend keychain
          echo "AUTHS_KEYCHAIN_BACKEND=file" >> $GITHUB_ENV
          echo "AUTHS_KEYCHAIN_FILE=/tmp/ci-keychain.enc" >> $GITHUB_ENV
          echo "AUTHS_PASSPHRASE=$AUTHS_CI_PASSPHRASE" >> $GITHUB_ENV

      - name: Build release artifact
        run: cargo build --release && tar czf myproject.tar.gz -C target/release myproject

      - name: Sign release artifact
        run: |
          auths sign myproject.tar.gz \
            --device-key ci-release-device

      - name: Upload release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            myproject.tar.gz
            myproject.tar.gz.auths.json
```

The `auths sign <file>` command detects that the target is a file (not a Git ref) and creates an attestation file at `<file>.auths.json` containing the cryptographic signature, the signer's DID, and the artifact digest.

## Signing Git commits in CI

To sign Git commits (not just artifacts), configure Git to use Auths as the signing program:

```yaml
      - name: Configure Git signing
        run: |
          git config --global gpg.format ssh
          git config --global gpg.ssh.program auths-sign
          git config --global commit.gpgsign true
          git config --global user.signingkey "$(auths key export --alias ci-release-device --format pub)"
```

Then any `git commit` in the workflow will be signed by the CI device key.

## Verifying signatures in pipelines

### Verifying commits

Use `auths verify` to check commit signatures. For CI, the `--identity-bundle` flag enables stateless verification without needing access to the full identity repository:

```bash
# Export a bundle on your local machine (one-time)
auths id export-bundle \
  --alias main \
  --output identity-bundle.json \
  --max-age-secs 7776000  # 90 days
```

Commit this bundle to your repository (e.g., `.auths/identity-bundle.json`), then verify in CI:

```yaml
      - name: Verify commit signatures
        run: |
          auths verify HEAD --identity-bundle .auths/identity-bundle.json
```

To verify a range of commits:

```bash
auths verify main..HEAD --identity-bundle .auths/identity-bundle.json
```

The verify command checks:

1. **SSH signature validity** -- The commit has a valid SSH signature from an allowed signer.
2. **Attestation chain** -- If the bundle contains attestations, the chain is verified (signatures, expiry, revocation).
3. **Witness quorum** -- If witness receipts are provided, the required threshold is checked.

Exit codes: `0` for valid, `1` for invalid/unsigned, `2` for errors.

### Verifying artifacts

Verify a signed artifact attestation:

```bash
auths verify myproject.tar.gz.auths.json --issuer-pk <hex-encoded-public-key>
```

Or using the issuer's DID:

```bash
auths verify myproject.tar.gz.auths.json --issuer-did did:keri:EaBcDeFg...
```

### JSON output for CI parsing

Use `--json` for machine-readable verification output:

```bash
auths verify HEAD --identity-bundle .auths/identity-bundle.json --json
```

```json
{
  "commit": "abc1234...",
  "valid": true,
  "ssh_valid": true,
  "chain_valid": true,
  "signer": "did:keri:EaBcDeFg..."
}
```

## GitHub Actions OIDC cross-reference

For higher assurance, combine Auths attestation chains with GitHub Actions OIDC tokens. This creates a two-factor proof: the request must originate from both a valid KERI identity holder and a specific GitHub Actions workflow.

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Get GitHub OIDC token
    id: github-oidc
    uses: actions/github-script@v7
    with:
      script: |
        const token = await core.getIDToken('auths-bridge');
        core.setOutput('token', token);

  - name: Exchange for bridge credentials
    env:
      BRIDGE_URL: https://your-bridge.example.com
      GITHUB_OIDC_TOKEN: ${{ steps.github-oidc.outputs.token }}
    run: |
      JWT=$(curl -s -X POST "$BRIDGE_URL/token" \
        -H "Content-Type: application/json" \
        -d "{
          \"attestation_chain\": $ATTESTATION_CHAIN,
          \"root_public_key\": \"$ROOT_PK\",
          \"github_oidc_token\": \"$GITHUB_OIDC_TOKEN\",
          \"github_actor\": \"$GITHUB_ACTOR\"
        }" | jq -r '.access_token')
```

The bridge verifies the KERI attestation chain, validates the GitHub OIDC token against GitHub's JWKS endpoint, and cross-references the GitHub `actor` claim against the expected KERI identity. If both pass, it issues a bridge JWT.

## Revoking CI access

To revoke a CI device at any time:

```bash
auths device revoke \
  --device-did <ci-device-did> \
  --key <your-key>
```

The device DID and identity key alias are printed by `cargo xt ci-setup` when the device is created. After revocation, the CI device key can no longer produce valid attestations, even if the secrets remain in GitHub.
