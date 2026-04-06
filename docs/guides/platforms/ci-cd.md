# CI/CD Integration

Sign every commit. Verify every release. Auths uses a limited-capability device key model so your root identity never leaves your machine — the CI runner only ever holds a scoped, revocable token.

---

## GitHub Actions

The fastest path. Two actions, one secret, zero ongoing maintenance.

### Setup (one-time)

```bash
auths ci setup
```

This creates a scoped CI device key, links it to your identity with `sign_release` capability, and sets `AUTHS_CI_TOKEN` on your repo via the `gh` CLI. If `gh` isn't authenticated, it prints the token value to paste in manually under **Repository → Settings → Secrets → Actions**.

### Sign commits

Add to any workflow that pushes to `main`:

```yaml
- uses: auths-dev/sign@v1
  with:
    token: ${{ secrets.AUTHS_CI_TOKEN }}
    commits: 'HEAD~1..HEAD'
```

### Verify commits

Add to every pull request and push:

```yaml
- uses: auths-dev/verify@v1
  with:
    fail-on-unsigned: true
    post-pr-comment: 'true'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

No token needed — the action reads `.auths/allowed_signers` from your repo.

### Show it off

Once both workflows are running, add badges to your README:

```markdown
[![Verify Commits](https://github.com/<org>/<repo>/actions/workflows/verify-commits.yml/badge.svg)](https://github.com/<org>/<repo>/actions/workflows/verify-commits.yml?query=branch%3Amain+event%3Apush)
[![Sign Commits](https://github.com/<org>/<repo>/actions/workflows/sign-commits.yml/badge.svg)](https://github.com/<org>/<repo>/actions/workflows/sign-commits.yml?query=branch%3Amain)
```

### Sign release artifacts

For releases triggered by a tag push, combine signing with your existing build step:

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

      - name: Build
        run: cargo build --release && tar czf myproject.tar.gz -C target/release myproject

      - name: Sign artifact
        uses: auths-dev/sign@v1
        with:
          token: ${{ secrets.AUTHS_CI_TOKEN }}
          files: 'myproject.tar.gz'
          verify: true

      - name: Upload release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            myproject.tar.gz
            myproject.tar.gz.auths.json
```

Signing produces `myproject.tar.gz.auths.json` alongside the artifact — ship both so downstream consumers can verify.

### Rotating or revoking access

To refresh the token (new TTL, updated identity snapshot):

```bash
auths ci rotate
```

To revoke a CI device entirely:

```bash
auths device revoke --device <ci-device-did> --key <your-key>
```

After revocation the CI key can no longer produce valid attestations, even if the secret is still in GitHub.

---

## Manual setup (other CI platforms)

Running GitLab CI, CircleCI, Bitbucket Pipelines, or your own runner? The same `AUTHS_CI_TOKEN` approach works anywhere you can set an environment variable and install a binary.

### Install the CLI

```yaml
# Example: generic shell step
- name: Install auths
  run: |
    curl -fsSL https://get.auths.dev | sh
    echo "$HOME/.auths/bin" >> $GITHUB_PATH   # or equivalent PATH export
```

### Sign commits

Configure Git to use Auths as the signing program, then any `git commit` in the workflow is signed:

```yaml
- name: Configure Git signing
  run: |
    git config --global gpg.format ssh
    git config --global gpg.ssh.program auths-sign
    git config --global commit.gpgsign true
    git config --global user.signingkey "$(auths key export --alias ci-release-device --format pub)"
```

### Sign artifacts

```bash
auths sign myproject.tar.gz
# → creates myproject.tar.gz.auths.json
```

### Verify commits

For stateless verification (no access to the identity repo), export a bundle once locally and commit it:

```bash
# Local — one-time export
auths id export-bundle \
  --alias main \
  --output .auths/identity-bundle.json \
  --max-age-secs 7776000   # 90 days
git add .auths/identity-bundle.json && git commit -m "add identity bundle"
```

Then in CI:

```bash
auths verify HEAD --identity-bundle .auths/identity-bundle.json
```

To verify a PR range:

```bash
auths verify main..HEAD --identity-bundle .auths/identity-bundle.json
```

### Verify artifacts

Pass the artifact file directly — Auths finds the `.auths.json` sidecar automatically:

```bash
auths verify myproject.tar.gz --signer-key <hex-encoded-public-key>
# or by DID
auths verify myproject.tar.gz --signer did:keri:EaBcDeFg...
```

Override the sidecar path with `--signature` if needed:

```bash
auths verify myproject.tar.gz --signature /path/to/custom.auths.json --signer-key <hex-encoded-public-key>
```

### Machine-readable output

Add `--json` to any verify command for structured output your pipeline can parse:

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

Exit codes: `0` valid · `1` invalid/unsigned · `2` error.

---

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
