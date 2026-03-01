# CI Verification

Verify commit signatures in CI pipelines using Auths.

## Python SDK (recommended for CI)

The Python SDK provides `verify_commit_range()` -- no Rust toolchain needed in CI.

```yaml
name: Verify Commit Signatures
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - run: pip install auths-verifier

      - name: Verify commit signatures
        run: |
          python -c "
          from auths_verifier import verify_commit_range

          results = verify_commit_range('origin/main..HEAD',
              identity_bundle='.auths/identity-bundle.json')

          for r in results:
              status = 'PASS' if r.is_valid else 'FAIL'
              print(f'{status}: {r.commit_sha[:8]} by {r.signer}')

          assert all(r.is_valid for r in results), 'Some commits have invalid signatures'
          print(f'All {len(results)} commits verified.')
          "
```

### Setup

1. Export your identity bundle locally:

    ```bash
    auths id export-bundle --alias mykey --output .auths/identity-bundle.json
    ```

2. Commit the bundle to your repo (it contains only public data).

3. Copy the workflow above to `.github/workflows/verify-signatures.yml`.

## CLI approach

For environments where you prefer the CLI:

```yaml
name: Verify Signatures
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: checkout@v4

      - name: Install Auths
        run: cargo install --git https://github.com/auths-dev/auths.git auths_cli

      - name: Verify HEAD
        run: auths verify-commit HEAD --json
```

### Full CLI workflow (push + PR)

See [`examples/ci/github-actions/verify-commits.yml`](https://github.com/auths-dev/auths/blob/main/examples/ci/github-actions/verify-commits.yml) for a complete workflow that handles both push events and pull requests with identity bundle support.

## JavaScript SDK

For Node.js-based CI:

```yaml
      - name: Verify with Node.js
        run: |
          npm install @auths/verifier
          node -e "
          const { init, verifyAttestation } = require('@auths/verifier');
          const fs = require('fs');

          (async () => {
            await init();
            const att = fs.readFileSync('.auths/attestation.json', 'utf8');
            const result = verifyAttestation(att, process.env.ROOT_PK_HEX);
            if (!result.valid) {
              console.error('Verification failed:', result.error);
              process.exit(1);
            }
            console.log('Signature verified');
          })();
          "
```

## Headless key storage

CI environments don't have a platform keychain. If the CI needs to **sign** (not just verify):

```bash
export AUTHS_KEYCHAIN_BACKEND=file
export AUTHS_PASSPHRASE="${{ secrets.AUTHS_PASSPHRASE }}"
```

!!! tip
    Most CI pipelines only need to **verify**, not sign. Verification requires no keychain -- just the attestation JSON and the issuer's public key.
