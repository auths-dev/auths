# Verifying Commits

This guide covers how to verify Git commit signatures using Auths, including single-commit checks, full-history verification, identity bundle verification for CI, and integrating verification into CI pipelines.

## How `auths verify` Works

The `auths verify` command is a unified entry point that detects whether you are verifying a Git commit or an attestation file. When given a Git ref, commit hash, or range, it performs commit verification. When given a file path or `-` for stdin, it performs attestation verification.

For commit verification, `auths verify`:

1. Reads the SSH signature embedded in the Git commit object
2. Looks up the signer's principal against the `--allowed-signers` file
3. Verifies the signature cryptographically using `ssh-keygen`
4. Optionally verifies the attestation chain (when `--identity-bundle` is provided)
5. Optionally verifies witness receipts (when `--witness-receipts` is provided)

## Verifying a Single Commit

Verify the latest commit:

```bash
auths verify
```

This defaults to verifying `HEAD`. You can specify any commit ref or hash:

```bash
auths verify HEAD
auths verify abc1234
auths verify v1.0.0
```

The default `--allowed-signers` path is `.auths/allowed_signers`. To use a different file:

```bash
auths verify HEAD --allowed-signers path/to/allowed_signers
```

### Output

On success:

```
Commit abc12345 verified: signed by you@example.com
```

On failure:

```
Verification failed for abc12345: No signature found
```

### JSON Output

For machine-readable output, use the `--json` flag:

```bash
auths verify HEAD --json
```

Returns a JSON object with fields: `commit`, `valid`, `ssh_valid`, `chain_valid`, `signer`, `error`, and `warnings`.

## Verifying a Commit Range

Verify all commits in a range:

```bash
auths verify main..HEAD
```

This resolves the range using `git rev-list` and verifies each commit individually. Output shows one line per commit:

```
abc12345: valid (signer: you@example.com)
def67890: valid (signer: teammate@example.com)
```

Exit code `0` means all commits are valid. Exit code `1` means at least one commit is invalid or unsigned.

## Verifying Full Repository History

To verify all commits from the initial commit to HEAD:

```bash
# Find the root commit
ROOT=$(git rev-list --max-parents=0 HEAD)

# Verify every commit
auths verify "${ROOT}..HEAD"
```

For large repositories, this may take time since each commit requires an `ssh-keygen` call.

## Identity Bundle Verification (Stateless / CI)

For CI environments that do not have access to identity repositories, you can verify against an identity bundle. The bundle contains the identity's public key and attestation chain, enabling stateless verification.

```bash
auths verify HEAD --identity-bundle identity-bundle.json
```

When an identity bundle is provided:

1. A temporary `allowed_signers` file is created from the bundle's public key
2. The SSH signature is verified against that key
3. The attestation chain in the bundle is cryptographically verified
4. Bundle freshness is checked (bundles have a `max_valid_for_secs` TTL)
5. Attestation expiry warnings are emitted if any attestation expires within 30 days

### Identity Bundle Format

An identity bundle is a JSON file with this structure:

```json
{
  "identity_did": "did:keri:E...",
  "public_key_hex": "abcdef...",
  "attestation_chain": [...],
  "bundle_timestamp": "2026-01-01T00:00:00Z",
  "max_valid_for_secs": 86400
}
```

## Witness Verification

Witnesses provide additional assurance by countersigning attestations. To verify witness receipts alongside commit signatures:

```bash
auths verify HEAD \
  --identity-bundle bundle.json \
  --witness-receipts receipts.json \
  --witness-threshold 2 \
  --witness-keys "did:key:z6Mk...:abcd1234..."
```

The `--witness-threshold` specifies how many witness signatures must be valid. If the quorum is not met, verification fails.

## CI Integration

### GitHub Actions

Use the Auths verify action to block PRs with unsigned commits:

```yaml
name: Verify Signatures
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # Full history required for commit verification

      - name: Install Auths
        run: cargo install auths-cli

      - name: Verify commit signatures
        run: auths verify origin/main..HEAD --json --allowed-signers .auths/allowed_signers
```

The `fetch-depth: 0` is required. Shallow clones do not contain the commit objects needed for signature extraction.

### Using the Verify Action

```yaml
- uses: auths-dev/auths-verify-action@v1
  with:
    allowed-signers: '.auths/allowed_signers'
    fail-on-unsigned: 'true'
```

This action runs `auths verify` across the PR's commit range, writes a results table to the GitHub Step Summary, and fails the check if any commit is unsigned.

### GitLab CI

```yaml
verify-signatures:
  stage: test
  script:
    - cargo install auths-cli
    - auths verify origin/main..HEAD --allowed-signers .auths/allowed_signers
  variables:
    GIT_DEPTH: 0
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All commits verified successfully |
| `1` | At least one commit is invalid or unsigned |
| `2` | Runtime error (missing `ssh-keygen`, invalid args, etc.) |

### Using the Audit Command

For compliance reporting, the `auths audit` command generates structured reports of signing status across a repository:

```bash
# Table format (default)
auths audit --repo . --since 2026-01-01

# JSON format for CI processing
auths audit --repo . --format json --require-all-signed --exit-code

# CSV for spreadsheet import
auths audit --repo . --format csv -o audit-report.csv

# HTML report
auths audit --repo . --format html -o audit-report.html
```

Audit options:

| Flag | Purpose |
|------|---------|
| `--since` | Start date (YYYY-MM-DD or YYYY-QN for quarter) |
| `--until` | End date (YYYY-MM-DD) |
| `--author` | Filter by author email |
| `--signer` | Filter by signing identity/device DID |
| `-n` / `--count` | Maximum number of commits (default: 100) |
| `--require-all-signed` | Require all commits to be signed |
| `--exit-code` | Return exit code 1 if any unsigned commits found |

## Verifying Attestation Files

The `auths verify` command also verifies attestation JSON files:

```bash
# Verify an attestation file
auths verify attestation.json --issuer-pk abcdef1234...

# Verify from stdin
cat attestation.json | auths verify - --issuer-did did:keri:E...
```

## Verification Library (auths-verifier)

For programmatic verification in your own tools, the `auths-verifier` crate provides the underlying verification functions. It is designed to be lightweight and embeddable, with support for FFI and WASM.

```rust
use auths_verifier::{verify_chain, VerificationStatus};

let report = verify_chain(&attestations, &root_public_key).await?;

match report.status {
    VerificationStatus::Valid => println!("Chain verified"),
    VerificationStatus::Expired { at } => println!("Expired at {}", at),
    VerificationStatus::InvalidSignature { step } => {
        println!("Bad signature at step {}", step);
    }
    VerificationStatus::Revoked { at } => println!("Revoked"),
    VerificationStatus::BrokenChain { missing_link } => {
        println!("Missing link: {}", missing_link);
    }
    VerificationStatus::InsufficientWitnesses { required, verified } => {
        println!("Witnesses: {}/{}", verified, required);
    }
}
```

### Capability-Scoped Verification

Verify that a device has a specific capability:

```rust
use auths_verifier::{verify_with_capability, Capability};

let report = verify_with_capability(&chain, Capability::SignCommit)?;
```

## Troubleshooting

### "Allowed signers file not found"

The default path `.auths/allowed_signers` does not exist. Generate it:

```bash
mkdir -p .auths
auths signers sync --output .auths/allowed_signers
```

### "Signature from non-allowed signer"

The commit was signed with a key that is not in the `allowed_signers` file. This happens when a teammate signs commits but their key has not been added. See [Team Workflows](team-workflows.md) for how to manage shared `allowed_signers` files.

### "No signature found"

The commit was never signed. Verify the author's git config:

```bash
git config user.signingKey   # should be auths:<alias>
git config commit.gpgSign    # should be true
git config gpg.ssh.program   # should be auths-sign
```

### "GPG signatures not supported"

The commit uses a GPG signature instead of SSH. Auths only supports SSH signatures. Reconfigure Git:

```bash
git config --global gpg.format ssh
```

### "Shallow clone detected" in CI

Commit verification requires full commit objects. Add `fetch-depth: 0` to your checkout step:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

## Next Steps

- [Signing Configuration](signing-configuration.md) -- set up Git signing
- [Team Workflows](team-workflows.md) -- shared registries and organization policies
