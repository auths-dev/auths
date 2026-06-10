# Verifying Commits

This guide covers how to verify Git commit signatures using Auths, including single-commit checks, full-history verification, identity bundle verification for CI, and integrating verification into CI pipelines.

## How `auths verify` Works

The `auths verify` command is a unified entry point that detects whether you are verifying a Git commit or an attestation file. When given a Git ref, commit hash, or range, it performs commit verification. When given a file path or `-` for stdin, it performs attestation verification.

Commit verification is **KEL-native** — there is no key list file to maintain. For each commit, `auths verify`:

1. Reads the SSH signature embedded in the Git commit object
2. Reads the `Auths-Device` trailer (the signer's `did:keri:` identifier)
3. Resolves the signer's key state from their key event log (KEL) in the local identity store — or, opt-in, from a git remote (`--remote`) or an OOBI HTTP endpoint (`--oobi`)
4. Verifies the signature cryptographically against the resolved key
5. Optionally verifies the attestation chain (when `--identity-bundle` is provided)
6. Optionally enforces witness quorum (`--require-witnesses`, `--witness-signatures`)

Resolution is local-only by default (no network). A remote can only advance a signer's key state, never roll it back — the local store stays the trusted floor.

## Who Verifies Green: Self-Trust and Pinned Roots

A cryptographically valid signature still needs a trust decision about the *root*
identity behind it. Three sources make a root trusted:

- **Self-trust** — your own identity is always trusted for your own verifications.
  Commits and artifacts you signed verify on your machine with zero setup.
- **The committed `.auths/roots` file** — the repo's trust declaration, seeded
  automatically by the first signed commit and shared with everyone who clones.
- **An identity bundle** (`--identity-bundle`) — trusted for that verification only.

A valid signature from a root in none of these fails with `Root … is not a pinned
trusted root`. Pin the signer (`auths trust pin --did <did>` or add the DID to
`.auths/roots`) and re-verify.

### "Commit carries no Auths-Id/Auths-Device trailer"

This means the commit message lacks the identity trailers verification replays. The
`prepare-commit-msg` hook installed by `auths init` adds them on every commit. If a
repository sets its own `core.hooksPath` (hook managers like husky do), the hook is
bypassed there — run `auths doctor` to detect this. Commits made before the hook
existed can be backfilled with `auths sign <ref>` (note: it amends, so the SHA
changes; never backfill already-pushed commits without coordinating).

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

If the signer's KEL is not in your local store (e.g. a teammate's commit), fetch it from the repository's remote:

```bash
auths verify HEAD --remote origin
```

### Output

On success:

```
Commit abc12345 verified: signed by did:keri:EBf2cE...
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

Returns a JSON object per commit:

```json
{"commit":"d4e7393e...","valid":true,"ssh_valid":true,"signer":"did:keri:EDxfiyav..."}
```

(`error` and `warnings` fields appear when relevant.)

## Verifying a Commit Range

Verify all commits in a range:

```bash
auths verify main..HEAD
```

This resolves the range using `git rev-list` and verifies each commit individually, one line per commit. Exit code `0` means all commits are valid. Exit code `1` means at least one commit is invalid or unsigned.

## Verifying Full Repository History

To verify all commits from the initial commit to HEAD:

```bash
# Find the root commit
ROOT=$(git rev-list --max-parents=0 HEAD)

# Verify every commit
auths verify "${ROOT}..HEAD"
```

For large repositories, this may take time since each commit is verified individually.

## Identity Bundle Verification (Stateless / CI)

For CI environments that do not have access to identity repositories, you can verify against an identity bundle. The bundle contains the identity's public key and attestation chain, enabling stateless verification.

The signer exports a bundle:

```bash
auths id export-bundle --alias main --output identity-bundle.json --max-age-secs 86400
```

The verifier uses it:

```bash
auths verify HEAD --identity-bundle identity-bundle.json
```

When an identity bundle is provided:

1. The SSH signature is verified against the bundle's public key
2. The attestation chain in the bundle is cryptographically verified
3. Bundle freshness is checked (bundles have a `max_valid_for_secs` TTL)
4. Attestation expiry warnings are emitted if any attestation expires within 30 days

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
  --witness-signatures receipts.json \
  --witnesses-required 2 \
  --witness-keys "did:key:z6Mk...:abcd1234..."
```

The `--witnesses-required` specifies how many witness signatures must be valid. If the quorum is not met, verification fails. Pass `--require-witnesses` to fail closed when the signer's root KEL has not reached witness quorum (the default is to warn and continue).

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

      - uses: auths-dev/verify@v1
        with:
          auths-version: '0.1.2'                 # pin — a verifier must not resolve `latest`
          identity-bundle: '.auths/ci-bundle.json'  # omit for KEL-native verification
          fail-on-unsigned: 'true'
```

The action runs `auths verify` across the PR's commit range, writes a results table to the GitHub Step Summary, and fails the check if any commit is unsigned. The `fetch-depth: 0` is required — shallow clones do not contain the commit objects needed for signature extraction.

To run the CLI directly instead:

```yaml
      - name: Verify commit signatures
        run: auths verify origin/main..HEAD --json
```

### GitLab CI

```yaml
verify-signatures:
  stage: test
  script:
    - cargo install auths-cli
    - auths verify origin/main..HEAD --identity-bundle .auths/ci-bundle.json
  variables:
    GIT_DEPTH: 0
```

### Exit Codes

The exit-code contract (also in `auths verify --help`):

| Code | Meaning |
|------|---------|
| `0` | Verified |
| `1` | Verification failed — bad signature, missing trailers, or an untrusted/unresolvable signer |
| `2` | Could not attempt — I/O error, malformed input, missing repository |

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
auths verify attestation.json --signer-key abcdef1234...

# Verify from stdin
cat attestation.json | auths verify - --signer did:keri:E...
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

### "Unknown identity ... and trust policy is 'explicit'"

The signer's identity is not in your trust store. Pin it explicitly:

```bash
auths trust pin --did did:keri:E... --key <signer-public-key-hex>
```

Or fetch their KEL from the repository's remote:

```bash
auths verify HEAD --remote origin
```

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
- [Team Workflows](team-workflows.md) -- trust pinning and organization policies
