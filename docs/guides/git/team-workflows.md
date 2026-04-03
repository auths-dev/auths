# Team Workflows

This guide covers how teams use Auths to manage shared signing registries, onboard new members, enforce organization-level policies, and maintain a trusted `allowed_signers` file across a project.

## Shared allowed_signers File

The `allowed_signers` file is the foundation of team-level commit verification. It maps principals (email addresses or DIDs) to public keys and tells Git which signatures to trust.

### Repository-Committed Approach

The recommended approach is to commit the `allowed_signers` file to your repository:

```bash
# Generate from your Auths identity
auths signers sync --output .auths/allowed_signers

# Configure Git to use it
git config --local gpg.ssh.allowedSignersFile .auths/allowed_signers

# Commit the file
git add .auths/allowed_signers
git commit -S -m "Add allowed signers"
```

Each team member adds their public key entry to the same file. The file format is one entry per line:

```
alice@example.com namespaces="git" ssh-ed25519 AAAA...
bob@example.com namespaces="git" ssh-ed25519 AAAA...
```

### Adding a Teammate's Key

Each developer generates their own entry and contributes it to the shared file:

```bash
# Teammate runs on their machine:
auths signers list
```

This outputs their entry to stdout. They copy it and open a PR to append it to `.auths/allowed_signers`. Alternatively, if you have access to the teammate's Auths identity repository, you can generate the full file from all known attestations:

```bash
auths signers sync --repo /path/to/shared/auths-repo --output .auths/allowed_signers
```

### Auto-Regeneration

Install a Git hook that regenerates the `allowed_signers` file after each merge or pull:

```bash
auths git install-hooks
```

This creates a `.git/hooks/post-merge` hook that runs:

```bash
auths signers sync --repo ~/.auths --output .auths/allowed_signers
```

The hook ensures the `allowed_signers` file stays in sync with the latest device authorizations from your identity repository. Use `--force` to overwrite an existing hook.

## Onboarding New Team Members

### Step 1: Member Initializes Their Identity

The new team member sets up Auths on their machine:

```bash
auths init
```

This creates their cryptographic identity, generates a key pair, stores it in the platform keychain, and configures Git signing.

### Step 2: Member Shares Their Public Key

The new member exports their public key entry:

```bash
auths signers list
```

They share the output line (e.g., via a PR or secure channel).

### Step 3: Add to allowed_signers

A maintainer appends the new entry to `.auths/allowed_signers` and commits the change:

```bash
# Append the new entry
echo 'newdev@example.com namespaces="git" ssh-ed25519 AAAA...' >> .auths/allowed_signers

# Commit
git add .auths/allowed_signers
git commit -S -m "Add newdev to allowed signers"
```

### Step 4: Member Verifies Setup

The new member confirms signing works:

```bash
auths status
git commit --allow-empty -m "Test signed commit"
auths verify HEAD
```

## Organization Identities

For teams that need formal membership management, Auths provides organization identities with role-based access control.

### Creating an Organization

```bash
auths org init --name "my-org"
```

This creates a dedicated KERI-based organization identity with an admin self-attestation. The creator receives all capabilities: `SignCommit`, `SignRelease`, `ManageMembers`, and `RotateKeys`.

Options:

```bash
# Custom key alias
auths org init --name "my-org" --key org-myorg

# With additional metadata
auths org init --name "my-org" --metadata-file org-metadata.json
```

### Adding Members

Organization admins (users with the `ManageMembers` capability) can add members with role-based permissions:

```bash
auths org add-member \
  --org did:keri:E... \
  --member did:keri:E... \
  --role member
```

Available roles:

| Role | Default Capabilities |
|------|---------------------|
| `admin` | `SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys` |
| `member` | `SignCommit`, `SignRelease` |
| `readonly` | (none) |

Override default capabilities with `--capabilities`:

```bash
auths org add-member \
  --org did:keri:E... \
  --member did:keri:E... \
  --role member \
  --capabilities sign-commit
```

### Listing Members

```bash
auths org list-members --org did:keri:E...
```

Output shows member DIDs, roles, capabilities, and delegation chains:

```
Members (3 total):
---
|- did:keri:E... [admin] [SignCommit, SignRelease, ManageMembers, RotateKeys]
|- did:keri:E... [member] [SignCommit, SignRelease]
|     delegated by: did:keri:E...
|- did:keri:E... [readonly]
|     delegated by: did:keri:E...
```

Use `--include-revoked` to show revoked members.

### Revoking Members

When a team member leaves or their access should be removed:

```bash
auths org revoke-member \
  --org did:keri:E... \
  --member did:keri:E... \
  --note "Left the team"
```

Revoked members' signatures remain valid for commits made before the revocation timestamp. Future commits signed with the revoked key will fail verification.

After revoking a member, regenerate the `allowed_signers` file to remove their key:

```bash
auths signers sync --output .auths/allowed_signers
```

## Trust Management

Auths supports trust-on-first-use (TOFU) and explicit trust pinning for identity roots.

### Pinning a Trusted Identity

Manually pin an identity as trusted:

```bash
auths trust pin \
  --did did:keri:E... \
  --key abcdef1234567890... \
  --note "Org root key"
```

### Listing Pinned Identities

```bash
auths trust list
```

### Removing a Pin

```bash
auths trust remove did:keri:E...
```

### Viewing Pin Details

```bash
auths trust show did:keri:E...
```

This shows the full public key, trust level (TOFU, Manual, or OrgPolicy), first-seen timestamp, and KEL tracking information.

## Organization Policies

Auths provides a policy engine for defining fine-grained authorization rules. Policies are JSON files that can be linted, compiled, tested, and compared.

### Policy Structure

Policies are boolean expressions over attestation contexts. A minimal policy that requires commits to be non-revoked and signed with the `sign-commit` capability:

```json
{
  "and": [
    { "not_revoked": true },
    { "has_capability": "sign-commit" }
  ]
}
```

### Validating Policies

Lint a policy for syntax errors:

```bash
auths policy lint policy.json
```

Compile with full validation (checks node counts, depth limits, and structural integrity):

```bash
auths policy compile policy.json
```

### Testing Policies

Define test cases in a JSON file:

```json
[
  {
    "name": "admin can sign",
    "context": {
      "issuer": "did:keri:E...",
      "subject": "did:key:z6Mk...",
      "capabilities": ["sign-commit"],
      "role": "admin",
      "revoked": false
    },
    "expect": "Allow"
  },
  {
    "name": "revoked member denied",
    "context": {
      "issuer": "did:keri:E...",
      "subject": "did:key:z6Mk...",
      "capabilities": ["sign-commit"],
      "revoked": true
    },
    "expect": "Deny"
  }
]
```

Run the test suite:

```bash
auths policy test policy.json --tests test-cases.json
```

### Evaluating Policies

Explain a policy decision for a specific context:

```bash
auths policy explain policy.json --context context.json
```

Output shows the decision (`ALLOW`, `DENY`, or `INDETERMINATE`), the reason, and the policy hash.

### Comparing Policies

Before deploying a policy change, compare the old and new versions:

```bash
auths policy diff old-policy.json new-policy.json
```

Output shows added, removed, and changed rules with risk scores (`LOW`, `MEDIUM`, `HIGH`).

## Multi-Device Signing

Team members who work across multiple machines can pair devices to sign with the same identity from any machine.

Each device generates its own key pair and receives a device attestation from the identity owner. The `allowed_signers` file includes entries for all authorized devices. When `auths signers list` is run, it scans all non-revoked attestations and generates entries for every authorized device key.

## Audit and Compliance

Generate signing audit reports for compliance purposes:

```bash
# Table format for quick review
auths audit --repo . --since 2026-Q1

# JSON for automated processing
auths audit --repo . --format json --since 2026-01-01 --until 2026-03-31

# HTML report for stakeholders
auths audit --repo . --format html -o q1-audit.html

# CI gate: fail if any unsigned commits
auths audit --repo . --require-all-signed --exit-code
```

Filter by author or signer:

```bash
auths audit --repo . --author alice@example.com
auths audit --repo . --signer did:keri:E...
```

## Workflow Summary

### Initial Team Setup

```bash
# Each team member (once)
auths init

# Collect allowed_signers entries from all members
# Commit the shared file to the repository
auths signers sync --output .auths/allowed_signers
git config --local gpg.ssh.allowedSignersFile .auths/allowed_signers
git add .auths/allowed_signers
git commit -S -m "Initialize team signing"

# Install auto-regeneration hook
auths git install-hooks
```

### Adding a New Member

```bash
# New member runs:
auths init

# New member shares their entry:
auths signers list
# (copy output line)

# Maintainer appends to .auths/allowed_signers and commits
```

### Verifying Team Commits in CI

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - run: auths verify origin/main..HEAD --allowed-signers .auths/allowed_signers
```

### Handling Member Departure

```bash
# Revoke the member's org attestation (if using org identities)
auths org revoke-member --org did:keri:E... --member did:keri:E...

# Remove their entry from allowed_signers
auths signers sync --output .auths/allowed_signers

# Commit the change
git add .auths/allowed_signers
git commit -S -m "Remove departed member from allowed signers"
```

## Next Steps

- [Signing Configuration](signing-configuration.md) -- configure Git signing
- [Verifying Commits](verifying-commits.md) -- verify signatures locally and in CI
