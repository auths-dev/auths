# Team Workflows

This guide covers how teams use Auths to verify each other's commits, onboard new members, manage organization identities, and enforce organization-level policies.

Verification in Auths is KEL-native: each member's identity is a key event log (KEL), and verifiers resolve a signer's current key state from that log. There is no shared key list file to generate, distribute, or keep in sync — trust is established once per identity (by pinning or fetching its KEL), and key rotations propagate automatically through the log.

## Verifying Teammates' Commits

When you verify a commit, `auths verify` reads the signer's `did:keri:` identifier from the commit's `Auths-Device` trailer and resolves their key state. For your own commits this works out of the box. For a teammate's commits, you need their KEL or a pinned trust entry.

### Option 1: Fetch the Signer's KEL from the Remote

If teammates' KELs are available on the repository's git remote, resolve them on demand:

```bash
auths verify origin/main..HEAD
```

This is opt-in (resolution is local-only by default). A remote can only advance a signer's key state, never roll it back — your local store stays the trusted floor.

### Option 2: The Committed Trust File (`.auths/roots`)

The repository itself carries its trust declaration: `.auths/roots`, one trusted root
`did:keri:` per line, version-controlled like any other file. A member's first signed
commit seeds their root into it automatically; everyone who pulls inherits it.

```
# .auths/roots
did:keri:EAliceRoot...
did:keri:EBobRoot...
```

Review changes to `.auths/roots` like you review code — a new line in this file is a
trust grant. This is the lowest-friction team model: trust ships with the repo.

### Option 3: Pin the Teammate's Identity Locally

For explicit per-verifier trust independent of any repo, pin a teammate's root once.
No raw key material needed — the key resolves from their key event log or an exported
bundle:

```bash
# from a bundle they shared
auths trust pin --did did:keri:E... --bundle alice-bundle.json --note "Alice — platform team"

# or, if their KEL is already in your local store
auths trust pin --did did:keri:E... --note "Alice — platform team"

# air-gapped ceremony only: explicit key bytes
auths trust pin --did did:keri:E... --key <hex-public-key>
```

After pinning, their commits verify with no network access:

```bash
auths verify HEAD
```

## Onboarding New Team Members

### Step 1: Member Initializes Their Identity

The new team member sets up Auths on their machine:

```bash
auths init
```

This creates their cryptographic identity, stores the key in the platform keychain,
configures Git signing, and installs the commit hook.

### Step 2: Member Makes Their First Signed Commit

```bash
git commit -m "docs: add myself to CONTRIBUTORS"
```

The commit hook stamps the commit with their identity and stages their root into the
repo's `.auths/roots`. The PR containing that change **is** the trust request — the
reviewer who merges it is approving the new root.

### Step 3 (optional): Share a Bundle for Out-of-Repo Verification

For teammates who verify outside this repo, the member exports a bundle over a trusted
channel:

```bash
auths id export-bundle --alias main --output me.json --max-age-secs 604800
```

and verifiers pin it: `auths trust pin --did <their-did> --bundle me.json`.

Teams using an organization identity can skip per-member pinning and add the member to the org instead (see below).

### Step 4: Member Verifies Setup

The new member confirms signing works end to end:

```bash
auths status
git commit --allow-empty -m "Test signed commit"
auths verify HEAD
```

## Organization Identities

For teams that need formal membership management, Auths provides organization identities with role-based access control. The org's KEL anchors every membership grant and revocation, so "who was authorized when" is provable from the log itself.

### Creating an Organization

```bash
auths org create --name "my-org"
```

This creates a dedicated KERI-based organization identity with an admin self-attestation. The creator receives all capabilities: `SignCommit`, `SignRelease`, `ManageMembers`, and `RotateKeys`.

Options:

```bash
# Custom key alias
auths org create --name "my-org" --key org-myorg

# With additional metadata
auths org create --name "my-org" --metadata-file org-metadata.json
```

### Adding Members

Organization admins (users with the `ManageMembers` capability) can add members with role-based permissions:

```bash
auths org add-member \
  --org did:keri:E... \
  --member did:keri:E... \
  --role member \
  --key org-myorg
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
  --capabilities sign-commit \
  --key org-myorg
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
  --note "Left the team" \
  --key org-myorg
```

Revoked members' signatures remain valid for commits made before the revocation timestamp. Future commits signed with the revoked key will fail verification — no key-list cleanup required, because verifiers see the revocation in the org's log.

For compliance-grade off-boarding evidence, see `auths org offboarding-log` and `auths org bundle` (air-gapped provenance bundles).

## Trust Management

Auths supports trust-on-first-use (TOFU) and explicit trust pinning for identity roots.

### Pinning a Trusted Identity

Manually pin an identity as trusted. The key material resolves automatically from the
identity's key event log or a supplied bundle:

```bash
auths trust pin --did did:keri:E... --note "Org root key"
auths trust pin --did did:keri:E... --bundle org-root.json
auths trust pin --did did:keri:E... --key <hex>   # air-gapped ceremony only
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

Team members who work across multiple machines can link devices to sign with the same identity from any machine:

```bash
auths pair        # link a new device via QR code or short code
```

Under KERI delegation, each device receives its own delegated identifier anchored by the root identity — the device's signing authority is provable from the shared KEL, and verifiers resolve it the same way they resolve the root. No per-device key distribution is needed.

To manage devices explicitly, see `auths device list`, `auths device add`, `auths device revoke`, and `auths device remove`.

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

# Trust ships with the repo: each member's first signed commit adds their root
# to the committed .auths/roots. For out-of-repo verification, pin explicitly:
auths trust pin --did did:keri:E... --note "alice"
```

### Adding a New Member

```bash
# New member runs:
auths init
auths whoami            # shares the did:keri: with the team

# Teammates pin it, or an org admin runs:
auths org add-member --org did:keri:E... --member did:keri:E... --role member --key org-myorg
```

### Verifying Team Commits in CI

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - uses: auths-dev/verify@v1
    with:
      auths-version: '0.1.2'
      identity-bundle: '.auths/ci-bundle.json'
```

### Handling Member Departure

```bash
# Revoke the member's org attestation (if using org identities)
auths org revoke-member --org did:keri:E... --member did:keri:E... --key org-myorg

# Or, for pin-based teams, remove the pin
auths trust remove did:keri:E...
```

The revocation is anchored in the org's KEL — verifiers reject the departed member's future signatures with no further action.

## Next Steps

- [Signing Configuration](signing-configuration.md) -- configure Git signing
- [Verifying Commits](verifying-commits.md) -- verify signatures locally and in CI
