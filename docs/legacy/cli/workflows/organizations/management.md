# Organization Management

Set up an organization, manage members, and audit the roster. This workflow is geared towards tech leads, security teams, and platform teams.

## Prerequisites

- Auths CLI installed (`cargo install auths_cli`)
- An initialized personal identity (`auths init --profile developer` or `auths init`)

## 1. Initialize the organization

Create the org identity. This generates a new `did:keri` for the organization and a signing key stored in your keychain.

```bash
auths org init --name "acme-eng"
```

The org identity is stored at `~/.auths` alongside your personal identity. The `--name` is metadata -- the cryptographic identifier is the `did:keri` DID.

To provide additional metadata:

```bash
auths org init --name "acme-eng" --metadata-file org-metadata.json
```

## 2. Add members

Add a member by specifying their identity DID, a role, and the org identifier:

```bash
auths org add-member \
  --org acme-eng \
  --member did:key:z6MkAlice... \
  --role member
```

### Roles

| Role | Default capabilities | Use case |
|------|---------------------|----------|
| `admin` | sign_commit, sign_release, manage_members, rotate_keys | Org owners, security leads |
| `member` | sign_commit, sign_release | Engineers |
| `readonly` | *(none)* | Auditors, external reviewers |

### Custom capabilities

Override the role defaults when a member needs a non-standard set:

```bash
auths org add-member \
  --org acme-eng \
  --member did:key:z6MkBot... \
  --role member \
  --capabilities sign_commit \
  --note "CI bot - commits only, no releases"
```

Available capabilities: `sign_commit`, `sign_release`, `manage_members`, `rotate_keys`.

## 3. List members

View the current roster:

```bash
auths org list-members --org acme-eng
```

Include revoked members for a full history:

```bash
auths org list-members --org acme-eng --include-revoked
```

## 4. Revoke a member

Remove a member's authorization. The revocation is recorded as a signed event -- it's permanent and auditable.

```bash
auths org revoke-member \
  --org acme-eng \
  --member did:key:z6MkAlice... \
  --note "Left the team"
```

After revocation:

- The member's attestation is marked `revoked: true`
- Existing signatures remain valid (they were valid at signing time)
- Verifiers will see the member is no longer authorized for future actions

## 5. View attestations

Inspect attestations for a specific member:

```bash
auths org show --subject did:key:z6MkAlice...
```

List all org attestations:

```bash
auths org list
auths org list --include-revoked
```

## 6. Audit

Generate an incident report covering device status, recent events, and recommendations:

```bash
auths emergency report --json --file audit-2026-02.json
```

The report covers all identities and devices managed in the local `~/.auths` repository.

## Example: onboarding a new engineer

```bash
# 1. New engineer sets up their personal identity
auths init --profile developer

# 2. They share their device DID
auths id show
# Controller DID: did:keri:ENewEngineer...

# 3. Admin adds them to the org
auths org add-member \
  --org acme-eng \
  --member did:key:z6MkNewEngineer... \
  --role member \
  --note "Jane - backend team"

# 4. Verify the membership
auths org list-members --org acme-eng
```

## Example: offboarding

```bash
# 1. Revoke org membership
auths org revoke-member \
  --org acme-eng \
  --member did:key:z6MkJane... \
  --note "Last day 2026-02-28"

# 2. Verify revocation
auths org list-members --org acme-eng --include-revoked
```
