# Organizations & Compliance

An organization is its own `did:keri` identity that authorizes members with roles and
capabilities — and because every grant and revocation is an anchored event in the
org's key event log, **compliance evidence is a query, not a spreadsheet**.

## Create an organization

```bash
auths org create --name "my-org"
```

The creator receives admin authority (all capabilities: `sign_commit`,
`sign_release`, `manage_members`, `rotate_keys`).

## Membership

```bash
auths org add-member    --org did:keri:E... --member did:keri:E... --role member
auths org revoke-member --org did:keri:E... --member did:keri:E... --note "offboarded"
auths org list-members  --org did:keri:E...
auths org join          # join via an invite code
```

| Role | Default capabilities |
|------|---------------------|
| `admin` | `sign_commit`, `sign_release`, `manage_members`, `rotate_keys` |
| `member` | `sign_commit`, `sign_release` |
| `readonly` | *(none)* |

Because membership changes are anchored in the org KEL, "who could sign what, when"
is answerable for any point in history — not just the present.

## Compliance as a query

### Authority at signing time

```bash
auths org audit --org did:keri:E... --member did:keri:E... --artifact sig.auths.json
```

Classifies a member's authority **at the artifact's signing position** in the KEL —
the question auditors actually ask ("was this person authorized *when they signed*,
not today").

### Provable off-boarding

```bash
auths org offboarding-log --org did:keri:E...
```

Lists durable off-boarding records: cryptographic evidence that access ended, when,
and on whose authority.

### Air-gapped evidence bundles

```bash
auths org bundle --org did:keri:E... --output org-evidence.bundle
auths artifact verify ./artifact --offline --roots .auths/roots
```

The bundle is self-contained provenance for an entire org — verifiable on a machine
with no network and no Auths state, against explicitly supplied trust roots.

## Org-wide policy

```bash
auths org policy --help
```

Organizations can anchor an authorization policy on the org KEL (e.g. which signer
types may sign which targets). Commit verification evaluates the policy *after* the
cryptographic verdict — an unverified commit never reaches policy. See
[Custom Policies](../advanced/custom-policies.md).

## Fleet visibility

```bash
auths org metrics --org did:keri:E...   # governance metrics for the fleet
auths org trace   --org did:keri:E... --agent did:keri:E...
```

`trace` walks an agent's delegation chain to its authorizing root and reports whether
its authority was live at a given signing position — the audit trail for agent fleets.
