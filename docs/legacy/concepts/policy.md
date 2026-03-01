# Policy

A policy is a set of rules that determines whether an action is allowed, denied, or indeterminate. Policies are the building block for organization-level access control in Auths.

## Why policies?

Attestations answer "is this device linked to this identity?" -- but organizations need more: *can this member sign commits to this repo, in this environment, right now?* Policies express those rules as composable, testable JSON documents.

## Policy expressions

A policy is a tree of boolean expressions. Leaf nodes are predicates (checks against the current context), combined with `And`, `Or`, and `Not`:

```json
{
  "And": [
    "NotRevoked",
    "NotExpired",
    { "HasCapability": "sign_commit" },
    { "RepoIn": ["org/frontend", "org/backend"] },
    { "MaxChainDepth": 2 }
  ]
}
```

This policy allows signing only if the attestation is active, unexpired, grants `sign_commit`, targets one of two repos, and the delegation chain is at most 2 levels deep.

## Available predicates

| Predicate | Description |
|-----------|-------------|
| `NotRevoked` | Attestation is not revoked |
| `NotExpired` | Attestation has not expired |
| `HasCapability(cap)` | Attestation grants the specified capability |
| `HasAllCapabilities([...])` | Attestation grants every listed capability |
| `HasAnyCapability([...])` | Attestation grants at least one listed capability |
| `IssuerIs(did)` | Issuer matches a specific DID |
| `IssuerIn([...])` | Issuer is one of the listed DIDs |
| `SubjectIs(did)` | Subject matches a specific DID |
| `DelegatedBy(did)` | Delegated by a specific DID |
| `RoleIs(role)` | Member has the specified role |
| `RoleIn([...])` | Member has one of the listed roles |
| `RepoIs(repo)` | Target repo matches |
| `RepoIn([...])` | Target repo is one of the listed repos |
| `RefMatches(pattern)` | Git ref matches a pattern |
| `PathAllowed([...])` | Changed paths match allowed patterns |
| `EnvIs(env)` | Environment matches (e.g. `production`, `staging`) |
| `EnvIn([...])` | Environment is one of the listed values |
| `MaxChainDepth(n)` | Delegation chain is at most `n` levels |
| `ExpiresAfter(secs)` | Attestation expires at least `secs` seconds from now |
| `IssuedWithin(secs)` | Attestation was issued within the last `secs` seconds |
| `IsHuman` | Signer is a human identity |
| `IsAgent` | Signer is an AI agent or bot |
| `IsWorkload` | Signer is an automated workload (CI, cron, etc.) |

## Decisions

Evaluating a policy returns one of three outcomes:

| Outcome | Meaning |
|---------|---------|
| **Allow** | All conditions satisfied |
| **Deny** | One or more conditions failed |
| **Indeterminate** | Not enough context to decide |

Each decision includes a reason code and a human-readable message.

## Compilation and limits

Policies are compiled before evaluation. The compiler enforces safety limits to prevent denial-of-service:

| Limit | Default |
|-------|---------|
| Max JSON size | 64 KB |
| Max AST nodes | 256 |
| Max tree depth | 16 |

Compilation also produces a content-addressable **hash** of the policy source, useful for auditing which policy version was in effect at a given time.

## Workflow

A typical policy workflow:

```bash
# 1. Write the policy
vim org-policy.json

# 2. Lint it
auths policy lint org-policy.json

# 3. Compile it (checks limits, shows hash)
auths policy compile org-policy.json

# 4. Test it against known scenarios
auths policy test org-policy.json --tests org-tests.json

# 5. Before deploying a change, diff it
auths policy diff old-policy.json org-policy.json
```

See [auths policy](../cli/commands/advanced.md#auths-policy) for the full command reference.
