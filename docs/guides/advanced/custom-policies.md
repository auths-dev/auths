# Custom Policies

Auths policies are composable boolean expression trees that control authorization decisions. They determine whether an action is allowed, denied, or indeterminate based on attestation properties, identity attributes, and environmental context.

Policies are defined as JSON documents, compiled with safety checks, and evaluated against a typed context. The policy engine lives in the `auths-policy` crate.

## How policy expressions work

A policy is a tree of tagged JSON objects. Each node has an `op` field that identifies the operation and an optional `args` field that carries data. Leaf nodes are predicates that check a single property. Combinator nodes (`And`, `Or`, `Not`) compose predicates into complex rules.

The pipeline from definition to decision:

```
JSON file  -->  parse  -->  Expr (AST)  -->  compile  -->  CompiledPolicy  -->  evaluate  -->  Decision
```

Compilation validates every string field (DIDs, capabilities, glob patterns), enforces safety limits, and produces a content-addressable Blake3 hash of the policy source for audit pinning.

### Expression format

Every expression is a JSON object with `"op"` (the operation) and `"args"` (the arguments, when needed):

```json
{"op": "NotRevoked"}
```

```json
{"op": "HasCapability", "args": "sign_commit"}
```

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "HasCapability", "args": "sign_commit"}
]}
```

### Combinators

| Combinator | Behavior |
|------------|----------|
| `And` | All children must evaluate to Allow. Short-circuits on the first Deny. |
| `Or` | At least one child must evaluate to Allow. Short-circuits on the first Allow. |
| `Not` | Inverts the child's outcome (Allow becomes Deny, Deny becomes Allow, Indeterminate stays Indeterminate). |
| `True` | Unconditional allow. |
| `False` | Unconditional deny. |

## Capability-based authorization

Capabilities are the atomic unit of authorization. They follow a naming convention: alphanumeric characters plus `:`, `-`, and `_`, with a maximum length of 64 characters. Capabilities are stored in canonical lowercase form.

**Well-known capabilities:**

- `sign_commit` -- permission to sign commits
- `sign_release` -- permission to sign releases
- `manage_members` -- permission to manage organization members
- `rotate_keys` -- permission to rotate identity keys

**Custom capabilities** use a namespace prefix convention (e.g., `acme:deploy`, `repo:read-write`). The `auths:` prefix is reserved.

### Capability predicates

```json
{"op": "HasCapability", "args": "sign_commit"}
```

Require a single capability.

```json
{"op": "HasAllCapabilities", "args": ["sign_commit", "sign_release"]}
```

Require every listed capability.

```json
{"op": "HasAnyCapability", "args": ["sign_commit", "sign_release"]}
```

Require at least one of the listed capabilities.

## Available predicates

### Lifecycle

| Predicate | Args | Description |
|-----------|------|-------------|
| `NotRevoked` | none | Attestation has not been revoked. |
| `NotExpired` | none | Attestation has not expired. Allows if no expiry is set. |
| `ExpiresAfter` | seconds (integer) | Attestation has at least this many seconds remaining before expiry. Returns Indeterminate if no expiry is set. |
| `IssuedWithin` | seconds (integer) | Attestation was issued within the last N seconds. Returns Indeterminate if no timestamp is set. |

### Identity

| Predicate | Args | Description |
|-----------|------|-------------|
| `IssuerIs` | DID string | Issuer DID must match exactly. |
| `IssuerIn` | array of DID strings | Issuer DID must be in the set. |
| `SubjectIs` | DID string | Subject DID must match exactly. |
| `DelegatedBy` | DID string | Attestation must have been delegated by this DID. |

DIDs must follow the `did:method:id` format. The method segment is lowercased during compilation; the id segment is preserved as-is.

### Role

| Predicate | Args | Description |
|-----------|------|-------------|
| `RoleIs` | role string | Subject's role must match exactly. |
| `RoleIn` | array of role strings | Subject's role must be in the set. |

### Scope

Scope predicates check environmental context. When a scope field is missing from the evaluation context, the result is `Indeterminate` (which becomes `Deny` in strict enforcement mode).

| Predicate | Args | Description |
|-----------|------|-------------|
| `RepoIs` | repo string | Repository must match exactly (e.g., `"org/repo"`). |
| `RepoIn` | array of repo strings | Repository must be in the set. |
| `RefMatches` | glob pattern | Git ref must match the pattern (e.g., `"refs/heads/*"`). |
| `PathAllowed` | array of glob patterns | All changed paths must match at least one pattern. |
| `EnvIs` | environment string | Environment must match (e.g., `"production"`). |
| `EnvIn` | array of environment strings | Environment must be in the set. |

### Glob pattern syntax

Glob patterns used in `RefMatches` and `PathAllowed` support:

| Pattern | Matches |
|---------|---------|
| `*` | Any single path segment (no `/`) |
| `**` | Zero or more path segments |
| `release-*` | Segment starting with `release-` |
| `*-beta` | Segment ending with `-beta` |
| `*feature*` | Segment containing `feature` |

Patterns are restricted to ASCII printable characters, max 256 characters, no `..` path traversal. Consecutive slashes are normalized.

### Signer type

| Predicate | Args | Description |
|-----------|------|-------------|
| `IsHuman` | none | Signer must be a human identity. |
| `IsAgent` | none | Signer must be an AI agent. |
| `IsWorkload` | none | Signer must be an automated workload (CI, cron, etc.). |

### Delegation chain

| Predicate | Args | Description |
|-----------|------|-------------|
| `MaxChainDepth` | integer | Delegation chain must not exceed N levels (0 = root attestation). |

### Workload claims

| Predicate | Args | Description |
|-----------|------|-------------|
| `WorkloadIssuerIs` | DID string | Workload identity issuer must match. |
| `WorkloadClaimEquals` | `{"key": "...", "value": "..."}` | A workload token claim must equal the expected value. Keys must be alphanumeric plus underscore, max 64 characters. |

### Custom attributes

For extension points not covered by first-class predicates:

| Predicate | Args | Description |
|-----------|------|-------------|
| `AttrEquals` | `{"key": "...", "value": "..."}` | Custom attribute must equal the value. |
| `AttrIn` | `{"key": "...", "values": [...]}` | Custom attribute must be in the set. |

Attribute keys must be alphanumeric plus underscore only (no dot-paths, no slashes), max 64 characters.

## Writing policy rules

### Minimal policy

A policy that only checks basic attestation validity:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"}
]}
```

### Organization commit signing policy

Restrict signing to active members of a specific organization, targeting specific repos:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "HasCapability", "args": "sign_commit"},
  {"op": "IssuerIs", "args": "did:keri:EOrg123"},
  {"op": "RepoIn", "args": ["myorg/frontend", "myorg/backend"]},
  {"op": "MaxChainDepth", "args": 2}
]}
```

### Branch protection policy

Allow writes only to feature branches, restricting the main branch:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "HasCapability", "args": "sign_commit"},
  {"op": "RefMatches", "args": "refs/heads/feature-*"}
]}
```

### Role-based access with environment gates

Require different roles for different environments:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "Or", "args": [
    {"op": "And", "args": [
      {"op": "RoleIn", "args": ["admin", "maintainer"]},
      {"op": "EnvIs", "args": "production"}
    ]},
    {"op": "And", "args": [
      {"op": "RoleIn", "args": ["admin", "maintainer", "developer"]},
      {"op": "EnvIs", "args": "staging"}
    ]}
  ]}
]}
```

### AI agent restrictions

Allow AI agents to sign commits but only in specific repos and with path restrictions:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "IsAgent"},
  {"op": "HasCapability", "args": "sign_commit"},
  {"op": "RepoIs", "args": "myorg/docs"},
  {"op": "PathAllowed", "args": ["docs/**", "README.md"]},
  {"op": "MaxChainDepth", "args": 1}
]}
```

### CI workload attestation policy

Verify CI-produced attestations match expected OIDC claims:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "NotExpired"},
  {"op": "IsWorkload"},
  {"op": "HasCapability", "args": "sign_release"},
  {"op": "WorkloadIssuerIs", "args": "did:keri:EGitHubActions"},
  {"op": "WorkloadClaimEquals", "args": {"key": "repo", "value": "myorg/myrepo"}},
  {"op": "IssuedWithin", "args": 300}
]}
```

### Negation: block specific identities

Deny a revoked member while allowing everyone else:

```json
{"op": "And", "args": [
  {"op": "NotRevoked"},
  {"op": "Not", "args": {"op": "SubjectIs", "args": "did:keri:EBannedUser123"}}
]}
```

## Decisions

Evaluating a policy returns one of three outcomes:

| Outcome | Meaning |
|---------|---------|
| **Allow** | All conditions satisfied. |
| **Deny** | One or more conditions failed. |
| **Indeterminate** | Not enough context to decide (e.g., a scope field was missing). |

Each decision includes:

- A machine-readable `ReasonCode` (e.g., `CapabilityMissing`, `Revoked`, `ScopeMismatch`, `MissingField`)
- A human-readable message explaining the decision
- The Blake3 hash of the policy that produced the decision (for audit pinning)

### Evaluation modes

- **`evaluate_strict`**: Used at enforcement points (CI gates, deploy admission). Collapses Indeterminate to Deny.
- **`evaluate3`**: Three-valued evaluation for audit logging, simulation, and retroactive analysis where "unknown" is meaningful.

## Compilation limits

Policies are compiled before evaluation. The compiler enforces safety bounds to prevent denial-of-service from malicious or runaway policy files:

| Limit | Default |
|-------|---------|
| Max JSON size | 64 KB |
| Max AST nodes | 1024 |
| Max tree depth | 64 |
| Max list items per node | 256 |

Compilation also rejects:

- Empty `And`/`Or` children (ambiguous semantics)
- Invalid DID formats
- Invalid capability characters
- Glob patterns with path traversal (`..`)
- Attribute keys with dots or slashes

## Shadow / canary evaluation

The `enforce()` function supports evaluating a shadow policy alongside the primary policy. The shadow policy decision is never enforced -- only the primary decision controls access. When the two disagree, a divergence callback fires for logging and alerting:

```rust
use auths_policy::{enforce, CompiledPolicy, EvalContext};

let decision = enforce(&production_policy, Some(&canary_policy), &ctx, |divergence| {
    if divergence.shadow_would_deny() {
        // Production allows, but the new policy would deny
        alert("Canary policy divergence detected");
    }
});
```

This enables safe rollout of policy changes by observing how a new policy would behave in production before switching it to primary.

## Quorum policies

For actions requiring multi-party approval, `QuorumPolicy` aggregates results across multiple signers:

```json
{
  "required_humans": 1,
  "required_agents": 1,
  "required_total": 2,
  "base_expression": {"op": "And", "args": [
    {"op": "NotRevoked"},
    {"op": "NotExpired"}
  ]}
}
```

Each signer must pass the `base_expression`, and the quorum thresholds must be met across signer types.

## CLI workflow

```bash
# Lint a policy file
auths policy lint org-policy.json

# Compile it (validates, checks limits, shows Blake3 hash)
auths policy compile org-policy.json

# Test against known scenarios
auths policy test org-policy.json --tests org-tests.json

# Diff two policy versions
auths policy diff old-policy.json org-policy.json
```
