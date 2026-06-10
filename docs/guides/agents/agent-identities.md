# Agent Identities

Give an AI agent (or any automation) its own cryptographic identity — **delegated
under yours, scoped to what it may do, and expiring on a schedule you set**. The agent
never holds your key; you can prove exactly what you authorized, and revoke it in one
command.

## Why agents get their own identity

An agent signing with a borrowed human credential is indistinguishable from the human.
An Auths agent is a **KERI delegated identifier**: it has its own key and its own
event log, whose first event names you as the delegator — and your identity's event
log anchors that delegation. Any verifier replaying the logs sees:

- *who* authorized the agent (you)
- *what* it was allowed to do (the capability scope)
- *until when* (the expiry)
- *whether the authorization still stands* (revocation is an anchored event)

No bearer tokens, no API keys, nothing to leak that outlives the delegation.

## Create an agent

You need a root identity first (`auths init`). Then:

```bash
auths id agent add \
  --label deploy-bot \
  --key main \
  --scope sign_commit \
  --expires-in 604800        # 7 days
```

```
✓ Agent delegated as a KERI delegated identifier:
  did:keri:EDl7POwC0OH7EzZS2cSweZ65q4Aj14e3fBd-6Lm_1vpt

The root anchored this agent's delegation in its KEL.
```

| Flag | Meaning |
|------|---------|
| `--label` | The agent's name — also the keychain alias its key is stored under |
| `--key` | Your root identity's signing key name (the delegator; default identity key is `main`) |
| `--scope` | Capability to grant (repeatable). Empty = unrestricted |
| `--expires-in` | Expire the agent after N seconds (delegator-anchored) |
| `--curve` | Key curve for the agent (`p256` default, `ed25519` available) |

Interactive alternative: `auths init` → choose the **Agent** profile — it walks you
through capability selection and runs the same delegation.

## What the agent can (and cannot) do

Capabilities are **delegator-anchored**: they live in *your* event log, asserted by
*your* key. The agent cannot widen its own scope — a verifier checks claims against
what you anchored, and a commit claiming a capability outside the agent's grant fails
verification.

Common scopes: `sign_commit`, `sign_release`. Grant the minimum the agent needs.

## Manage agents

```bash
auths id agent list                          # agents you have delegated (excludes devices)
auths id agent rotate did:keri:EDl7... --key main
auths id agent revoke did:keri:EDl7... --key main
```

Rotation (`drt`) and revocation are both anchored by your root — the full lifecycle is
replayable history, which is what makes agent activity auditable after the fact.

## How agent commits verify

Commits made by an agent carry the same `Auths-Id` / `Auths-Device` trailers as human
commits — `Auths-Id` is your root, `Auths-Device` is the agent's delegated
`did:keri:`. `auths verify` replays both logs, checks the delegation anchor, the
expiry at signing position, and the capability scope. A revoked or expired agent's
later commits fail verification; its earlier, in-authority commits remain valid.

## Request authentication (agent passports)

Beyond signing commits, agents can authenticate HTTP requests to relying parties via
the `Auths-Presentation` scheme: a server issues a single-use challenge, the agent
signs it, and the verifier maps the result to a principal with the agent's scopes —
embedding only the lightweight `auths-rp` library (no storage, no Git). See the
[Architecture overview](../../architecture/overview.md) and the `auths-rp` crate docs.

There is also an MCP server (`auths-mcp-server`) exposing signing and verification as
MCP tools for agent frameworks.

## Concepts

The full delegation model — `dip` events, scope seals, narrowing — is in
[Delegation](../../getting-started/delegation.md).
