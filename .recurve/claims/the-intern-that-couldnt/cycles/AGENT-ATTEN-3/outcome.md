# Cycle AGENT-ATTEN-3 — a mid-chain key-holder cannot self-widen (subset rule at issuance)

- **Date:** 2026-06-15
- **Gap:** `AGENT-ATTEN-3` (class `missing-surface`, severity `feature`)
- **Result:** **CLOSED — promoted.** The pre-authored probe + over-grant trap
  were baselined RED; the issuance-time subset check was hardened in `../auths`
  and the probe driven GREEN; the `over-grant-issued` trap stays RED; ATTEN-1,
  ATTEN-2, ATTEN-4, ATTEN-5 still GREEN. Federated gate green (suite probes 5/5
  GREEN + 5/5 traps RED, demo `run.sh --check` exit 0, leakcheck clean).
  `open → closed` in `gaps.yaml`.
- **auths rev:** branch `dev-privacy`.

## The claim, and why it was genuinely RED

A delegate can only *narrow*: a mid-chain key-holder must not be able to mint a
sub-delegation broader than the authority it itself was granted (PRD §4 FR-3,
§3 G3). At baseline a manager holding an anchored scope of `{sign_commit}`
successfully delegated a sub-worker `{sign_commit, deploy}` — exit 0, an agent
DID minted — a self-widen:

```
$ NO_COLOR=1 ./probes/agent-atten-3.sh
ours=over-grant-issued expected=refused — the manager (holding only {sign_commit})
successfully delegated a sub-worker {sign_commit,deploy} (exit 0,
did=did:keri:EAH136SC8…); the issuance-time subset check reads the delegator's own
KEL, not its delegator-anchored seal, so a scoped delegate self-widens   (exit 1 RED)
```

The root cause: `enforce_scope_subset` read the delegator's scope keyed by the
**loaded root prefix** (`root_prefix`), not by the party whose key actually signs
the delegation. A scoped mid-chain delegate signing on the same registry has no
scope seal keyed by the *root* prefix, so the read returned `None` ("unrestricted")
and the wider grant slipped through. Note this is **issuance hardening, not a
containment fix**: the verify-time gate (ATTEN-2) already refuses the over-claim
with `outside-agent-scope`, so the over-broad agent could never have its broader
capability honored — but it could be minted. This cycle closes that defense-in-depth
gap so the broader agent is never issued in the first place.

## The fix (smallest honest change in `../auths`)

`crates/auths-sdk/src/domains/agents/delegation.rs`, `enforce_scope_subset`:

1. Resolve the **delegator** from the signing key (`root_alias`), not the loaded
   root: `ctx.key_storage.load_key(root_alias)` yields the signing identity's own
   `did:keri`, parsed to `delegator_prefix`.
2. Read the scope seal anchored **for that delegator** — `read_agent_scope(&root_kel,
   &delegator_prefix)` — instead of keying the read by `root_prefix`. Scope seals
   are anchored by the party that delegated each agent and keyed by the delegate's
   own prefix, so the manager's `{sign_commit}` grant is found and `deploy` is
   refused.
3. Behavior preserved at the top: a root signing for itself has no self-anchored
   seal → `None` → unrestricted (a top-level root may grant any scope). The
   existing `scope_cannot_exceed_delegator` unit test (root with a self-anchored
   `{read,write}` seal rejecting `{read,admin}`) stays green because the seal is
   keyed by the root prefix, which now equals the resolved delegator prefix.

The one-line truth: the subset check now reads from *who signs*, not *who is
loaded as root*.

## The adversarial twin (kept RED)

`probes/agent-atten-3.trap/over-grant-issued/` — a frozen issuance run that
SUCCEEDED (`issue.code = 0`, `issue.out` carries a minted `did:keri:`) for an
over-grant. The probe's trap arm calls that exit-0-agent-minted outcome RED. A
probe that called a successful over-grant "refused" would be cosmetic; the trap
forbids precisely the self-widen the claim forbids, and stays RED after the fix.

## Gate (the conjunction, in order)

- Suite probes → **5/5 GREEN** (atten-1..5); **5/5 traps RED**.
- `recurve --config .recurve/the-intern-that-couldnt.toml matrix --gate` →
  **exit 0**: holding 5 · ready_to_close 0 · regressions 0 · broken 0 · stale 0;
  sculpt `the-intern-that-couldnt` gate OK; leakcheck clean.
- `cargo test -p auths-sdk` → **332 pass, 0 fail** (126 lib + 203 integration,
  incl. `scope_cannot_exceed_delegator`, + 3 doctests).
- `cargo clippy -p auths-sdk` → clean (no code warnings).
- No loop vocabulary leaked into `crates/` (leakcheck enforces).

## Security-review flag

This cycle changed **agent scope-subset enforcement at delegation issuance**
(`crates/auths-sdk/src/domains/agents/delegation.rs`). Flag for the morning
security-review queue: the authority a scoped delegate may hand out is now read
from the signing key's anchored grant, not the loaded root — verify the
root-is-unrestricted path and the delegate-narrowing path are both correct.

## Files

- `../auths/crates/auths-sdk/src/domains/agents/delegation.rs` —
  `enforce_scope_subset` resolves the delegator from the signing alias and reads
  its anchored scope; `add_scoped` passes `root_alias` through.
- Suite: `probes/agent-atten-3.sh`, `probes/agent-atten-3.trap/over-grant-issued/`
  (frozen counterexample), `gaps.yaml` (ATTEN-3 `open → closed`),
  `cycles/AGENT-ATTEN-3/outcome.md` (this record).
