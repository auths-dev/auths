# PRD: The Intern That Couldn't — attenuation as physics, not policy code

> **One line:** a manager agent spawns worker sub-agents, hands each a *scoped slice*
> of its own authority, and a buggy/injected worker tries to do more than it was
> handed — and the verifier **rejects it even though every signature is valid**,
> because a child cannot hold more authority than its parent, *by construction*.
>
> **Status — honest:** this demo rides on aspirational claim **AGT-1**, which is
> **RED today for a real, non-security CLI-wiring reason** (below). The fail-closed
> scope gate is *implemented and unit-tested in the verifier library*; this demo's
> job is to **build the reachable end-to-end path** — org→dev→agent→sub-agent through
> the CLI/runtime — that makes the property *drivable and provable*, not just
> unit-tested. No hype: until that path lands, AGT-1's probe is RED. This PRD names
> exactly what "GREEN" requires.
>
> **Scope:** READ-ONLY on `../auths` for authoring. The demo, once built, sculpts
> `../auths` (the recurve loop) to turn AGT-1 GREEN. House style: a sibling of
> `death-of-the-api-key` — narrative + falsifiable `gaps.yaml` + accept/adversarial
> probes + a staged `run.sh`.

---

## 1. One line + scenario

A team runs a multi-agent orchestration: a **manager** ("orchestrator") agent
decomposes a task and spawns **worker** sub-agents — a `code-reviewer`, a `committer`,
a `deployer-that-shouldnt-exist`. The manager was delegated by a human developer; the
developer was delegated by their org. So the live chain is **org → dev → manager
agent → worker sub-agent**, four hops, each a real KERI delegation anchored in the
delegator's key-event log.

The manager hands each worker exactly the slice it needs: the `committer` gets
`{sign_commit}`, nothing else. Then the realistic failure: a worker is **buggy, or
prompt-injected, or simply over-eager** — it decides it also needs to `deploy`, or to
act for a *sibling org* it can see in shared context. It assembles a perfectly
well-formed, perfectly-signed request claiming `admin`. Its signature is valid. Its
delegation chain is valid. **It is asking for more than its parent ever held.**

**How it breaks today.** Every incumbent trusts the *issuer to have behaved*. A bearer
token / OAuth access token carries scopes the **authorization server** stamped in; the
resource server reads the scope string and grants — it has no way to re-derive, at
verify time, that the issuer was *itself* allowed to grant that scope. API keys are
ambient authority: possession is permission, with no parent at all. IAM roles are
evaluated against a *central policy the provider controls* — assume-role chains trust
the provider's evaluator, not a cryptographic parent→child containment. In all three,
a mid-chain actor that over-issues (a compromised AS, a misconfigured role, a leaked
key minting broader children) is honored, because **nothing at the far end checks that
each link holds no more than the link above it.**

**What auths does.** The worker's request is a commit claiming `Auths-Scope: admin`.
The verifier resolves the worker's delegated KEL *and* its delegator's KEL, replays the
delegation with delegator-aware lookup, reads the **delegator-anchored scope seal**, and
checks the claim against it. `admin ∉ {sign_commit}` → a distinct fail-closed verdict
(`OutsideAgentScope`). The signature was real. The rejection is real. **The grant the
worker is exercising was never anchored for it by its parent — so it does not exist.**

---

## 2. The property it proves

**Full-chain attenuation, enforced at verify time.** Every link in an
org→dev→agent→sub-agent delegation holds a capability set that is a **subset of its
delegator's**, and the *verifier* — not a policy engine, not the issuer, not a
middleware string-match — re-derives and enforces that containment from the signed
key-event logs alone, offline, on every request. A child cannot hold more than its
parent: the narrowing is anchored into the parent's KEL at delegation time, and read
back from the parent's KEL at verify time. Authority is **monotonically decreasing down
the chain, by construction.** "Attenuation as physics, not policy code."

**Why incumbents structurally can't match it:**

| Incumbent | Where the scope lives | Why it can't enforce full-chain attenuation at verify |
|---|---|---|
| **OAuth/OIDC scopes** | a string in a token the AS minted | The resource server trusts the AS to have only granted what it was allowed to. There is no cryptographic parent the RP can re-derive containment against; a token's scopes are *asserted*, not *contained*. A compromised/over-broad AS issues wider scopes and they are honored. |
| **API keys** | nowhere — possession *is* the grant | Ambient authority with no parent and no chain. Attenuation is impossible: a key is all-or-nothing, and a sub-key is just another key the holder chose to trust. |
| **IAM roles / assume-role** | a policy document in the provider's evaluator | Chained roles are evaluated by the *provider's* central engine against policies the provider stores and mutates. The relying party doesn't verify containment cryptographically — it trusts AWS/GCP. Capture the evaluator or the policy store and the chain says whatever you want. |

None of the three lets a **stranger relying party**, offline, prove from signatures
alone that link *N+1* holds no more than link *N* all the way to the org root. That is
the property, and it is the property that makes a 10,000-agent fleet *insurable*: an
underwriter can price "a sub-agent provably cannot exceed its parent" — they cannot
price "we configured scopes correctly in an issuer we don't control."

---

## 3. Goals — what makes it believable

- **G1 — A real chain, not a toy.** A genuine four-hop delegation
  **org → dev → manager agent → worker sub-agent**, each hop a real KERI `dip`
  anchored by an `ixn` in the delegator's KEL, every key independently generated, the
  whole chain stored as real Git objects under `refs/auths/*`. The audience can `git
  log` the anchors.
- **G2 — A maliciously-broadened mid-chain credential with VALID signatures is
  rejected.** The worker's over-claim is not a malformed request or a bad signature —
  it is a *cryptographically perfect* request asking for authority its parent never
  anchored. The rejection comes from containment, not from a signature failure or a
  policy lookup. This is the visceral beat: *valid signature, still rejected.*
- **G3 — A self-issued broadened child by a mid-chain key-holder is rejected.** The
  manager agent (a legitimate mid-chain key-holder) tries to **self-widen**: spawn a
  worker and grant it more than the manager itself holds. Issuance refuses (subset
  rule), and even if forced, verify refuses — because scope is read from the
  *delegator's anchored seal*, which only the delegator's key can change. A
  key-holder cannot mint authority it was never given.
- **G4 — Believable failure causes.** The over-claim is framed as the three real ways
  agents go wrong: a **bug**, a **prompt injection**, an **over-eager planner** — not a
  cartoon attacker. The point is that *it doesn't matter why*; containment holds
  regardless of intent.

---

## 4. Functional requirements as claims

Each FR is a falsifiable claim with a probe-able **observable (accept)** and an
**adversarial twin (fail-closed, rejected)**. All map to **AGT-1** (commit scope ⊆
delegator-anchored agent scope, enforced at verify, fail-closed). **FR-1 is the
load-bearing one: it builds the missing end-to-end CLI/runtime wiring.**

- **FR-1 — The end-to-end path reaches the scope gate (THE BUILD).**
  *Maps: AGT-1 (smallest_fix).* A delegated worker agent, signing a commit through the
  **CLI/runtime** (not a library unit test), produces a commit whose `Auths-Id` names
  the **root/delegator** and whose `Auths-Device` names the **worker** — resolved as
  two *distinct* KELs, the worker's replayed with **delegator-aware lookup** — so
  `auths verify` actually evaluates the worker's delegator-anchored scope against the
  commit's `Auths-Scope` claim and can return `OutsideAgentScope`.
  - **Observable (accept):** a worker delegated with anchored scope `{sign_commit}`
    signs a commit claiming `Auths-Scope: sign_commit`; `auths verify` returns
    valid/accepted, with the worker as device and the root as identity.
  - **Adversarial twin:** before this wiring, the same flow dies *before the scope
    gate* with `Root KEL failed to replay: Delegator lookup required …` (the documented
    AGT-1 RED). The twin asserts that after the build, the verify path **reaches** the
    scope gate rather than failing on resolution — i.e. a beyond-scope claim is rejected
    *by scope*, not by a replay wall.

- **FR-2 — A broadened mid-chain claim is rejected with a distinct verdict.**
  *Maps: AGT-1.* The worker holds anchored `{sign_commit}` and signs a commit claiming
  `Auths-Scope: admin` (or `deploy`), `admin ∉ {sign_commit}`.
  - **Observable (accept):** the within-scope commit (`sign_commit`) verifies.
  - **Adversarial twin:** the beyond-scope commit is **rejected with the distinct
    `OutsideAgentScope` verdict** (not a generic "invalid"), naming the signer and the
    offending capability — *despite a valid signature and a valid delegation chain.*

- **FR-3 — A mid-chain key-holder cannot self-widen (issuance + verify).**
  *Maps: AGT-1 (the "cannot self-widen" trap).* The manager agent, holding `{commit}`,
  attempts to delegate a worker `{commit, deploy}` — more than the manager itself holds.
  - **Observable (accept):** the manager delegating a worker `{commit}` (a subset)
    succeeds and that worker verifies.
  - **Adversarial twin:** the manager delegating a worker `{commit, deploy}` is
    **refused at issuance** by the subset rule; and a hand-forged worker scope seal not
    signed by the delegator's key fails at verify, because scope is read from the
    *delegator-anchored* seal — only the delegator's key changes it.

- **FR-4 — A worker acting for a sibling org is rejected (wrong-root).**
  *Maps: AGT-1 (delegation names THIS root).* The worker, delegated under org A,
  presents a commit whose `Auths-Id` claims a sibling org B's root.
  - **Observable (accept):** the worker's commit under its true root (A) verifies.
  - **Adversarial twin:** the commit claiming root B is rejected — the worker's `dip` is
    not anchored by B's KEL (`reject_unauthorized_delegate` / "not delegated by the
    claimed root"). A valid agent of A cannot borrow B's authority.

- **FR-5 — Expiry is enforced at verify when a signing time is injected (stretch).**
  *Maps: AGT-1 (anchored expiry, `AgentExpired`).* A worker delegated with `expires_at`
  signs after expiry.
  - **Observable (accept):** a commit signed before `expires_at` verifies.
  - **Adversarial twin:** a commit signed at/after `expires_at` is rejected
    (`AgentExpired`) **when a signing time `now` is injected at the verify boundary** —
    note the witnessed CLI path today passes `now = None`, so this FR also requires
    plumbing the injected signing time through the binary (a smaller sibling of FR-1).

---

## 5. The auths surfaces

Named precisely from `../auths/crates` (dev-privacy, HEAD `3aa4426a` at authoring).
**Distinguish what EXISTS from what this demo must BUILD.**

### Exists (library-level fail-closed scope gate + unit tests + most CLI plumbing)
- **`auths-verifier/src/commit_kel.rs`** — the heart:
  - `CommitVerdict::OutsideAgentScope { signer_did, capability }` (`:80`, returned at
    `:744`) — the **distinct fail-closed verdict** for a beyond-scope claim.
  - `authorize_commit(...)` replays the **device (worker) KEL with
    `replay_with_lookup(Some(&KelSealIndex::from_events(root_kel)))`** — i.e. **delegator-aware
    replay is already wired in the library path**; then `reject_unauthorized_delegate`
    enforces "delegation names THIS root", revocation, and the scope/expiry gate.
  - `verify_commit_against_kel_witnessed(...)` (`:436`) — the wrapper the CLI calls;
    replays the root KEL with `replay_with_receipts`, then `authorize_commit` with
    `now = None`.
  - `verify_commit_against_kel_scoped(...)` (`:533`) — the **`now`-injected** variant
    that also enforces `AgentExpired`; **not** on the witnessed CLI path today.
  - `SCOPE_TRAILER = "Auths-Scope"` (`:254`), `scope_trailer(...)`,
    `read_agent_scope_from_kel(...)` (`:293`), the expiry/scope enforcement (`:730`).
  - Unit tests assert the property: `agent_out_of_scope_signing_rejected`,
    `scope_is_delegator_anchored_not_self`.
- **`auths-keri/src/events.rs`** — `AgentScope` (`:1063`), `encode_agent_scope` /
  `decode_agent_scope`; the KEL `Dip`/`Ixn` events that anchor a delegation + scope seal.
- **`auths-cli/src/commands/sign.rs`** — emits `Auths-Id` = root, `Auths-Device` =
  signer, and an `Auths-Scope` trailer (`commit_trailer_args`, `:70`).
- **`auths-cli/src/commands/verify_commit.rs`** — reads the `Auths-Id`/`Auths-Device`
  trailers (`:435`), resolves **device KEL and root KEL distinctly** via
  `resolve_signer_kel` (`:455`, `:464`), calls `verify_commit_against_kel_witnessed`
  (`:479`), and already maps `OutsideAgentScope` to a CLI message (`:647`).
- **`auths-cli/src/commands/id/agent.rs`** — `id agent add --scope <cap> --expires-in`
  (`:56`, `:60`) → `auths_sdk::domains::agents::add_scoped`.
- **`auths-sdk/src/domains/agents/delegation.rs`** — `add_scoped(...)` anchors the
  scope seal via `mark_agent_scope` and enforces `enforce_scope_subset` (`:127`) — the
  **subset rule at issuance** (a delegate can only narrow). `scope.rs` carries the
  capability-subset / TTL / depth constraints + their unit tests.

### Build (the reachable end-to-end path this demo must produce)
1. **Drive the scope gate from the binary across a real chain (FR-1).** The library
   reaches `OutsideAgentScope`; the open question AGT-1 flags is whether the **CLI/runtime
   end-to-end** (commit creation → trailer emission → distinct device/root KEL
   resolution → delegator-aware replay → scope read) actually lands a *delegated worker's*
   commit on that gate over the demo's registry, rather than tripping the
   `validate.rs:153` "Delegator lookup required" wall. The demo builds the orchestration
   (bootstrap of org→dev→manager→worker) and proves the gate fires through `auths
   verify`, with the worker as `Auths-Device` and the root as `Auths-Id`.
2. **Plumb injected signing time through the witnessed path (FR-5).** Route a signing
   `now` into the witnessed CLI verify so `AgentExpired` is reachable end-to-end (today
   `verify_commit_against_kel_witnessed` passes `now = None`).
3. **The orchestration harness itself** — a scripted manager that spawns workers and
   issues each a scoped slice — and the staged `run.sh`/probes that exercise all of FR-1..5.

If, during the recurve sculpt, FR-1 turns out to already pass end-to-end on the current
checkout, the gap is **reclassified to a regression guard** (status `closed`), exactly
as `death-of-the-api-key` did for DOTAK-1/4/5 — never quietly dropped.

---

## 6. Non-goals

- **NOT a per-credential capability *chain* with broadenable links.** That model — an
  ACDC capability credential whose links could each widen — **does not exist on this
  branch.** The real, implemented model is **delegator-anchored commit scope**: scope is
  a seal in the *delegator's* KEL, narrowed at delegation, read at verify. This demo
  proves *that* model. (The old "capability-credential chain" framing was explicitly
  re-baselined out of AGT-1 on 2026-06-14.)
- **NOT quantitative caps.** "≤ 3 calls / ≤ $100" is **AGT-4**, a separate claim with no
  schema support here. This demo is categorical scope (which capabilities), not numeric
  budgets.
- **NOT human-presence / custody attestation** (AGT-2) — orthogonal.
- **NOT a live LLM driving the agents.** Following `death-of-the-api-key`'s honest
  offline-first stance: the manager/worker *intents* are scripted; every delegation,
  signature, scope seal, and verdict is real and live. Disclosed on screen.
- **NOT cross-org *discovery*.** FR-4 proves a worker can't *borrow* a sibling org's
  authority; it does not build OOBI mutual-introduction (that's AGT-3's open half).
- **NOT a perf claim.** Deep-chain latency is OPS-2; this demo asserts *correctness of
  containment*, not milliseconds.

---

## 7. The narrative / run.sh dramaturgy

Self-performing, staged in acts (like `death-of-the-api-key`): `./run.sh` (the show),
`./run.sh check` (preflight), `./run.sh reset` (pristine). Auto/non-TTY plays itself.

- **Act 1 — The org chart, signed.** Show the chain being built:
  `org → dev → manager agent → worker sub-agents`, each a real `dip` anchored by an
  `ixn`. `git log --oneline refs/auths/*` shows the anchors. Disclose the one honesty:
  intents are scripted, crypto is live.
- **Act 2 — The manager hands out slices.** The manager delegates a `committer` worker
  `--scope sign_commit` and a `reviewer` worker `--scope read`. Print each worker's
  *anchored* scope — read back from the **delegator's KEL**, not asserted by the worker.
- **Act 3 — The workers do their jobs — verified on every commit.** The `committer`
  signs an in-scope commit (`Auths-Scope: sign_commit`) → **accepted**, worker shown as
  device, org shown as identity. The honest framing: *every commit is re-verified from
  the chain, not from a session.*
- **Act 4 — The intern that couldn't (the over-claim).** The `committer` worker goes
  wrong — framed as bug / injection / over-eager planner — and signs a commit claiming
  `Auths-Scope: admin`. **Pledge before proof:** "its signature is valid, its delegation
  is valid; it is asking for more than its parent ever held. Expect rejection."
  `auths verify` → **`OutsideAgentScope`**, naming the signer and the capability `admin`.
- **Act 5 — The self-widen (the manager overreaches).** The manager tries to spawn a
  worker with *more* than the manager holds (`--scope deploy` when the manager has only
  `commit`). Issuance **refuses** (subset rule); the forged seal **fails verify**. "A
  key-holder cannot mint authority it was never given."
- **Act 6 — The wrong org.** The worker presents a commit claiming a *sibling org's*
  root → **rejected** ("not delegated by the claimed root"). Close on the line:
  **"Every signature here was valid. Three were still rejected — because a child cannot
  hold more than its parent, and the verifier checks that on every commit, from the
  chain alone, offline. That is the property no incumbent can state."**

The climax is Act 4: a **valid signature, rejected** — the unsee-able moment.

---

## 8. Success metrics

The show and the probes assert these verdicts (not timings):

- **M1 (accept):** the correctly-attenuated chain verifies — an in-scope worker commit
  returns accepted, with the worker as device and the org root as identity (FR-1, FR-2
  accept).
- **M2 (broadened mid-chain rejected, distinct verdict):** the beyond-scope worker
  commit is rejected with **`OutsideAgentScope`** naming the offending capability —
  distinct from a signature failure or a generic invalid (FR-2 twin). *The signature was
  valid.*
- **M3 (self-widen rejected):** the manager's attempt to delegate more than it holds is
  refused at issuance (subset rule), and a forged-seal worker fails verify (FR-3 twin).
- **M4 (wrong-org rejected):** a worker's commit claiming a sibling org's root is
  rejected as not-delegated-by-that-root (FR-4 twin).
- **M5 (expiry, stretch):** with an injected signing time, a post-expiry worker commit
  is rejected `AgentExpired`; a pre-expiry one verifies (FR-5).
- **M0 (the meta-metric):** **AGT-1's probe goes from RED → GREEN** because a
  delegated-worker commit now *reaches and is judged by* the scope gate through the
  binary — the demo's whole reason to exist.

Every verdict is produced by real `auths-verifier` code over real KEL/TEL events in a
real Git registry. Nothing mocked, slept-then-printed, or hardcoded.

---

## 9. Recurve gap sketch

Draft claims in riclib gap style, ready for `recurve init --from-prd`. IDs `AGENT-ATTEN-*`.
All map to **AGT-1**; `AGENT-ATTEN-1` is the load-bearing build. Probes are RED until
sculpted; reclassify to a `closed` regression guard if a claim is already GREEN at
baseline (the DOTAK precedent).

```yaml
- id: AGENT-ATTEN-1
  title: "A delegated worker's commit reaches the OutsideAgentScope gate through the CLI (end-to-end wiring)"
  maps: AGT-1
  class: missing-surface
  status: open
  one_line: >
    Build the org→dev→manager→worker chain so a worker-signed commit resolves the
    worker as device (delegator-aware replay) and the root as identity, landing on the
    scope gate instead of the "Delegator lookup required" replay wall.
  probe: probes/agent-atten-1.sh
  accept: >
    A worker delegated --scope sign_commit signs an in-scope commit; `auths verify`
    accepts it, device=worker, identity=org-root.
  adversarial: >
    The same flow does NOT die before the gate with "Root KEL failed to replay:
    Delegator lookup required"; a beyond-scope claim is judged by scope, not blocked at
    resolution.

- id: AGENT-ATTEN-2
  title: "A broadened mid-chain commit is rejected with the distinct OutsideAgentScope verdict"
  maps: AGT-1
  class: missing-surface
  status: open
  one_line: >
    A worker holding anchored {sign_commit} that signs a commit claiming admin is
    rejected at verify with a scope-specific verdict, despite a valid signature.
  probe: probes/agent-atten-2.sh
  accept: "Within-scope commit (sign_commit) verifies."
  adversarial: >
    Beyond-scope commit (Auths-Scope: admin) rejected as OutsideAgentScope naming
    signer + capability — not a signature failure, not generic invalid.

- id: AGENT-ATTEN-3
  title: "A mid-chain key-holder cannot self-widen (subset rule at issuance + delegator-anchored seal at verify)"
  maps: AGT-1
  class: missing-surface
  status: open
  one_line: >
    A manager holding {commit} cannot delegate a worker {commit,deploy}; issuance
    refuses, and a forged worker scope seal fails verify because scope is read from the
    delegator-anchored seal.
  probe: probes/agent-atten-3.sh
  accept: "Manager delegating a subset {commit} succeeds; that worker verifies."
  adversarial: >
    Manager delegating {commit,deploy} refused at issuance (subset rule); a hand-forged
    seal not signed by the delegator's key fails verify.

- id: AGENT-ATTEN-4
  title: "A worker cannot act for a sibling org (delegation must name THIS root)"
  maps: AGT-1
  class: missing-surface
  status: open
  one_line: >
    A worker delegated under org A presenting a commit whose Auths-Id claims org B is
    rejected, because A's worker dip is not anchored by B's KEL.
  probe: probes/agent-atten-4.sh
  accept: "Worker's commit under its true root A verifies."
  adversarial: "Commit claiming root B rejected: not delegated by the claimed root."

- id: AGENT-ATTEN-5
  title: "Anchored expiry is enforced end-to-end when a signing time is injected"
  maps: AGT-1
  class: missing-surface
  status: open
  one_line: >
    Plumb an injected signing time through the witnessed CLI verify path so a worker
    commit signed at/after its anchored expiry is rejected AgentExpired (today the
    witnessed path passes now = None).
  probe: probes/agent-atten-5.sh
  accept: "Commit signed before expires_at verifies."
  adversarial: >
    Commit signed at/after expires_at rejected AgentExpired under an injected now;
    absent the now plumbing the gate is unreachable.
```

---

*Generated 2026-06-14. Companion to `roadmap/aspirational_claims/gaps.yaml` (claim
AGT-1) and `roadmap/aspirational_claims/the_missing_layer.md` (group A — WED, the
agent wedge). House style mirrors `auths-demos/death-of-the-api-key`. Surfaces named
against `../auths` @ `dev-privacy` HEAD `3aa4426a`; AGT-1 is RED at authoring for the
CLI-wiring reason stated above — this demo exists to make it GREEN.*
