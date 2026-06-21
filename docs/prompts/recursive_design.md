# Recursive Design — an autonomous, self-improving build system

How the pieces in `docs/prompts/` + `docs/plans/` compose into a closed loop that turns a fixed
**vision** into shipped, proven software — and keeps doing it, cycle after cycle, without drifting.

> **The one-sentence model.** This is a control loop: a **setpoint** (the grounding doc) defines where
> the product must go; a **planner** turns the gap between vision and reality into a work order; a
> **controller** (the runbook) builds it under a fixed **engineering bar** (the meta-prompt); two
> adversarial **sensors** (the reviews) measure drift and risk and emit the next work order. The loop
> *recursively improves the product*; it never rewrites its own constitution. The grounding doc is the
> constant that makes the recursion **converge toward the vision** instead of wandering.

---

## 1. The components (what you have, in control-systems terms)

| File | Role | Owner | Changes |
|---|---|---|---|
| `grounding_doc.md` *(new — the keystone)* | **Setpoint / constitution** — the invariant goal, the anti-goals, the strategic boundaries, the "done-enough" destination, and the `decide-default` defaults | **Human** | Rarely, deliberately |
| `meta_prompt.md` | **Engineering bar** — how any code must be built (typed, fail-closed, curve-agnostic, tested) | Human | Rarely |
| `runbook.md` | **Controller** — how one cycle runs (per-row loop, gates, git workflow, the strengthened test battery) | Human | Occasionally |
| `plan.md` *(new — closes the automation gap)* | **Planner** — turns *grounding + current state + last cycle's findings* into the next `progress.md` | Human-authored prompt; loop-run | Rarely |
| `plans/<area>/<timestamp>/progress.md` | **Work order + state** — this cycle's epics/rows, ordered by attack, with live status | **Loop** | Every iteration |
| `architectural_review.md` | **Sensor 1** — coherence/bloat/drift across the cycle's whole range | Human prompt; loop-run | Rarely |
| `red_team_general.md` | **Sensor 2** — adversarial "green is guilty"; re-derives every claim against real code | Human prompt; loop-run | Rarely |
| `plans/<area>/<timestamp>/cycle_summary.md` *(new)* | **Handoff** — what this cycle changed, the drift check vs grounding, the seed for the next cycle | Loop | Once per cycle |

**The load-bearing rule that keeps it safe:** *the loop may build and merge **product** code, but it may
**never edit its own control files*** — `grounding_doc.md`, `meta_prompt.md`, `runbook.md`, `plan.md`,
or the two review prompts. Those are the constitution; they change only by a human, deliberately. A loop
that can rewrite its own goal or its own safety rules is an *unbounded* recursion (meta-drift) with no
fixed point. Keep the control plane human-owned; let the loop recurse only on the plant (the codebase).

---

## 2. The grounding doc — the new keystone (and the answer to "don't let it drift")

The reviews catch *local* defects; the grounding doc prevents *directional* ones — the loop optimizing
toward a coherent-but-wrong product. It is read at **two** points every cycle: by the **planner**
(what's in-scope to build next) and by the **red-team/architectural reviews** (did we drift out of
scope?). It contains *direction*, never *implementation*:

- **Mission** — one sentence. *("Auths is offline-verifiable, KERI-rooted identity for developers,
  machines, and agents — no central server, no blockchain.")*
- **What Auths IS — the invariants** that every change must preserve. *(Verification is a pure function
  of the bytes given; trust is rooted in a KEL the holder controls; fail-closed; curve-agnostic.)*
- **What Auths IS NOT — the anti-goals** the loop must refuse to build toward. *Your example, verbatim
  in spirit:* **"Auths is not an IdP you keep logging into; it does not become an ongoing consumer or
  issuer of OIDC tokens. The runtime path makes zero calls to a foreign IdP."**
- **Strategic boundaries — the "bridge to, don't become" frontier.** The directional rules that turn a
  fuzzy vision into a decidable in/out test. *Your example:* **"Auths DOES bridge OIDC→native: accept an
  OIDC token *once, at enrollment*, to bootstrap a KERI-native identity, then never depend on the IdP
  again."** (Note this is exactly the runbook's existing *bootstrap-only* rule — the grounding doc is
  where that boundary becomes a first-class, testable invariant the planner and reviews both enforce.)
- **The destination — "done-enough."** What state ends the recursion (or a phase of it): the launch
  criteria, the must-ship surface, the explicitly-deferred. Without a destination, recursion never
  terminates (§5).
- **Decision defaults** — the documented recommended answers that make `decide-default` work, so the
  loop proceeds on reversible calls instead of pausing. *(e.g. "an archived crate with no in-vision
  role → discard, don't resurrect.")*
- **Out of scope for this doc:** the current backlog, file:line detail, anything that changes per cycle.
  Those live in the ledger. If the grounding doc changes every week, it isn't a setpoint.

A change to the grounding doc is a **human act** — it is how you *steer*. Everything downstream re-plans
against the new setpoint on the next cycle.

---

## 3. The closed loop (the cycle)

```
            ┌──────────────────────────────────────────────────────────────┐
            │                      grounding_doc.md                         │
            │            (setpoint: vision · anti-goals · destination)      │
            └───────────┬───────────────────────────────────┬──────────────┘
            reads (scope)│                                   │reads (drift check)
                         ▼                                   ▼
   ┌─────────┐     ┌──────────┐     ┌──────────────────┐     ┌──────────────────┐
   │ last    │────▶│  PLAN    │────▶│      BUILD       │────▶│     REVIEW       │
   │ cycle's │     │ plan.md  │     │  runbook.md +    │     │ architectural_   │
   │ reviews │     │  →       │     │  meta_prompt.md  │     │ review.md +      │
   │+summary │     │progress  │     │  (per-row loop,  │     │ red_team_        │
   └─────────┘     │  .md     │     │  proof-gates)    │     │ general.md       │
        ▲          └──────────┘     └──────────────────┘     └────────┬─────────┘
        │                                                             │ findings
        │              cycle_summary.md  ◀── drift check vs grounding │ (per Step 4:
        └─────────────────────────────────────────────────────────────┘  test levels)
                         next cycle's timestamp folder
```

1. **GROUND** — read `grounding_doc.md`. It is the only source of *direction*.
2. **PLAN** (`plan.md`) — synthesize {grounding roadmap + repo `HEAD` state + the previous cycle's two
   review reports + `cycle_summary.md`} into the next `progress.md`: epics ordered by attack, each row
   gated (`proof-gate` / `audit-flag` / `decide-default` / `gated-ext`) per the runbook. **Reject at
   plan-time any row that violates a grounding invariant or crosses an anti-goal** — drift is cheapest
   to stop before it's built.
3. **BUILD** (`runbook.md`, bar = `meta_prompt.md`) — burn the ledger down row by row: verify premise →
   RED-first **on the wired path** → GREEN → red-team-until-dry → local green-gate → merge. No per-PR
   human gate; verifier/crypto rows merge on the strengthened battery and carry `audit-flag`.
4. **REVIEW** — over the cycle's whole commit range, run both sensors. They **diagnose, never auto-fix**.
   Output: architectural drift/bloat + adversarial findings, each naming the test *level* that closes it.
5. **RE-GROUND** — write `cycle_summary.md`: what merged, the **drift check** ("did anything cross a
   grounding boundary?"), and the seed for the next cycle. The review findings + grounding roadmap are
   the next `progress.md`. Loop.

Each cycle is one timestamp folder (`plans/<area>/<YYYYMMDD>/`) holding `progress.md`, the two review
reports, and `cycle_summary.md` — a complete, auditable record. The tree itself stays free of process
metadata (runbook directive); the *history* lives in the cycle folders + git.

---

## 4. "Can an agent endlessly run it?" — three levels, and which to pick

| Level | Autonomy | Human touch | When |
|---|---|---|---|
| **L0** | One cycle, human drives each phase | Every phase | Bootstrapping; what you do today |
| **L1 — recommended** | **Autonomous *within* a cycle; pause at the cycle boundary** | Approve the next ledger + steer grounding | Steady state, pre-launch |
| **L2** | Autonomous *across* cycles (truly endless) | Only on one-way-doors + the pre-launch audit | Only after L1 has proven safe over many cycles |

**Endless = a sequence of bounded cycles, not one unbounded run.** "Run forever" is implemented as: a
scheduler (cron, the loop tool's wake-up, or CI) that, at each boundary, runs PLAN→BUILD→REVIEW and then
either **notifies-and-waits** (L1) or **auto-continues within budget** (L2). The bound per cycle is what
makes it tractable — a finite ledger, a token/agent budget, a wall-clock cap.

**Recommendation:** run **L1**. Let the loop take a whole ledger to completion and produce the next one,
but require a human "go" at the boundary — that one checkpoint is where you (a) confirm direction against
the grounding doc, (b) catch a cycle that gamed its metric, and (c) decide whether the destination is
reached. It keeps ~95% of the autonomy at ~5% of the risk. Graduate to L2 only when you've watched
several L1 cycles converge and the product is still pre-launch (so a bad cycle is "fix before users,"
not "harm a user").

---

## 5. The drawbacks of endless recursion (honest — these are real and partly irreducible)

1. **Specification gaming / Goodhart.** The loop optimizes the *measurable* (rows merged, tests green),
   not the *intended* (the property holds). You have already seen this: green tests on dead code,
   security tests commented out to go green. *Counter:* the red-team's "green is guilty," the
   review-feeds-the-next-ledger immune system, and the rule that **the loop never authors its own success
   criteria** (they come from the grounding doc + the reviews, not the builder).
2. **Directional drift.** A thousand locally-sensible changes can walk the product somewhere the vision
   never intended (becoming an IdP, say). *Counter:* the grounding doc as a setpoint, checked at *both*
   plan-time and review-time. This is the single reason the grounding doc exists.
3. **The oracle problem.** The loop cannot fully verify itself; the reviews are LLM passes that can share
   blind spots with the builder. *Counter:* independent oracles (keripy, RFC vectors) for differential
   testing, agent diversity across review rounds, and the **one batched human crypto audit** before
   launch for the residual no machine catches.
4. **Entropy / bloat / compounding error.** Each minimal change can erode global coherence until no one
   can hold the system in their head; small errors compound across cycles. *Counter:* the architectural
   review every cycle + an explicit **complexity budget** (deletion ratio, public-surface count) that a
   cycle must not blow.
5. **Non-termination / divergence.** A review *always* finds something, so "all rows merged" may never
   arrive; recursive self-improvement can expand scope forever or oscillate. *Counter:* a **destination**
   in the grounding doc, per-cycle budgets, and a **diminishing-returns stop rule** — when a full review
   cycle yields only LOW/INFO and the destination criteria are met, *stop* (or drop to on-demand).
6. **Cost / compute runaway.** Endless loops burn tokens and CI with no natural brake. *Counter:* hard
   per-cycle budgets and the agent-count caps; a runaway trips the budget, not your bill.
7. **Direction is a human prerogative.** The loop can improve *toward* a goal; it cannot *choose* the
   goal or make value/strategy/portfolio calls. *Counter:* grounding supplies direction; `decide-default`
   handles reversible calls; one-way-doors and cycle boundaries reserve the rest for you.
8. **Map/territory desync.** The ledger and reviews are a *model* that can drift from the real repo (a row
   says `merged` while the property silently regressed). *Counter:* premise-correction (verify vs `HEAD`
   first) and reviews that re-derive against real code, never against the ledger's claims.
9. **Autonomy is itself an attack surface.** An agent with merge rights is a supply-chain risk — a
   prompt-injection, a poisoned dependency, or one bad cycle could ship harm. *Counter:* the secrets-scan
   gate, no-auto-merge on one-way-doors, branch protection, the pre-launch audit, and human cycle
   boundaries. **Never give the loop credentials to a live external system** (that's what `gated-ext` is).

The honest summary: a fixed setpoint + adversarial sensors + bounded cycles + human boundary checkpoints
make recursion *converge and stay safe* for the **product**. They do **not** make it safe to let the loop
recurse on its own **constitution**, nor do they remove the human's job of *steering* and *deciding when
done*. Design for "autonomous execution, human direction," not "autonomous everything."

---

## 6. The guardrails, as design invariants

- **Control plane is human-only.** The loop cannot edit grounding / meta-prompt / runbook / plan / review
  prompts (§1). Enforce with a path-deny in the build gate.
- **Two grounding checkpoints.** Plan-time (don't plan out-of-vision work) *and* review-time (did we
  drift?). The red-team gets an explicit "scope/anti-goal drift" lens.
- **Bounded cycles + budgets.** Finite ledger, token/agent/wall-clock budget, complexity budget. Endless
  = many bounded cycles.
- **Diminishing-returns termination.** Stop the recursion when a clean cycle yields only LOW/INFO and the
  grounding destination is met. Recursion is a means, not the goal.
- **Decide-default vs one-way-doors.** Autonomous on reversible calls; pause on irreversible ones.
- **The pre-launch audit** is the one batched human step on the verifier/crypto surface — milestone, not
  per-PR gate.
- **Every cycle is auditable.** The timestamp folder is the provenance record; git is the ground truth.

---

## 7. File & folder topology

```
docs/prompts/
  grounding_doc.md         # NEW — the constitution (setpoint). Human-owned.
  recursive_design.md      # this file — how the system composes.
  meta_prompt.md           # the engineering bar.
  runbook.md               # the controller (per-cycle operating procedure).
  plan.md                  # NEW — the planner prompt (grounding + last review → next progress.md).
  architectural_review.md  # sensor 1 (coherence/bloat/drift).
  red_team_general.md      # sensor 2 (adversarial; green is guilty).

docs/plans/<area>/<YYYYMMDD>/        # one folder per cycle
  progress.md                        # the work order + live status (the loop's source of truth).
  architectural_review_<date>.md     # this cycle's sensor-1 report.
  red_team_<date>.md                 # this cycle's sensor-2 report.
  cycle_summary.md                   # NEW — what changed, drift check vs grounding, seed for next cycle.
```

Two artifacts are new and close the automation gap: **`plan.md`** (so the next ledger is *generated*, not
hand-authored) and **`cycle_summary.md`** (the explicit cycle-to-cycle handoff). Plus **`grounding_doc.md`**
(the setpoint).

---

## 8. One cycle, end to end (the executable lifecycle)

1. **Ground.** Read `grounding_doc.md`.
2. **Plan.** Run `plan.md` → emit `plans/<area>/<today>/progress.md`. Inputs: grounding roadmap, repo
   `HEAD`, previous cycle's two reviews + `cycle_summary.md`. Drop any row that crosses an anti-goal.
3. **Build.** `/loop` over the ledger per `runbook.md` until every row is `merged`/`gated`. (This is the
   loop prompt you already have, pointed at the new folder.)
4. **Review.** Run `architectural_review.md` then `red_team_general.md` over `<cycle-base>..HEAD`. Reports
   land in the same folder. Each finding names its closing test level (Step 4).
5. **Re-ground.** Write `cycle_summary.md`: merged list, the **drift check** vs grounding, residual risk,
   and the seed backlog for next cycle. If the destination criteria are met and findings are only
   LOW/INFO → **stop / go on-demand**. Else → boundary checkpoint (L1: human "go"), then back to step 1.
6. **Pre-launch, once:** the batched human crypto audit over all `audit-flag` rows.

---

## 9. Is there a better way? — the recommendation

You're ~80% there. The highest-leverage additions, in order:

1. **Write `grounding_doc.md` first.** It's the missing setpoint and the thing that answers "don't let it
   drift." Without it, the recursion is a random walk with good local hygiene. (It would already have
   *encoded* your OIDC boundary as a testable invariant.)
2. **Add `plan.md`** so the next ledger is generated from {grounding + last review}, not hand-built — that
   is the one manual step between you and L1 autonomy.
3. **Add `cycle_summary.md`** as the cycle handoff (and the drift check).
4. **Run at L1** (autonomous-within-cycle, human-at-the-boundary). Don't reach for L2/endless until L1 has
   visibly converged across several cycles *and* you've added budgets + the diminishing-returns stop rule.
5. **Forbid the loop from editing the control plane.** One path-deny rule; it's the difference between
   recursive *product* improvement (safe, convergent) and recursive *self*-modification (unbounded).

Net: keep **execution** autonomous and **direction** human. The grounding doc is how you steer; the
reviews are the immune system; the bounded cycle is the heartbeat; and the one rule that the loop may not
rewrite its own constitution is what keeps the whole thing pointed at the vision instead of at the metric.
