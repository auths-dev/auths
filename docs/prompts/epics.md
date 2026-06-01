# Auths — Epic Plan Generation Prompt

> Paste or load this file at the start of a new LLM session. It instructs you to **review the codebase and produce an actionable epic plan** that complies with the strategic posture defined in `prompt.md`. This is a task-specific prompt; `prompt.md` is the substrate. Read `prompt.md` first, in full, before proceeding.

---

## 1. Mission

Produce **`epic_plan.md`** — a complete, prioritized, implementable epic plan that takes Auths from its current pre-launch state to a launch-ready, spec-compliant KERI implementation.

The plan must be detailed enough that an engineer can pick up any epic, read its subtasks and code snippets, and start work without further design discussion.

You are not asked to *implement* anything in this session. You are asked to *plan*, with enough precision that implementation is mechanical.

---

## 2. Prerequisite reading

In this exact order. **Do not write a single epic before completing this reading.**

1. **`prompt.md`** — the strategic posture. All 11 sections. The "Strategic posture for this session" (§ 4) and "What NOT to do" (§ 8) are non-negotiable constraints on your output. The "Priority work" (§ 5) is your initial outline.
2. **`CLAUDE.md`** — project conventions. Your code snippets must respect every rule here (clock injection, error types, `unwrap` policy, dependency direction, etc.).
3. **`SECURITY.md`** — memory hygiene rules. Crypto-touching code snippets must respect every rule.
4. **`ARCHITECTURE.md`** — current crate layering. Your epic assignments (which crate gets the change) must respect the bounded-context guide.
5. **`docs/architecture/multi_device_accepted_risks.md`** — existing Epics 1–6 roadmap. Your plan extends and supplements this, never contradicts it.
6. **`docs/plans/keri_compliance.md`** — the compliance audit. Every CRITICAL and MAJOR finding maps to one or more tasks in your plan. Quote finding IDs (F-01, F-06, etc.) in your task descriptions.
7. **`docs/architecture/cryptography.md`** — the wire-format curve tagging rule. Your crypto-related epics must respect this.
8. **`docs/security/primitive-inventory.md`** — the crypto primitive inventory + known concerns. The "known concerns" section is partial backlog material.

Optionally, for context:
- `critique.md` (prior session's security/architecture review — most findings still apply)
- `critique_epics.md` (prior session's epic plan — **do not copy its strategic direction**; the user rejected its "fork KERI" recommendation. Use it only for cross-cutting improvements that don't depend on forking)

---

## 3. What to produce

**Output: a single file at `/Users/bordumb/workspace/repositories/auths-base/auths/epic_plan.md`.**

The file must contain:

### 3.1 Top-of-document summary

- Priority table: epic number, name, status (new / supplements existing roadmap epic N / fixes finding F-NN), focused estimate, buffered estimate.
- Total estimate, both focused and with 50% buffer, in eng-weeks and calendar months for one and two engineers.
- Critical path diagram (ASCII) showing sequencing constraints.

### 3.2 Per-epic structure

Every epic must include:

- **Goal.** One sentence. What done looks like.
- **Closes.** Which `keri_compliance.md` findings or accepted-risks items this epic resolves. Quote IDs.
- **Prerequisites.** Which other epics must land first.
- **Subtasks**, each with:
  - A short rationale (why this change, in one or two sentences).
  - The specific file(s) and (when known) line ranges that change.
  - A **code snippet** showing the actual change. Before/after where the contrast is informative; just "after" otherwise. Snippets must be valid Rust that would compile in context (modulo `...` elisions).
  - An individual estimate in eng-days.
- **Verification.** How you'll know the epic is done. Concrete test names, CI gates, or fixture round-trips — never vague.
- **Epic total estimate.**

### 3.3 Required epics

At minimum, your plan must include epics covering:

- **Epic A: Spec-compliance wire-format fixes.** Closes all CRITICAL and MAJOR findings in `keri_compliance.md`. Maps to Epic 4 in `multi_device_accepted_risks.md`. **This is P0 — sequenced first.**
- **Epic B: Dual-index CESR signatures + true removal.** Supplements Epic 1 in the existing roadmap. Your version should refine the existing spec with concrete code.
- **Epic C: Multi-sig threshold upgrade (`kt ≥ m` of `n`).** Supplements Epic 2 in the existing roadmap.
- **Epic D: Witness infrastructure (minimum viable for launch).** Supplements Epic 3. Scope down to "one Auths-operated witness with the architecture to add more later" — do not try to land full multi-witness diversity at launch.
- **Epic E: Crypto provider trait completion + dependency hardening.** Covers the cross-cutting items in `prompt.md § 5`: `sign_p256` trait method, `rand::random` replacement, `cargo deny` in CI, exact-pin crypto deps, Rekor trust-root decision.
- **Epic F: Backup, recovery, and durability.** `auths backup export/import`, Git GC disable on init, `auths sync` as a first-class command, pre-rotation seed escrow on co-controllers.
- **Epic G: Agent delegation as the headline feature.** Distinct from commit signing. Includes the verifier-side scope-down logic and an end-to-end demo.
- **Epic H: Scope consolidation + cross-impl interop CI gate.** Consolidate the workspace (32 crates → ~12, per `critique.md`). Add a CI gate that round-trips Auths-produced KELs through KERIox. Delete or feature-gate dormant infrastructure (`auths-infra-rekor`, `auths-transparency` with `[0u8; 32]` placeholder trust root, `auths-mobile-ffi` until F-14 lands).

You may add additional epics if you identify gaps. You may split an epic into sub-epics if scope warrants. You may not omit any of the above.

### 3.4 Deferred section

A final section listing what is **deferred to post-launch**, with a one-line rationale per item. Per the user's recorded preference, this section must include a step to file a GitHub issue per deferred item.

---

## 4. Quality bars

Your plan will be reviewed against these criteria. Self-check before declaring complete.

### 4.1 Compliance with strategic posture

- [ ] No epic proposes forking the KERI wire format.
- [ ] No epic proposes renaming `did:keri:` to anything else.
- [ ] No epic proposes replacing Blake3 with SHA-256 (or vice versa) on a non-compliance basis.
- [ ] No epic proposes dropping CESR, dropping witnesses, or dropping multi-sig.
- [ ] No epic proposes adding `Utc::now()` to domain code.
- [ ] No epic proposes adding a Rekor / Sigstore submission crate. (`auths-infra-rekor` is to be deleted, not enhanced. Users submit via `cosign` / `rekor-cli`.)
- [ ] No epic proposes a `kt=1` shared identity in any production path.

### 4.2 Concreteness

- [ ] Every subtask names specific files (e.g., `crates/auths-keri/src/validate.rs:766-797`).
- [ ] Every code snippet is realistic — types, function signatures, and crate imports match what's in the codebase today.
- [ ] Every estimate is in eng-days for a subtask, eng-weeks for an epic. No vague ranges.
- [ ] Every verification criterion names a concrete test or fixture, not "tests pass."

### 4.3 Sequencing

- [ ] Epic A (spec compliance) lands before Epic B (which depends on the dual-index work).
- [ ] Epic B lands before Epic C (multi-sig needs dual-index sigs).
- [ ] Epic D (witnesses) sequences after Epic C — without multi-sig, witnesses ratify a kt=1 race winner rather than a true threshold-met event.
- [ ] Epic E (crypto trait + deps) is parallel-safe with Epic A. Show in the critical-path diagram.
- [ ] Epic F (backup) is parallel-safe with Epic A but must not block launch.
- [ ] Epic G (agent delegation) depends on Epic A landing (the event model must be stable).
- [ ] Epic H (scope consolidation + CI gate) runs throughout; cross-impl CI gate must be live before Epic A is declared complete.

### 4.4 Spec-traceability

- [ ] Every Epic A subtask quotes the `keri_compliance.md` finding ID it closes (F-01, F-04, F-06, F-10, F-13, F-14, F-15, F-16, F-19, F-32, etc.).
- [ ] Every wire-format-touching subtask references the relevant section of ToIP KERI v1.1 by section number.

### 4.5 User-preference compliance

- [ ] No epic proposes work that requires the user to commit on your behalf.
- [ ] No epic refers to `.flow` task IDs (`fn-N.M`) in code that would land in committed files.
- [ ] Any "Out of scope" section includes a step to file a GitHub issue.
- [ ] No epic proposes intermediate `cargo build` / `cargo test` runs as the deliverable for a subtask — these are sanity checks at epic boundaries, not work products.

---

## 5. Format template per epic

Use this exact template for consistency. The user will scan the document by skimming epic headers and tables; consistency makes that fast.

```markdown
## Epic <letter> — <name>

**Goal:** <one sentence>

**Closes:** <compliance-finding IDs, accepted-risk items, or "new gap not previously tracked">

**Prerequisites:** <other epic letters, or "none">

**Parallel-safe with:** <other epic letters, or "n/a">

### <letter>.1 <subtask name>

**Why:** <one or two sentences>

**Files:**
- `crates/<crate>/src/<file>.rs:<lines>`
- ...

**Spec reference (if applicable):** ToIP KERI v1.1 § <X.Y>; `draft-ssmith-<spec>-03` § <Z>.

**Change:**

​```rust
// BEFORE (if informative)
...

// AFTER
...
​```

**Estimate:** <N> eng-days.

### <letter>.2 ...

...

### Verification

- <concrete test name or CI gate>
- <concrete test name or CI gate>
- Cross-impl round-trip: <what exactly>

### Epic <letter> total: <N> eng-days ≈ <M> eng-weeks focused.
```

---

## 6. Anti-patterns to avoid

These shape what your plan *isn't*, as much as the quality bars shape what it *is*.

1. **Do not propose any epic whose deliverable is "documentation only."** Documentation is part of every epic; it is not an epic itself. The exception is `SPEC.md`-style work, which is a deliverable inside Epic A and Epic G.
2. **Do not propose epics that "investigate" or "evaluate."** Investigation belongs in a 0.5-day spike inside a concrete epic, not as a standalone deliverable.
3. **Do not pad estimates.** The user reads them and the 50% buffer is applied at the document level, not per task. Inflated per-task estimates compound badly.
4. **Do not write epics for code paths that should be deleted.** If `auths-mobile-ffi` should be deleted until the spec stabilizes, the epic action is "delete," not "rewrite." Same for `auths-infra-rekor`, `auths-transparency`, and any other dormant code.
5. **Do not propose backwards-compat shims, deprecation periods, or migration guides for internal code.** Pre-launch, zero users.
6. **Do not propose features that contradict the deferred list in `prompt.md § 5`.** SCIM, Radicle integration, external federation, mixed-curve controllers are out of scope.
7. **Do not invent finding IDs.** If a problem is real but not in `keri_compliance.md`, name it descriptively rather than fabricating a finding ID.
8. **Do not propose changes to the strategic posture itself.** If you believe a posture decision in `prompt.md § 4` is wrong, flag it at the *top* of your plan in a "Recommendations for the user to consider" section, but do not rewrite epics around the unaccepted change.

---

## 7. First-session checklist

Before writing the first line of `epic_plan.md`, confirm:

- [ ] You have read `prompt.md` in full.
- [ ] You have read `CLAUDE.md`, `SECURITY.md`, `ARCHITECTURE.md`.
- [ ] You have read `docs/architecture/multi_device_accepted_risks.md` and `docs/plans/keri_compliance.md`.
- [ ] You have skimmed `docs/architecture/cryptography.md` and `docs/security/primitive-inventory.md`.
- [ ] You have run `find crates -name "*.rs" | head -50` and looked at the actual crate structure.
- [ ] You have looked at `crates/auths-keri/src/validate.rs`, `events.rs`, and `said.rs` — these are where most of Epic A's work lands.
- [ ] You have looked at `crates/auths-id/src/keri/shared_kel.rs` — this is where Epic B and C land.
- [ ] You have an explicit mapping in your notes from every CRITICAL and MAJOR `keri_compliance.md` finding to a subtask in Epic A.

Only then begin writing `epic_plan.md`.

---

## 8. How to handle ambiguity

If you encounter a design question while planning:

- **Spec-defined** (i.e., the answer is in ToIP KERI v1.1 or a CESR / SAID draft) — follow the spec. Quote the section number in the subtask.
- **Posture-defined** (i.e., the answer is in `prompt.md § 4` or § 8) — follow the posture.
- **Convention-defined** (i.e., the answer is in `CLAUDE.md` or `SECURITY.md`) — follow the convention.
- **Genuinely undecided** — name the question in a "Decisions deferred to implementation" subsection inside the relevant epic. Do not invent an answer; flag it so the user can decide before implementation starts.

Common shape: "Should the new threshold validator reject `bt > |b|` strictly or allow it for forward compatibility?" — flag as decision deferred, propose the strict answer with rationale, leave room for the user to override.

---

## 9. Output expectations

The user will read `epic_plan.md` end to end. Optimize for:

- **Skimmability:** clean headers, tables for priority and estimates, ASCII critical-path diagram.
- **Density:** no filler, no restating the prompt, no apologies. The user has read `prompt.md`; do not re-explain it.
- **Actionability:** every subtask should be picked up by an engineer who has read the prompt and the linked files, without further conversation.
- **Honesty:** if an epic is uncertain in scope, say so explicitly with the source of uncertainty. Do not paper over with confident-sounding prose.

When you finish, end the document with a one-sentence note: "Ready for review."

---

Begin by completing § 2 (Prerequisite reading). Do not produce the plan from memory of these documents — actually read them. The codebase has evolved; your training data has not.
