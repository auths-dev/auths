# RUN — the sculptor's entrypoint

You are an agent told to run the improvement loop for **auths-network**. This
file is your entrypoint: it tells you your first action and your exact stop
condition.

Your job: run **exactly ONE sculpting cycle** — take the ledger from N red
gaps to N−k, and leave every suite green. Not two cycles. Not "as many as
fit." One, finished and proven, then stop and report.

The whole loop is safe to run because one command is ground truth you cannot
argue with: **`recurve matrix --gate`** exits non-zero on any regression,
broken probe, stale artifact, or a guard probe that blessed its own
counterexample. Anchor every claim to it. A gap is closed when its probe is
GREEN and the gate is green fleet-wide — never because you believe it is.

---

## PREFLIGHT — never start on a broken or stale baseline

```bash
recurve validate     # the ledger must be sound (probes present, traps present)
recurve matrix       # the baseline: note which gaps are RED and that GATE is OK
```

- Any `BROKEN`: a probe is missing its prerequisite — fix the harness first.
  Do not start a cycle on a broken baseline.
- Any `STALE`: a suite's built artifacts predate the tree — those probes
  were NOT run because their verdict would be a lie. Run that suite's
  rebuild command, then re-run. **This is the rule for the whole cycle:**
  every time you change `../auths`, rebuild before trusting any probe.

## TRIAGE — value first; the policy lives in code, not here

```bash
recurve next         # highest-value open gap; review-gated and parked listed separately
recurve cycle new <name> --gaps <ID>    # scaffold the cycle plan with a captured baseline
```

Rules:
- **Never sculpt a review-gated gap** (`security-tradeoff`): a green gate is
  necessary but NOT sufficient there. Those go through REVIEW.md, never
  through an unattended cycle.
- If the gap's `smallest_fix` says "spike first", this cycle produces a
  design in `plan.md`, not code. That is a complete cycle.

## SCULPT — the smallest honest change

Make the smallest change in `../auths` that turns the recommended gap's RED
line GREEN, under the quality constitution (`.recurve/quality.md`). Build,
lint, and tests must be clean. No suppressions.

**Rules you cannot break:**
- Never `git reset`, `git checkout`, or otherwise revert shared state.
- Never touch sacred paths (see `[target] sacred` in recurve.toml).
- No loop vocabulary in the tree: gap IDs, cycle names, and the word that
  names this tool must not appear in product code — the change must stand
  alone as a real feature.
- Problems you discover but cannot close this cycle become NEW draft entries
  with probe sketches — never TODO comments, never silent scope drops.
- ~3 honest attempts on the gap, then park it with what you tried
  (`recurve park <ID> --reason ... --attempt ... --observed ...`) and stop.

## REBUILD

Run the suite's rebuild command. Probes read copied artifacts, not the
tree's build output — an un-rebuilt suite makes every verdict a lie.

## GATE — the conjunction, in order

```bash
recurve probe --gap <ID>     # the gap's own probe: GREEN
recurve matrix --gate        # fleet-wide: zero regressions/broken/stale/failed traps
```

Then the suite's behavioral harness if it has one. All of it, every cycle.

## PROMOTE

Edit the ledger entry `open → closed`. Rewrite its GAPS.md section to
describe the NEW reality (the gap becomes a feature note). Run
`recurve coverage --gate` — prose and ledger must not drift.

## SNAPSHOT + COMMIT

Write `cycles/<name>/outcome.md` (what changed, what the gate said) and the
diffs. Commit policy: **none**.
no git repo detected — `git init` first; per-cycle commits are the loop's rollback granularity

## REPORT — then STOP

Emit one structured run record (see `schema/run-record.schema.json`):
status `closed | parked | no-work-left | failed`, the gap, attempts, files
touched, verdict deltas, one-paragraph summary. Append it with
`recurve record append --file <record.json>`. Then stop. One cycle = one
agent. The ledger is the only memory the next agent gets.
