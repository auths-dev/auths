# TROUBLESHOOTING — symptom → which rule fired → what to do

You are an operator whose loop did something unexpected. Find your symptom
below; each entry names the design rule that fired and the exact next action.

## "matrix shows STALE and refuses to run probes"
**Rule:** a probe reading artifacts older than the tree would return a lying
verdict; STALE blocks the gate exactly like BROKEN.
**Do:** run the named suite's rebuild command, re-run `recurve matrix`.
Rebuild proactively after every tree change.

## "matrix shows BROKEN"
**Rule:** BROKEN means "could not measure" (missing oracle, fixture, build) —
absence of evidence never reads as a verdict.
**Do:** fix the harness prerequisite the detail line names. Never start a
cycle on a broken baseline.

## "a trap went GREEN and the gate failed"
**Rule:** every guard probe keeps a counterexample it must turn RED; a probe
that blesses its own counterexample can no longer fail and guards nothing.
**Do:** the probe was weakened (or the trap fixture rotted). Restore the
probe's adversarial path — do NOT delete the trap to get green.

## "validate fails: probe has no trap"
**Rule:** a probe that has never been seen RED is not yet evidence.
**Do:** add a counterexample under `probes/<name>.trap/<fixture>/`, or — if a
fixture is genuinely impractical (perf SLO, live-state) — add a
`trap_waiver: "<why>"` to the entry. Waivers are counted, listed debt.

## "the loop refuses to start: tree is locked"
**Rule:** two loops on one tree corrupt each other; suites sharing a tree
federate into one gate instead of running in parallel.
**Do:** `recurve lock status` names the holder. If (and only if) the holder
is confirmed dead: `recurve lock steal`. Never automate the steal.

## "a commit hung forever"
**Rule:** agents never run a command that can prompt; signing prompts hang
headless agents.
**Do:** set `[commit] policy = "unsigned-per-cycle"` and have humans
sign/squash after the run. If pre-commit hooks are the hang and the gate
provably ran a superset of them this cycle, `hooks = "gate-supersedes"`
permits `--no-verify` — never globally, never to skip a failure.

## "the run halted with 'runaway scope'"
**Rule:** N consecutive cycles filing more gaps than they close means the
backlog is growing under the loop — more cycles won't fix a scoping problem.
**Do:** re-scope: split oversized gaps, park speculative ones, re-run.

## "the run halted on consecutive failures"
**Rule:** repeated failure ≠ try harder forever; per-gap it's ~3 honest
attempts then park.
**Do:** read the attempt journals (`recurve park`), fix the common cause
(usually harness or scoping), seed the next run's `--parked` list.

## "a closed gap's probe went RED"
**Rule:** that is a regression — the ratchet only turns one way; the gate
exists precisely to catch this.
**Do:** the cycle that caused it must repair it before promoting anything.
Find it via the cycle snapshots/per-cycle commits.

## "prose says one thing, ledger says another"
**Rule:** coverage is checked, not hoped; orphan prose gaps are invisible to
the loop and therefore never fixed.
**Do:** `recurve coverage` lists orphans; `recurve import <suite>`
seeds drafts; an agent finding prose contradicting a guard probe must park,
not pick a side — a human adjudicates (`recurve adjudicate`).

## "I need to re-prove the guards actually guard"
**Rule:** the sabotage drill exercises end-to-end what per-probe traps prove
piecewise — and leaves no trace in the ledger or run records.
**Do:** `recurve drill` (optionally `--suite S`).
