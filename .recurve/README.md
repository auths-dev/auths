# auths — claims, probed

> **Reader:** anyone meeting this project's improvement loop for the first
> time. Your next action: run the three commands below; everything else
> follows from what they print.

```bash
recurve ledger      # every claim and its status — the red backlog is the honest one
recurve matrix      # run every probe: GREEN/RED/BROKEN/STALE, and the gate verdict
recurve next        # the highest-value gap to work on right now
```

## How this works (60 seconds)

Every promise this project makes exists in three synchronized places: prose
(`claims/<suite>/GAPS.md`), a ledger entry (`gaps.yaml`), and an
**executable probe** that emits GREEN (proven), RED (not yet true), or BROKEN
(could not measure). Probes for closed claims stay forever as regression
guards, and each keeps a **trap** — a counterexample it must turn RED — so a
weakened probe is caught mechanically.

The loop: one fresh agent per cycle takes the highest-value RED line and
turns it GREEN without breaking any guarded other (`recurve matrix --gate`
is the arbiter). What it can't prove, it parks for human triage. What
machines shouldn't judge (`security-tradeoff`) routes to an adversarial
review protocol instead (REVIEW.md).

## The pieces

| File | What it is |
| --- | --- |
| `.recurve/recurve.toml` | all project variability: suites, tree, freshness, gate |
| `.recurve/claims/<suite>/` | prose + ledger + probes + traps + harness for one domain |
| `.recurve/RUN.md` | the per-cycle agent contract (one cycle, proven, stop) |
| `.recurve/RUN-AUTO.md` | unattended operation runbook |
| `.recurve/REVIEW.md` | the adversarial protocol for review-gated gaps |
| `.recurve/workflows/` | the burndown orchestrator (and a portable shell loop) |
| `.recurve/state/` | run state: parked gaps, run records, receipts (gitignored) |

## Adding a claim

1. Write the prose section in .recurve/claims/<suite>/GAPS.md (observable + negative space).
2. Add a draft entry to that suite's `gaps.draft.yaml` with a probe path.
3. Author the probe (exit 0 GREEN · 1 RED · anything else BROKEN) and a trap
   fixture under `probes/<name>.trap/<fixture>/`.
4. `recurve baseline <suite>` — the ceremony measures it for real and
   promotes it. Nothing enters the ledger as an opinion.
