---
name: burndown
description: Launch the unattended claims burndown for auths — sequential fresh agents close RED gaps under the fleet gate until done, capped, or parked out
---

# Burndown launcher

You were invoked to run the unattended improvement loop.

1. Read `.recurve/RUN-AUTO.md` (operator runbook) — verify its preconditions:
   `recurve validate`, `recurve matrix --gate`, `recurve lock status` all
   green/unlocked. If any fails, STOP and report; never start unattended on a
   broken baseline.
2. Launch `.recurve/workflows/burndown.js` via the Workflow tool (knobs via args:
   `cap`, `maxConsecFails`, `parked` seed list) — or, without a workflow
   runtime, run `.recurve/workflows/burndown.sh` with `AGENT_CMD` set.
3. When it halts, relay the wrap-up verbatim: ledger delta, parked gaps with
   reasons, and the ranked human queue (adjudications → review-gated →
   parked). Do not summarize away the parked reasons — they are the next
   run's seed.
