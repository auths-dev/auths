---
name: cycle
description: Run exactly ONE improvement cycle for auths — triage the highest-value RED gap, sculpt, gate, promote, snapshot, stop
---

# Single cycle

You were invoked to run one sculpting cycle by hand (no orchestrator).

Read `.recurve/RUN.md` and follow it exactly — it is your entrypoint and your stop
condition. The short form: `recurve validate && recurve matrix` (clean
baseline), `recurve next` (triage), sculpt the smallest honest change,
rebuild, `recurve matrix --gate` (the arbiter), promote open→closed +
rewrite the prose, snapshot, commit per policy, append your run record
(`recurve record append`), STOP. One cycle = one agent — do not start a
second cycle because the first went well.
