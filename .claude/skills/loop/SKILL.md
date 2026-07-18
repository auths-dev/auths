---
name: loop
description: Run the improvement loop for auths from *inside this session* — orchestrate cycles by spawning one fresh sub-agent per cycle, gated, until done / capped / parked out
---

# In-session loop

You were invoked to run the auths improvement loop **without leaving this
chat session**. You are the **orchestrator**, not the sculptor — you never edit
`.` yourself. Each cycle is done by a **fresh sub-agent** you spawn; you
read the gate, decide, and move on.

**Why fresh sub-agents.** The loop's safety comes from *one clean agent per
cycle* — no context rot, contained failures, per-cycle rollback. If you sculpted
the cycles yourself, this one long session would accumulate context and start
"remembering" what is not in the ledger. **The ledger is the only memory a cycle
gets.** So: one fresh sub-agent per cycle, handed only the gap id and
`.recurve/RUN.md` — never the prior cycles' conversation.

**Permissions — let cycles flow.** So a cycle never stalls waiting for you to
approve a file write or a command, run this session in a skip-permissions mode
(start it with `claude --dangerously-skip-permissions`, or your host's
equivalent). That is safe *here specifically* because the loop is a cage, not a
trust exercise: each sub-agent is held off the referee surface by the write
boundary, every cycle is a one-command rollback (per-cycle commits), the tree
lock keeps a single writer, and nothing closes without `recurve matrix --gate`.
The safety is the cage — keep `.` scoped and do not point the loop at
paths it must not touch.

## Preconditions — never start on a broken baseline

Run these; if any fails, STOP and report — do not start:

```bash
recurve validate                 # ledger sound: every open gap has a probe + trap
recurve matrix --gate            # the baseline is fleet-green
recurve lock status              # must be UNLOCKED — a held lock means another driver
```

Then **acquire the lock** so a terminal loop or a second session cannot collide
with you:

```bash
recurve lock acquire
```

One loop per tree. If the lock is already held, something else is driving —
stop. Stealing a lock is a human-only act (`recurve lock steal`), never yours.

## The loop — you orchestrate, a fresh sub-agent sculpts

Repeat until a halt condition (below). Each pass:

1. **Pick the work (you):**

    ```bash
    recurve next        # highest-value open gap; review-gated + parked listed apart
    ```

    Skip review-gated gaps (`security-tradeoff`) — those go through REVIEW.md,
    never an unattended cycle. If `next` reports no open work, halt.

2. **Spawn ONE fresh sub-agent for exactly one cycle.** Use this session's
   sub-agent / task tool. Hand it only: the recommended gap id, and the
   instruction to *read `.recurve/RUN.md` and follow it exactly for ONE cycle,
   then stop*. Do not paste earlier cycles' context — the ledger is its memory.
   The sub-agent sculpts the smallest honest change in `.`, rebuilds,
   gates, promotes open→closed, snapshots, commits per policy, writes its run
   record, and STOPS. **One cycle = one sub-agent.**

3. **Judge by the gate, never the sub-agent's word (you):**

    ```bash
    recurve matrix --gate           # the arbiter — the sub-agent's summary is not evidence
    ```

    - Green *and* the gap closed → good cycle; continue.
    - Gate red / gap not closed → the cycle failed. The sub-agent should have
      reverted to the last green per RUN.md; verify the tree is clean
      (`git status`). If a half-cycle was left behind, restore the last
      per-cycle commit's state — never `git reset` shared state by hand. Count a
      failed cycle.
    - Un-greenable after ~3 honest attempts → the sub-agent parks it
      (`recurve park`); you continue past it.

4. **Never touch the referee surface.** Neither you nor the sub-agent may edit
   claims / probes / traps / the gate to make a cycle pass — that is the one move
   the whole system exists to prevent. A weakened probe is caught by its trap at
   the gate regardless; do not try.

## Halt conditions — stop the loop

Stop, and do not start another cycle, when any of these holds:

- `recurve next` reports no open work left (and no pending drafts you were asked
  to arm).
- 3 consecutive failed cycles.
- 2 consecutive cycles that grow the backlog net-positive (runaway
  scope).
- A pending adjudication appears — a human decision is required before more work.
- A cap the human set for this run is reached.

Do **not** keep going because the last cycle went well.

## When you halt

1. Release the lock:

    ```bash
    recurve lock release
    ```

2. Relay the wrap-up **verbatim** — do not summarize away the parked reasons:

    ```bash
    recurve matrix          # what turned green; is the gate holding
    recurve park            # parked gaps + attempt journals (the next run's seed)
    recurve stats           # close rate, attempts, wall-clock by class
    ```

    Then give the human queue, in order: adjudications first, then review-gated
    promotions (REVIEW.md), then parked triage. Per-cycle commits mean a killed
    run lost at most one cycle's work.
