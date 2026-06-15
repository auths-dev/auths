# RUN-AUTO — unattended operation addendum

You are the operator starting an unattended burndown on **auths-network**. Your
first action: read .recurve/RUN.md (the per-cycle contract), then start the
loop with `.recurve/workflows/burndown.sh` (any agent harness) or
`.recurve/workflows/burndown.js`
(orchestrator runtime). Your stop condition: the loop halts itself.

## Before you start

- `recurve validate && recurve matrix --gate` must both be green. An
  unattended run started on a broken baseline burns every cycle on the same
  rock.
- `recurve lock status` must say unlocked. Two loops on one tree corrupt
  both; the loop refuses to start if a lock is held. If the holder is
  confirmed dead, a human runs `recurve lock steal` — never automate this.
- Keep the machine awake for the duration (on laptops, a keep-awake tool);
  a sleeping machine reads as a hung agent to any watchdog.
- Commit policy is **none** — verify the loop can commit without
  any prompt (signing prompts hang headless agents; that is why unsigned
  per-cycle commits exist).

## The loop's own guarantees (you do not babysit these)

- **Park-and-continue:** an un-greenable gap is parked with an attempt
  journal; the loop moves on. It halts only on: no work left, the cycle cap,
  3 consecutive failures, or 2 consecutive
  net-gap-positive cycles (runaway scope).
- **Per-cycle commits** mean a dead run loses at most one cycle's work.
- **Timed-out agents count as failed cycles**, not hangs.

## Resume after a kill / crash / sleep

1. `git log` — per-cycle commits show exactly which cycles landed.
2. `recurve matrix` — trust only the gate, not the dead run's logs.
3. A half-written cycle (sculpt without gate) is reverted by consulting the
   last cycle snapshot diff — never by `git reset` on shared state.
4. Restart the loop; it re-derives everything from the ledger. Seed
   `--parked` with still-stuck gaps from `recurve park`.

## When it finishes

Read the wrap-up record (`.recurve/records.jsonl`): ledger delta, parked
list with reasons, the review queue. The human queue is ranked: adjudications
first, then review-gated promotions, then parked triage.
