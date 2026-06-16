# Sculpting cycle: a-forked-kel-is-rejected

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| WIT-1 | murmur | headline | missing-surface | `wit-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **WIT-1** — Make the replay refuse a FORKED KEL (two different rotations claiming the same sequence number must be rejected, never silently last-writer-wins) and make a relay-suppressed / stale key-state FAIL the witness-threshold check (a key-state under the receipt threshold, or staler than a corroborated witness set, is not accepted as current). This is the single most important correctness dependency: MSG-2's verified-continuation badge is only trustworthy if the key-state it replays is the one true witnessed log. Adversarial (the trap): a forked KEL accepted, or a stale/relay-suppressed key-state passed without witness corroboration, must fail. TRAP probes/wit-1.trap/forked-kel/ — a captured replay where a forked or stale key-state was accepted must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **WIT-1** unlocks: The correctness root of the whole continuity story — the badge means something only because the log under it is the one true witnessed log.

## Definition of done (the GATE)

- [ ] Every gap probe above flips RED → GREEN (`recurve probe --gap <id>`).
- [ ] `recurve matrix --gate` green across all suites: zero regressions, zero broken.
- [ ] Each touched suite's harness green.
- [ ] Tree changes satisfy the quality constitution (parse-don't-validate,
      ports/adapters, one source of truth); build/lint/tests clean; no suppressions.
- [ ] `gaps.yaml` statuses promoted open→closed; `GAPS.md` prose updated to
      describe the NEW reality (the gap becomes a feature note).
- [ ] Anything discovered mid-cycle that can't be closed is filed as a NEW gap
      with its own RED probe (the loop never silently drops scope).

## Matrix baseline (captured at cycle start)

```
    gap         outcome   status     Δ        detail
  ○ WIT-1       RED      open                 ours=feature-absent expected=fork-rejected+stale-caught — th

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
