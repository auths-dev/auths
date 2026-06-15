# Sculpting cycle: a-delegated-device--the

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| MSG-4 | murmur | headline | missing-surface | `msg-4.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **MSG-4** — Resolve a delegated device to its root: open() must verify a message from a delegated device (the Mac) as the SAME root AID (device=Mac, identity=root), and after the root revokes that device its next message must FAIL to verify for every contact. Adversarial (the trap): a message from a revoked device must be rejected (clawback from the chain), not accepted. TRAP probes/msg-4.trap/revoked-device-accepted/ — a captured flow where a revoked device's message still verified must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **MSG-4** unlocks: Multi-device on real hardware — send from the Mac as you; revoke it as a chain event.

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
  ○ MSG-4       RED      open                 ours=feature-absent expected=device-as-root+revoked-rejected

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
