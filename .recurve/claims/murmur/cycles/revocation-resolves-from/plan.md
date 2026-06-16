# Sculpting cycle: revocation-resolves-from

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| RVK-1 | murmur | headline | missing-surface | `rvk-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **RVK-1** — Resolve revocation from WITNESS-CORROBORATED key-state, never a relay's cache: after the root revokes a delegated device, a contact re-resolving corroborated state must REJECT the device's next message — and the honest stale-served window (an offline contact, or one served a relay's stale cache) must be ACKNOWLEDGED in the verdict, never silently waved through as safe. This strengthens MSG-4's clawback (PRD §6.5): clawback is detection, witness-dependent, not an instant global kill. Adversarial (the trap): a revoked device accepted from corroborated state, a relay cache trusted over the witnesses, or a hidden stale window, must fail. TRAP probes/rvk-1.trap/revoked-from-corroborated/ — a captured flow where a revoked device verified from corroborated state, or the stale window was hidden, must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **RVK-1** unlocks: Revocation as honest detection — clawback from corroborated state, with the stale-served window disclosed rather than oversold as an instant kill.

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
  ○ RVK-1       RED      open                 ours=feature-absent expected=revoked-rejected-from-corrobora

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
