# Sculpting cycle: post-compromise-healing

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-3 | murmur | feature | missing-surface | `enc-3.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-3** — Wire the DH ratchet so that after a simulated state compromise the next ratchet step locks the attacker back out (post-compromise security). Adversarial (the trap): a run where the attacker remains able to decrypt AFTER a ratchet step must fail. TRAP probes/enc-3.trap/no-healing/ — a captured run where confidentiality did not recover after the ratchet step must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-3** unlocks: Post-compromise security — a transient compromise does not become permanent.

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
  ○ ENC-3       RED      open                 ours=feature-absent expected=post-compromise-healed — the DH

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
