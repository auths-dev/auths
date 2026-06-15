# Sculpting cycle: vetted-implementation--u

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-6 | murmur | headline | missing-surface | `enc-6.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-6** — The misuse-resistant wrapper around libsignal must pass libsignal's OFFICIAL test vectors AND a differential/interop test (our send vs a reference Double-Ratchet decrypt); a property test asserts no one-time prekey or message key is ever reused. Adversarial (the trap): a wrapper that reuses a one-time prekey or message key must fail the property test. TRAP probes/enc-6.trap/key-reused/ — a captured run reusing a one-time prekey must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-6** unlocks: Proof we use Signal CORRECTLY — battle-tested is the premise, never the proof.

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
  ○ ENC-6       RED      open                 ours=feature-absent expected=libsignal-vectors-pass+no-key-r

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
