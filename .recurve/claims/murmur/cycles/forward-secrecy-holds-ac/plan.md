# Sculpting cycle: forward-secrecy-holds-ac

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-2 | murmur | headline | missing-surface | `enc-2.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-2** — Integrate the Double Ratchet (via libsignal) so each message has forward secrecy and used message keys are zeroized. Adversarial (the trap): snapshot the session state at message N and fail to decrypt message N-k from it. TRAP probes/enc-2.trap/late-state-decrypts-old/ — a captured run where a later compromised state decrypted an earlier ciphertext must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-2** unlocks: Per-message forward secrecy across OUR wiring, not just Signal's premise.

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
  ○ ENC-2       RED      open                 ours=feature-absent expected=forward-secrecy-held — the Doub

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
