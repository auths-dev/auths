# Sculpting cycle: a-message-sent-from-the

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| DEV-1 | murmur | headline | missing-surface | `dev-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **DEV-1** — Prove the flagship beat end-to-end: a message composed on the macOS app is sealed (MSG-1/ENC-1), stored-and-forwarded through the untrusted relay (MSG-3), pulled on the iOS sim, and verified+decrypted (MSG-4) — arriving authenticated as the sender on the iPhone. The deterministic gate drives the relay + the core seam hermetically; the live two-device demo on a booted simulator is the operator's dev confirmation (allowed for this suite), never the gate. Adversarial (the trap): a delivery where the arriving message failed to authenticate must fail. TRAP probes/dev-1.trap/arrives-unauthenticated/ — a captured delivery where the message arrived but did not authenticate must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **DEV-1** unlocks: The whole pitch in one gesture — send from the Mac, watch it arrive verified on the phone.

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
  ○ DEV-1       RED      open                 ours=feature-absent expected=delivered-and-authenticated — t

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
