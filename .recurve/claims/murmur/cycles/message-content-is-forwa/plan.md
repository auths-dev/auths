# Sculpting cycle: message-content-is-forwa

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| MSG-3 | murmur | headline | missing-surface | `msg-3.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **MSG-3** — Stand up the relay wire over a forward-secret envelope: the bytes the relay queues must be Signal-Protocol ciphertext (forward-secret per message) addressed to a pairwise mailbox id — no plaintext, no sender AID, no phone number in the relay-visible OuterEnvelope. Adversarial (the trap): a compromised relay capturing the queue must read neither plaintext nor any PII. TRAP probes/msg-3.trap/relay-sees-plaintext/ — a captured relay queue containing plaintext or a phone number must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **MSG-3** unlocks: The privacy floor — the untrusted relay never had your number to begin with.

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
  ○ MSG-3       RED      open                 ours=feature-absent expected=forward-secret+number-free-rela

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
