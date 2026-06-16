# Sculpting cycle: a-message-is-addressed-t

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| MSG-1 | murmur | headline | missing-surface | `msg-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **MSG-1** — Bind the sender: seal() must KERI-authenticate the sender AID (sign the Signal identity key with the AID's current KERI key) and address the OuterEnvelope to the recipient AID's pairwise mailbox — with NO phone number or email anywhere in Message or the envelope. Adversarial (the trap): a message claiming an AID the sender does not control must be REJECTED (CoreError::Rejected), never surfaced as authenticated. TRAP probes/msg-1.trap/unauthenticated/ — a captured flow where a message from an uncontrolled AID was accepted as authentic must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **MSG-1** unlocks: The floor — a message can be addressed to and authenticated by an AID at all (no number).

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
  ○ MSG-1       RED      open                 ours=feature-absent expected=aid-authenticated+number-free —

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
