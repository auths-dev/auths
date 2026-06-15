# Sculpting cycle: the-untrusted-relay-cann

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-5 | murmur | headline | missing-surface | `enc-5.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-5** — On receive, reject bit-flipped ciphertext via AEAD (no padding/oracle), dedup a replayed ciphertext, and ensure the relay-visible envelope carries only a pairwise mailbox id (never a stable cross-contact linker). Adversarial (the trap): a tampered ciphertext accepted, or a replay delivered twice, must fail. TRAP probes/enc-5.trap/tamper-accepted/ — a captured run where a bit-flipped ciphertext was accepted must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-5** unlocks: The relay is dumb AND safe — tamper/replay/link all closed at the boundary.

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
  ○ ENC-5       RED      open                 ours=feature-absent expected=aead-rejected+replay-deduped — 

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
