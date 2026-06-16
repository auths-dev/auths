# Sculpting cycle: nothing-but-routing-leav

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-4 | murmur | headline | missing-surface | `enc-4.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-4** — Guarantee the outer envelope / relay-visible bytes / logs / receipts carry NO plaintext, message key, ratchet state, or sender AID — only the pairwise mailbox id. A leakcheck-style scan AND a relay-capture assertion. Adversarial (the trap): a captured envelope that leaks the sender AID or a key must fail. TRAP probes/enc-4.trap/sender-aid-in-envelope/ — a captured outer envelope carrying the sender AID must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-4** unlocks: Metadata hygiene — the relay sees routing only, never identity or content.

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
  ● ENC-4       GREEN    closed               the outer envelope / relay-visible bytes carried only the pa

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
traps: 1/1 counterexamples still RED
GATE OK
```
