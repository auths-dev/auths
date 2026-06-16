# Sculpting cycle: the-signal-session-rooted

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| ENC-1 | murmur | headline | missing-surface | `enc-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **ENC-1** — Before X3DH, verify the recipient's signed prekey bundle against their AID's current key (KEL replay); reject a bundle signed by a wrong or non-pre-committed key. Assert key hygiene: the AID key signs a distinct Signal identity key. Embed libsignal (audited Rust) behind a misuse-resistant wrapper — do NOT reimplement the crypto. Adversarial (the trap): a bundle signed by the wrong key must be rejected, closing the MITM the safety-number warning exists to catch. TRAP probes/enc-1.trap/wrong-key-bundle/ — a captured session rooted in a mis-signed bundle must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **ENC-1** unlocks: The join KERI-to-Signal — the session starts from keys you VERIFIED belong to that AID.

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
  ○ ENC-1       RED      open                 ours=feature-absent expected=keri-rooted-bundle+wrong-key-re

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
