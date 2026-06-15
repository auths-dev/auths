# Sculpting cycle: verified-continuation-rotation

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| MSG-2 | murmur | headline | missing-surface | `msg-2.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **MSG-2** — Wire evaluate() to replay the contact's KEL and run the pre-rotation commitment check (verify the new key was pre-committed by the prior key-state): a pre-committed rotation yields VerifiedContinuation; a substituted (not-pre-committed) key yields NonContinuationWarning, NOT a soft re-pin. STRENGTHENED (PRD §2 binding mechanism — these are load-bearing, not cosmetic): on a verified rotation the app must RE-KEY the Signal session deterministically — tear down and re-establish X3DH against the freshly-replayed key-state, NEVER continue the old ratchet across an identity change — AND re-verify the republished prekey bundle against the freshly-replayed CURRENT key (accepting a bundle whose signer you did not re-check is the dangerous bug). Adversarial (the trap): a substituted key a pinning model would wave through as a mere warning must yield NonContinuationWarning here; AND the old ratchet must never be continued across an identity change, and a stale-signer prekey must never be accepted. TRAP probes/msg-2.trap/substituted-key/ — a captured rotation where a non-pre-committed key verified as a continuation, where the ratchet was continued across an identity change, or where a stale-signer prekey was accepted, must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **MSG-2** unlocks: The wedge — verifiable key continuity (pre-rotation) no pinning model can match.

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
  ○ MSG-2       RED      open                 ours=feature-absent expected=verified-continuation+rekeyed+p

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
