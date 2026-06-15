# Sculpting cycle: pay-mode-inverted-default

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| AGENT-PAY-3 | auths-mcp | headline | missing-surface | `agent-pay-3.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **AGENT-PAY-3** — Build the inverted payment-mode default over a CLEAN PaymentMode port/adapter (ports/adapters, PRD §11): (1) REAL is the DEFAULT — with no flag the gateway/adapter resolves to live Stripe (api.stripe.com, sk_live_… expected) and x402 on base MAINNET (real USDC); TEST is a SINGLE opt-in — `--test-mode` on `auths-mcp wrap` AND `AUTHS_MCP_TEST_MODE=1` for the adapter → sk_test_… / base-sepolia. (2) The cross-rail budget cap is the MANDATORY seatbelt — the gateway REFUSES to wrap a payment rail without a `--budget` (fail-closed, distinct budget-required error), in BOTH modes; with a `--budget` it is accepted. (3) The mode is DISCLOSED — a startup banner + a `mode=real|test` field (on the receipt and on the `wrap --show-mode` resolve+disclose dry-run) so an operator always knows whether real money is live. Accept (hermetic, no charge): the --show-mode dry-run discloses default→mode=real / --test-mode→mode=test; a budget-less payment-rail wrap is refused budget-required in both modes; a real-mode wrap discloses mode=real, a test-mode wrap discloses mode=test. The docs update (real-focus, test-note-at-bottom — the auths-mcp wrapper walkthrough + provider docs) is part of the build, not this ARM.

## What gets stronger (the REBUILD payoff)

- **AGENT-PAY-3** unlocks: An operator can default to REAL money safely — real is the default, the cap is a mandatory seatbelt that cannot be skipped, and the mode is never silent (PRD §11). Test mode is a single, deliberate opt-in.

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
  ○ AGENT-PAY-3 RED      open                 ours=no-real-default-disclosure(default→mode=real+live-rails

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
