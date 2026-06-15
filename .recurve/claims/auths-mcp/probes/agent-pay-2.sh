#!/usr/bin/env bash
# AGENT-PAY-2 — the x402/USDC rail is METERED into the SAME cross-rail cap as PAY-1
# (cross-rail summing, testnet-flagged) (PRD §4 AGENT-PAY-2 / §11).
#
# Same as PAY-1 but the x402 rail: the gateway, given a RECORDED x402 settlement
# RESPONSE (probes/fixtures/x402-settlement.testnet.json — the x402 SettlementResponse
# + PaymentRequirements shapes from coinbase/x402 specs, network=base-sepolia, USDC
# 6-decimal atomic units), EXTRACTS the paid amount and meters it into the SAME $5 cap
# the Stripe rail meters into. The cross-rail moat (PRD §11): a tiny x402 amount that a
# per-rail x402 silo would wave through is refused when summed cross-rail past the cap.
#
# *** LIVE x402 SCOPE FLAG ***  The LIVE x402 rail needs a FUNDED USDC TESTNET WALLET
# (base-sepolia) to actually settle on-chain — OUT OF HERMETIC SCOPE. This probe proves
# COST-EXTRACTION (atomic-USDC → cents) + CROSS-RAIL METERING ONLY, over the recorded
# settlement response. The funded-wallet live leg is evidence-only, deferred (D7-style).
#
# GREEN means: driving the gateway over the PAY-2 transcript (one $5 cap spanning the
# stripe AND x402 rails),
#   1. the in-budget Stripe charge ($3.00 EXTRACTED from amount_captured) and the
#      in-budget x402 settlement ($1.50 EXTRACTED from maxAmountRequired=1500000 atomic
#      USDC / 1e6 → 1.50 USDC → 150 cents) both settle `allowed` and are METERED into the
#      SAME cross-rail total — each receipt naming the rail (stripe / x402) AND the
#      settlement id it metered (ch_… / tx 0x…);
#   2. the x402 call that would reserve PAST the cap ACROSS rails ($4.50 + $0.60 = $5.10)
#      is refused `usage-cap-exceeded` BEFORE the x402 facilitator settles — even though
#      x402 ALONE is under budget (the moat a per-rail-siloed budget cannot express).
# The receipts MUST evidence cross-rail cost-EXTRACTION (the x402 tx id + atomic→cents
# conversion + rail attribution), not transcript-supplied numbers.
#
# RED means the gateway does not extract the x402 amount from the recorded settlement
# (atomic-USDC → cents) and sum it cross-rail with the Stripe rail (the x402 cost
# extraction + the testnet-flagged x402 adapter + cross-rail summing are not built).
# BROKEN means no staged binary or a missing fixture/transcript.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# cap-not-enforced (cross-rail): a captured stream where the x402 call that crosses
# the cap ACROSS rails was ALLOWED (settled past the $5 cross-rail cap) instead of
# refused usage-cap-exceeded before the facilitator settled — the regression forbidden.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qi 'usage-cap-exceeded'; then
        red "ours=cap-not-enforced expected=usage-cap-exceeded — the x402 call that crosses the cap ACROSS rails was settled past the cross-rail cap (\"$(printf '%s' "$out" | head -1)\"); the cross-rail reservation did not refuse before the x402 facilitator settled (the per-rail silo waved it through)"
    fi
    green "captured stream refused the cross-rail-over-cap x402 settlement usage-cap-exceeded before the facilitator settled — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-pay-2)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"
X402_FIXTURE="$SUITE_DIR/probes/fixtures/x402-settlement.testnet.json"
[ -f "$X402_FIXTURE" ] || broken "missing recorded x402 settlement fixture: $X402_FIXTURE"

# The doc-accurate settlement tx the gateway must EXTRACT the x402 amount alongside.
X402_TX="0x1234567890abcdef"
STRIPE_CHARGE_ID="ch_3MmlLrLkdIwHu7ix0snN0B15"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/pay2.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
export AUTHS_MCP_RAIL_FIXTURES="$SUITE_DIR/probes/fixtures"

RAW="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
VERDICTS="$(printf '%s\n' "$RAW" | sed -n 's/^  verdict=\([a-z-]\{1,\}\).*/\1/p')"
R0="$(printf '%s\n' "$VERDICTS" | sed -n '1p')"
R1="$(printf '%s\n' "$VERDICTS" | sed -n '2p')"
OVER="$(printf '%s\n' "$VERDICTS" | sed -n '3p')"

# The verdict SEQUENCE: stripe + x402 in-budget pass, the cross-rail-over-cap x402 fails.
seq_ok=0
[ "$R0" = "allowed" ] && [ "$R1" = "allowed" ] && [ "$OVER" = "usage-cap-exceeded" ] && seq_ok=1

# CROSS-RAIL COST-EXTRACTION — both rails extracted from their recorded responses and
# summed into ONE counter. Require BOTH the stripe charge id AND the x402 settlement tx
# in the receipts (cost extracted from the rail responses, both rails attributed).
extract_ok=0
if printf '%s' "$RAW" | grep -qiE 'rail[=":[:space:]]*stripe' \
   && printf '%s' "$RAW" | grep -qiE 'rail[=":[:space:]]*x402' \
   && printf '%s' "$RAW" | grep -qF "$STRIPE_CHARGE_ID" \
   && printf '%s' "$RAW" | grep -qF "$X402_TX"; then
    extract_ok=1
fi

if [ $seq_ok -eq 1 ] && [ $extract_ok -eq 1 ]; then
    green "the x402 rail is metered into the SAME \$5 cap as Stripe: the Stripe charge (\$3.00 from amount_captured) and the x402 settlement (\$1.50 EXTRACTED from maxAmountRequired=1500000 atomic USDC → cents, tx $X402_TX…) both settled allowed and summed CROSS-RAIL to \$4.50, and the next x402 call that would reserve to \$5.10 across rails was refused usage-cap-exceeded BEFORE the facilitator settled — even though x402 alone is under budget (the moat). (LIVE x402 needs a funded USDC testnet wallet — out of hermetic scope.)"
fi

[ -z "$R0" ] && [ -z "$R1" ] && [ -z "$OVER" ] \
    && red "ours=no-verdicts expected=allowed+allowed+usage-cap-exceeded — the gateway produced no verdict over the cross-rail x402 transcript; AGENT-PAY-2 is open (the x402 settlement cost extraction is not built)"

miss=""
[ $seq_ok     -eq 0 ] && miss="${miss}verdict-seq(got ${R0:-none}/${R1:-none}/${OVER:-none}) "
[ $extract_ok -eq 0 ] && miss="${miss}no-x402-extraction(stripe-charge/x402-tx absent or rail unattributed) "
red "ours=${miss}expected=x402-amount-extracted(atomic-USDC→cents)+cross-rail-summed+cap-enforced — the gateway does not EXTRACT the x402 amount from the recorded settlement response and meter it CROSS-RAIL into the same cap as Stripe; the x402 cost extraction + the testnet-flagged x402 adapter + cross-rail summing (PRD §11) are not built. (LIVE x402 also needs a funded USDC testnet wallet — out of hermetic scope.)"
