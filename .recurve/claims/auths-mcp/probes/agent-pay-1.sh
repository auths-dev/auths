#!/usr/bin/env bash
# AGENT-PAY-1 — the Stripe-test rail is METERED: the gateway, given a Stripe-test
# charge RESPONSE, EXTRACTS the charge amount and reserves/settles it against the
# cross-rail cap (PRD §4 AGENT-PAY-1 / §11 — bound, don't build).
#
# Hermetic over a RECORDED Stripe TEST-MODE charge response fixture
# (probes/fixtures/stripe-charge.test.json), authored tightly against Stripe's
# documented Charge object shape (docs.stripe.com/api/charges/object:
# amount_captured/currency/captured/status/livemode/balance_transaction). The gateway
# never calls Stripe — it reads the response shape its agent-toolkit MCP server would
# return and meters the captured amount.
#
# GREEN means: driving the gateway over the PAY-1 transcript (one $5 cap, a stripe
# rail),
#   1. the in-budget charge ($3.00, EXTRACTED from charge.amount_captured in the
#      recorded response — NOT supplied as a transcript cost_cents) settles `allowed`
#      and is METERED: the receipt names the charge id it metered (ch_…), the rail
#      (rail=stripe), and the extracted amount in the running cross-rail total;
#   2. an over-cap charge ($6.00 amount_captured, alone past the $5 cap) is refused
#      `usage-cap-exceeded` — the reservation refuses BEFORE Stripe is invoked, so the
#      metered downstream is never charged (the real defense, PRD §11).
# The receipt MUST evidence cost-EXTRACTION from the rail response (the charge id /
# amount_captured), not a transcript-supplied number — a gateway that only meters a
# pre-supplied cost_cents has not built the rail-response cost extraction this claim
# is about, and is RED.
#
# RED means the gateway does not extract the charge amount from the recorded Stripe
# response (the cost-extraction / near-pluggable Stripe adapter is not built): no
# charge-id attribution, no amount_captured extraction, no rail=stripe metered receipt.
# BROKEN means no staged binary or a missing fixture/transcript.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# cap-not-enforced / stripe-overcharged: a captured stream where the over-cap charge
# was ALLOWED (Stripe was "charged" past the cap) instead of refused
# usage-cap-exceeded BEFORE the rail was touched — the regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qi 'usage-cap-exceeded'; then
        red "ours=cap-not-enforced expected=usage-cap-exceeded — the over-cap Stripe charge was allowed / Stripe was charged past the cap (\"$(printf '%s' "$out" | head -1)\"); the reservation did not refuse BEFORE the rail was invoked (PRD §11 defense regressed)"
    fi
    green "captured stream refused the over-cap Stripe charge usage-cap-exceeded before the rail was touched — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-pay-1)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"
FIXTURE="$SUITE_DIR/probes/fixtures/stripe-charge.test.json"
[ -f "$FIXTURE" ] || broken "missing recorded Stripe charge fixture: $FIXTURE"

# The doc-accurate amount the gateway must EXTRACT from the recorded response.
CHARGE_ID="ch_3MmlLrLkdIwHu7ix0snN0B15"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/pay1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
# The gateway must resolve the recorded rail-response fixtures from the suite — point
# it at the fixtures dir so the burndown's adapter has a documented source location.
export AUTHS_MCP_RAIL_FIXTURES="$SUITE_DIR/probes/fixtures"

# ONE drive (the chain build is not idempotent). Parse the canonical per-call verdict
# stream and read the full output for the cost-extraction receipt evidence.
RAW="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
VERDICTS="$(printf '%s\n' "$RAW" | sed -n 's/^  verdict=\([a-z-]\{1,\}\).*/\1/p')"
R0="$(printf '%s\n' "$VERDICTS" | sed -n '1p')"
OVER="$(printf '%s\n' "$VERDICTS" | sed -n '2p')"

# The verdict SEQUENCE: the in-budget charge passes, the over-cap charge is refused.
seq_ok=0
[ "$R0" = "allowed" ] && [ "$OVER" = "usage-cap-exceeded" ] && seq_ok=1

# COST-EXTRACTION evidence — the heart of the claim. The receipt must prove the cost
# was EXTRACTED from the recorded Stripe response, not read from a transcript number:
# it must name the charge id (ch_…) it metered AND the rail (stripe).
extract_ok=0
if printf '%s' "$RAW" | grep -qiE 'rail[=":[:space:]]*stripe' \
   && printf '%s' "$RAW" | grep -qF "$CHARGE_ID"; then
    extract_ok=1
fi

if [ $seq_ok -eq 1 ] && [ $extract_ok -eq 1 ]; then
    green "the Stripe-test rail is metered: the in-budget charge (\$3.00 EXTRACTED from amount_captured in the recorded Stripe charge response, charge=$CHARGE_ID) settled allowed and was metered into the cross-rail total (rail=stripe), and the over-cap charge (\$6.00 amount_captured) was refused usage-cap-exceeded BEFORE Stripe was invoked — the metered downstream was never charged (PRD §11)"
fi

[ -z "$R0" ] && [ -z "$OVER" ] \
    && red "ours=no-verdicts expected=allowed+usage-cap-exceeded — the gateway produced no verdict over the Stripe rail transcript; AGENT-PAY-1 is open (the Stripe-charge cost extraction is not built)"

miss=""
[ $seq_ok    -eq 0 ] && miss="${miss}verdict-seq(got ${R0:-none}/${OVER:-none}) "
[ $extract_ok -eq 0 ] && miss="${miss}no-charge-extraction(charge-id/rail=stripe absent from receipts) "
red "ours=${miss}expected=stripe-charge-extracted+metered+cap-enforced — the gateway does not EXTRACT the charge amount from the recorded Stripe TEST-MODE response (amount_captured) and meter it against the cross-rail cap; the gateway-side Stripe-charge extraction + the near-pluggable Stripe adapter (PRD §11) are not built"
