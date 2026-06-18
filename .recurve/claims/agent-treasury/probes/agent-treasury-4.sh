#!/usr/bin/env bash
# AGENT-TREASURY-4 — x402 inbound: a sub-agent EARNS, and the credit lands in its
# verifiable P&L. Given a RECORDED x402/USDC SettlementResponse for a service the
# self-monetizing sub-agent SOLD, the engine extracts the paid amount (atomic USDC
# at 6 decimals → cents), credits it to the sub-agent's receipted P&L
# (direction=inbound, rail=x402), and raises its rebalancing share. A credit not
# matching the recorded settlement (a padded earn) is rejected.
#
# LIVE-SCOPE FLAG: the live inbound leg needs a funded USDC testnet wallet
# (base-sepolia) — OUT of hermetic scope, evidence-only, deferred. This probe proves
# credit-extraction + P&L crediting over a RECORDED settlement only; no live x402.
#
# GREEN: the recorded settlement's amount is extracted to the exact cents and
#   credited (direction=inbound, rail=x402); a padded credit (amount ≠ the recorded
#   SettlementResponse) is rejected. RED: the credit side is absent (the gap at
#   baseline), or a padded credit is accepted. BROKEN: missing fixture/build.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

SETTLEMENT="./probes/fixtures/x402-settlement.json"

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/credit.json" ] \
        || broken "trap fixture missing credit.json: ${TRAP_FIXTURE}"
    accepted="$(jq -r '.data.accepted // empty' "${TRAP_FIXTURE}/credit.json" 2>/dev/null)"
    if [ "$accepted" = "true" ]; then
        red "ours=padded-credit:accepted expected=rejected — a credit whose amount does not match the recorded x402 SettlementResponse was accepted; a fabricated inbound stream could pump a sub-agent's allocation"
    fi
    green "captured padded credit is rejected — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"
[ -f "$SETTLEMENT" ] || broken "missing recorded settlement fixture: $SETTLEMENT"

# The credit side is net-new; its absence IS the gap (RED, not BROKEN).
has_subcommand treasury credit \
    || red "ours=no-credit-surface expected=x402 inbound credit extraction (atomic USDC→cents, direction=inbound, rail=x402) — the engine meters only the debit (spend) side; a sub-agent cannot EARN into a verifiable P&L"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury4.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
X402="$(delegate_subagent x402 manager)"; [ -n "$X402" ] || broken "could not delegate x402 sub-agent"
issue_slice manager "$X402" calls:1 >/dev/null; [ "$(issue_rc)" -eq 0 ] || broken "could not issue x402 slice"

# The recorded settlement pays 2.50 USDC = 2_500_000 atomic (6 decimals) = 250 cents.
EXPECT_CENTS=250
CREDITED="$("$AUTHS_BIN" --repo "$ORG_REPO" --json treasury credit \
    --to "$X402" --settlement "$SETTLEMENT" 2>/dev/null | jq -r '.data.credited_cents // empty')"
[ "$CREDITED" = "$EXPECT_CENTS" ] \
    || red "ours=credited:${CREDITED:-none} expected=${EXPECT_CENTS} — the recorded x402 settlement (2.50 USDC) was not extracted to the exact cents and credited inbound"

# Padded credit: claim more than the recorded settlement — must be rejected.
PADDED="$("$AUTHS_BIN" --repo "$ORG_REPO" --json treasury credit \
    --to "$X402" --settlement "$SETTLEMENT" --claim-cents 99999 2>/dev/null | jq -r '.data.status // empty')"
[ "$PADDED" != "credited" ] \
    || red "ours=padded:credited expected=rejected — a credit claiming 99999 cents over a 250-cent recorded settlement was accepted; earn is not metered from the recorded settlement"

green "the recorded x402 settlement (2.50 USDC) is extracted to ${CREDITED} cents and credited inbound to the x402 sub-agent's P&L, and a padded credit (99999c over a 250c settlement) is rejected — the treasury grows from agent revenue, and the growth is as verifiable as the spend"
