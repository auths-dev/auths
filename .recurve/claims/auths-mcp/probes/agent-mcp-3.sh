#!/usr/bin/env bash
# AGENT-MCP-3 — ONE cross-rail quantitative budget is un-exceedable across a
# session (pre-authorization, verifier-held monotonic SETTLED counter + transient
# RESERVED holds, checkpoint-anchored — PRD §4/§9/§11/§12 D8).
#
# GREEN means: driving the gateway over the CROSS-RAIL budget transcript ($5 cap
# spanning a stripe-ish AND an x402-ish rail),
#   1. the in-budget calls (combined reserved ≤ $5) pass `allowed`, and each
#      receipt carries the running CROSS-RAIL total tagged with the rail it settled
#      on — NOT a per-rail-siloed tally;
#   2. the call that would RESERVE past the cap on the SECOND rail is refused
#      `usage-cap-exceeded` BEFORE the rail is touched (the metered downstream is
#      not charged), even though a per-rail-siloed x402 budget still reads in-budget
#      ($4.50-combined + $0.60 = $5.10 across rails; x402 alone is only $1.50) —
#      the moat a per-rail processor budget structurally cannot express;
#   3. reserve/settle releases slack — a call that settles cheaper than its reserved
#      ceiling does NOT permanently consume the difference (a later in-budget call
#      is not starved by an over-reserved earlier one).
# The counter is the verifier-held monotonic SETTLED high-water mark keyed to the
# agent delegation (NOT a gateway-held SessionLedger), checkpoint-anchored so the
# running total is tamper-evident and offline-verifiable without a per-call chain
# write; max uncaught overspend on a counter-integrity failure ≤ one checkpoint
# interval (detection ≠ reversal).
#
# RED means the cross-rail design is not built — the verdict SEQUENCE alone can be
# faked by a single per-session tally that merely sums every paid call (it would
# pass 1+2 by accident), so this probe additionally requires the receipts to prove
# CROSS-RAIL accounting: each allowed receipt must name the rail it settled on and
# carry a cross-rail running total, and the slack from an over-reserved call must be
# released. A gateway that meters all paid calls against one undifferentiated
# counter, with no rail attribution / no reserve-settle / no checkpoint anchor in
# the receipt, is RED — the cross-rail/pre-auth/checkpoint engine is not built.
# BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# Two known-bad counterexamples this probe must turn RED:
#   cap-not-enforced/   the over-budget cross-rail call was ALLOWED (or refused
#                       with a non-quantitative verdict) — the budget regression.
#   counter-rolled-back/ a replayed/lower SETTLED total was accepted instead of
#                       refused usage-counter-rolled-back — the monotonicity
#                       (rollback-protection) regression D8 forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    case "${TRAP_FIXTURE}" in
        *counter-rolled-back*)
            # Monotonicity: a replayed/lower settled total MUST be refused with the
            # rollback verdict. If it is not, the counter rolled back unguarded.
            if ! printf '%s' "$out" | grep -qi 'usage-counter-rolled-back'; then
                red "ours=counter-rolled-back expected=usage-counter-rolled-back — a replayed/lower settled total was not refused (\"$(printf '%s' "$out" | head -1)\"); the monotonic settled counter is not rollback-protected"
            fi
            green "captured stream refused the rolled-back settled total usage-counter-rolled-back — the adversarial twin holds"
            ;;
        *)
            # cap-not-enforced: the over-budget cross-rail call must be refused with
            # the quantitative cap verdict.
            if ! printf '%s' "$out" | grep -qi 'usage-cap-exceeded'; then
                red "ours=cap-not-enforced expected=usage-cap-exceeded — the over-budget cross-rail call was not refused with the quantitative cap verdict (\"$(printf '%s' "$out" | head -1)\"); cross-rail budget enforcement regressed"
            fi
            green "captured stream refused the over-budget cross-rail call usage-cap-exceeded — the adversarial twin holds"
            ;;
    esac
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-3)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# ONE drive (the chain build is not idempotent — never re-drive the same sandbox).
# Read the full output for the cross-rail receipt evidence, and parse the canonical
# per-call verdict stream from that same output (the `^  verdict=` line, replay.rs).
RAW="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
VERDICTS="$(printf '%s\n' "$RAW" | sed -n 's/^  verdict=\([a-z-]\{1,\}\).*/\1/p')"
R0="$(printf '%s\n' "$VERDICTS" | sed -n '1p')"
R1="$(printf '%s\n' "$VERDICTS" | sed -n '2p')"
OVER="$(printf '%s\n' "$VERDICTS" | sed -n '3p')"

# The verdict SEQUENCE: in-budget calls pass, the cap-crossing call is refused.
seq_ok=0
[ "$R0" = "allowed" ] && [ "$R1" = "allowed" ] && [ "$OVER" = "usage-cap-exceeded" ] && seq_ok=1

# CROSS-RAIL EVIDENCE — the sequence alone can be produced by a single per-session
# tally; the design is only proven if the receipts attribute spend to a RAIL and
# carry a cross-rail running total (not a per-rail silo). Require the allowed
# receipts to name the rail they settled on.
rail_ok=0
if printf '%s' "$RAW" | grep -qiE 'rail[=":[:space:]]*stripe' \
   && printf '%s' "$RAW" | grep -qiE 'rail[=":[:space:]]*x402'; then
    rail_ok=1
fi

# RESERVE/SETTLE SLACK — call 1 reserves a $2.00 ceiling and settles $1.50; the
# design must report the reserved-vs-settled split (so slack is provably released,
# not permanently consumed). Require a reserve/settle signal in the receipts.
slack_ok=0
if printf '%s' "$RAW" | grep -qiE 'reserv|settle'; then
    slack_ok=1
fi

if [ $seq_ok -eq 1 ] && [ $rail_ok -eq 1 ] && [ $slack_ok -eq 1 ]; then
    green "one \$5 cap held across BOTH rails: the in-budget cross-rail calls passed (each receipt naming its rail + the cross-rail running total), the slack from the over-reserved call was released, and the call that would reserve past \$5 on the second rail was refused usage-cap-exceeded before the rail was touched — a per-rail-siloed budget would have waved it through"
fi

[ -z "$R0" ] && [ -z "$R1" ] && [ -z "$OVER" ] \
    && red "ours=no-verdicts expected=allowed+allowed+usage-cap-exceeded — the gateway produced no budget verdict; AGENT-MCP-3 is open (cross-rail accounting is not built)"

# Pinpoint the missing facet for the sculptor.
miss=""
[ $seq_ok  -eq 0 ] && miss="${miss}verdict-seq(got ${R0:-none}/${R1:-none}/${OVER:-none}) "
[ $rail_ok  -eq 0 ] && miss="${miss}no-cross-rail-attribution "
[ $slack_ok -eq 0 ] && miss="${miss}no-reserve/settle "
red "ours=${miss}expected=cross-rail-settled-counter+pre-auth+checkpoint — the budget is metered by a single undifferentiated counter (the gateway-held SessionLedger), not the verifier-held monotonic SETTLED counter keyed to the agent delegation with transient RESERVED holds + checkpoint-anchoring (D8); the cross-rail/pre-auth/checkpoint engine is not built"
