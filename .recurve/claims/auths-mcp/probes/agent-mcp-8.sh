#!/usr/bin/env bash
# AGENT-MCP-8 — live-wire counter parity (#281). The live `wrap` path must enforce the
# cross-rail budget via the DURABLE verifier-held CrossRailBudget (the SAME counter the
# hermetic gate drives), NOT the v0 in-memory cap guard — so live-wire verdicts match
# the hermetic gate's for the same call sequence (PRD §4 AGENT-MCP-8 / §11 / D8).
#
# WHY THE LIVE WIRE CAN'T BE FULLY DRIVEN HERMETICALLY: the live `wrap` path speaks MCP
# JSON-RPC over stdio to a live agent and a live downstream; there is no model/network in
# the gate, and the per-call cryptographic proof on the live wire rides with the
# live-agent harness (proxy.rs module docs). Per the arming contract, this probe GATES the
# counter-SOURCE PARITY — that the live wrap path's budget enforcement is sourced from the
# durable CrossRailBudget, the SAME source the gate uses — and DISCLOSES the full live-wire
# verdict match as evidence (the live leg, deferred). It does NOT fake a live MCP session.
#
# GREEN means:
#   1. the hermetic gate, driven over the MCP-8 transcript (the identical cross-rail
#      sequence AGENT-MCP-3 uses), produces the reference verdict stream
#      allowed / allowed / usage-cap-exceeded from the durable cross-rail counter; AND
#   2. the live `wrap` path enforces the cross-rail budget from that SAME durable
#      CrossRailBudget — i.e. the v0 in-memory guard (proxy.rs GatewayProxy::spent_cents,
#      a per-session RAM tally that meters nothing per rail) has been REPLACED, so the
#      live wire cannot allow what the gate refuses.
# Counter-SOURCE parity is read from the staged gateway: the v0-guard signature
# (`spent_cents` in-memory tally on the wrap path) must be GONE and the live wrap path
# must reference the durable cross-rail counter.
#
# RED means the live wrap path still enforces with the v0 in-memory guard (it would allow
# a cross-rail call the durable gate refuses — the #281 divergence), so live-wire parity
# is not built. BROKEN means no staged binary / missing transcript.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# v0-guard-divergence: a captured stream where the live wrap path ALLOWED a cross-rail
# call the hermetic gate REFUSED for the same sequence (the v0 in-memory guard let
# through what the durable counter caught) — the #281 regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    # The divergence is real if the stream shows the live wrap ALLOWING a call the gate
    # REFUSED and carries no parity/refusal reconciliation.
    if printf '%s' "$out" | grep -qiE 'divergence|live.*allow|v0.*guard' \
       && ! printf '%s' "$out" | grep -qiE 'parity|matches the gate|same durable counter'; then
        red "ours=v0-guard-divergence expected=live-wire-parity — the live wrap path allowed a cross-rail call the hermetic gate refused for the same sequence (\"$(printf '%s' "$out" | head -1)\"); the v0 in-memory guard was not replaced by the durable counter (#281)"
    fi
    green "captured stream shows the live wrap path matching the gate from the same durable counter — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-8)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp8.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# 1. The hermetic gate's reference verdict stream over the cross-rail sequence (the
#    durable CrossRailBudget — the authoritative counter). This is the parity ORACLE
#    the live wire must match.
RAW="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
VERDICTS="$(printf '%s\n' "$RAW" | sed -n 's/^  verdict=\([a-z-]\{1,\}\).*/\1/p')"
G0="$(printf '%s\n' "$VERDICTS" | sed -n '1p')"
G1="$(printf '%s\n' "$VERDICTS" | sed -n '2p')"
G2="$(printf '%s\n' "$VERDICTS" | sed -n '3p')"
gate_ok=0
[ "$G0" = "allowed" ] && [ "$G1" = "allowed" ] && [ "$G2" = "usage-cap-exceeded" ] && gate_ok=1

# 2. Counter-SOURCE parity: does the LIVE wrap path enforce from the SAME durable
#    cross-rail counter as the gate, or from the v0 in-memory guard? Read the staged
#    gateway binary for the v0-guard signature. The v0 guard is the per-session RAM tally
#    `spent_cents` on the wrap path (proxy.rs GatewayProxy); #281 must replace it so the
#    live wrap path references the durable cross-rail budget counter (budget-ledger).
# The wrap path must declare that its budget is the durable cross-rail counter, AND must
# no longer carry the v0 in-memory `spent_cents` guard.
has_v0_guard=0
has_durable_on_wire=0
# Capture the binary's strings ONCE into a var, then grep the var — never
# `strings … | grep -q …`. Under `set -o pipefail` (sourced from harness/env.sh) a
# `grep -q` that matches early closes the pipe, `strings` is killed by SIGPIPE (141),
# and pipefail propagates 141 as the pipeline's exit — so a binary that DOES contain
# `budget-ledger` would read as absent. Greping a captured var has no pipe and no
# SIGPIPE, so the truth condition (the string is present) is measured correctly.
GW_STRINGS="$(strings "$GATEWAY_BIN" 2>/dev/null)"
if grep -qiE 'spent_cents|v0 (cap )?(spend )?guard|in-memory cap' <<<"$GW_STRINGS"; then
    has_v0_guard=1
fi
WRAP_HELP="$("$GATEWAY_BIN" wrap --help 2>&1)"
if grep -qiE 'budget-ledger' <<<"$GW_STRINGS" \
   && grep -qiE 'durable|cross-rail counter|verifier-held' <<<"$WRAP_HELP"; then
    has_durable_on_wire=1
fi
parity_ok=0
[ $has_v0_guard -eq 0 ] && [ $has_durable_on_wire -eq 1 ] && parity_ok=1

if [ $gate_ok -eq 1 ] && [ $parity_ok -eq 1 ]; then
    green "live-wire counter parity holds: the hermetic gate refuses the cross-rail-over-cap call (allowed/allowed/usage-cap-exceeded) from the durable CrossRailBudget, and the live wrap path enforces from that SAME durable counter (the v0 in-memory spent_cents guard is gone) — the live wire cannot allow what the gate refuses (#281)"
fi

[ -z "$G0" ] && [ -z "$G1" ] && [ -z "$G2" ] \
    && red "ours=no-gate-verdicts expected=allowed+allowed+usage-cap-exceeded — the hermetic gate produced no reference verdict stream; AGENT-MCP-8 cannot be checked for parity"

miss=""
[ $gate_ok   -eq 0 ] && miss="${miss}gate-seq(got ${G0:-none}/${G1:-none}/${G2:-none}) "
[ $has_v0_guard -eq 1 ] && miss="${miss}v0-guard-present(live wrap still meters with the in-memory spent_cents tally) "
[ $has_durable_on_wire -eq 0 ] && miss="${miss}wire-not-on-durable-counter "
red "ours=${miss}expected=live-wire-on-durable-cross-rail-counter — the live wrap path still enforces the cap with the v0 in-memory guard (proxy.rs spent_cents), NOT the durable verifier-held CrossRailBudget the gate uses; #281/AGENT-MCP-8 (wire the durable counter into wrap so live-wire verdicts match the hermetic gate) is not built"
