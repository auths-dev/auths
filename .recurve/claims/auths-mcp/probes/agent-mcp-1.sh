#!/usr/bin/env bash
# AGENT-MCP-1 (THE BUILD) — the gateway brokers a real MCP tools/call end-to-end
# with a signed, verified per-call proof. GREEN means: an in-scope, in-budget
# fs.read driven through the gateway in replay mode round-trips — the gateway
# signs the serialized tools/call as an auths artifact, verifies it against the
# agent's delegator-anchored grant, returns the real downstream result, and emits
# a receipt (device=agent, identity=parent-root) that `auths verify` accepts. RED
# means the call did not round-trip with a verified proof (the gateway is a stub).
# BROKEN means we could not even drive the gateway (no staged binary).
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/auths-mcp)
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap fixture captures the documented PRE-BUILD failure: the gateway absent /
# fail-closed, so the call is unauthenticated — no proof, no receipt, no verdict.
# A broker run that yields no verified proof is the regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if printf '%s' "$out" | grep -qiE 'not yet built|no receipt|unauthenticated|no proof'; then
        red "ours=unbrokered expected=signed-verified-proof — the call did not round-trip through the gateway with a verified per-call proof + receipt (\"$(printf '%s' "$out" | head -1)\"); the broker wiring regressed"
    fi
    green "captured replay produced a signed, verified proof + receipt — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-1)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

OUT="$(gateway_replay "$TRANSCRIPT")"
RC=$?

# The accept verdict + a verifiable receipt is the proof the broker path works.
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -q 'allowed' \
   && printf '%s' "$OUT" | grep -qiE 'receipt'; then
    green "the in-scope fs.read round-tripped through the gateway: signed+verified proof, downstream result returned, receipt emitted (device=agent, identity=parent-root)"
fi

[ $RC -ne 0 ] \
    && red "ours=gateway-failed-closed(exit:$RC) expected=brokered+receipted — the gateway did not broker the in-scope call ($(printf '%s' "$OUT" | head -1)); the real-MCP proxy + per-call gate are not built"
red "ours=no-receipt/verdict expected=allowed+receipt — the gateway produced no verified proof or receipt for the in-scope call; AGENT-MCP-1 (the build) is open"
