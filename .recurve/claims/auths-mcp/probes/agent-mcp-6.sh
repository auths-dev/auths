#!/usr/bin/env bash
# AGENT-MCP-6 (STRETCH) — cross-org: org A's agent is bounded by its A->B scoped
# introduction at org B's gateway. GREEN means: a call within the A->B grant
# passes at B's gateway AND a call exceeding it is refused at B (A cannot widen its
# own introduction; B never trusts A's self-asserted scope). RED means the
# introduction was not honored / not bounded. BROKEN means no staged binary OR the
# AGT-3 live mutual-introduction runtime is absent — in which case this claim is
# PARKED (per PRD §4/§9: PARK, do not stub).
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a stream where the call EXCEEDING the A->B grant was honored at
# B (A widened its own introduction) — the cross-org regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qiE 'outside-agent-scope|rejected'; then
        red "ours=A-widened-its-own-grant expected=refused-at-B — a call exceeding the A->B introduction was honored at B (\"$(printf '%s' "$out" | head -1)\"); B trusted A's self-asserted scope"
    fi
    green "captured stream refused the over-grant call at B — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

# The AGT-3 live mutual-introduction runtime is not yet built (PRD §4/§9: this
# claim rides AGT-3's open live half). With no introduction runtime, this measures
# nothing real — surface BROKEN so baseline records it honestly (the human PARKs it
# rather than the loop stubbing a cross-org path).
TRANSCRIPT="$(transcript_path agent-mcp-6)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

WITHIN="$(verdict_for "$TRANSCRIPT" 0)"
OVER="$(verdict_for "$TRANSCRIPT" 1)"

if [ "$WITHIN" = "allowed" ] && [ "$OVER" = "outside-agent-scope" ]; then
    green "a call within the A->B introduction passed at B and one exceeding it was refused at B — A cannot widen its own introduction"
fi

[ -z "$WITHIN" ] && [ -z "$OVER" ] \
    && red "ours=no-cross-org-verdict expected=allowed+outside-agent-scope — B's gateway produced no introduction-bounded verdict; AGENT-MCP-6 rides AGT-3's live leg (likely PARK until the mutual-introduction runtime lands)"
red "ours=within:${WITHIN:-none}/over:${OVER:-none} expected=allowed+outside-agent-scope — the A->B introduction was not honored-and-bounded at B"
