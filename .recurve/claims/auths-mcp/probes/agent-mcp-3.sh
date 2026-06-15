#!/usr/bin/env bash
# AGENT-MCP-3 — a quantitative budget is un-exceedable across a session. GREEN
# means: driving the gateway over the budget transcript, the call(s) summing to
# <= $5 pass (allowed, with the running total in the receipt) AND the call that
# would cross $5 is refused usage-cap-exceeded — the boolean-scope incumbents
# cannot express this — with the metered tool not charged for the refused call.
# RED means the cap was not enforced quantitatively (the accounting is a stub).
# BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a stream where the over-budget call was ALLOWED (or refused
# with a non-quantitative verdict) — the budget regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qi 'usage-cap-exceeded'; then
        red "ours=cap-not-enforced expected=usage-cap-exceeded — the over-budget call was not refused with the quantitative cap verdict (\"$(printf '%s' "$out" | head -1)\"); budget enforcement regressed"
    fi
    green "captured stream refused the over-budget call usage-cap-exceeded — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-3)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

IN="$(verdict_for "$TRANSCRIPT" 0)"
OVER="$(verdict_for "$TRANSCRIPT" 1)"

if [ "$IN" = "allowed" ] && [ "$OVER" = "usage-cap-exceeded" ]; then
    green "the in-budget call passed (running total receipted) and the call crossing \$5 was refused usage-cap-exceeded — the metered tool was not charged for the refused call"
fi

[ -z "$IN" ] && [ -z "$OVER" ] \
    && red "ours=no-verdicts expected=allowed+usage-cap-exceeded — the gateway produced no budget verdict; AGENT-MCP-3 is open (session accounting is not built)"
red "ours=in:${IN:-none}/over:${OVER:-none} expected=allowed+usage-cap-exceeded — the quantitative cap was not enforced across the session"
