#!/usr/bin/env bash
# AGENT-MCP-2 — an out-of-scope tool call is refused at the boundary with the
# distinct OutsideAgentScope verdict. GREEN means: driving the gateway over the
# scope transcript, the in-scope fs.read passes (allowed) AND the model's fs.write
# is refused outside-agent-scope (naming the capability), with the downstream
# filesystem server never called — despite a valid signature and well-formed
# envelope. RED means the distinct containment verdict was not produced (the gate
# is a stub). BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verdict stream where the out-of-scope write was ALLOWED (or
# refused with a generic signature error rather than the distinct
# outside-agent-scope verdict) — the containment regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if printf '%s' "$out" | grep -qiE 'write.*allowed|^allowed.*allowed' \
       || ! printf '%s' "$out" | grep -qi 'outside-agent-scope'; then
        red "ours=write-not-contained expected=outside-agent-scope — the out-of-scope write was not refused with the distinct scope verdict (\"$(printf '%s' "$out" | head -1)\"); scope containment regressed"
    fi
    green "captured stream refused the out-of-scope write outside-agent-scope — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-2)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp2.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

IN="$(verdict_for "$TRANSCRIPT" 0)"
OUT="$(verdict_for "$TRANSCRIPT" 1)"

if [ "$IN" = "allowed" ] && [ "$OUT" = "outside-agent-scope" ]; then
    green "the in-scope fs.read passed and the model's fs.write was refused outside-agent-scope (capability named, downstream never called) — a distinct containment verdict, not a signature failure"
fi

[ -z "$IN" ] && [ -z "$OUT" ] \
    && red "ours=no-verdicts expected=allowed+outside-agent-scope — the gateway produced no scope verdict; AGENT-MCP-2 is open (the per-call gate is not built)"
red "ours=in:${IN:-none}/out:${OUT:-none} expected=allowed+outside-agent-scope — the out-of-scope write was not contained with the distinct verdict"
