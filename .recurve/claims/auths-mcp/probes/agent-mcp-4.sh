#!/usr/bin/env bash
# AGENT-MCP-4 — revocation is instant, mid-session, with no propagation window.
# GREEN means: driving the gateway over the killswitch transcript, calls before
# the revoke event pass (allowed) AND the very next tools/call after the
# revocation is refused revoked — no token still valid for its TTL, no
# introspection-cache lag; the gateway re-derives liveness from the chain on every
# call. RED means revocation was not instant per-call (liveness is not re-derived).
# BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a stream where the post-revocation call was still ALLOWED (the
# propagation-window regression OPS-1 forbids) or not refused revoked.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qi 'revoked'; then
        red "ours=revocation-lagged expected=revoked — the post-revocation call was not refused revoked (\"$(printf '%s' "$out" | head -1)\"); a propagation window reopened"
    fi
    green "captured stream refused the post-revocation call revoked — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-4)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp4.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# The transcript has a revoke event between call 0 (pre) and call 1 (post). The
# verdict stream skips the event, so verdict 0 = pre-revoke, verdict 1 = post.
PRE="$(verdict_for "$TRANSCRIPT" 0)"
POST="$(verdict_for "$TRANSCRIPT" 1)"

if [ "$PRE" = "allowed" ] && [ "$POST" = "revoked" ]; then
    green "the pre-revocation call passed and the very next call after revocation was refused revoked — liveness re-derived from the chain per call, no TTL/introspection lag"
fi

[ -z "$PRE" ] && [ -z "$POST" ] \
    && red "ours=no-verdicts expected=allowed+revoked — the gateway produced no revocation verdict; AGENT-MCP-4 is open (per-call liveness is not built)"
red "ours=pre:${PRE:-none}/post:${POST:-none} expected=allowed+revoked — revocation was not instant mid-session"
