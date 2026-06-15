#!/usr/bin/env bash
# AGENT-MCP-5 — the over-reach is a real model's decision and reproduces
# deterministically in CI. GREEN means: the gateway driven twice over the SAME
# frozen transcript yields byte-stable verdicts (no model/network), and the
# recorded over-bounds call is refused — and (the adversarial guard) a transcript
# edited to drop the proof or forge a wider scope still fails closed. RED means
# replay is not byte-stable or the recorded over-reach is not refused (the replay
# path is a stub). BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a TAMPERED transcript replay (proof dropped / scope forged)
# whose over-bounds call was nonetheless ALLOWED — the adversarial guard this
# probe forbids. A forged-wider replay that does not fail closed is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qiE 'outside-agent-scope|revoked|usage-cap-exceeded|rejected|invalid'; then
        red "ours=tampered-replay-passed expected=fail-closed — a transcript edited to drop the proof / forge a wider scope did not fail closed (\"$(printf '%s' "$out" | head -1)\"); the adversarial replay guard regressed"
    fi
    green "captured tampered replay failed closed — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-5)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp5.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# Byte-stability: two drives of the same frozen transcript must produce identical
# verdict streams (the hermetic-replay property).
RUN1="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
RC1=$?
RUN2="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"

if [ $RC1 -eq 0 ] \
   && [ -n "$RUN1" ] && [ "$RUN1" = "$RUN2" ] \
   && printf '%s' "$RUN1" | grep -qi 'outside-agent-scope'; then
    green "replay over the frozen transcript is byte-stable across runs and refuses the recorded over-bounds call — deterministic in CI with no model/network"
fi

[ $RC1 -ne 0 ] || [ -z "$RUN1" ] \
    && red "ours=no-replay expected=byte-stable-verdicts — the gateway produced no replay verdict stream; AGENT-MCP-5 is open (the transcript replayer is not built)"
red "ours=unstable-or-unrefused expected=byte-stable+over-reach-refused — replay did not reproduce a stable, fail-closed verdict for the recorded decision"
