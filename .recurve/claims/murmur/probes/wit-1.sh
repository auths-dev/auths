#!/usr/bin/env bash
# WIT-1 — the missing surface the whole continuity story rests on: a FORKED KEL
# (two different rotations claiming the same sequence number) is REJECTED, and a
# relay-suppressed / stale key-state is CAUGHT by the witness threshold. GREEN
# means a fork is refused and a stale/suppressed key-state fails the witness
# corroboration check (the launch-centralization asterisk, §3.1, is load-bearing
# — a malicious relay must not be able to serve a forked or stale log to suppress
# or fake a rotation). RED means the fork-detection / witness-threshold check is
# unbuilt (the skeleton fails closed). BROKEN means we could not drive the engine.
#
# This is the single most important correctness dependency (PRD §2 binding
# mechanism + §3.1): MSG-2's verified-continuation badge is only trustworthy if
# the key-state it replays is the one true witnessed log.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the documented failure: a forked or stale/relay-suppressed
# KEL was ACCEPTED as the contact's current key-state. That must be RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'forked-kel-accepted|stale-keystate-accepted|witness-threshold-bypassed|not built|feature absent'; then
        red "ours=forked-or-stale-kel-accepted expected=fork-rejected+stale-caught — a forked or relay-suppressed key-state was accepted (\"$(printf '%s' "$out" | head -1)\"); the witness-threshold fork detection regressed"
    fi
    green "captured replay rejected the forked KEL and caught the stale/suppressed key-state at the witness threshold — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

# Drive the engine seam through the relay binary. In the skeleton the KEL-replay /
# witness-threshold path is unbuilt, so serve fails closed — there is no
# fork-detected, witness-corroborated key-state to observe yet.
OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'fork-rejected' \
   && printf '%s' "$OUT" | grep -qiE 'witness-corroborated'; then
    green "a forked KEL was rejected and a stale/relay-suppressed key-state was caught by the witness threshold — the continuity story rests on the one true witnessed log"
fi

red "ours=feature-absent expected=fork-rejected+stale-caught — the forked-KEL detection + witness-threshold corroboration is unbuilt ($(printf '%s' "$OUT" | head -1)); WIT-1 is open"
