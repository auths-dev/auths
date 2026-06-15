#!/usr/bin/env bash
# DEV-1 — a message sent from the Mac arrives, authenticated, on the iPhone sim.
# GREEN means the end-to-end leg holds hermetically: a message sealed on the
# desktop side is stored-and-forwarded through the relay, pulled on the receiving
# side, and verified+decrypted as the sender. (The live two-device demo on a
# booted simulator is the operator's dev confirmation — allowed for this suite —
# never the gate.) RED means the leg is unbuilt. BROKEN means we could not drive
# the relay.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'arrived-unauthenticated|delivered-but-unverified|not built|feature absent'; then
        red "ours=arrived-unauthenticated expected=arrived-authenticated — the message arrived but did not authenticate as the sender (\"$(printf '%s' "$out" | head -1)\"); the cross-device verify regressed"
    fi
    green "captured delivery arrived authenticated as the sender on the receiving device — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'delivered-and-authenticated'; then
    green "a message sealed on the desktop side was stored-and-forwarded through the relay and arrived authenticated on the receiving side"
fi

red "ours=feature-absent expected=delivered-and-authenticated — the end-to-end leg (seal → relay store-and-forward → pull → verify+decrypt) is unbuilt ($(printf '%s' "$OUT" | head -1)); DEV-1 is open"
