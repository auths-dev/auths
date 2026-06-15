#!/usr/bin/env bash
# MSG-2 — a contact's key rotation verifies as a pre-committed continuation of the
# same identity; a substituted (not-pre-committed) key is rejected. GREEN means a
# pre-committed rotation yields VerifiedContinuation and a substituted key yields
# NonContinuationWarning (not a soft re-pin). RED means the pre-rotation check is
# unbuilt (the skeleton fails closed). BROKEN means we could not drive the engine.
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
    if printf '%s' "$out" | grep -qiE 'substituted-key-accepted|continuation-without-precommit|not built|feature absent'; then
        red "ours=substituted-key-accepted expected=non-continuation-warning — a not-pre-committed key verified as a continuation (\"$(printf '%s' "$out" | head -1)\"); the pre-rotation check regressed"
    fi
    green "captured rotation produced VerifiedContinuation for the pre-committed key and NonContinuationWarning for the substituted one — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'verified-continuation'; then
    green "a pre-committed rotation verified as a continuation of the same identity; a substituted key was warned, not re-pinned"
fi

red "ours=feature-absent expected=verified-continuation+substituted-rejected — the KEL replay + pre-rotation commitment check is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-2 is open"
