#!/usr/bin/env bash
# MSG-4 — a delegated device (the Mac) sends authenticated as the same ROOT
# identity the iPhone holds, and revoking that device stops its next message.
# GREEN means a message from a delegated device verifies as the root AID, and
# after revocation the device's next message is rejected (clawback from the
# chain). RED means open() is unbuilt. BROKEN means we could not drive the engine.
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
    if printf '%s' "$out" | grep -qiE 'revoked-device-accepted|clawback-failed|revoked-accepted-from-corroborated|not built|feature absent'; then
        red "ours=revoked-device-accepted expected=revoked-rejected-from-corroborated — a revoked device's message still verified, or revocation resolved from a relay cache rather than witness-corroborated state (\"$(printf '%s' "$out" | head -1)\"); the chain clawback regressed"
    fi
    green "captured flow verified the delegated device as the root AID and rejected it after revocation from witness-corroborated state — the adversarial twin holds (the honest stale-served window is carried by RVK-1)"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'device-as-root' \
   && printf '%s' "$OUT" | grep -qiE 'revoked-rejected'; then
    green "a delegated device verified as the same root identity, and its next message after revocation was rejected — clawback from the chain"
fi

red "ours=feature-absent expected=device-as-root+revoked-rejected — the sender-AID KEL replay (delegated-device resolve + revocation) is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-4 is open"
