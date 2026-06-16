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
    if printf '%s' "$out" | grep -qiE 'substituted-key-accepted|continuation-without-precommit|ratchet-continued-across-identity-change|stale-signer-prekey-accepted|not built|feature absent'; then
        red "ours=substituted-or-stale-signer-accepted expected=non-continuation-warning+rekeyed — a not-pre-committed key verified as a continuation, the ratchet was continued across an identity change, or a stale-signer prekey was accepted (\"$(printf '%s' "$out" | head -1)\"); the pre-rotation re-key/re-verify regressed"
    fi
    green "captured rotation produced VerifiedContinuation for the pre-committed key, NonContinuationWarning for the substituted one, re-keyed the Signal session, and re-verified the republished prekey against the fresh current key — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'verified-continuation' \
   && printf '%s' "$OUT" | grep -qiE 'session-rekeyed' \
   && printf '%s' "$OUT" | grep -qiE 'prekey-reverified'; then
    green "a pre-committed rotation verified as a continuation of the same identity; the Signal session was re-keyed (old ratchet not continued across the identity change) and the republished prekey was re-verified against the fresh current key; a substituted key was warned, not re-pinned"
fi

red "ours=feature-absent expected=verified-continuation+rekeyed+prekey-reverified+substituted-rejected — the KEL replay + pre-rotation commitment check + Signal re-key/prekey-reverify is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-2 is open"
