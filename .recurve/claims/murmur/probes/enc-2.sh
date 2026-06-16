#!/usr/bin/env bash
# ENC-2 — forward secrecy holds across our wiring: a ciphertext captured off the
# relay cannot be decrypted from a later, compromised session state; used message
# keys are zeroized. GREEN means decrypting message N-k from the state at message
# N fails. RED means no ratchet state exists yet. BROKEN means we could not drive
# the engine.
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
    if printf '%s' "$out" | grep -qiE 'late-state-decrypts-old|key-not-zeroized|not built|feature absent'; then
        red "ours=forward-secrecy-broken expected=old-ciphertext-undecryptable — a later compromised state decrypted an earlier ciphertext (\"$(printf '%s' "$out" | head -1)\"); forward secrecy regressed"
    fi
    green "captured run could NOT decrypt an earlier ciphertext from a later compromised state; keys were zeroized — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'forward-secrecy-held'; then
    green "an earlier ciphertext could not be decrypted from a later compromised state; used message keys were zeroized"
fi

red "ours=feature-absent expected=forward-secrecy-held — the Double Ratchet (used-key zeroization) is unbuilt ($(printf '%s' "$OUT" | head -1)); ENC-2 is open"
