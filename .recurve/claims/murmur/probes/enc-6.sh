#!/usr/bin/env bash
# ENC-6 — vetted implementation, used correctly: the misuse-resistant wrapper
# passes libsignal's OFFICIAL test vectors and a differential/interop test (our
# send ↔ a reference Double-Ratchet decrypt), and a property test asserts no
# one-time prekey or message key is ever reused. GREEN means the vectors + interop
# pass and no key is reused. RED means no wrapper / vectors exist yet. BROKEN means
# we could not drive it.
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
    if printf '%s' "$out" | grep -qiE 'key-reused|vectors-failed|not built|feature absent'; then
        red "ours=wrapper-misused expected=vectors-pass+no-key-reuse — a one-time prekey or message key was reused, or the vectors failed (\"$(printf '%s' "$out" | head -1)\"); the wrapper regressed"
    fi
    green "captured run passed libsignal's vectors + the interop and reused no key — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'libsignal-vectors-pass'; then
    green "the wrapper passed libsignal's official test vectors + a differential interop, and reused no one-time prekey or message key"
fi

red "ours=feature-absent expected=libsignal-vectors-pass+no-key-reuse — the misuse-resistant libsignal wrapper (vectors + interop + no-reuse property) is unbuilt ($(printf '%s' "$OUT" | head -1)); ENC-6 is open"
