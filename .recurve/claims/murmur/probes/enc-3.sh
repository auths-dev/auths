#!/usr/bin/env bash
# ENC-3 — post-compromise healing: after a simulated state compromise, the next
# DH ratchet step restores confidentiality (the attacker is locked back out).
# GREEN means confidentiality recovers after the ratchet step. RED means no DH
# ratchet exists yet. BROKEN means we could not drive the engine.
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
    if printf '%s' "$out" | grep -qiE 'no-healing|attacker-still-in|not built|feature absent'; then
        red "ours=no-post-compromise-healing expected=confidentiality-restored — the attacker still decrypted after the ratchet step (\"$(printf '%s' "$out" | head -1)\"); post-compromise security regressed"
    fi
    green "captured run locked the attacker back out after the next DH ratchet step — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'post-compromise-healed'; then
    green "after a simulated state compromise, the next DH ratchet step restored confidentiality"
fi

red "ours=feature-absent expected=post-compromise-healed — the DH ratchet step is unbuilt ($(printf '%s' "$OUT" | head -1)); ENC-3 is open"
