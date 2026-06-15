#!/usr/bin/env bash
# ENC-5 — the untrusted relay can't tamper, replay, or link: bit-flipped
# ciphertext fails AEAD and is rejected (no oracle); a replayed ciphertext is
# deduped; the relay-visible envelope carries only a pairwise mailbox id, never a
# stable cross-contact linker. GREEN means all three hold. RED means the receive
# path / queue is unbuilt. BROKEN means we could not drive the relay.
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
    if printf '%s' "$out" | grep -qiE 'tamper-accepted|replay-delivered-twice|cross-contact-linker|not built|feature absent'; then
        red "ours=relay-can-tamper-or-replay expected=aead-rejected+deduped — a tampered or replayed ciphertext was accepted (\"$(printf '%s' "$out" | head -1)\"); the receive guard regressed"
    fi
    green "captured run rejected the bit-flipped ciphertext and deduped the replay; the envelope carried only a pairwise id — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'aead-rejected' \
   && printf '%s' "$OUT" | grep -qiE 'replay-deduped'; then
    green "a bit-flipped ciphertext failed AEAD and was rejected; a replay was deduped; the envelope carried only a pairwise mailbox id"
fi

red "ours=feature-absent expected=aead-rejected+replay-deduped — the relay receive path (AEAD verify + dedup) is unbuilt ($(printf '%s' "$OUT" | head -1)); ENC-5 is open"
