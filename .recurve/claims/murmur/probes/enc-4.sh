#!/usr/bin/env bash
# ENC-4 — nothing but routing leaves the device in the clear: no plaintext,
# message key, ratchet state, or SENDER AID appears in the outer envelope, the
# relay-visible bytes, logs, receipts, or telemetry. GREEN means a leakcheck-style
# scan AND a relay-capture assertion find only the pairwise mailbox id. RED means
# seal() does not produce the envelope yet. BROKEN means we could not drive it.
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
    if printf '%s' "$out" | grep -qiE 'sender-aid-in-envelope|plaintext-in-envelope|not built|feature absent'; then
        red "ours=envelope-leaks expected=routing-only — the outer envelope carried the sender AID or a key (\"$(printf '%s' "$out" | head -1)\"); the no-leak property regressed"
    fi
    green "captured outer envelope carried only the pairwise mailbox id — no plaintext, key, ratchet state, or sender AID — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'routing-only-envelope' \
   && ! printf '%s' "$OUT" | grep -qiE 'sender-aid|plaintext|message-key|ratchet-state'; then
    green "the outer envelope / relay-visible bytes carried only the pairwise mailbox id — no plaintext, key, ratchet state, or sender AID"
fi

red "ours=feature-absent expected=routing-only-envelope — seal() does not yet produce the leak-free outer envelope ($(printf '%s' "$OUT" | head -1)); ENC-4 is open"
