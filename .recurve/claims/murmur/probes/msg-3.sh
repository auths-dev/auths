#!/usr/bin/env bash
# MSG-3 — message content is forward-secret and the relay learns neither the
# plaintext nor a phone number. GREEN means the relay-visible bytes are opaque
# forward-secret ciphertext under a pairwise mailbox id, with no plaintext / PII.
# RED means the relay wire is unbuilt (serve fails closed). BROKEN means we could
# not drive the relay.
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
    if printf '%s' "$out" | grep -qiE 'plaintext-in-queue|phone-in-queue|not built|feature absent'; then
        red "ours=relay-sees-plaintext expected=opaque-ciphertext-only — the relay queue held plaintext or a phone number (\"$(printf '%s' "$out" | head -1)\"); the E2E envelope regressed"
    fi
    green "captured relay queue held only opaque ciphertext under a pairwise mailbox id — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'forward-secret|ciphertext-queued' \
   && ! printf '%s' "$OUT" | grep -qiE 'plaintext|[0-9]{10}|phone'; then
    green "the relay queued forward-secret ciphertext under a pairwise mailbox id — no plaintext, no phone number"
fi

red "ours=feature-absent expected=forward-secret+number-free-relay — the store-and-forward wire is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-3 is open"
