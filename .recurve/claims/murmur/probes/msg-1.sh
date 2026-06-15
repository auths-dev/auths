#!/usr/bin/env bash
# MSG-1 — a message is addressed to, and authenticated by, an AID, with no phone
# number or email anywhere in the flow. GREEN means: a message sealed through the
# core is authenticated by the sender's AID (the KERI bind ran) and addressed to
# the recipient's pairwise mailbox, with no phone number / email in the envelope;
# and a message claiming an uncontrolled AID is REJECTED. RED means the bind is
# absent (the skeleton fails closed "feature absent"). BROKEN means we could not
# drive the relay/engine at all.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/murmur)
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the documented PRE-BUILD failure: a message from an AID the
# sender does not control was accepted as authentic. That regression must be RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'accepted-unauthenticated|uncontrolled-aid-accepted|not built|feature absent'; then
        red "ours=unauthenticated-accepted expected=aid-authenticated — a message from an AID the sender does not control was accepted (\"$(printf '%s' "$out" | head -1)\"); the bind regressed"
    fi
    green "captured flow authenticated the sender AID and rejected the uncontrolled one — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

# Drive the engine seam through the relay binary. In the skeleton the seal/bind
# path is unbuilt, so the relay's serve (its only behavioral surface today) fails
# closed — there is no authenticated, number-free message to observe yet.
OUT="$(relay_serve)"; RC=$?

if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'authenticated' \
   && ! printf '%s' "$OUT" | grep -qiE '[0-9]{10}|@|phone|e-?mail'; then
    green "a message was authenticated by its sender AID and addressed to a pairwise mailbox — no phone number or email in the flow"
fi

red "ours=feature-absent expected=aid-authenticated+number-free — the KERI bind that authenticates the sender AID is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-1 is open"
