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

# Drive the engine seam through the relay binary. The floor leg (`run_addressed`)
# seals a message addressed to an AID's pairwise mailbox, authenticated as the
# sender AID, scans the message + both envelopes for any number/email, and rejects
# a forgery claiming an uncontrolled AID — emitting one marker line. We assert on
# THAT line so the floor's own claim is judged, not another leg's device narration.
#
# GREEN requires: serve exits 0; the floor marker `aid-authenticated-number-free`
# is present and says `authenticated`; and, independently, the floor line carries
# no actual phone number or email ADDRESS. The AIDs in the line are `did:keri:` /
# `did:webs:` identifiers — addresses by construction, whose hex can contain a long
# digit run by chance — so they are MASKED out before the scan, exactly as the
# engine masks them. We then look for a real telco *shape*, not an English word: a
# run of 7+ digits (a dialable number) or a `local@domain.tld` email address. A
# leak of either turns the probe RED. Until the bind is built, serve fails closed
# and the marker is absent.
OUT="$(relay_serve)"; RC=$?
FLOOR_LINE="$(printf '%s\n' "$OUT" | grep -E 'aid-authenticated-number-free' | head -1)"
# Mask the AID strings (addresses, not numbers) before the leak scan.
FLOOR_SCAN="$(printf '%s' "$FLOOR_LINE" | sed -E 's#did:(keri|webs):[A-Za-z0-9._:-]+# #g')"

if [ $RC -eq 0 ] \
   && [ -n "$FLOOR_LINE" ] \
   && printf '%s' "$FLOOR_LINE" | grep -qiE 'authenticated' \
   && ! printf '%s' "$FLOOR_SCAN" | grep -qE '[0-9]{7,}|[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}'; then
    green "a message was authenticated by its sender AID and addressed to a pairwise mailbox — no phone number or email in the flow"
fi

red "ours=feature-absent expected=aid-authenticated+number-free — the KERI bind that authenticates the sender AID is unbuilt ($(printf '%s' "$OUT" | head -1)); MSG-1 is open"
