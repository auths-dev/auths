#!/usr/bin/env bash
# RVK-1 — revocation resolves from WITNESS-CORROBORATED key-state, not a relay's
# cache. GREEN means: after the root revokes a delegated device, the device's next
# message FAILS to verify when the contact resolves witness-corroborated state, AND
# the honest stale-served window is acknowledged (a contact served a relay's stale
# cache is the named gap, not a silent pass). RED means the corroborated-revocation
# path is unbuilt (the skeleton fails closed). BROKEN means we could not drive the
# engine.
#
# PRD §6.5 — revocation is prevention-vs-detection, not an instant global kill: it
# is only as fast as each contact RE-RESOLVES, and only safe if they get
# witness-corroborated state rather than a relay's stale cache. This strengthens
# MSG-4's clawback: the clawback must hold *from corroborated state*, and the
# stale-served window must be disclosed, never hidden.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the documented failure: a revoked device was accepted from
# witness-corroborated state (the revocation was resolved from a relay's stale
# cache and waved through). That must be RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'revoked-accepted-from-corroborated|relay-cache-trusted-over-witness|stale-window-hidden|not built|feature absent'; then
        red "ours=revoked-accepted-from-corroborated expected=revoked-rejected+stale-window-disclosed — a revoked device was accepted from corroborated state, or the stale window was hidden (\"$(printf '%s' "$out" | head -1)\"); the corroborated-revocation path regressed"
    fi
    green "captured flow rejected the revoked device from witness-corroborated state and disclosed the honest stale-served window — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

# Drive the engine seam through the relay binary. In the skeleton the
# witness-corroborated revocation resolution is unbuilt, so serve fails closed —
# there is no corroborated revocation verdict to observe yet.
OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] \
   && printf '%s' "$OUT" | grep -qiE 'revoked-from-corroborated-state' \
   && printf '%s' "$OUT" | grep -qiE 'stale-window-disclosed'; then
    green "a revoked device was rejected from witness-corroborated key-state (not a relay cache), and the honest stale-served window was acknowledged — clawback as detection, disclosed"
fi

red "ours=feature-absent expected=revoked-rejected-from-corroborated+stale-window-disclosed — revocation resolution from witness-corroborated state is unbuilt ($(printf '%s' "$OUT" | head -1)); RVK-1 is open"
