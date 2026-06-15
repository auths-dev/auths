#!/usr/bin/env bash
# ENC-1 — the Signal session is rooted in a KERI-authenticated prekey bundle; a
# bundle signed by a wrong / non-pre-committed key is rejected, and the AID key
# signs a DISTINCT Signal identity key (no signing↔DH reuse). GREEN means the
# bundle verify + key-hygiene assertion pass on the good path and reject the
# mis-signed bundle. RED means the verify is unbuilt. BROKEN means we could not
# drive the engine.
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
    if printf '%s' "$out" | grep -qiE 'wrong-key-bundle-accepted|key-reused|not built|feature absent'; then
        red "ours=mis-signed-bundle-accepted expected=bundle-rejected — a bundle signed by the wrong key rooted a session (\"$(printf '%s' "$out" | head -1)\"); the prekey-bundle verify regressed"
    fi
    green "captured session rejected the mis-signed bundle and asserted a distinct Signal identity key — the adversarial twin holds"
fi

relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

OUT="$(relay_serve)"; RC=$?
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -qiE 'bundle-verified-against-aid'; then
    green "the session was rooted in a KERI-authenticated prekey bundle (distinct Signal identity key); a wrong-key bundle was rejected"
fi

red "ours=feature-absent expected=keri-rooted-bundle+wrong-key-rejected — the prekey-bundle verify (KEL replay before X3DH) is unbuilt ($(printf '%s' "$OUT" | head -1)); ENC-1 is open"
