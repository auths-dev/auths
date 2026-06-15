#!/usr/bin/env bash
# AGENT-CAP-3 — within-cap presentations VERIFY (the accept path). Calls 1..N
# (N=3) each present the credential bound to the current observed count and return
# `valid`; the protected action would run N times. Authorized spend keeps working
# under the new enforcement.
#
# GREEN means BOTH halves hold:
#   (accept) with cap `calls:3`, the three in-budget counts 0 -> 1 -> 2 each
#     verify `valid`, and the verifier's high-water mark advances each time.
#   (reject) cap enforcement runs only on an OTHERWISE-AUTHENTIC credential: a
#     within-cap count presented against a credential SAID that does not resolve
#     (a forged/unanchored credential) does NOT yield `valid` — it fails the
#     authenticity verify first and never reaches the cap-admit path. A count is
#     only honored for a credential that actually verifies.
#
# RED means an in-budget count did not verify (the cap broke authorized spend), or
# a forged credential's within-cap count was admitted as valid. BROKEN means we
# could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verify run that returned `valid` for an UNRESOLVABLE
# credential SAID carrying a within-cap count — i.e. cap-admit was reached without
# an authentic credential underneath. A `valid` on a forged credential is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/forged-verify.json" ] \
        || broken "trap fixture missing forged-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/forged-verify.json" 2>/dev/null)"
    if [ "$status" = "valid" ]; then
        red "ours=forged-credential-valid expected=non-valid — a within-cap count against an unresolvable credential was admitted valid; cap-admit ran without an authentic credential underneath"
    fi
    green "captured forged-credential verify was not valid (status=${status:-none}) — cap-admit requires an authentic credential; the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"
AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

CAP_SAID="$(issue_capped finance "$AGENT_DID" calls:3 sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$CAP_SAID" ] \
    || broken "could not issue the capped credential (exit $(issue_rc))"

# ── Accept half: counts 0 -> 1 -> 2 (all under the cap of 3) each verify valid. ─
OBS="$LAB/obs.json"
admitted=0
for n in 0 1 2; do
    write_observation "$OBS" "$CAP_SAID" "$n"
    st="$(verify_status finance "$CAP_SAID" "$OBS")"
    if [ "$st" = "valid" ]; then
        admitted=$((admitted + 1))
    else
        red "ours=call$((n + 1)):${st:-none} expected=valid — within-cap call $((n + 1)) of 3 (calls_used=$n) did not verify; the cap broke authorized spend"
    fi
done
[ "$admitted" -eq 3 ] \
    || red "ours=admitted:${admitted} expected=3 — fewer than N=3 within-cap presentations verified"

# ── Reject half: a within-cap count against a FORGED credential is not valid. ──
# A SAID that resolves to no credential must fail authenticity before cap-admit.
FORGED_SAID="EForgedCredentialSaidThatWasNeverIssuedAnywhere0000000"
write_observation "$OBS" "$FORGED_SAID" 0
FORGED_STATUS="$(verify_status finance "$FORGED_SAID" "$OBS")"

if [ "$admitted" -eq 3 ] && [ "$FORGED_STATUS" != "valid" ]; then
    green "all three within-cap counts (0,1,2 under calls:3) verified valid and advanced the ledger, while a within-cap count against a forged/unanchored credential did NOT verify (status=${FORGED_STATUS:-none}) — authorized spend works, but a count is only honored for an authentic credential"
fi
red "ours=forged:${FORGED_STATUS:-none} expected=non-valid — a within-cap count against a forged credential was admitted valid; cap-admit ran without authenticity"
