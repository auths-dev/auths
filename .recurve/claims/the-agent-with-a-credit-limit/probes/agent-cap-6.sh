#!/usr/bin/env bash
# AGENT-CAP-6 — the cap is enforced by the VERIFIER, not the app, and it is
# PER-CREDENTIAL-AUTHORITY, not per-route. The counter lives in the verifier's
# own ledger keyed by the credential SAID, so it is bypass-proof: there is no
# app-level spend check to disable, and routing the over-cap call through a
# "second tool/endpoint" (a separate verify invocation) on the SAME credential
# does not get a fresh budget — every route reads the one per-authority counter.
#
# GREEN means BOTH halves hold:
#   (accept) the demo harness runs ONLY the auths verify path (there is no
#     app-level spend check anywhere in this probe), and the 1..N-then-N+1 outcome
#     still fail-closes: within-cap counts verify and the over-cap count is
#     cap_exceeded — the verifier ALONE is the boundary.
#   (reject / per-route bypass) after the budget is spent via "route A" (one
#     verify call), presenting the over-cap count via "route B" (a distinct verify
#     call, the second tool) is STILL cap_exceeded — the counter is per-credential-
#     authority (keyed by SAID), not per-route, so a sibling endpoint cannot mint
#     fresh budget for the same credential.
#
# RED means the over-cap call slipped through a second route as valid, or the
# verifier-only path did not fail-close. BROKEN means we could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the over-cap call admitted valid when routed through a SECOND
# verify invocation (a sibling tool) on the same credential — the per-route bypass
# this claim forbids. `valid` via the second route is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/route-b-verify.json" ] \
        || broken "trap fixture missing route-b-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/route-b-verify.json" 2>/dev/null)"
    if [ "$status" = "valid" ]; then
        red "ours=route-b-valid expected=cap_exceeded — the over-cap call was admitted valid through a second route/tool on the same credential; the counter is per-route, so a sibling endpoint mints fresh budget"
    fi
    green "captured second-route over-cap verdict is not valid (status=${status:-none}) — the counter is per-credential-authority; the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap6.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"
AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

CAP_SAID="$(issue_capped finance "$AGENT_DID" calls:3 sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$CAP_SAID" ] \
    || broken "could not issue the capped credential (exit $(issue_rc))"

# ── Accept half: the VERIFIER ALONE fail-closes (no app-level spend check). ───
# This probe never consults any app spend gate; the only authority is the verify
# path. Spend the budget, then over-spend.
OBS="$LAB/obs.json"
for n in 0 1 2; do
    write_observation "$OBS" "$CAP_SAID" "$n"
    st="$(verify_status finance "$CAP_SAID" "$OBS")"
    [ "$st" = "valid" ] \
        || red "ours=verifier-only-call$((n + 1)):${st:-none} expected=valid — with no app spend check, an in-budget call did not verify; the verifier-alone accept path failed"
done
write_observation "$OBS" "$CAP_SAID" 3
ROUTE_A_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$ROUTE_A_STATUS" = "cap_exceeded" ] \
    || red "ours=verifier-only-overcap:${ROUTE_A_STATUS:-none} expected=cap_exceeded — with no app spend check, the over-cap call was not fail-closed by the verifier alone"

# ── Reject half: route the over-cap call through a SECOND tool/endpoint. ──────
# "Route B" is a distinct verify invocation (a sibling tool that also gates on the
# credential). Because the counter is keyed by the credential SAID — not by route —
# it shares the same spent budget and is still cap_exceeded.
write_observation "$OBS" "$CAP_SAID" 3
ROUTE_B_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"

if [ "$ROUTE_A_STATUS" = "cap_exceeded" ] && [ "$ROUTE_B_STATUS" = "cap_exceeded" ]; then
    green "with NO app-level spend check, the verifier alone fail-closes (counts 0,1,2 valid; count=3 cap_exceeded), and routing the over-cap call through a SECOND verify/tool on the same credential is STILL cap_exceeded — the counter is per-credential-authority (keyed by SAID), not per-route, so a sibling endpoint cannot bypass the budget"
fi
red "ours=route-b:${ROUTE_B_STATUS:-none} expected=cap_exceeded — the over-cap call routed through a second tool/endpoint on the same credential was not refused; the counter is per-route, so a sibling endpoint mints fresh budget"
