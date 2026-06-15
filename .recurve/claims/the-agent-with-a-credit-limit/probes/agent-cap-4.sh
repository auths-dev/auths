#!/usr/bin/env bash
# AGENT-CAP-4 — the (N+1)th, OVER-CAP presentation is UNVERIFIABLE, with a DISTINCT
# verdict. With cap `calls:3`, the 4th call (which would make count = 3, reaching
# the bound) fails verification with `cap_exceeded` — a verdict distinct from
# valid, schema_invalid, revoked, expired, and stale_or_unresolvable. The verdict
# NAMES THE BUDGET as the cause; the executor never runs.
#
# GREEN means BOTH halves hold:
#   (accept of the reject) the 4th presentation (calls_used=3 against calls:3)
#     returns exactly `cap_exceeded` — not `valid`, and not a GENERIC failure
#     verdict that fails to attribute the rejection to the budget.
#   (reject / coercion) the over-cap call cannot be COERCED back to valid: re-running
#     verify (a "fresh" attempt) stays cap_exceeded, and UNDER-CLAIMING a lower
#     count than the recorded high-water mark does not re-open budget (it is caught
#     as a rolled-back counter, never valid).
#
# RED means the 4th call verified valid, OR it was rejected by a GENERIC verdict
# that does not name the budget, OR it could be coerced to valid. BROKEN means we
# could not build the chain.
#
# The visceral beat: "we configured a limit" becomes "exceeding the limit is
# unverifiable." Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the over-cap verify returning a verdict that is NOT the
# distinct cap_exceeded — either `valid` (the cap did not fire) or a GENERIC
# failure (`schema_invalid`, a bare invalid) that does not name the budget. Either
# is RED: the claim's whole point is the distinct, attributable verdict.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/overcap-verify.json" ] \
        || broken "trap fixture missing overcap-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/overcap-verify.json" 2>/dev/null)"
    if [ "$status" != "cap_exceeded" ]; then
        red "ours=status:${status:-none} expected=cap_exceeded — the over-cap call was admitted or rejected by a GENERIC verdict that does not name the budget; the cap is not a distinct, attributable boundary"
    fi
    green "captured over-cap verdict is the distinct cap_exceeded — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap4.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"
AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

CAP_SAID="$(issue_capped finance "$AGENT_DID" calls:3 sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$CAP_SAID" ] \
    || broken "could not issue the capped credential (exit $(issue_rc))"

# Spend the budget: counts 0,1,2 all verify (the high-water mark reaches 2).
OBS="$LAB/obs.json"
for n in 0 1 2; do
    write_observation "$OBS" "$CAP_SAID" "$n"
    st="$(verify_status finance "$CAP_SAID" "$OBS")"
    [ "$st" = "valid" ] \
        || broken "in-budget count $n did not verify (status=${st:-none}); cannot test the N+1 boundary"
done

# ── The boundary: the 4th call (count=3) reaches the cap and is unverifiable. ──
write_observation "$OBS" "$CAP_SAID" 3
OVERCAP_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$OVERCAP_STATUS" = "cap_exceeded" ] \
    || red "ours=overcap:${OVERCAP_STATUS:-none} expected=cap_exceeded — the 4th (over-cap) presentation was not refused with the distinct cap_exceeded verdict; the budget is not the verify boundary"

# ── Coercion 1: re-running verify (a "fresh" attempt) stays cap_exceeded. ─────
write_observation "$OBS" "$CAP_SAID" 3
RETRY_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$RETRY_STATUS" = "cap_exceeded" ] \
    || red "ours=retry:${RETRY_STATUS:-none} expected=cap_exceeded — a re-run of the over-cap verify was coerced off cap_exceeded; the boundary is not fail-closed across attempts"

# ── Coercion 2: UNDER-CLAIMING a lower count cannot re-open budget. ───────────
# Present count=1 (below the recorded high-water of 2). It must NOT verify valid —
# it is caught as a rolled-back counter, so an attacker cannot lower the claimed
# amount to slip the over-budget action through.
write_observation "$OBS" "$CAP_SAID" 1
UNDERCLAIM_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$UNDERCLAIM_STATUS" != "valid" ] \
    || red "ours=underclaim:valid expected=non-valid — under-claiming a lower count after the budget was spent re-opened it to valid; the over-cap action was coerced through"

green "the 4th over-cap presentation (calls_used=3 against calls:3) is unverifiable with the DISTINCT cap_exceeded verdict (not valid, not a generic invalid); it stays cap_exceeded on re-run, and under-claiming a lower count is refused (${UNDERCLAIM_STATUS}) — exceeding the limit is unverifiable, and cannot be coerced to valid"
