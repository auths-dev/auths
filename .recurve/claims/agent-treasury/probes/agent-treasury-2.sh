#!/usr/bin/env bash
# AGENT-TREASURY-2 — A sub-agent provably cannot exceed its own attenuated slice.
# The flip sub-agent holds a `calls:4` slice ("$4,000"). Its in-slice calls verify;
# the call that would push it past its slice is refused `cap_exceeded` BEFORE the
# rail is touched — even though the PARENT treasury still has headroom (the other
# three slices are unspent). A sub-agent is bounded by ITS slice, not the total.
#
# GREEN: counts 0..3 (the four in-slice calls) verify valid; the 5th (count 4) is
#   refused with the distinct cap_exceeded; under-claiming a lower count after the
#   high-water advanced is refused (usage_counter_rolled_back), so the over-slice
#   call cannot be coerced back to valid.
# RED: the over-slice call verified valid, or was rejected by a generic verdict, or
#   could be coerced to valid. BROKEN: could not build the chain.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/overslice-verify.json" ] \
        || broken "trap fixture missing overslice-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/overslice-verify.json" 2>/dev/null)"
    if [ "$status" != "cap_exceeded" ]; then
        red "ours=status:${status:-none} expected=cap_exceeded — the over-slice call was admitted or rejected by a GENERIC verdict; a sub-agent is not bounded by its slice"
    fi
    green "captured over-slice verdict is the distinct cap_exceeded — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury2.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
# Two sub-agents so the PARENT has headroom while flip is bounded by its own slice.
FLIP="$(delegate_subagent flip manager)";   [ -n "$FLIP" ]  || broken "could not delegate flip"
YIELD="$(delegate_subagent yield manager)"; [ -n "$YIELD" ] || broken "could not delegate yield"
FLIP_SAID="$(issue_slice manager "$FLIP" calls:4)"; [ "$(issue_rc)" -eq 0 ] && [ -n "$FLIP_SAID" ] \
    || broken "could not issue the flip slice (exit $(issue_rc))"
# yield's calls:3 slice is unspent — the treasury has headroom flip cannot borrow.
issue_slice manager "$YIELD" calls:3 >/dev/null; [ "$(issue_rc)" -eq 0 ] || broken "could not issue yield slice"

OBS="$LAB/obs.json"
# In-slice: the four calls (counts 0,1,2,3) verify.
for n in 0 1 2 3; do
    write_observation "$OBS" "$FLIP_SAID" "$n"
    st="$(verify_status manager "$FLIP_SAID" "$OBS")"
    [ "$st" = "valid" ] || broken "in-slice count $n did not verify (status=${st:-none}); cannot test the slice boundary"
done

# The 5th call (count 4) is over the slice — refused cap_exceeded, even with parent headroom.
write_observation "$OBS" "$FLIP_SAID" 4
OVER="$(verify_status manager "$FLIP_SAID" "$OBS")"
[ "$OVER" = "cap_exceeded" ] \
    || red "ours=overslice:${OVER:-none} expected=cap_exceeded — the call past flip's calls:4 slice was not refused, despite the treasury having unspent headroom in other slices; the sub-agent is not bounded by ITS slice"

# Coercion: under-claiming a lower count after the high-water advanced is refused.
write_observation "$OBS" "$FLIP_SAID" 1
UNDER="$(verify_status manager "$FLIP_SAID" "$OBS")"
[ "$UNDER" != "valid" ] \
    || red "ours=underclaim:valid expected=non-valid — under-claiming a lower count after the slice was spent re-opened it to valid; the over-slice call was coerced through"

green "the flip sub-agent's four in-slice calls verify, the 5th (count 4) is refused cap_exceeded with the treasury still holding unspent headroom, and under-claiming a lower count is refused (${UNDER}) — a sub-agent is bounded by its own attenuated slice, not the treasury total"
