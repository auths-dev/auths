#!/usr/bin/env bash
# AGENT-CAP-5 — a REPLAYED earlier counter state is REJECTED (freshness /
# monotonicity). After the budget has been spent up to a high-water mark, re-
# presenting an EARLIER, lower counter state (to "rewind" spend and re-open
# budget) is rejected with the distinct `usage_counter_rolled_back` verdict —
# budget is NOT re-opened. An agent cannot rewind its own spend to buy more.
#
# GREEN means BOTH halves hold:
#   (accept of the reject) after the verifier has recorded a high-water mark of 2,
#     re-presenting the earlier count=1 state returns `usage_counter_rolled_back`
#     (a distinct verdict, not valid) — budget stays closed.
#   (reject / internally-valid replay) the replay is refused EVEN THOUGH the
#     replayed count was itself a legitimately-admitted state earlier: the SAME
#     count=1 verified `valid` on its first presentation, yet is refused when
#     replayed after the mark advanced. Freshness is enforced against the LATEST
#     recorded state, not merely "was this count ever valid."
#
# RED means the replayed lower count was admitted (budget re-opened), or it was
# rejected by a generic verdict that does not name the rollback. BROKEN means we
# could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verify run that ADMITTED (status=valid) a replayed earlier
# counter after a higher mark was recorded — the budget rewind this claim forbids.
# `valid` on the replay is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/rewind-verify.json" ] \
        || broken "trap fixture missing rewind-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/rewind-verify.json" 2>/dev/null)"
    if [ "$status" != "usage_counter_rolled_back" ]; then
        red "ours=status:${status:-none} expected=usage_counter_rolled_back — a replayed earlier counter was admitted or rejected by a generic verdict; the budget could be rewound, or the rewind is not attributable"
    fi
    green "captured replay verdict is the distinct usage_counter_rolled_back — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap5.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"
AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

CAP_SAID="$(issue_capped finance "$AGENT_DID" calls:5 sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$CAP_SAID" ] \
    || broken "could not issue the capped credential (exit $(issue_rc))"

OBS="$LAB/obs.json"

# The earlier count=1 is a LEGITIMATELY-admitted state on first presentation —
# capture that it verified valid, so the replay refusal cannot be dismissed as the
# count having always been bad.
write_observation "$OBS" "$CAP_SAID" 0
st0="$(verify_status finance "$CAP_SAID" "$OBS")"
write_observation "$OBS" "$CAP_SAID" 1
FIRST_TIME_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$st0" = "valid" ] && [ "$FIRST_TIME_STATUS" = "valid" ] \
    || broken "the early counts 0,1 did not both verify (0=${st0:-none}, 1=${FIRST_TIME_STATUS:-none}); cannot stage the replay"

# Advance the high-water mark to 2.
write_observation "$OBS" "$CAP_SAID" 2
st2="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$st2" = "valid" ] || broken "count=2 did not verify (status=${st2:-none}); cannot advance the mark"

# ── The rewind attempt: re-present the EARLIER count=1 state. ─────────────────
write_observation "$OBS" "$CAP_SAID" 1
REPLAY_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"

if [ "$FIRST_TIME_STATUS" = "valid" ] && [ "$REPLAY_STATUS" = "usage_counter_rolled_back" ]; then
    green "the count=1 state verified valid on first presentation, but after the high-water mark advanced to 2 the SAME count=1 replay is refused usage_counter_rolled_back (a distinct verdict, not valid) — freshness is enforced against the latest recorded state, so an internally-valid earlier counter cannot rewind spend to re-open budget"
fi
[ "$REPLAY_STATUS" = "valid" ] \
    && red "ours=replay:valid expected=usage_counter_rolled_back — a replayed earlier counter (count=1, once valid) was admitted after the mark advanced to 2; the agent rewound its own spend to re-open budget"
red "ours=replay:${REPLAY_STATUS:-none} expected=usage_counter_rolled_back — the replayed earlier counter was not rejected with the distinct rollback verdict; monotonicity is not attributable (or not enforced)"
