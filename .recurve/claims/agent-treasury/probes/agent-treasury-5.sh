#!/usr/bin/env bash
# AGENT-TREASURY-5 — Instant clawback: revoking a sub-agent is recorded (its spend
# authority is withdrawn, offline-verifiable from the registry) AND its slice returns
# to the treasury free pool — re-allocatable, but never double-counted.
#
# GREEN: after the manager revokes the arb sub-agent, (a) the registry records arb
#   revoked (a relying party re-deriving liveness sees it withdrawn — the gateway
#   refuses arb's next call from exactly this state), while a non-revoked sibling
#   stays live; AND (b) arb's slice is released to the free pool (`treasury reclaim`
#   raises free_pool by the freed amount); a second reclaim is a no-op
#   (nothing_to_reclaim — no double-count), and a reallocation from the reclaimed
#   (gone) slice does NOT commit.
# RED: the revoke is not recorded, or the freed slice is not released / is
#   double-counted, or a freed-slice reallocation commits. BROKEN: could not build.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# Trap: a reallocation that double-counts a freed (revoked) slice and WRONGLY commits
# (status=reallocated) — the freed budget was over-committed. That is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/freed-realloc.json" ] \
        || broken "trap fixture missing freed-realloc.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/freed-realloc.json" 2>/dev/null)"
    if [ "$status" = "reallocated" ]; then
        red "ours=status:reallocated expected=refused — a reallocation that double-counts a freed (revoked) slice committed; the freed budget was over-committed"
    fi
    green "captured double-counting reallocation of a freed slice does not commit — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

# The free-pool reclaim surface is net-new; its absence is the gap.
has_subcommand treasury reclaim \
    || red "ours=no-free-pool-surface expected=revoke releases the slice to parent_cap − Σ live slices (free pool), re-allocatable but never double-counted — the engine has no revoke→free-pool reclaim"

agent_revoked() {  # <agent-did> → echoes true/false from the registry
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id agent list --include-revoked 2>/dev/null \
        | jq -r --arg d "$1" '.data.agents[]? | select(.agent_did==$d) | .revoked' 2>/dev/null
}

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury5.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
FLIP="$(delegate_subagent flip manager)"; [ -n "$FLIP" ] || broken "could not delegate flip"
ARB="$(delegate_subagent arb manager)";   [ -n "$ARB" ]  || broken "could not delegate arb"
[ "$(treasury_open manager calls:10)" = "opened" ] || broken "could not establish the treasury cap"
[ "$(treasury_allot manager "$FLIP" 4)" = "allotted" ] || broken "could not allot flip's slice"
[ "$(treasury_allot manager "$ARB" 2)"  = "allotted" ] || broken "could not allot arb's slice"

FREE_BEFORE="$(treasury_field manager '.data.free_pool')"
[ "$FREE_BEFORE" = "4" ] || broken "free pool not 4 before clawback (got ${FREE_BEFORE:-none})"

# (a) Revoke arb — the registry records it withdrawn; the sibling stays live.
revoke_subagent manager "$ARB" >/dev/null
[ "$(revoke_rc)" -eq 0 ] || red "ours=revoke-failed expected=revoked — the manager could not revoke the arb sub-agent"
[ "$(agent_revoked "$ARB")" = "true" ] \
    || red "ours=arb-revoked:$(agent_revoked "$ARB") expected=true — the revocation is not recorded; a relying party cannot see arb's authority withdrawn"
[ "$(agent_revoked "$FLIP")" = "false" ] \
    || red "ours=flip-revoked:$(agent_revoked "$FLIP") expected=false — revoking arb wrongly withdrew a sibling's authority"

# (b) Reclaim arb's slice → the freed 2 returns to the free pool.
[ "$(treasury_reclaim manager "$ARB")" = "reclaimed" ] \
    || red "ours=reclaim:$(treasury_reclaim manager "$ARB") expected=reclaimed — arb's slice was not released on revoke"
FREE_AFTER="$(treasury_field manager '.data.free_pool')"
[ "$FREE_AFTER" = "6" ] \
    || red "ours=free_pool:${FREE_BEFORE}->${FREE_AFTER:-none} expected=4->6 — the revoked arb slice (2) was not released to the free pool"

# No double-count: a second reclaim is a no-op; the free pool is unchanged.
[ "$(treasury_reclaim manager "$ARB")" = "nothing_to_reclaim" ] \
    || red "ours=second-reclaim:$(treasury_reclaim manager "$ARB") expected=nothing_to_reclaim — a repeat reclaim double-counted the freed slice"
[ "$(treasury_field manager '.data.free_pool')" = "6" ] \
    || red "ours=free_pool-after-2nd-reclaim:$(treasury_field manager '.data.free_pool') expected=6 — the second reclaim mutated the free pool"

# A reallocation FROM the reclaimed (gone) slice must NOT commit (no re-pull of freed budget).
REPULL="$(reallocate manager "$ARB" "$FLIP" 2)"
[ "$REPULL" != "reallocated" ] \
    || red "ours=repull:reallocated expected=refused — budget was re-pulled from a reclaimed (gone) slice; the freed amount was double-committed"

green "revoking arb is recorded in the registry (arb revoked, flip still live — the gateway refuses arb's next call from this state), and arb's slice (2) is reclaimed to the free pool (4→6); a second reclaim is a no-op (nothing_to_reclaim) and a reallocation from the gone slice does not commit — one revoke is clawback, and the freed budget can be recommitted but never over-committed"
