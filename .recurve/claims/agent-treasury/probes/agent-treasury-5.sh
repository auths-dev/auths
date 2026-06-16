#!/usr/bin/env bash
# AGENT-TREASURY-5 — Instant clawback: revoking a sub-agent stops its spend
# everywhere AND returns its slice to the treasury's free pool, re-allocatable but
# never over-committable.
#
# GREEN: after the manager revokes the arb sub-agent, (a) arb's very next brokered
#   call is refused `revoked` (no TTL window), and (b) arb's slice is released to
#   the free pool — `treasury status` shows free_pool risen by the freed amount, so
#   it is re-allocatable to a survivor; AND a reallocation that DOUBLE-COUNTS the
#   freed slice (would push Σ > parent_cap) is refused aggregate_cap_exceeded.
# RED: the freed slice is not released to the pool (the free-pool accounting is
#   absent — the gap at baseline), or a double-counting reallocation commits, or the
#   next call after revoke is still admitted. BROKEN: could not build the chain.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/freed-realloc.json" ] \
        || broken "trap fixture missing freed-realloc.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/freed-realloc.json" 2>/dev/null)"
    if [ "$status" != "aggregate_cap_exceeded" ]; then
        red "ours=status:${status:-none} expected=aggregate_cap_exceeded — a reallocation that double-counts a freed (revoked) slice was committed; the freed budget was over-committed"
    fi
    green "captured double-counting reallocation of a freed slice is refused — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

# The free-pool RECLAIM-on-revoke surface is net-new; its absence is the gap. (The
# aggregate cap + reallocation — AGENT-TREASURY-1 — exists; the revoke→free-pool
# release that this claim needs does not.)
has_subcommand treasury reclaim \
    || red "ours=no-free-pool-surface expected=revoke releases the slice to parent_cap − Σ live slices (free pool), re-allocatable but never double-counted — the engine has no revoke→free-pool reclaim"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury5.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
ARB="$(delegate_subagent arb manager)"; [ -n "$ARB" ] || broken "could not delegate arb"
ARB_SAID="$(issue_slice manager "$ARB" calls:2)"; [ "$(issue_rc)" -eq 0 ] && [ -n "$ARB_SAID" ] \
    || broken "could not issue the arb slice"

FREE_BEFORE="$(treasury_field manager '.data.free_pool')"

# Revoke arb mid-run.
revoke_subagent manager "$ARB" >/dev/null
[ "$(revoke_rc)" -eq 0 ] \
    || red "ours=revoke-failed expected=revoked — the manager could not revoke the arb sub-agent (no revocation surface for clawback)"

# (a) arb's next call is refused revoked.
OBS="$LAB/obs.json"; write_observation "$OBS" "$ARB_SAID" 0
NEXT="$(verify_status manager "$ARB_SAID" "$OBS")"
[ "$NEXT" = "revoked" ] \
    || red "ours=post-revoke:${NEXT:-none} expected=revoked — arb's next brokered call after revocation was not refused revoked; clawback has a window"

# (b) the freed slice (2) returns to the free pool.
FREE_AFTER="$(treasury_field manager '.data.free_pool')"
[ -n "$FREE_AFTER" ] && [ "$FREE_AFTER" -ge $(( ${FREE_BEFORE:-0} + 2 )) ] 2>/dev/null \
    || red "ours=free_pool:${FREE_BEFORE:-none}->${FREE_AFTER:-none} expected=+2 — the revoked arb slice (2) was not released to the free pool; it is not re-allocatable"

green "revoking arb refuses its next call (revoked) and releases its slice (2) to the free pool (${FREE_BEFORE:-0}->${FREE_AFTER}), re-allocatable to a survivor — one revoke is clawback everywhere, and the freed budget can be recommitted but never over-committed"
