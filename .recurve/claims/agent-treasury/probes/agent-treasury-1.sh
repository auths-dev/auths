#!/usr/bin/env bash
# AGENT-TREASURY-1 — Aggregate-capped reallocation (THE load-bearing build).
# A manager holds a treasury cap (calls:10, narrated "$10,000") and sub-delegates
# four slices summing to the cap (flip:4, x402:1, yield:3, arb:2 = 10). It then
# REALLOCATES 2 from yield to flip (yield 3->1, flip 4->6) and the sum provably
# stays <= the parent cap.
#
# GREEN means BOTH halves hold:
#   (accept) the four slices verify, Σ = parent_cap, and a reallocation that moves
#     Δ from a loser to a winner COMMITS atomically with post-move Σ ≤ parent_cap;
#     a brokered call under the GROWN slice (flip now 6) that was over the OLD slice
#     (5 > 4) now passes.
#   (adversarial) a reallocation that FEEDS A WINNER WITHOUT PULLING FROM A LOSER
#     (raise flip to 6 while yield stays 3, so Σ = 12 > 10) is REFUSED with the
#     distinct `aggregate_cap_exceeded` verdict and does NOT commit (Σ unchanged).
#
# RED means the over-sum move committed, OR was rejected by a GENERIC verdict that
# does not name the aggregate cap, OR the aggregate-cap surface is absent (the gap
# at baseline). BROKEN means we could not build the chain.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures an over-sum reallocation whose verdict is NOT the distinct
# aggregate_cap_exceeded — either it `reallocated` (the cap did not fire) or a
# generic failure that does not name the aggregate. Either is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/reallocate.json" ] \
        || broken "trap fixture missing reallocate.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/reallocate.json" 2>/dev/null)"
    if [ "$status" != "aggregate_cap_exceeded" ]; then
        red "ours=status:${status:-none} expected=aggregate_cap_exceeded — the over-sum reallocation was committed or rejected by a GENERIC verdict that does not name the aggregate cap; Σ slices could exceed the parent"
    fi
    green "captured over-sum reallocation verdict is the distinct aggregate_cap_exceeded — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

# The net-new surface must exist; its absence IS the gap (RED, not BROKEN).
has_subcommand id agent reallocate \
    || red "ours=no-reallocate-surface expected=aggregate-capped reallocate(from,to,Δ) with Σ ≤ parent_cap + distinct aggregate_cap_exceeded — the engine has no aggregate cap across sub-delegations; budget is per-delegation only"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

MGR_DID="$(bootstrap_manager manager)"
[ -n "$MGR_DID" ] || broken "could not establish the treasury manager root identity"

# Four sub-agents, four slices summing to the treasury cap of 10.
FLIP="$(delegate_subagent flip manager)";   [ -n "$FLIP" ]  || broken "could not delegate flip"
X402="$(delegate_subagent x402 manager)";   [ -n "$X402" ]  || broken "could not delegate x402"
YIELD="$(delegate_subagent yield manager)"; [ -n "$YIELD" ] || broken "could not delegate yield"
ARB="$(delegate_subagent arb manager)";     [ -n "$ARB" ]   || broken "could not delegate arb"

FLIP_SAID="$(issue_slice manager "$FLIP"  calls:4)"; [ "$(issue_rc)" -eq 0 ] || broken "could not issue flip slice"
X402_SAID="$(issue_slice manager "$X402"  calls:1)"; [ "$(issue_rc)" -eq 0 ] || broken "could not issue x402 slice"
YLD_SAID="$(issue_slice manager "$YIELD" calls:3)";  [ "$(issue_rc)" -eq 0 ] || broken "could not issue yield slice"
ARB_SAID="$(issue_slice manager "$ARB"   calls:2)";  [ "$(issue_rc)" -eq 0 ] || broken "could not issue arb slice"

# Accept half: the aggregate invariant holds at issuance (Σ = parent_cap = 10).
AGG="$(treasury_status manager)"
[ "$AGG" = "valid" ] \
    || red "ours=aggregate:${AGG:-none} expected=valid — the four slices (Σ=10) do not verify against the parent cap; the aggregate invariant Σ slices ≤ parent_cap is not enforced from the manager KEL"

# The reallocation: pull 2 from yield, feed flip (yield 3->1, flip 4->6).
MOVE="$(reallocate manager "$YIELD" "$FLIP" 2)"
[ "$MOVE" = "reallocated" ] \
    || red "ours=realloc:${MOVE:-none} expected=reallocated — a valid reallocation (move 2 yield→flip, post-move Σ=10 ≤ 10) did not commit"

# Post-move: Σ still ≤ parent, and a call under the GROWN flip slice (count 5,
# over the OLD cap of 4, under the NEW cap of 6) now passes.
AGG2="$(treasury_status manager)"
[ "$AGG2" = "valid" ] \
    || red "ours=post-move-aggregate:${AGG2:-none} expected=valid — after the reallocation the aggregate invariant did not hold (Σ slices ≤ parent_cap)"
OBS="$LAB/obs.json"
write_observation "$OBS" "$FLIP_SAID" 5
GROWN="$(verify_status manager "$FLIP_SAID" "$OBS")"
[ "$GROWN" = "valid" ] \
    || red "ours=grown-slice:${GROWN:-none} expected=valid — a call at count 5 (over the OLD flip cap of 4, under the reallocated cap of 6) did not pass; the reallocation did not actually grow the slice"

# Adversarial half: feed flip again WITHOUT pulling — would push Σ to 12 > 10.
OVER="$(reallocate manager "$ARB" "$FLIP" 4)"   # arb only holds 2; this would over-sum the parent
if [ "$OVER" = "aggregate_cap_exceeded" ]; then
    # And it must NOT have committed: the aggregate is unchanged (still valid ≤ cap).
    AGG3="$(treasury_status manager)"
    [ "$AGG3" = "valid" ] \
        || red "ours=after-refusal-aggregate:${AGG3:-none} expected=valid — the refused over-sum reallocation still mutated the committed authority; refusal must not commit"
    green "the four slices verify (Σ=10=parent_cap), a reallocation of 2 (yield→flip) commits atomically with Σ still ≤ cap and the grown flip slice now passes at count 5, and an over-sum reallocation (Σ→12>10) is refused with the distinct aggregate_cap_exceeded and does NOT commit — the manager can move capital but never breach the human's cap"
else
    red "ours=oversum:${OVER:-none} expected=aggregate_cap_exceeded — a reallocation that would push Σ slices to 12 > parent_cap of 10 was admitted or rejected by a GENERIC verdict; the aggregate cap is not the boundary, so the swarm's committed authority can exceed the parent"
fi
