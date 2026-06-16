#!/usr/bin/env bash
# AGENT-TREASURY-1 — Aggregate-capped reallocation (THE load-bearing build).
# A manager holds a treasury cap (calls:10, narrated "$10,000") and allots four
# slices summing to the cap (flip:4, x402:1, yield:3, arb:2 = 10). It then
# REALLOCATES 2 from yield to flip (yield 3->1, flip 4->6) and the sum provably
# stays <= the parent cap.
#
# GREEN means BOTH halves hold:
#   (accept) the aggregate cap is established, the four slices allot within it
#     (Σ = parent_cap = 10), and a reallocation that moves Δ from a loser to a
#     winner COMMITS with the destination slice provably grown (flip 4→6) and
#     Σ unchanged ≤ cap.
#   (adversarial) TWO refusals, each with the distinct `aggregate_cap_exceeded`
#     and NO commit: (a) allotting a fifth slice when the four already sum to the
#     cap; (b) a reallocation that pulls more than the source slice holds (arb
#     holds 2, pull 4) — which would fabricate budget on the destination.
#
# RED means an over-sum allot/reallocation committed, OR was rejected by a GENERIC
# verdict that does not name the aggregate cap, OR the aggregate-cap surface is
# absent (the gap at baseline). BROKEN means we could not build the chain.
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
has_subcommand treasury reallocate \
    || red "ours=no-reallocate-surface expected=aggregate-capped reallocate(from,to,Δ) with Σ ≤ parent_cap + distinct aggregate_cap_exceeded — the engine has no aggregate cap across sub-delegations; budget is per-delegation only"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

MGR_DID="$(bootstrap_manager manager)"
[ -n "$MGR_DID" ] || broken "could not establish the treasury manager root identity"

# Four real sub-agents, for their DIDs.
FLIP="$(delegate_subagent flip manager)";   [ -n "$FLIP" ]  || broken "could not delegate flip"
X402="$(delegate_subagent x402 manager)";   [ -n "$X402" ]  || broken "could not delegate x402"
YIELD="$(delegate_subagent yield manager)"; [ -n "$YIELD" ] || broken "could not delegate yield"
ARB="$(delegate_subagent arb manager)";     [ -n "$ARB" ]   || broken "could not delegate arb"

# Establish the aggregate treasury cap of 10.
[ "$(treasury_open manager calls:10)" = "opened" ] \
    || broken "could not establish the treasury cap"

# Allot the four slices (Σ = 10 = parent_cap).
[ "$(treasury_allot manager "$FLIP" 4)"  = "allotted" ] || red "ours=allot-flip-failed expected=allotted — the flip slice (4) was not committed under the cap"
[ "$(treasury_allot manager "$X402" 1)"  = "allotted" ] || red "ours=allot-x402-failed expected=allotted — the x402 slice (1) was not committed"
[ "$(treasury_allot manager "$YIELD" 3)" = "allotted" ] || red "ours=allot-yield-failed expected=allotted — the yield slice (3) was not committed"
[ "$(treasury_allot manager "$ARB" 2)"   = "allotted" ] || red "ours=allot-arb-failed expected=allotted — the arb slice (2) was not committed"

# Accept: the aggregate invariant holds (Σ = parent_cap = 10, free pool 0).
AGG="$(treasury_status manager)"
COMMITTED="$(treasury_field manager '.data.committed')"
[ "$AGG" = "valid" ] && [ "$COMMITTED" = "10" ] \
    || red "ours=aggregate:${AGG:-none}/committed:${COMMITTED:-none} expected=valid/10 — the four slices do not verify against the parent cap; Σ slices ≤ parent_cap is not enforced"

# Adversarial 1 (issuance guard): a fifth slice when the four already sum to the cap
# is refused with the distinct verdict, and does NOT commit (committed stays 10).
OVERALLOT="$(treasury_allot manager did:keri:Eextra 2)"
[ "$OVERALLOT" = "aggregate_cap_exceeded" ] \
    || red "ours=overallot:${OVERALLOT:-none} expected=aggregate_cap_exceeded — a fifth slice (Σ→12>10) was admitted or rejected by a GENERIC verdict; the aggregate cap is not the issuance boundary"
[ "$(treasury_field manager '.data.committed')" = "10" ] \
    || red "ours=after-overallot-committed:$(treasury_field manager '.data.committed') expected=10 — the refused over-cap allotment still mutated the committed authority"

# The reallocation: pull 2 from yield, feed flip (yield 3->1, flip 4->6).
MOVE="$(reallocate manager "$YIELD" "$FLIP" 2)"
[ "$MOVE" = "reallocated" ] \
    || red "ours=realloc:${MOVE:-none} expected=reallocated — a valid reallocation (move 2 yield→flip, post-move Σ=10 ≤ 10) did not commit"

# Post-move: Σ still ≤ parent, and the destination slice provably grew (flip 4→6).
AGG2="$(treasury_status manager)"
FLIP_SLICE="$(treasury_slice manager "$FLIP")"
[ "$AGG2" = "valid" ] && [ "$FLIP_SLICE" = "6" ] \
    || red "ours=post-move-aggregate:${AGG2:-none}/flip-slice:${FLIP_SLICE:-none} expected=valid/6 — after the reallocation the invariant did not hold or the flip slice did not grow to 6"

# Adversarial 2 (the headline): pull 4 from arb (which holds 2) — would fabricate
# budget on flip, pushing Σ over the cap. Refused aggregate_cap_exceeded, no commit.
OVER="$(reallocate manager "$ARB" "$FLIP" 4)"
if [ "$OVER" = "aggregate_cap_exceeded" ]; then
    AGG3="$(treasury_field manager '.data.committed')"
    [ "$AGG3" = "10" ] \
        || red "ours=after-refusal-committed:${AGG3:-none} expected=10 — the refused over-sum reallocation still mutated the committed authority; refusal must not commit"
    green "the aggregate cap is established and the four slices allot to Σ=10=parent_cap; a reallocation of 2 (yield→flip) commits with the flip slice grown to 6 and Σ unchanged; and BOTH an over-cap allotment (Σ→12) and an over-sum reallocation (pull 4 from a slice holding 2) are refused with the distinct aggregate_cap_exceeded and do NOT commit — the manager can move capital but never breach the human's cap"
else
    red "ours=oversum:${OVER:-none} expected=aggregate_cap_exceeded — a reallocation pulling 4 from a slice holding 2 (which would push Σ over the cap of 10) was admitted or rejected by a GENERIC verdict; the aggregate cap is not the boundary"
fi
