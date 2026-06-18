#!/usr/bin/env bash
# AGENT-TREASURY-6 — Depth attenuation: a sub-agent cannot sub-delegate more budget
# than it holds; the aggregate cap holds transitively down the tree.
#
# The flip sub-agent (holding a slice of 4) spins up child workers. A child slice ≤
# flip's own (and Σ child slices ≤ flip's) succeeds; a child whose admission would
# push Σ children over what flip holds is refused at issuance.
#
# GREEN: the quantitative subset holds at depth — an in-budget child (2 under flip's
#   4) is sub-delegated, but a second child (3, making Σ children 5 > 4) is refused
#   with the distinct aggregate_cap_exceeded, and the first child still stands.
# RED: the over-budget child is admitted (the quantitative depth subset is absent —
#   the gap at baseline), or rejected by a generic verdict. BROKEN: could not build
#   the chain. Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/child-issue.json" ] \
        || broken "trap fixture missing child-issue.json: ${TRAP_FIXTURE}"
    minted="$(jq -r '.data.minted // empty' "${TRAP_FIXTURE}/child-issue.json" 2>/dev/null)"
    if [ "$minted" = "true" ]; then
        red "ours=over-budget-child:minted expected=refused — a child slice larger than the parent sub-agent holds was minted; the aggregate cap does not hold transitively, a mid-swarm key-holder can mint budget it was never given"
    fi
    green "captured over-budget child issuance is refused — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

# The quantitative depth-subset surface is net-new; its absence is the gap (RED, not BROKEN).
has_subcommand treasury subdelegate \
    || red "ours=no-quantitative-subset expected=Σ child slices ≤ the sub-agent's own slice enforced at issuance (transitive aggregate cap) — issuance enforces only the CATEGORICAL subset (AGT-1); the QUANTITATIVE per-depth sum is not built"

subdelegate() {  # <manager> <parent-did> <child-did> <amount>
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury subdelegate \
        --manager "$1" --parent "$2" --child "$3" --amount "$4" 2>/dev/null \
        | jq -r '.data.status // empty' 2>/dev/null
}

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury6.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
FLIP="$(delegate_subagent flip manager)"; [ -n "$FLIP" ] || broken "could not delegate flip"

# flip holds a slice of 4 under the manager's aggregate cap.
[ "$(treasury_open manager calls:10)" = "opened" ] || broken "could not establish the treasury cap"
[ "$(treasury_allot manager "$FLIP" 4)" = "allotted" ] || broken "could not allot flip's slice of 4"

# In-budget child (2 ≤ flip's 4): sub-delegated.
IN="$(subdelegate manager "$FLIP" did:keri:Eflipchild1 2)"
[ "$IN" = "subdelegated" ] \
    || red "ours=in-budget-child:${IN:-none} expected=subdelegated — an in-budget child (2 under flip's 4) was refused; legitimate nesting is broken"

# Over-budget child (3, making Σ children 2+3=5 > flip's 4): refused at issuance.
OVER="$(subdelegate manager "$FLIP" did:keri:Eflipchild2 3)"
if [ "$OVER" = "aggregate_cap_exceeded" ]; then
    # And the first child still stands (the refusal did not corrupt the record).
    AGAIN="$(subdelegate manager "$FLIP" did:keri:Eflipchild3 2)"
    [ "$AGAIN" = "subdelegated" ] \
        || red "ours=after-refusal:${AGAIN:-none} expected=subdelegated — the refused over-budget child corrupted flip's sub-delegation record"
    green "an in-budget child (2) is sub-delegated under flip's slice of 4 while an over-budget child (3, Σ children 5 > 4) is refused with the distinct aggregate_cap_exceeded — the quantitative aggregate cap holds transitively down the tree"
else
    red "ours=over-budget-child:${OVER:-none} expected=aggregate_cap_exceeded — a child slice (3) pushing Σ children to 5 over flip's slice of 4 was admitted or rejected by a GENERIC verdict; the aggregate cap does not hold transitively"
fi
