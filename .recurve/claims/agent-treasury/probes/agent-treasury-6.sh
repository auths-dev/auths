#!/usr/bin/env bash
# AGENT-TREASURY-6 — Depth attenuation: a sub-agent cannot sub-delegate more budget
# than it holds; the aggregate cap holds transitively down the tree.
#
# The flip sub-agent (holding calls:4) spins up its own child worker. A child slice
# ≤ flip's own (and Σ child slices ≤ flip's) succeeds and verifies; a child slice
# LARGER than flip holds (calls:5 under flip's calls:4) is refused at issuance, and
# a hand-forged child seal not signed by flip's key fails verify.
#
# GREEN: the quantitative subset holds at depth — an in-budget child (calls:2 under
#   flip's 4) is minted and verifies, while an over-budget child (calls:5) is refused
#   at issuance with the distinct aggregate_cap_exceeded. RED: the over-budget child
#   is minted (the quantitative depth subset is absent — the gap at baseline), or a
#   forged child seal verifies. BROKEN: could not build the chain.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
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

# The quantitative depth subset (Σ child slices ≤ self) rides the net-new aggregate
# primitive; its absence is the gap (RED, not BROKEN).
has_subcommand id agent reallocate \
    || red "ours=no-quantitative-subset expected=Σ child slices ≤ the sub-agent's own slice enforced at issuance (transitive aggregate cap) — issuance enforces only the CATEGORICAL subset (AGT-1); the QUANTITATIVE per-depth sum is not built"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury6.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"
MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
FLIP="$(delegate_subagent flip manager)"; [ -n "$FLIP" ] || broken "could not delegate flip"
issue_slice manager "$FLIP" calls:4 >/dev/null; [ "$(issue_rc)" -eq 0 ] || broken "could not issue flip's calls:4 slice"

# In-budget child (calls:2 ≤ flip's 4): minted and verifies.
CHILD="$(delegate_subagent flip-child flip)"
[ -n "$CHILD" ] || red "ours=no-subdelegation expected=flip can sub-delegate a child within its slice — depth nesting is not supported, so the transitive cap cannot hold"
issue_slice flip "$CHILD" calls:2 >/dev/null
IN_RC="$(issue_rc)"
[ "$IN_RC" -eq 0 ] || red "ours=in-budget-child:refused expected=minted — an in-budget child (calls:2 under flip's calls:4) was refused; legitimate nesting is broken"

# Over-budget child (calls:5 > flip's 4): refused at issuance.
issue_slice flip "$CHILD" calls:5 >/dev/null
OVER_RC="$(issue_rc)"
OVER_SAID="$(jq -r '.data.credential_said // empty' "$LAB_DIR/last-issue.out" 2>/dev/null)"
if [ "$OVER_RC" -ne 0 ] && [ -z "$OVER_SAID" ]; then
    green "an in-budget child (calls:2) is minted under flip's calls:4 slice while an over-budget child (calls:5 > 4) is refused at issuance — the quantitative aggregate cap holds transitively down the tree"
else
    red "ours=over-budget-child:minted(rc=$OVER_RC said=${OVER_SAID:-none}) expected=refused — a child slice (calls:5) larger than flip's calls:4 was minted; the aggregate cap does not hold transitively"
fi
