#!/usr/bin/env bash
# AGENT-ATTEN-5 — anchored expiry is enforced end-to-end. GREEN means: a worker
# delegated with a short --expires-in signs a commit, and `auths verify` (the
# witnessed path, with the signing time injected at the boundary) rejects a commit
# verified after expiry with status `agent-expired`. RED means the post-expiry
# commit was NOT rejected as expired (the expiry gate is unreachable, e.g. the
# witnessed path passes now=None). BROKEN means we could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verify of a post-expiry commit whose verdict is NOT
# agent-expired (the documented unreachable-gate failure: now=None, so expiry is
# never evaluated). A non-expired verdict for an after-expiry commit is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/verify.json" ] \
        || broken "trap fixture missing verify.json: ${TRAP_FIXTURE}"
    status="$(grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]*"' "${TRAP_FIXTURE}/verify.json" \
              | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')"
    if [ "$status" != "agent-expired" ]; then
        red "ours=status:${status:-none} expected=agent-expired — a commit signed after the agent's anchored expiry was not rejected as expired; the expiry gate was not reached (now likely passed as None on the witnessed path)"
    fi
    green "captured post-expiry verdict is agent-expired — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or auths-sign) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/atten5.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org org)"
[ -n "$ORG_DID" ] || broken "could not establish the org root identity"
ORG_PFX="${ORG_DID#did:keri:}"

# A worker delegated with a short expiry, scoped to sign_commit. delegate_worker
# forwards only --scope, so this probe issues the delegation directly to control
# the TTL (anchored expires_at in the delegator's seal).
EXP_ALIAS="committer-ttl"
"$AUTHS_BIN" --repo "$ORG_REPO" --json id agent add \
    --label "$EXP_ALIAS" --key org --curve ed25519 --scope sign_commit --expires-in 1 \
    >"$LAB/agent-ttl.out" 2>&1 \
    || broken "could not delegate a short-TTL worker: $(tail -1 "$LAB/agent-ttl.out")"
EXP_WORKER_DID="$(grep -oE 'did:keri:[A-Za-z0-9_-]+' "$LAB/agent-ttl.out" | head -1)"
[ -n "$EXP_WORKER_DID" ] || broken "could not capture the short-TTL worker did"

materialize_worker_machine "$ORG_PFX"
worker_env "$EXP_ALIAS"

# Let the anchored expiry pass, then sign — the commit's signing time is after
# expires_at.
sleep 2
EXP_SHA="$(worker_signs_commit "$LAB/work-exp" "after expiry" sign_commit)"
[ -n "$EXP_SHA" ] || broken "the worker could not sign the post-expiry commit"

org_env
STATUS="$(verify_commit_status "$LAB/work-exp" "$EXP_SHA")"

if [ "$STATUS" = "agent-expired" ]; then
    green "a commit signed after the worker's anchored expiry is rejected agent-expired — the witnessed verify path injects the signing time and the delegator-anchored expiry gate fires"
fi
[ -z "$STATUS" ] \
    && red "ours=no-verdict expected=agent-expired — \`auths verify\` produced no status for the post-expiry commit"
red "ours=status:${STATUS} expected=agent-expired — a commit signed after the anchored expiry was not rejected as expired; the expiry gate was not reached end-to-end"
