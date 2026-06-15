#!/usr/bin/env bash
# BOOT-1 — the harness exists: the 3-witness local fixture boots with distinct
# identities, the kill-node failure-injection lever works, and the conformance
# oracle is pinned (and actually present at the pinned version).
#
# Behavioral, end to end. The desired behavior (GREEN) is: a real, running
# 3-node witness fixture that a later probe can stand on — three nodes, three
# DISTINCT identities, a working kill lever, and an oracle we can cross-check
# against. RED while no such fixture is wired/healthy.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The harness boots the fixture
# (harness/up.sh) — this probe is hermetic and only READS it.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh

# ── Trap mode ────────────────────────────────────────────────────────────────
# When TRAP_FIXTURE is set the runner feeds a KNOWN-BAD roster from
# probes/boot-1.trap/<fixture>/health/*.json instead of the live fixture. The
# distinctness check below must reject it (exit RED). A roster of three nodes
# that are not three distinct identities is not a witness network — it is one
# operator wearing three hats, the oligopoly the diversity rule exists to stop.
ROSTER_SOURCE="live"
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -d "${TRAP_FIXTURE}/health" ] || broken "trap fixture has no health/ dir: ${TRAP_FIXTURE}"
    ROSTER_SOURCE="${TRAP_FIXTURE}/health"
fi

# ── 1. Harness assets are wired ──────────────────────────────────────────────
for f in harness/env.sh harness/up.sh harness/down.sh harness/kill-node.sh \
         harness/versions.lock harness/compose/docker-compose.yml; do
    [ -f "$f" ] || red "harness asset missing: $f (the fixture is not wired)"
done
[ -x harness/up.sh ] && [ -x harness/kill-node.sh ] \
    || red "harness/up.sh and harness/kill-node.sh must be executable"

# ── 2. The oracle is pinned AND present at the pinned version ─────────────────
pinned="$(oracle_version)"
[ -n "$pinned" ] || red "no keripy oracle pinned in harness/versions.lock"
if ! command -v kli >/dev/null 2>&1; then
    broken "keripy oracle (kli) absent — cannot confirm the pinned version is the one installed"
fi
installed="$(python3 -c 'import keri; print(keri.__version__)' 2>/dev/null || true)"
[ -n "$installed" ] || broken "keripy importable check failed — oracle not measurable"
[ "$installed" = "$pinned" ] \
    || red "oracle drift — versions.lock pins keripy=$pinned but installed=$installed"

# ── 3. Collect the node roster (live fixture, or the trap's counterexample) ───
declare -a aids=()
if [ "$ROSTER_SOURCE" = "live" ]; then
    if ! all_nodes_healthy; then
        # The oracle is present (checked above) — the only thing absent is the
        # standup itself. That is the behavior under test, so its absence is RED,
        # not BROKEN. `harness/up.sh` is the bring-up that turns this GREEN.
        red "no 3-witness fixture standing on ports ${NODE_PORTS[*]} — harness/up.sh has not brought up a healthy network"
    fi
    for port in "${NODE_PORTS[@]}"; do
        aid="$(node_aid "$port")"
        [ -n "$aid" ] || broken "node on :$port returned no identity in /health"
        aids+=("$aid")
    done
else
    # Trap: read the three supplied health JSONs in name order.
    while IFS= read -r hf; do
        aid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["witness_did"])' "$hf" 2>/dev/null || true)"
        [ -n "$aid" ] || broken "trap health file has no witness_did: $hf"
        aids+=("$aid")
    done < <(find "$ROSTER_SOURCE" -maxdepth 1 -name '*.json' | sort)
fi

# ── 4. Exactly three nodes, three DISTINCT identities ─────────────────────────
[ "${#aids[@]}" -eq 3 ] \
    || red "roster has ${#aids[@]} nodes, expected 3 (fixture is 3-of-3 capable)"
distinct="$(printf '%s\n' "${aids[@]}" | sort -u | wc -l | tr -d ' ')"
[ "$distinct" -eq 3 ] \
    || red "ours=${distinct}-distinct oracle=3-distinct — roster is not 3 independent identities: ${aids[*]}"

# ── 5. The kill-node lever actually injects failure (live only) ───────────────
# Behavioral proof the failure-injection helper works: stop node 1, confirm its
# port goes dark while the other two stay healthy (a 2-of-3 set survives one
# loss), then restore it so the fixture is left as we found it.
if [ "$ROSTER_SOURCE" = "live" ]; then
    if ! bash harness/kill-node.sh 1 stop >/dev/null 2>&1; then
        broken "kill-node.sh could not stop node 1"
    fi
    restore() { bash harness/kill-node.sh 1 start >/dev/null 2>&1 || true; }
    # node 1 dark
    if node_health "${NODE_PORTS[0]}" >/dev/null 2>&1; then
        restore; red "kill-node stopped node 1 but :${NODE_PORTS[0]} still answers — failure injection is a no-op"
    fi
    # nodes 2 and 3 still up (threshold-survives-one-loss)
    if ! node_health "${NODE_PORTS[1]}" >/dev/null 2>&1 || ! node_health "${NODE_PORTS[2]}" >/dev/null 2>&1; then
        restore; broken "killing node 1 took down a peer — fixture is not independent"
    fi
    restore
    # and it comes back (a stop is recoverable, not a teardown)
    deadline=$(( $(date +%s) + 30 ))
    until node_health "${NODE_PORTS[0]}" >/dev/null 2>&1; do
        [ "$(date +%s)" -ge "$deadline" ] && red "node 1 did not recover after kill-node.sh 1 start"
        sleep 1
    done
fi

green "harness GREEN: 3 distinct witness nodes healthy (${aids[*]}), kill-node lever proven, oracle keripy=$pinned pinned and installed"
