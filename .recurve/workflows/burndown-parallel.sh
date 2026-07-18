#!/usr/bin/env bash
# burndown-parallel.sh — the v2 contract: parallel lanes, single-file ratchet.
#
# Lanes sculpt in WORKTREE-ISOLATED clones of a git tree, over PAIRWISE-
# DISJOINT suites (`next --lanes` guarantees no two lanes share a ledger or
# prose). The FEDERATED GATE IS THE SERIALIZATION POINT: candidates land on
# the real tree one at a time; each landing must turn its gap's probe GREEN
# and keep the fleet gate green, then is committed; a candidate that fails is
# REVERTED AND DISCARDED — its gap returns to the backlog for a fresh attempt
# against the new baseline. Never merge two sculpts.
#
# Agent contract (per lane): $AGENT_CMD is invoked with the cycle prompt on
# stdin and env LANE_GAP, LANE_TREE (the lane's worktree — sculpt ONLY
# there), RECURVE_RESULT_FILE (write the run record JSON). Promotion is the
# ORCHESTRATOR's, after the gated landing — a lane never edits the ledger.
#
# Knobs (env > stamped defaults): AGENT_CMD (required), PARALLEL, CAP
# (rounds), TREE_DIR, RECURVE_BIN, GIT_USER_NAME/EMAIL.
#
# NOTE on rebuilds: if a suite's probes read built artifacts, set its
# `rebuild` and run it between landing and gate (the stale check will
# otherwise rightly refuse the verdict). Engine-from-source projects skip it.

set -u
PROG="${RECURVE_BIN:-recurve}"
PARALLEL="${PARALLEL:-2}"
CAP="${CAP:-12}"
TREE="${TREE_DIR:-.}"
: "${AGENT_CMD:?set AGENT_CMD to your agent invocation (reads prompt on stdin)}"
RUN_ID="parallel-$$"

py() { python3 -c "$1" "${@:2}"; }

git -C "$TREE" rev-parse HEAD >/dev/null 2>&1 \
  || { echo "parallel burndown requires the target tree to be a git repository"; exit 1; }

$PROG lock acquire || { echo "another loop holds the tree — refusing (never two loops on one tree)"; exit 1; }
trap '$PROG lock release >/dev/null 2>&1' EXIT

echo "parallel burndown $RUN_ID: preflight"
$PROG validate || { echo "broken ledger — fix before running unattended"; exit 1; }
$PROG matrix --gate || { echo "baseline gate is not green — never start here"; exit 1; }

empty_rounds=0
landed_total=0
for round in $(seq 1 "$CAP"); do
  LANES_JSON="$($PROG next --json --lanes "$PARALLEL")"
  N="$(py 'import json,sys; print(len(json.loads(sys.argv[1])["lanes"]))' "$LANES_JSON")"
  if [ "$N" -eq 0 ]; then
    DRAFTS="$($PROG next --json | py 'import json,sys; print(sum(x["pending"] for x in json.load(sys.stdin).get("drafts", [])))')"
    if [ "${DRAFTS:-0}" -gt 0 ]; then
      echo "no open gaps, but $DRAFTS draft(s) pend — arm the next wave with the serial loop (workflows/burndown.sh arms automatically) or author probes + \`$PROG baseline <suite>\`. Halting."
    else
      echo "no work left. Halting."
    fi
    break
  fi
  BASE="$(git -C "$TREE" rev-parse HEAD)"
  WTROOT="$(mktemp -d)"
  echo "round $round/$CAP: $N lane(s) from base ${BASE:0:10}"

  GAPS=(); DIRS=(); WTS=(); RESULTS=()
  i=0
  while [ "$i" -lt "$N" ]; do
    GAP="$(py 'import json,sys; print(json.loads(sys.argv[1])["lanes"][int(sys.argv[2])]["gap"])' "$LANES_JSON" "$i")"
    DIR="$(py 'import json,sys; print(json.loads(sys.argv[1])["lanes"][int(sys.argv[2])]["dir"])' "$LANES_JSON" "$i")"
    WT="$WTROOT/lane-$i"
    git -C "$TREE" worktree add --detach -q "$WT" "$BASE"
    RES="$WTROOT/result-$i.json"
    PROMPT="You are ONE lane of a parallel burndown (lane $i, round $round).
Your gap: $GAP  (details: \`$PROG show $GAP\`)
Sculpt ONLY inside \$LANE_TREE — it is your isolated worktree; the real tree
is the orchestrator's. Do NOT edit any ledger or prose: promotion happens at
the gated landing, not in your lane. Hard rules: no resets, no sacred paths,
no loop vocabulary in product code, ~3 honest attempts then report failed.
Write your run record JSON to \$RECURVE_RESULT_FILE, then STOP."
    echo "$PROMPT" | LANE_GAP="$GAP" LANE_TREE="$WT" RECURVE_RESULT_FILE="$RES" $AGENT_CMD &
    GAPS[$i]="$GAP"; DIRS[$i]="$DIR"; WTS[$i]="$WT"; RESULTS[$i]="$RES"
    i=$((i+1))
  done
  wait

  landed=0
  i=0
  while [ "$i" -lt "$N" ]; do
    GAP="${GAPS[$i]}"; DIR="${DIRS[$i]}"; WT="${WTS[$i]}"
    git -C "$WT" add -A
    PATCH="$WTROOT/patch-$i.diff"
    git -C "$WT" diff --cached "$BASE" > "$PATCH"
    if [ ! -s "$PATCH" ]; then
      echo "  discarded $GAP (lane produced no candidate)"
    elif ! git -C "$TREE" apply --check "$PATCH" 2>/dev/null; then
      echo "  discarded $GAP (conflicts with an earlier winner — re-run fresh against the new baseline)"
    else
      git -C "$TREE" apply "$PATCH"
      if $PROG probe --gap "$GAP" 2>/dev/null | grep -q "READY→close" \
         && $PROG matrix --gate >/dev/null 2>&1; then
        py 'import sys
path, gap = sys.argv[1], sys.argv[2]
t = open(path).read()
i = t.index(f"- id: {gap}\n")
j = t.find("- id: ", i + 1)
j = len(t) if j < 0 else j
open(path, "w").write(t[:i] + t[i:j].replace("status: open", "status: closed", 1) + t[j:])' \
          "$DIR/gaps.yaml" "$GAP"
        git -C "$TREE" add -A
        git -C "$TREE" -c commit.gpgsign=false \
            -c user.name="${GIT_USER_NAME:-burndown}" \
            -c user.email="${GIT_USER_EMAIL:-burndown@invalid}" \
            commit -qm "landed $GAP (gate green) [$RUN_ID]"
        $PROG record append --file "${RESULTS[$i]}" --run-id "$RUN_ID" >/dev/null 2>&1 || true
        echo "  landed $GAP (gate green)"
        landed=$((landed+1))
      else
        git -C "$TREE" apply -R "$PATCH" 2>/dev/null
        echo "  discarded $GAP (candidate failed its probe or the fleet gate — reverted)"
      fi
    fi
    git -C "$TREE" worktree remove --force "$WT" 2>/dev/null
    i=$((i+1))
  done
  git -C "$TREE" worktree prune 2>/dev/null
  rm -rf "$WTROOT"

  if [ "$landed" -eq 0 ]; then empty_rounds=$((empty_rounds+1)); else
    empty_rounds=0; landed_total=$((landed_total+landed)); fi
  if [ "$empty_rounds" -ge 2 ]; then
    echo "two consecutive rounds without a landing — halting (fix the common cause, don't retry harder)."
    break
  fi
done

echo "parallel burndown $RUN_ID wrap-up: landed $landed_total"
$PROG matrix || true
$PROG park || true
