#!/usr/bin/env bash
# burndown.sh — the portable unattended loop. Deterministic control flow in
# this script; judgment in the agents. Works with ANY agent harness via one
# contract:
#
#   $AGENT_CMD is invoked once per cycle with the cycle prompt on stdin.
#   It must sculpt exactly one gap per .recurve/RUN.md and write a run-record JSON
#   (schema/run-record.schema.json) to the path in $RECURVE_RESULT_FILE.
#   Its exit code is ignored; only the record and the gate are believed.
#
# Knobs (env > config defaults):
#   AGENT_CMD       (required) the agent invocation
#   CAP             max cycles                       [default 12]
#   MAX_FAILS       consecutive-failure halt         [default 3]
#   RUNAWAY         net-gap-positive-cycle halt      [default 2]
#   PARKED_SEED     comma-separated gap ids to park before starting
#
# Halts ONLY on: no-work-left, cap, runaway scope, consecutive failures, or
# a lock refusal. An un-greenable gap is parked, never fatal.

set -u
PROG="${RECURVE_BIN:-recurve}"   # override for unusual installs/test rigs
CAP="${CAP:-12}"
MAX_FAILS="${MAX_FAILS:-3}"
RUNAWAY="${RUNAWAY:-2}"
RUN_ID="burndown-$$"
: "${AGENT_CMD:?set AGENT_CMD to your agent invocation (reads prompt on stdin)}"

py() { python3 -c "$1" "${@:2}"; }

if ! $PROG lock status >/dev/null 2>&1; then
  echo "burndown: tree is locked — refusing to start (a second loop corrupts both)."
  $PROG lock status
  exit 1
fi

if [ -n "${PARKED_SEED:-}" ]; then
  IFS=',' read -ra SEED <<< "$PARKED_SEED"
  for g in "${SEED[@]}"; do
    $PROG park "$g" --reason "seeded parked by $RUN_ID (still-stuck from a prior run)" || true
  done
fi

echo "burndown $RUN_ID: preflight"
$PROG validate || { echo "burndown: broken ledger — fix before running unattended."; exit 1; }
$PROG matrix --gate || { echo "burndown: baseline gate is not green — never start here."; exit 1; }

fails=0
runaway=0
closed=0
for cycle in $(seq 1 "$CAP"); do
  NEXT_JSON="$($PROG next --json)"
  GAP="$(py 'import json,sys; d=json.loads(sys.argv[1]); print(d["recommended"]["gap"] if d.get("recommended") else "")' "$NEXT_JSON")"
  if [ -z "$GAP" ]; then
    echo "burndown: no work left (green-gate-sufficient backlog is empty). Halting."
    break
  fi

  echo "burndown cycle $cycle/$CAP: $GAP"
  RESULT_FILE="$(mktemp)"
  PROMPT="You are running ONE improvement cycle. Read .recurve/RUN.md and obey it exactly.
Your gap: $GAP  (details: \`$PROG show $GAP\`)
Hard rules (non-negotiable, embedded because you are stateless):
- never git reset/checkout shared state; never touch sacred paths
- no loop vocabulary (gap ids, cycle names, tool name) in product code
- never sculpt review-gated gaps; ~3 honest attempts then park with the journal
- rebuild before trusting any probe; the gate is \`$PROG matrix --gate\`
- commit policy: none (never run a command that can prompt)
Write your run record JSON to: $RESULT_FILE  (status closed|parked|failed; never free text)
Then STOP."

  echo "$PROMPT" | RECURVE_RESULT_FILE="$RESULT_FILE" $AGENT_CMD
  STATUS="$(py 'import json,sys
try: print(json.load(open(sys.argv[1])).get("status",""))
except Exception: print("")' "$RESULT_FILE")"

  if [ -z "$STATUS" ]; then
    echo "  cycle $cycle: agent left no readable record → failed cycle"
    fails=$((fails+1))
  else
    $PROG record append --file "$RESULT_FILE" --run-id "$RUN_ID" \
      || echo "  (record rejected by schema — kept raw at $RESULT_FILE)"
    case "$STATUS" in
      closed)
        if $PROG matrix --gate >/dev/null 2>&1; then
          echo "  cycle $cycle: closed $GAP, gate green"
          fails=0; closed=$((closed+1))
        else
          echo "  cycle $cycle: agent claimed closed but the GATE disagrees → failed cycle"
          fails=$((fails+1))
        fi ;;
      parked)
        echo "  cycle $cycle: parked $GAP (journal recorded)"
        fails=0 ;;
      *)
        echo "  cycle $cycle: status=$STATUS → failed cycle"
        fails=$((fails+1)) ;;
    esac
    NET="$(py 'import json,sys
try: print(json.load(open(sys.argv[1])).get("net_new_gaps",0))
except Exception: print(0)' "$RESULT_FILE")"
    if [ "${NET:-0}" -gt 0 ]; then runaway=$((runaway+1)); else runaway=0; fi
  fi

  if [ "$fails" -ge "$MAX_FAILS" ]; then
    echo "burndown: $MAX_FAILS consecutive failures — halting (fix the common cause, don't retry harder)."
    break
  fi
  if [ "$runaway" -ge "$RUNAWAY" ]; then
    echo "burndown: $RUNAWAY consecutive net-gap-positive cycles — runaway scope; halting to re-scope."
    break
  fi
done

echo "burndown $RUN_ID wrap-up: closed=$closed"
$PROG matrix || true
$PROG park || true
echo "human queue: adjudications first, then review-gated promotions, then parked triage."
