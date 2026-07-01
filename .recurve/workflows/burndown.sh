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
# Waves: when the strict ledger empties but drafts pend in gaps.draft.yaml,
# the loop ARMS the next wave — one agent authors probes + traps for a batch
# of drafts (never product code), then `baseline` measures them for real and
# promotes RED ones as open work. Arming never happens while ADJUDICATE.md
# has pending forks: a probe must encode a human decision, never a guess.
# Launching this loop is your sign-off that you have skimmed the drafts.
#
# Knobs (env > config defaults):
#   AGENT_CMD       (required) the agent invocation
#   CAP             max sculpting cycles              [default 12]
#   MAX_FAILS       consecutive-failure halt          [default 3]
#   RUNAWAY         net-gap-positive-cycle halt       [default 2]
#   ARM_WAVES       max wave armings (0 disables)     [default 4]
#   WAVE            drafts to author per arming       [default 8]
#   PARKED_SEED     comma-separated gap ids to park before starting
#
# Halts ONLY on: backlog-and-drafts empty, pending adjudications, cap, wave
# limit, an arming that opens no work, runaway scope, consecutive failures,
# or a lock refusal. An un-greenable gap is parked, never fatal.

set -u
PROG="${RECURVE_BIN:-recurve}"   # override for unusual installs/test rigs
CAP="${CAP:-12}"
MAX_FAILS="${MAX_FAILS:-3}"
RUNAWAY="${RUNAWAY:-2}"
ARM_WAVES="${ARM_WAVES:-4}"
WAVE="${WAVE:-8}"
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

# arm_wave: send one agent to author probes+traps for pending drafts, then
# run the baseline ceremony so RED drafts become open, sculptable gaps.
# Returns 0 if the strict ledger gained recommendable work, 1 otherwise.
arm_wave() {
  local next_json="$1" wave_n="$2"
  local suites
  suites="$(py 'import json,sys
d=json.loads(sys.argv[1])
print(" ".join(x["suite"] for x in d.get("drafts", [])))' "$next_json")"
  echo "burndown: arming wave $wave_n — drafts pend in: $suites"

  local arm_prompt="You are ARMING the next wave of an unattended burndown — authoring probes, never product code.
Read .recurve/RUN.md for the probe contract, then for suite(s): $suites
1. Open each suite's gaps.draft.yaml and pick up to $WAVE drafts, highest severity first (feature before friction before cosmetic). Leave 'security-tradeoff' drafts alone — those wait for a human.
2. For each picked draft: author probes/<id>.sh per the frozen probe contract (exit 0 GREEN / 1 RED with one 'ours=X oracle=Y' line / 2 BROKEN), mirroring the style of the suite's existing probes; author a known-bad trap fixture under probes/<id>.trap/<name>/; replace the smallest_fix TODO with the minimal observable slice; set 'probe:' on the draft entry and delete its 'needs_authoring' flag.
3. Touch ONLY gaps.draft.yaml, probes/, and GAPS.md prose for the picked drafts. Never the product tree, never gaps.yaml — the baseline ceremony is the only door into the ledger.
4. Commit policy: unsigned-per-cycle (never run a command that can prompt).
Then STOP. Do not run baseline yourself; the loop runs it."

  echo "$arm_prompt" | $AGENT_CMD
  local s
  for s in $suites; do
    # Exit code intentionally ignored: a partial baseline (some kept-draft)
    # still promotes every RED probe it measured. Progress is judged below.
    $PROG baseline "$s" || true
  done
  $PROG next --json | py 'import json,sys
d=json.load(sys.stdin)
sys.exit(0 if d.get("recommended") else 1)'
}

# stop_verdict: ask the stopping controller whether the loop is done, from the
# FULL MEASURED vector — never a mechanical guess. `open` (RED/open gaps) comes
# from `next --json`; `regressed`/`broken` are parsed from the matrix summary
# line ("... regressions R · broken B ..."). The gate counts are only half the
# vector: `recurve sense` assembles the whole one, adding `uncovered` from the
# completeness frontier and `divergent` from fidelity, so the loop feeds the
# controller completeness and fidelity, not just soundness. (For a target with
# no configured surface these are 0 / False, so behavior is unchanged.) The
# controller's verdict is printed on stdout (STOP-SUCCESS / STOP-REVERT /
# CONTINUE); the caller gates its success-halt on it. The cap/failure/runaway
# watchdogs remain as backstops.
stop_verdict() {
  local next_json="$1" matrix_out open regressed broken sense_out uncovered divergent
  open="$(py 'import json,sys
d=json.loads(sys.argv[1])
n=(1 if d.get("recommended") else 0)+len(d.get("then",[]))+len(d.get("review_gated",[]))
print(n)' "$next_json")"
  matrix_out="$($PROG matrix 2>/dev/null)"
  regressed="$(py 'import re,sys
m=re.search(r"regressions\s+(\d+)", sys.argv[1]); print(m.group(1) if m else 0)' "$matrix_out")"
  broken="$(py 'import re,sys
m=re.search(r"broken\s+(\d+)", sys.argv[1]); print(m.group(1) if m else 0)' "$matrix_out")"

  # Source the FULL vector: sense takes the gate counts and adds `uncovered`
  # from the frontier and `divergent` from fidelity. With no configured surface
  # these come back 0 / False, which is correct — the completeness and fidelity
  # signals only bind when the target has a surface to be incomplete about.
  sense_out="$($PROG sense --open "${open:-0}" --regressed "${regressed:-0}" --broken "${broken:-0}" 2>/dev/null)"
  uncovered="$(py 'import re,sys
m=re.search(r"uncovered\s+(\d+)", sys.argv[1]); print(m.group(1) if m else 0)' "$sense_out")"
  divergent="$(py 'import re,sys
m=re.search(r"divergent\s+(\w+)", sys.argv[1]); print("1" if m and m.group(1)=="True" else "0")' "$sense_out")"

  # Feed the whole vector to the controller. --divergent is a store_true flag on
  # decide, so pass it only when fidelity actually diverged.
  if [ "${divergent:-0}" = "1" ]; then
    $PROG decide --open "${open:-0}" --regressed "${regressed:-0}" --broken "${broken:-0}" --uncovered "${uncovered:-0}" --divergent
  else
    $PROG decide --open "${open:-0}" --regressed "${regressed:-0}" --broken "${broken:-0}" --uncovered "${uncovered:-0}"
  fi
}

fails=0
runaway=0
closed=0
cycle=0
waves=0
while [ "$cycle" -lt "$CAP" ]; do
  NEXT_JSON="$($PROG next --json)"
  GAP="$(py 'import json,sys; d=json.loads(sys.argv[1]); print(d["recommended"]["gap"] if d.get("recommended") else "")' "$NEXT_JSON")"
  if [ -z "$GAP" ]; then
    DRAFTS="$(py 'import json,sys; d=json.loads(sys.argv[1]); print(sum(x["pending"] for x in d.get("drafts", [])))' "$NEXT_JSON")"
    FORKS="$(py 'import json,sys; print(json.loads(sys.argv[1]).get("adjudications_pending", 0))' "$NEXT_JSON")"
    if [ "${DRAFTS:-0}" -eq 0 ]; then
      # No backlog and no drafts — but the STOP decision is the controller's,
      # not the empty-backlog watchdog's. Measure the cycle's gate vector and
      # halt as burned-down ONLY when controller.decide returns STOP-SUCCESS;
      # any other verdict means a regression or unmeasurable claim slipped in
      # that no open gap tracks, so halt for the human instead of blind victory.
      VERDICT="$(stop_verdict "$NEXT_JSON")"
      if [ "$VERDICT" = "STOP-SUCCESS" ]; then
        echo "burndown: no work left and no drafts pend — controller.decide verdict STOP-SUCCESS — the spec is burned down. Halting."
        break
      fi
      # The backlog holds no gap the loop can pick up, yet the controller
      # withholds STOP-SUCCESS — a regression or unmeasurable claim slipped in
      # that no open gap tracks. Do not declare victory; halt for the human.
      echo "burndown: backlog empty but controller.decide verdict is $VERDICT (not STOP-SUCCESS) — a regression or unmeasurable claim remains with no gap to sculpt. Halting for the human."
      break
    fi
    if [ "${FORKS:-0}" -gt 0 ]; then
      echo "burndown: $DRAFTS draft(s) pend but $FORKS fork(s) await ADJUDICATE.md — a probe must encode a decision, never a guess. Halting for the human."
      break
    fi
    if [ "$waves" -ge "$ARM_WAVES" ]; then
      echo "burndown: wave limit ($ARM_WAVES) reached with $DRAFTS draft(s) still pending. Halting; restart to continue."
      break
    fi
    waves=$((waves+1))
    if ! arm_wave "$NEXT_JSON" "$waves"; then
      echo "burndown: arming opened no sculptable work (drafts unprobed or baseline kept them) — halting for the human."
      break
    fi
    continue
  fi

  cycle=$((cycle+1))
  echo "burndown cycle $cycle/$CAP: $GAP"
  RESULT_FILE="$(mktemp)"
  PROMPT="You are running ONE improvement cycle. Read .recurve/RUN.md and obey it exactly.
Your gap: $GAP  (details: \`$PROG show $GAP\`)
Hard rules (non-negotiable, embedded because you are stateless):
- never git reset/checkout shared state; never touch sacred paths
- no loop vocabulary (gap ids, cycle names, tool name) in product code
- never sculpt review-gated gaps; ~3 honest attempts then park with the journal
- rebuild before trusting any probe; the gate is \`$PROG matrix --gate\`
- commit policy: unsigned-per-cycle (never run a command that can prompt)
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

  # Post the cycle's report — observability, never control flow: the loop
  # must survive a reporting failure ('|| true' is load-bearing).
  $PROG report --out ".recurve/state/reports/$RUN_ID.md" >/dev/null 2>&1 || true

  if [ "$fails" -ge "$MAX_FAILS" ]; then
    echo "burndown: $MAX_FAILS consecutive failures — halting (fix the common cause, don't retry harder)."
    break
  fi
  if [ "$runaway" -ge "$RUNAWAY" ]; then
    echo "burndown: $RUNAWAY consecutive net-gap-positive cycles — runaway scope; halting to re-scope."
    break
  fi
done
if [ "$cycle" -ge "$CAP" ]; then
  echo "burndown: cycle cap ($CAP) reached. Halting; restart to continue."
fi

echo "burndown $RUN_ID wrap-up: closed=$closed, waves armed=$waves"
$PROG matrix || true
$PROG park || true
echo "human queue: adjudications first, then review-gated promotions, then parked triage."
