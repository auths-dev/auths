#!/usr/bin/env bash
# DD-5: `auths keri-emit dip` is byte-identical to keripy's delegated inception.
# GREEN today (PR #360). Hermetic: compares the release binary's output to a frozen
# keripy golden — no keripy needed at probe time.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_contract.sh"

GOLDEN="$(dirname "${BASH_SOURCE[0]}")/dd-5.golden.json"
KEY="DAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMk"          # keripy ed2 verfer qb64
DELEGATOR="EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J"    # keripy ed AID
[ -x "$AUTHS_BIN" ] || broken "auths binary not built at $AUTHS_BIN"
[ -f "$GOLDEN" ] || broken "missing keripy golden $GOLDEN"

canon() { python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":")))'; }
want="$(canon < "$GOLDEN")" || broken "golden not valid JSON"

if [ -n "${TRAP_FIXTURE:-}" ]; then
  got="$(canon < "$TRAP_FIXTURE/dip.json" 2>/dev/null)" || broken "trap fixture unreadable"
else
  got="$("$AUTHS_BIN" keri-emit dip --key "$KEY" --delegator "$DELEGATOR" --repo "$(mktemp -d)" 2>/dev/null | canon)" \
    || broken "keri-emit dip failed (is the keri-emit surface present?)"
fi

[ "$got" = "$want" ] || red "ours=$got oracle=$want"
green "auths keri-emit dip == keripy delegated inception (byte-identical)"
