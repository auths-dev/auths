#!/usr/bin/env bash
# DD-4: one canonical device DID. The device identity reported by `whoami`
# (did:keri) matches the device the sign path attributes the signature to — no
# did:key/did:keri split where the two disagree. RED while whoami says did:keri
# (collapsing to root) and the attestation subject says did:key.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_contract.sh"

if [ -n "${TRAP_FIXTURE:-}" ]; then
  whoami_dev="$(cat "$TRAP_FIXTURE/whoami_device_did" 2>/dev/null)"
  att_dev="$(cat "$TRAP_FIXTURE/attestation_device_did" 2>/dev/null)"
else
  dd_fresh_identity || broken "auths init failed or binary missing ($AUTHS_BIN)"
  whoami_dev="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field device_did)"
  work="$(mktemp -d)/app.bin"; echo probe > "$work"
  "$AUTHS_BIN" sign "$work" --repo "$AUTHS_HOME" >/dev/null 2>&1 || broken "auths sign failed"
  # The attestation records the device it was signed by; it must name the SAME device as whoami.
  att_dev="$(python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(d.get("device_did") or d.get("subject",""))' "$work.auths.json" 2>/dev/null)"
fi

[ -n "$whoami_dev" ] && [ -n "$att_dev" ] || broken "could not read both the whoami and attestation device DIDs"
[ "$whoami_dev" = "$att_dev" ] \
  || red "ours=whoami($whoami_dev)!=attestation($att_dev) oracle=one canonical delegated did:keri everywhere"
green "one canonical device DID across surfaces: $whoami_dev"
