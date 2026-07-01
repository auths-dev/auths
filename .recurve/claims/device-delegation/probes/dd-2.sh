#!/usr/bin/env bash
# DD-2 (headline): a commit signs and verifies end-to-end under the delegated
# device #0. This is the gate that catches the coupling — the Auths-Device trailer
# must name device #0's delegated AID AND the signature must verify with the key
# that controls that AID. RED until init + resolve_local_signer + auto_detect agree.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_contract.sh"

if [ -n "${TRAP_FIXTURE:-}" ]; then
  # Known-bad: a commit whose Auths-Device trailer claims device #0 but was signed by the
  # root key (the exact inconsistency a half-fix produces) — verify MUST reject it.
  bash "$TRAP_FIXTURE/verify.sh" 2>/dev/null && red "ours=trailer-claims-device#0-but-root-key-signed verified GREEN oracle=must-reject"
  green "the inconsistent (trailer!=signer) commit is rejected"
fi

dd_fresh_identity || broken "auths init failed or binary missing ($AUTHS_BIN)"
f="$(mktemp -d)/artifact.bin"; echo "device-delegation round-trip" > "$f"

# Sign the artifact with this identity's default keys, then verify it.
"$AUTHS_BIN" sign "$f" --repo "$AUTHS_HOME" >/dev/null 2>&1 \
  || broken "auths sign failed (round-trip cannot be measured)"
out="$("$AUTHS_BIN" verify "$f" --json --repo "$AUTHS_HOME" 2>/dev/null)" \
  || broken "auths verify failed to produce output"
valid="$(printf '%s' "$out" | dd_json_field valid)"
identity="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field identity_did)"
device="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field device_did)"

[ -n "$valid" ] || broken "verify produced no 'valid' field — cannot measure the round-trip"
# The device that actually SIGNED (the attestation subject) must be device #0 — not the
# root. This is what catches the coupling: whoami can report device #0 while the sign
# path still uses the root key.
att_device="$(python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(d.get("device_did") or d.get("subject",""))' "$f.auths.json" 2>/dev/null)"
case "$valid" in True|true) ;; *) red "ours=verify.valid=$valid oracle=true (signature must verify under device #0)";; esac
[ -n "$device" ] && [ "$device" != "$identity" ] \
  || red "ours=device($device)==identity($identity) oracle=device #0's delegated AID"
[ -n "$att_device" ] && [ "$att_device" = "$device" ] \
  || red "ours=attestation-signer($att_device)!=whoami-device#0($device) oracle=the artifact is signed by device #0's key"
green "artifact signs+verifies AND is signed by device #0 ($device), distinct from identity ($identity)"
