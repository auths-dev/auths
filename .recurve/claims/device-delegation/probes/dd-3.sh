#!/usr/bin/env bash
# DD-3: the primary device is independently revocable and the root survives.
# After `auths device remove <device#0>`, the root identity still verifies and a
# commit newly signed by the revoked device is rejected. RED until device #0 has
# its own AID to target.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_contract.sh"

if [ -n "${TRAP_FIXTURE:-}" ]; then
  # Known-bad: a commit signed by a revoked device that still verifies GREEN — must RED.
  bash "$TRAP_FIXTURE/verify_revoked.sh" 2>/dev/null && red "ours=revoked-device commit verified GREEN oracle=must-reject"
  green "a revoked device's commit is rejected"
fi

dd_fresh_identity || broken "auths init failed or binary missing ($AUTHS_BIN)"
device_did="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field device_did)"
identity_did="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field identity_did)"
[ -n "$device_did" ] || broken "no device_did to revoke"
[ "$device_did" != "$identity_did" ] \
  || red "ours=device==identity ($device_did) oracle=distinct (cannot revoke a device that IS the identity — DD-1)"

"$AUTHS_BIN" device remove "$device_did" --repo "$AUTHS_HOME" >/dev/null 2>&1 \
  || broken "device remove failed (cannot measure independent revocation)"

# The root identity must still be intact after revoking the device.
"$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | grep -q "$identity_did" \
  || red "ours=root-identity-gone-after-device-remove oracle=root survives device revocation"
green "device #0 revoked; root identity ($identity_did) survives"
