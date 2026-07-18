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

# The revocation is authored by the ROOT's key (--key main), not device #0's — the root
# anchors the revocation on its own KEL, so revoking device #0 never needs the device.
"$AUTHS_BIN" device remove --device-did "$device_did" --key main --repo "$AUTHS_HOME" >/dev/null 2>&1 \
  || broken "device remove failed (cannot measure independent revocation)"

# The root identity must still be intact after revoking the device.
"$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null | grep -q "$identity_did" \
  || red "ours=root-identity-gone-after-device-remove oracle=root survives device revocation"

# The headline: a commit NEWLY signed by the revoked device must be rejected. Force the
# revoked device #0 key ("main-device") and require it can no longer produce a verifiable
# artifact — either signing is refused fail-closed (no sidecar) or verify rejects it.
g="$(mktemp -d)/post-revocation.bin"; echo "signed after revocation" > "$g"
if "$AUTHS_BIN" sign "$g" --device-key main-device --repo "$AUTHS_HOME" >/dev/null 2>&1 \
   && [ -f "$g.auths.json" ]; then
  postvalid="$("$AUTHS_BIN" verify "$g" --json --repo "$AUTHS_HOME" 2>/dev/null | dd_json_field valid)"
  case "$postvalid" in
    True|true) red "ours=revoked-device($device_did) artifact verifies valid=$postvalid oracle=rejected (revocation must bite)";;
  esac
fi
green "device #0 revoked; root ($identity_did) survives; the revoked device can no longer sign a verifiable artifact"
