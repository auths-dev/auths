#!/usr/bin/env bash
# Reproducible off-boarding lifecycle demo: create -> add-member -> revoke ->
# audit -> bundle -> offline verify (reject revoked signer, pass valid one).
#
# Runs against an ISOLATED scratch repo via `--repo`, so it never touches your real
# ~/.auths identity. Requires the `auths` CLI on PATH:
#     cargo install --path crates/auths-cli
#
# Usage: ./offboarding-demo.sh
set -euo pipefail

DEMO_DIR="$(mktemp -d)"
trap 'rm -rf "$DEMO_DIR"' EXIT
AUTHS=(auths --repo "$DEMO_DIR")

echo "== 1. Create the org identity =="
"${AUTHS[@]}" org create --name "Acme Security"
ORG="$("${AUTHS[@]}" id show --json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["controller_did"])')"
echo "ORG = $ORG"

echo "== 2. Add a member (minted key for the demo) =="
"${AUTHS[@]}" org add-member --org "$ORG" --member alice \
  --role member --capabilities sign_commit,deploy:staging
MEMBER="$("${AUTHS[@]}" org list-members --org "$ORG" --json 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["member_did"])' 2>/dev/null \
  || true)"
echo "MEMBER = ${MEMBER:-<see list-members output above>}"

echo "== 3. Bundle BEFORE off-boarding; a valid signer should pass =="
"${AUTHS[@]}" org bundle --org "$ORG" --out "$DEMO_DIR/acme.before.auths-offline"
printf '%s\n' "$ORG" > "$DEMO_DIR/roots"
# signed-at 1 is before any revocation -> AuthorizedBeforeRevocation -> exit 0
"${AUTHS[@]}" artifact verify "$DEMO_DIR/acme.before.auths-offline" \
  --offline --roots "$DEMO_DIR/roots" --member "$MEMBER" --signed-at 1 \
  && echo "PASS: valid signer authorized (as expected)"

echo "== 4. Off-board the member (emits a signed, durable record) =="
"${AUTHS[@]}" org revoke-member --org "$ORG" --member "$MEMBER" --note "left the company"
"${AUTHS[@]}" org offboarding-log --org "$ORG" --json

echo "== 5. Audit: classify an artifact by KEL position =="
"${AUTHS[@]}" org audit --org "$ORG" --member "$MEMBER" --artifact ./release.tar.gz --signed-at 99 --json || true

echo "== 6. Rebuild the bundle; a revoked signer must FAIL the gate =="
"${AUTHS[@]}" org bundle --org "$ORG" --out "$DEMO_DIR/acme.after.auths-offline"
# signed-at 99 is at/after the revocation -> RejectedAfterRevocation -> non-zero exit
if "${AUTHS[@]}" artifact verify "$DEMO_DIR/acme.after.auths-offline" \
     --offline --roots "$DEMO_DIR/roots" --member "$MEMBER" --signed-at 99; then
  echo "UNEXPECTED: revoked signer was authorized" >&2
  exit 1
else
  echo "PASS: revoked signer rejected by the offline gate (as expected)"
fi

echo "== Demo complete: off-boarding produced provable, air-gapped evidence. =="
