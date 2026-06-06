#!/usr/bin/env bash
# Agent Passport — ships-today commit-path demo.
#
# Delegates a scoped, expiring agent passport, has the agent sign a commit, and shows that
# anyone can verify OFFLINE that the commit was authorized by YOU, in-scope, unexpired, and
# unrevoked — with no platform or issuer in the trust path. Revoking the agent makes its
# future commits fail to verify instantly.
#
# This exercises the SHIPPED commit-path passport (auths/crates/auths-verifier/src/commit_kel.rs);
# the request-auth (presentation) counterpart is covered by the `authenticate` integration tests.
#
# Prereqs: `auths` on PATH (`cargo install --path crates/auths-cli`), a git repo, and an Auths
# identity (`auths init`). The flags below are the verified shipped CLI surface.
set -euo pipefail

ROOT_KEY="${ROOT_KEY:-my-key}"   # your root identity's signing-key alias (the delegator)

echo "==> 1) Delegate a scoped, 1-hour agent passport (P-256 default):"
auths id agent add --label release-bot --key "$ROOT_KEY" --curve p256 --scope sign_commit --expires-in 3600
#   Note the agent's did:keri printed here; you'll need it to revoke in step 4.

echo "==> 2) The agent signs a commit carrying an 'Auths-Scope: sign_commit' trailer, e.g.:"
echo "       git commit -m 'release: cut v1.2.3'   # signed with the release-bot agent key"

echo "==> 3) Anyone verifies OFFLINE that authority traces to you, in-scope/unexpired/unrevoked:"
auths verify HEAD
#   in-scope + fresh  -> OK (the signer traces to the delegator = you)
#   out-of-scope      -> CommitVerdict::OutsideAgentScope
#   past --expires-in -> CommitVerdict::AgentExpired
#   after revoke      -> CommitVerdict::SignedAfterRevocation / DeviceRevoked

echo "==> 4) Kill the passport instantly with one KEL event (use the did from step 1):"
echo "       auths id agent revoke <agent-did:keri> --key $ROOT_KEY"
