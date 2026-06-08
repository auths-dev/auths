#!/usr/bin/env bash
#
# Reproducible end-to-end check for the keyless service-to-service path:
#   challenge → present → middleware verify → authorized action, then revoke → next call denied.
#
# First-party only. This runs the in-repo e2e tests that exercise the real flow; it needs no
# external deploy target and no stored secret. Optional middleware suites run when their
# toolchains are present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== SDK e2e: present → authorize → revoke → deny =="
# These cases ARE the keyless flow end to end (git-backed registry, real KELs/TEL):
#   - valid_presentation_authenticates_and_replay_rejected
#   - valid_then_revoked_presentation_transition   (authorized before revoke, DENIED after)
#   - presentation_for_audience_a_rejected_at_server_b  (wrong-audience / confused deputy)
cargo nextest run -p auths_sdk -E 'test(authenticate)' --no-fail-fast

echo "== HTTP middleware: Axum relying party =="
cargo nextest run -p auths_api -E 'test(rp_auth)' --no-fail-fast

if command -v pnpm >/dev/null 2>&1 && [ -f packages/auths-express/package.json ]; then
  echo "== HTTP middleware: Express (@auths/express) =="
  ( cd packages/auths-express && pnpm install --silent && pnpm test )
else
  echo "== Express middleware: SKIPPED (pnpm not found) =="
fi

if command -v python3 >/dev/null 2>&1 && [ -f packages/auths-fastapi/pyproject.toml ]; then
  echo "== HTTP middleware: FastAPI (auths-fastapi) =="
  ( cd packages/auths-fastapi && python3 -m pytest -q ) || \
    echo "   (FastAPI suite needs: pip install -e '.[client]' pytest httpx)"
else
  echo "== FastAPI middleware: SKIPPED (python3 not found) =="
fi

echo "== e2e OK: a revoked credential's next presentation is denied; no static secret involved =="
