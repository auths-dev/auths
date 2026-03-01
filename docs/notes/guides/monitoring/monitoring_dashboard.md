# Monitoring with the Auths Dashboard

This guide explains how to use the Auths dashboard to monitor your organization's devices, members, and commit verification activity in real time.

## Overview

The Auths dashboard is a web UI that connects to the registry server and displays:

- **Members** - Organization members, their roles, and capabilities
- **Devices** - Paired devices authorized to sign on behalf of the organization
- **Commit verification** - Verify Git commit signatures against your identity registry
- **Real-time updates** - A WebSocket connection pushes changes to the dashboard as they happen (device pairings, member changes, verification results)

## Prerequisites

1. **An initialized identity** at `~/.auths`:
   ```bash
   auths init
   ```

2. **At least one paired device** (so the dashboard has data to display):
   ```bash
   auths pair --registry http://localhost:3000
   ```
   See [Pairing Devices](../pairing/pairing_devices.md) for the full walkthrough.

3. **Node.js 18+** installed (for the dashboard dev server).

## Quick Start

### Terminal 1: Start the registry server

```bash
cargo run --package auths-registry-server -- --cors
```

The `--cors` flag is required for the dashboard to make cross-origin requests during development. Expected output:

```
2026-02-10T20:40:16Z  INFO auths_registry_server: Auths Registry Server v0.0.1-rc.9
2026-02-10T20:40:16Z  INFO auths_registry_server: Repository: "/Users/<you>/.auths"
2026-02-10T20:40:16Z  INFO auths_registry_server: Bind address: 0.0.0.0:3000
2026-02-10T20:40:16Z  INFO auths_registry_server: CORS: enabled
2026-02-10T20:40:16Z  INFO auths_registry_server: Starting registry server on 0.0.0.0:3000
```

### Terminal 2: Start the dashboard

```bash
cd auths-dashboard
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

### What you should see

- **Members page** (`/`) - Lists organization members with roles, capabilities, and the date they were added.
- **Devices page** (`/devices`) - Shows paired devices with a green shield icon for valid `did:key` DIDs.
- **Analytics page** (`/analytics`) - Signing coverage and adoption metrics.

## Verifying a Commit

The dashboard can verify Git commit signatures via the registry server. The endpoint is `POST /v1/verify/commit`.

### Using curl

```bash
# Get a commit SHA from your repo
COMMIT_SHA=$(git rev-parse HEAD)

# Verify it against the registry
curl -X POST http://localhost:3000/v1/verify/commit \
  -H 'Content-Type: application/json' \
  -d "{\"commit_sha\": \"$COMMIT_SHA\"}"
```

### Response

A signed commit returns:

```json
{
  "commit_sha": "a1b2c3d4e5f6...",
  "valid": true,
  "status": "verified",
  "signer_did": "did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM",
  "warnings": []
}
```

An unsigned commit returns:

```json
{
  "commit_sha": "a1b2c3d4e5f6...",
  "valid": false,
  "status": "unsigned",
  "warnings": ["Commit a1b2c3d4 by Alice has no signature"],
  "error": "No signature found on commit"
}
```

### Status values

| Status | Meaning |
|--------|---------|
| `verified` | Valid SSH signature from an allowed signer |
| `unsigned` | Commit has no signature |
| `invalid_signature` | Signature present but verification failed |
| `unsupported_signature_type` | GPG signature (only SSH is supported) |
| `no_allowed_signers` | Repository has no `.auths/allowed_signers` file |
| `verification_error` | `ssh-keygen` not available or other system error |

## Real-Time Events

The dashboard connects to the registry server via WebSocket at `GET /v1/ws/events`. Events are pushed automatically when state changes occur.

### Event types

| Event | Triggers when | Dashboard effect |
|-------|---------------|------------------|
| `attestation_created` | A new device attestation is issued | Devices page refreshes |
| `attestation_revoked` | An attestation is revoked | Devices page refreshes |
| `attestation_expired` | An attestation expires | Devices page refreshes |
| `member_added` | A member is added to the org | Members page refreshes |
| `member_revoked` | A member is removed from the org | Members page refreshes |
| `verification_completed` | A commit is verified via the API | Verification cache refreshes |
| `device_added` | A device is paired | Devices page refreshes |
| `device_removed` | A device is unpaired | Devices page refreshes |

### Observing events in the browser

1. Open the dashboard at http://localhost:5173
2. Open browser DevTools > Network tab
3. Filter by "WS" to see the WebSocket connection to `/api/ws/events`
4. In another terminal, trigger an event (e.g., verify a commit):
   ```bash
   curl -X POST http://localhost:3000/v1/verify/commit \
     -H 'Content-Type: application/json' \
     -d '{"commit_sha": "'$(git rev-parse HEAD)'"}'
   ```
5. The WebSocket frame should show a `verification_completed` event in the Messages tab

### Example event payload

```json
{
  "type": "verification_completed",
  "commit_sha": "a1b2c3d4e5f6...",
  "valid": true,
  "signer_did": "did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM",
  "timestamp": "2026-02-10T20:45:00Z"
}
```

## Mock Data vs. Live Data

By default the dashboard connects to the live registry server. To use mock data instead (for UI development without a running server), set the environment variable before starting the dev server:

```bash
VITE_USE_MOCK_DATA=true npm run dev
```

When `VITE_USE_MOCK_DATA` is unset or set to anything other than `"true"`, the dashboard fetches from the registry server API.

## Troubleshooting

### Dashboard shows "Error loading devices" or "Error loading members"

**Cause**: The registry server isn't running, or CORS is not enabled.

**Solution**: Start the server with `--cors`:
```bash
cargo run --package auths-registry-server -- --cors
```

### WebSocket doesn't connect

**Cause**: The Vite dev server proxy isn't forwarding WebSocket upgrades.

**Solution**: Make sure you're running the dashboard with `npm run dev` (not a static build). The Vite config proxies `/api/ws` to `ws://localhost:3000/v1/ws` automatically.

### Commit verification returns "Cannot verify: no allowed_signers file"

**Cause**: The repository at `~/.auths` doesn't have an `allowed_signers` file.

**Solution**: Create one with your SSH public key:
```bash
mkdir -p ~/.auths/.auths
echo 'your@email.com ssh-ed25519 AAAA...' > ~/.auths/.auths/allowed_signers
```

Or pair a device first (pairing creates the necessary attestation structure).

### Data doesn't update in real time

**Cause**: The WebSocket connection dropped or the browser tab was backgrounded.

**Solution**: The client reconnects automatically after 3 seconds. Refresh the page if the connection doesn't recover.

## See Also

- [Pairing Devices](../pairing/pairing_devices.md) - Pair devices to populate the dashboard
- [Git Signing and Verification](../git-signing.md) - Set up commit signing with Auths
