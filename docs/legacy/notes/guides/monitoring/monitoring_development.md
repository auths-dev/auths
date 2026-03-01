# Monitoring: Local Development & Testing

A step-by-step walkthrough for contributors to test the real-time monitoring pipeline on a single machine. This covers the registry server, the dashboard, WebSocket events, and commit verification.

## Prerequisites

1. **An initialized identity at `~/.auths`**:
   ```bash
   auths init
   ```
   If you already have one, verify with `auths status`.

2. **A key in your keychain**:
   ```bash
   auths key list
   # Should show at least one alias (e.g., "macbook", "main")
   ```

3. **The project built**:
   ```bash
   cargo build --package auths-registry-server
   ```

4. **Dashboard dependencies installed**:
   ```bash
   cd auths-dashboard
   npm install
   ```

## The Three-Terminal Setup

You need three terminals. Terminal 1 and 2 stay running; Terminal 3 is used for ad hoc commands.

### Terminal 1: Registry Server

Start the server with CORS enabled (required for browser access during development):

```bash
cargo run --package auths-registry-server -- --cors
```

Expected output:
```
2026-02-10T20:40:16Z  INFO auths_registry_server: Auths Registry Server v0.0.1-rc.9
2026-02-10T20:40:16Z  INFO auths_registry_server: Repository: "/Users/<you>/.auths"
2026-02-10T20:40:16Z  INFO auths_registry_server: Bind address: 0.0.0.0:3000
2026-02-10T20:40:16Z  INFO auths_registry_server: CORS: enabled
2026-02-10T20:40:16Z  INFO auths_registry_server: Starting registry server on 0.0.0.0:3000
```

Leave this running. For verbose logging, add `--log-level debug` or set `RUST_LOG=debug`.

### Terminal 2: Dashboard Dev Server

```bash
cd auths-dashboard
npm run dev
```

Expected output:
```
  VITE v5.4.x  ready in 300ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

Open http://localhost:5173 in your browser. You should see the Members page with live data from the registry server.

### Terminal 3: Testing Commands

Use this terminal to trigger events and observe them in the dashboard.

## Walkthrough: End-to-End Monitoring

### Step 1: Verify the server is healthy

```bash
curl http://localhost:3000/v1/health
```

Expected:
```json
{"status":"ok"}
```

### Step 2: View members and devices in the dashboard

Open the browser to http://localhost:5173. Navigate between pages:

- **Members** (`/`) - Shows org members from the registry
- **Devices** (`/devices`) - Shows paired devices

If you have a freshly initialized identity with no org members, these pages will be empty or show a 404 from the server. That's expected - pair a device or add members to populate data.

### Step 3: Pair a device (to generate monitoring data)

In Terminal 3, initiate pairing:

```bash
auths pair --registry http://localhost:3000
```

Open a fourth terminal and join:

```bash
auths pair --join <CODE> --registry http://localhost:3000
```

After pairing completes, the dashboard's Devices page should update automatically (the `device_added` event fires over the WebSocket and invalidates the devices cache).

### Step 4: Verify a commit via the API

Find a signed commit in any Git repo managed by your Auths identity:

```bash
cd /path/to/your/repo
COMMIT_SHA=$(git rev-parse HEAD)

curl -s -X POST http://localhost:3000/v1/verify/commit \
  -H 'Content-Type: application/json' \
  -d "{\"commit_sha\": \"$COMMIT_SHA\"}" | python3 -m json.tool
```

Example response for a signed commit:
```json
{
    "commit_sha": "d64c3e5abc...",
    "valid": true,
    "status": "verified",
    "signer_did": "did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM"
}
```

Example response for an unsigned commit:
```json
{
    "commit_sha": "d64c3e5abc...",
    "valid": false,
    "status": "unsigned",
    "warnings": [
        "Commit d64c3e5a by Test User has no signature"
    ],
    "error": "No signature found on commit"
}
```

### Step 5: Observe the WebSocket event

While the dashboard is open, go to browser DevTools > Network > WS. You should see a WebSocket connection to `/api/ws/events`. Each commit verification triggers a `verification_completed` message:

```json
{
    "type": "verification_completed",
    "commit_sha": "d64c3e5abc...",
    "valid": true,
    "signer_did": "did:keri:EnXNxUaRegVPCxYYrLHvsj3WcsN-0qyM39KCNfnQsRcM",
    "timestamp": "2026-02-10T20:45:00Z"
}
```

### Step 6: Test WebSocket reconnection

1. Stop the registry server (Ctrl+C in Terminal 1)
2. Watch the browser DevTools console - the WebSocket closes
3. Restart the server: `cargo run --package auths-registry-server -- --cors`
4. Within ~3 seconds the dashboard reconnects automatically

## Testing with Mock Data

To work on the dashboard UI without a running server:

```bash
cd auths-dashboard
VITE_USE_MOCK_DATA=true npm run dev
```

This returns hardcoded members and devices. The WebSocket connection will still attempt to connect (and silently retry), but the pages will display mock data regardless.

To switch back to live data, stop the dev server and restart without the variable:

```bash
npm run dev
```

## Testing Variations

### Custom server port

```bash
cargo run --package auths-registry-server -- --bind 127.0.0.1:4000 --cors
```

Update `auths-dashboard/vite.config.ts` proxy target to match, or set the env var:

```bash
AUTHS_BIND_ADDR=127.0.0.1:4000 cargo run --package auths-registry-server -- --cors
```

### Debug-level server logs

```bash
cargo run --package auths-registry-server -- --cors --log-level debug
```

Or:

```bash
RUST_LOG=debug cargo run --package auths-registry-server -- --cors
```

This logs every HTTP request, WebSocket connection, and event broadcast.

### Verify multiple commits in a loop

```bash
for sha in $(git log --format=%H -5); do
  echo "--- $sha ---"
  curl -s -X POST http://localhost:3000/v1/verify/commit \
    -H 'Content-Type: application/json' \
    -d "{\"commit_sha\": \"$sha\"}" | python3 -m json.tool
done
```

Each verification emits a WebSocket event, so the dashboard receives 5 rapid updates.

### WebSocket with wscat

For lower-level testing without the dashboard:

```bash
npx wscat -c ws://localhost:3000/v1/ws/events
```

Then trigger a verification in another terminal. Events appear as raw JSON lines in wscat.

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Error loading devices` / `Error loading members` | Server not running or CORS not enabled | Start server with `--cors` |
| WebSocket never connects | Vite proxy misconfigured or running a static build | Use `npm run dev`, not a production build |
| `Cannot verify: no allowed_signers file` | `~/.auths/.auths/allowed_signers` missing | Pair a device or create the file manually |
| `Failed to open repository` | Server's `--repo` path doesn't exist | Run `auths init` to create `~/.auths` |
| `Commit not found` | SHA doesn't exist in the repo at `~/.auths` | The server verifies commits in its own repo, not yours - make sure the repo paths match |
| `Failed to run ssh-keygen` | `ssh-keygen` not in PATH | Install OpenSSH tools |
| Mock data still showing | `VITE_USE_MOCK_DATA` was set previously | Restart the dev server without the env var |

## Architecture Notes

For contributors working on the monitoring pipeline:

- **Event types**: `crates/auths-registry-server/src/events.rs` - `AuthsEvent` enum with tagged JSON serialization
- **Broadcast channel**: `crates/auths-registry-server/src/lib.rs` - `ServerStateInner.event_sender` (tokio broadcast, capacity 256)
- **WebSocket handler**: `crates/auths-registry-server/src/routes/ws.rs` - subscribes to broadcast, forwards as JSON text frames
- **Commit verification**: `crates/auths-registry-server/src/routes/verify_commit.rs` - opens repo via `git2`, verifies SSH signatures with `ssh-keygen`
- **API path definitions**: `crates/auths-registry-server/src/paths.rs` - `verify_commit()` and `ws_events()` helpers
- **Frontend API client**: `auths-dashboard/src/api/AuthsApiClient.ts` - class with `verifyCommit()` and `subscribe()` methods
- **Cache invalidation**: `auths-dashboard/src/hooks/useAuthsEvents.ts` - maps WebSocket events to TanStack Query invalidations
- **Vite proxy**: `auths-dashboard/vite.config.ts` - `/api/ws` proxied with `ws: true`, `/api` proxied to `http://localhost:3000`

The broadcast channel is in-memory. Events are not persisted. If no WebSocket clients are connected, events are silently dropped.

## See Also

- [Monitoring Dashboard](monitoring_dashboard.md) - end-user guide
- [Pairing: Local Development](../pairing/pairing_development.md) - pair devices to generate monitoring data
- [Git Signing](../git-signing.md) - set up signed commits for verification
