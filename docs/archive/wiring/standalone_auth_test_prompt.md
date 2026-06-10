# Prompt: Build Standalone Auth Test Frontend

## Goal

Build a minimal standalone web app that proves the DID signature auth flow works end-to-end against the real registry server. This app exists to validate the `BearerPayload` signing pattern before porting it to the main `auths-site` frontend.

This is a **test harness**, not a product. Keep it as simple as possible.

## Context

The Auths registry server (`auths-registry-server`) has an auth middleware that accepts two formats in the `Authorization: Bearer` header:

1. **Session UUID** (current, being replaced): `Bearer 550e8400-e29b-41d4-a716-446655440000`
2. **Signed DID payload** (target): `Bearer {"did":"did:keri:...","timestamp":"2026-03-16T12:00:00Z","signature":"ab12cd34..."}`

Path 2 is already implemented in the middleware but has never been tested from a browser. This standalone app tests path 2.

### Key backend file to understand

**`auths-cloud/crates/auths-registry-server/src/middleware/identity_auth.rs`**

The middleware does this:
```rust
let token = request.headers().get("authorization")
    .and_then(|v| v.to_str().ok())
    .and_then(|h| h.strip_prefix("Bearer "));

let identity = match token {
    None => anonymous_identity(),
    Some(t) => match Uuid::parse_str(t) {
        Ok(uuid) => validate_session_token(auth_url, uuid).await?,
        Err(_) => match serde_json::from_str::<BearerPayload>(t) {
            Ok(payload) => validate_signed_challenge(&state, payload).await?,
            Err(_) => anonymous_identity(),
        },
    },
};
```

When the Bearer value is NOT a UUID, it tries to parse as `BearerPayload` and calls `validate_signed_challenge()`. **You must read `identity_auth.rs` to understand the exact `BearerPayload` struct and what `validate_signed_challenge` expects** — field names, signature format (hex? base64?), what message is signed, timestamp validation window, etc. Do not assume — read the code.

### Key backend file for identity registration

**`auths-cloud/crates/auths-registry-server/src/routes/identity.rs`**

The `POST /v1/identities` endpoint is public and self-authenticating (no auth required to register). Read it to understand the exact request body shape for registering a new identity with a public key.

## Repositories

- **Backend (cloud)**: `/Users/bordumb/workspace/repositories/auths-base/auths-cloud`
- **Core logic**: `/Users/bordumb/workspace/repositories/auths-base/auths`
- **Standalone app**: Create at `/Users/bordumb/workspace/repositories/auths-base/auths-auth-test`

## What To Build

A single-page web app with **4 steps**, displayed vertically on one page. Each step shows its output inline. No routing, no state management library, no build complexity.

### Tech stack

- **Vite + vanilla TypeScript** (no React, no framework)
- Single `index.html` + `src/main.ts` + `src/crypto.ts` + `src/api.ts`
- Minimal CSS — just enough to be readable

### Step 1: Generate Keypair

A button that:
1. Generates an Ed25519 keypair via `crypto.subtle.generateKey('Ed25519', ...)`
2. Stores the private key (CryptoKey object) in IndexedDB — use `extractable: false`
3. Exports the public key as raw bytes → hex string
4. Displays the public key hex on screen
5. Stores `{ publicKeyHex }` in a module-level variable for subsequent steps

**Display:**
```
[Generate Keypair]

Public Key: 3b6a27bceeb6a0...  (64 hex chars)
Stored in: IndexedDB ✓
```

### Step 2: Register Identity

A button that:
1. Calls `POST /v1/identities` on the registry server with the public key from Step 1
2. Displays the returned DID
3. Stores the DID in the module-level variable

**Important:** Read `identity.rs` in the registry server to determine the exact request body format. It may require a KERI inception event, not just a raw public key. If so, read the core `auths-id` crate to understand how inception events are constructed, and build the minimum viable request. If building a full KERI inception event is too complex for a test harness, document what you found and use whichever simpler registration path exists.

**Display:**
```
[Register Identity]

DID: did:keri:EBf1...
Status: 201 Created ✓
```

### Step 3: Make Authenticated Request

A button that:
1. Constructs the message to sign (read `identity_auth.rs` to find the exact format — likely `"{did}\n{timestamp}"` but verify)
2. Retrieves the private key from IndexedDB
3. Signs the message via `crypto.subtle.sign('Ed25519', privateKey, messageBytes)`
4. Constructs the `BearerPayload` JSON (match the exact struct from `identity_auth.rs`)
5. Sends a GET request to an authenticated endpoint with `Authorization: Bearer <payload-json>`
6. Displays the full request headers sent and the response

Use an endpoint that behaves differently for authenticated vs anonymous users. Good candidates:
- `GET /v1/account/status` (if it exists — returns identity info for authenticated users)
- `GET /v1/orgs` or any endpoint that returns user-specific data
- If no good candidate exists, use `GET /v1/health` and check that the server at least doesn't reject the auth header

**Display:**
```
[Make Authenticated Request]

Request:
  GET /v1/account/status
  Authorization: Bearer {"did":"did:keri:EBf1...","timestamp":"2026-03-16T...","signature":"a1b2c3..."}

Response:
  Status: 200 OK
  Body: { "did": "did:keri:EBf1...", "tier": "session", ... }
```

### Step 4: Verify Anonymous vs Authenticated

Two buttons side by side that call the same endpoint — one without auth, one with. Displays both responses so you can visually confirm the auth is working.

**Display:**
```
[Request Without Auth]          [Request With Auth]

Status: 200                     Status: 200
Body: { anonymous: true }       Body: { did: "did:keri:..." }
```

### Debug Panel

At the bottom of the page, a persistent log that shows:
- Every IndexedDB operation (store/retrieve)
- Every `crypto.subtle` call and its result
- Every HTTP request/response with full headers
- Any errors with stack traces

This is the most important part of the UI. The four steps above are just buttons — the debug panel is where you'll actually diagnose issues.

## File Structure

```
auths-auth-test/
├── index.html
├── package.json          (vite + typescript only)
├── tsconfig.json
├── vite.config.ts
└── src/
    ├── main.ts           (UI wiring — buttons, display, debug log)
    ├── crypto.ts         (WebCrypto + IndexedDB operations)
    ├── api.ts            (fetch calls to registry server)
    └── style.css         (minimal)
```

## Configuration

The registry server URL should be configurable at the top of `api.ts`:

```typescript
const REGISTRY_URL = 'http://localhost:3000';
```

The app should handle CORS. The registry server has CORS enabled when `AUTHS_CORS=1` is set.

## Before You Write Code

1. **Read `identity_auth.rs`** — find the `BearerPayload` struct definition, the `validate_signed_challenge` function, and understand exactly what it validates (signature format, message format, timestamp window, DID resolution path).
2. **Read the identity registration route** — find the `POST /v1/identities` handler and understand the request body.
3. **Read the `BearerPayload` struct** — find every field. The struct may have fields beyond `did`, `timestamp`, `signature`. Match it exactly.
4. **Check the signature format** — is it hex-encoded? base64? raw bytes? The registry middleware will reject the request if the encoding is wrong.
5. **Check what message is signed** — is it `"{did}\n{timestamp}"` or something else? A single wrong byte means signature verification fails.

If you find that the `BearerPayload` / `validate_signed_challenge` code doesn't match what's described in this prompt, **trust the code, not this prompt**. This prompt is based on an exploration of the codebase — the code is the source of truth.

## Definition of Done

1. `npm run dev` serves the app on localhost
2. Clicking through Steps 1-4 in order produces a successful authenticated request against a locally running registry server
3. The debug panel shows the exact `Authorization` header sent and confirms the server accepted it (not falling back to anonymous)
4. If anything fails (wrong payload format, signature mismatch, etc.), the debug panel shows enough detail to diagnose why

## What NOT To Do

- No React, no Next.js, no framework — vanilla TypeScript only
- No CSS framework — raw CSS, just enough to not be ugly
- No state management — module-level variables are fine for a test harness
- No tests — this IS the test
- No production concerns (error boundaries, loading states, accessibility) — this is a throwaway diagnostic tool
- Do not modify the backend — the point is to test the backend as-is
