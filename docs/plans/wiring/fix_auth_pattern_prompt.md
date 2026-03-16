# Prompt: Replace Bearer Token Auth with DID Signature Auth

## Context

You are working on **Auths**, a decentralized identity system where cryptographic identity IS the credential. The fundamental principle is: **users authenticate by signing with their Ed25519 private key, and servers verify signatures against the user's DID-resolved public key.** There are no API keys, no session tokens, no OAuth tokens.

The current frontend violates this principle. After a challenge-response flow, the auth server returns a UUID session token, and the frontend passes it as `Authorization: Bearer <uuid>` on every subsequent request. The registry server then makes a roundtrip to the auth server to validate that session — a centralized session pattern layered on top of a system designed to eliminate it.

**The registry server already supports the correct pattern.** Its `identity_auth` middleware has a fallback path that accepts a signed `BearerPayload` (`{ did, timestamp, signature }`) and validates the Ed25519 signature directly — no auth server roundtrip. The frontend simply doesn't use this path.

## The Problem

### Current flow (wrong):
```
1. Frontend calls POST /auth/init → gets { id, nonce, domain }
2. User runs CLI: auths auth challenge --nonce ... --domain ... --json
3. User pastes JSON { signature, public_key, did } into frontend
4. Frontend calls POST /auth/verify → gets { token: "<uuid>", did, expires_at }
5. Frontend stores { token, did, expiresAt } in React context (memory only)
6. Every authenticated request sends: Authorization: Bearer <uuid>
7. Registry server receives Bearer <uuid>, parses as UUID
8. Registry server calls auth-server GET /auth/status/<uuid> to validate session
9. Auth server looks up session in DB, returns { status: "verified", did }
10. Registry server extracts DID, continues
```

Problems:
- Step 5: Token stored in memory only — page reload = logged out
- Steps 7-9: Every authenticated request requires a roundtrip from registry → auth server
- The UUID token IS a session — this is traditional session auth, not decentralized identity
- The token parameter propagates through every frontend API function

### Correct flow (DID signature auth):
```
1. User's Ed25519 keypair lives in browser (WebCrypto + IndexedDB)
2. For each authenticated request, frontend signs: "{did}\n{iso8601_timestamp}" with private key
3. Frontend sends: Authorization: Bearer {"did":"...","timestamp":"...","signature":"..."}
4. Registry server parses BearerPayload, verifies Ed25519 signature against DID's public key
5. No roundtrip to auth server. No session state. No expiry dance.
```

The registry server's `validate_signed_challenge()` already implements step 4.

## Repositories

- **Frontend**: `/Users/bordumb/workspace/repositories/auths-base/auths-site` (Next.js 16, React 19, TypeScript)
- **Backend (cloud)**: `/Users/bordumb/workspace/repositories/auths-base/auths-cloud` (Rust, Axum)
- **Core logic**: `/Users/bordumb/workspace/repositories/auths-base/auths`

## Current Code

### Frontend: Auth Context

**File:** `auths-site/apps/web/src/lib/auth/auth-context.tsx`

```typescript
interface AuthState {
  token: string;       // ← UUID session token (wrong)
  did: string;
  expiresAt: string;
}

interface AuthContextValue {
  auth: AuthState | null;
  setAuth: (state: AuthState) => void;
  clearAuth: () => void;
  isAuthenticated: boolean;
}
```

### Frontend: API Client (authenticated requests)

**File:** `auths-site/apps/web/src/lib/api/registry.ts`

```typescript
async function registryFetchAuth<T>(
  path: string,
  options: {
    method?: string;
    token?: string;                                                    // ← token param
    body?: Record<string, unknown>;
    params?: Record<string, string>;
    signal?: AbortSignal;
  } = {},
): Promise<T> {
  const url = new URL(path, REGISTRY_BASE_URL);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.token) headers.Authorization = `Bearer ${options.token}`;  // ← Bearer UUID
  if (options.body) headers['Content-Type'] = 'application/json';
  const res = await fetch(url.toString(), { ... });
  return res.json() as Promise<T>;
}

// Every authenticated function takes token as parameter:
export async function createOrg(name: string, token: string, signal?: AbortSignal) { ... }
export async function fetchOrgStatus(orgDid: string, token: string, signal?: AbortSignal) { ... }
export async function createInvite(orgDid: string, role: string, expiresIn: string, token: string, signal?: AbortSignal) { ... }
export async function setOrgPolicy(orgDid: string, requireSigning: boolean, token: string, signal?: AbortSignal) { ... }
```

### Frontend: Challenge-Response Component

**File:** `auths-site/apps/web/src/components/challenge-auth.tsx`

After the user pastes CLI output and verification succeeds:
```typescript
const res = await verifyChallenge(sessionId, {
  signature: data.signature,
  public_key: data.public_key,
  did: data.did,
});
setAuth({ token: res.token, did: res.did, expiresAt: res.expires_at });
```

### Backend: Auth Server Verify Endpoint

**File:** `auths-cloud/crates/auths-auth-server/src/routes/verify.rs`

```rust
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub token: String,       // ← Session UUID returned as "token"
    pub did: String,
    pub expires_at: String,
}
```

### Backend: Registry Server Auth Middleware (already supports both paths)

**File:** `auths-cloud/crates/auths-registry-server/src/middleware/identity_auth.rs`

```rust
pub async fn auth_middleware(...) -> Result<Response, ApiError> {
    let token = request.headers().get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let identity = match token {
        None => anonymous_identity(),
        Some(t) => match Uuid::parse_str(t) {
            // Path A: Session UUID → roundtrip to auth server (WRONG)
            Ok(uuid) => validate_session_token(auth_url, uuid).await?,
            Err(_) => match serde_json::from_str::<BearerPayload>(t) {
                // Path B: Signed DID payload → direct verification (CORRECT)
                Ok(payload) => validate_signed_challenge(&state, payload).await?,
                Err(_) => anonymous_identity(),
            },
        },
    };
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}
```

The `BearerPayload` and `validate_signed_challenge` already exist and work. The frontend simply never sends a payload in this format.

## Security Model: Where Keys Live

**CRITICAL: The server NEVER stores or sees private keys.**

All private key material lives exclusively on the user's device:

| Data | Where it lives | Why |
|---|---|---|
| **Private key** | User's browser — **IndexedDB only** (via WebCrypto). Never sent to the server. Never stored in memory as a raw string. Use `extractable: false` for HSM-like protection where possible. | The server has no business holding private keys. Decentralized identity means the user controls their own key material. |
| **Public key** | Already on the server (in the registry as part of the DID). Also stored in browser `localStorage` for convenience. | Public keys are not secrets — they're published by design. |
| **DID identifier** | Already on the server (registry). Also in browser `localStorage`. | DIDs are public identifiers, like email addresses. |

The signing flow is entirely client-side:
```
User's browser (IndexedDB private key)
  → WebCrypto signs "{did}\n{timestamp}"
  → sends only the signature + DID + timestamp to server
  → server resolves DID → gets public key from registry
  → server verifies signature
  → server NEVER receives the private key
```

This is the same model as SSH key auth, GPG signing, or hardware security keys — the private key never leaves the device.

## What To Change

### 1. Replace AuthState with DID identity state

**File:** `auths-site/apps/web/src/lib/auth/auth-context.tsx`

Replace the `token`-based state with a DID + public key reference:

```typescript
interface AuthState {
  did: string;
  publicKeyHex: string;
  // Private key is in IndexedDB on the user's device — NOT here, NOT on the server
}
```

The auth context should:
- Store DID + public key reference (not a session token). These are both public information — safe for `localStorage`.
- Persist to `localStorage` so users stay logged in across page reloads
- Provide a `signRequest(data: string): Promise<string>` function that retrieves the private key **from the user's local IndexedDB** and signs via WebCrypto
- Load persisted identity on initialization

### 2. Add WebCrypto signing utility (client-side only)

**File:** `auths-site/apps/web/src/lib/auth/signing.ts` (new)

Create a utility module for **client-side-only** key operations. None of these functions communicate with the server:

- `generateKeypair()`: Ed25519 via `crypto.subtle.generateKey()` — key is generated in the browser
- `storePrivateKey(did, key)`: Save CryptoKey to **the user's local IndexedDB** (not the server)
- `loadPrivateKey(did)`: Retrieve CryptoKey from **the user's local IndexedDB**
- `signData(did, data)`: Load key from local IndexedDB + sign + return hex. The signature (not the key) is what gets sent to the server.
- `exportPublicKeyHex(publicKey)`: Export raw Ed25519 public key as hex

IndexedDB is a browser-local database — it lives on the user's machine, like cookies or localStorage, but supports storing non-extractable CryptoKey objects that can't even be read by JavaScript.

### 3. Replace registryFetchAuth token pattern with per-request signing

**File:** `auths-site/apps/web/src/lib/api/registry.ts`

Replace the `token` parameter on every function with automatic per-request signing. Each request gets a fresh signature (signed client-side, verified server-side):

```typescript
async function registryFetchAuth<T>(path: string, options: { ... }): Promise<T> {
  const { auth, signRequest } = getAuthContext();
  if (auth) {
    const timestamp = new Date().toISOString();
    // signRequest uses WebCrypto locally — private key never leaves the browser
    const signature = await signRequest(`${auth.did}\n${timestamp}`);
    const payload = JSON.stringify({ did: auth.did, timestamp, signature });
    headers.Authorization = `Bearer ${payload}`;
  }
  // ... rest unchanged
}
```

Remove the `token` parameter from every function that currently accepts it:
- `createOrg(name, token, signal)` → `createOrg(name, signal)`
- `fetchOrgStatus(orgDid, token, signal)` → `fetchOrgStatus(orgDid, signal)`
- `createInvite(orgDid, role, expiresIn, token, signal)` → `createInvite(orgDid, role, expiresIn, signal)`
- `setOrgPolicy(orgDid, requireSigning, token, signal)` → `setOrgPolicy(orgDid, requireSigning, signal)`
- All other `*Auth*` functions

### 4. Update challenge-auth flow to store keypair locally, not server token

**File:** `auths-site/apps/web/src/components/challenge-auth.tsx`

The challenge-response flow currently proves the user controls a DID. After verification:

- **Current**: stores `{ token: uuid, did, expiresAt }` — the proof is a server-side session token
- **New**: stores `{ did, publicKeyHex }` in localStorage and the user's signing key in their local IndexedDB — the proof is the key itself, held on their device

Two onboarding paths:
1. **CLI users** (existing flow): Complete challenge-response, then the frontend needs the user's key in the browser. Options: (a) generate a browser-specific device key in the browser and have the CLI attest it, or (b) export the key from CLI and import to browser IndexedDB.
2. **Web-native users** (new flow): Generate Ed25519 keypair via WebCrypto in the browser, register the public key with `POST /v1/identities`, store private key in the user's local IndexedDB. The private key never touches the server.

### 5. Update all consuming components

Every component that currently reads `auth.token` and passes it to API functions needs updating. Search for all occurrences of:
- `auth?.token`
- `auth.token`
- `token: string` in function signatures that come from auth context
- `useAuth()` destructuring that reads `token`

## What NOT To Change

- **Backend registry server middleware**: `identity_auth.rs` already supports `BearerPayload` signature validation. No changes needed. The server already knows how to verify signatures against DID-resolved public keys.
- **Backend auth server**: Keep it functional for the CLI challenge-response proof flow. The auth server still serves a purpose — it's how users prove DID ownership during onboarding. But its session token is no longer used for subsequent API requests.
- **Public (unauthenticated) API functions**: `registryFetch()` (without Auth) stays the same.
- **React Query hooks**: The hooks themselves don't change shape — only the underlying fetch functions lose their `token` parameter.

## Constraints

- Ed25519 WebCrypto support: Available in all modern browsers (Chrome 113+, Firefox 127+, Safari 17+). Use feature detection with a fallback message.
- IndexedDB for private key storage: This is a standard browser API for client-side storage (like localStorage but supports CryptoKey objects). WebCrypto's `extractable: false` option means the private key can be used for signing but cannot be exported or read — even by the page's own JavaScript.
- Clock skew: The `timestamp` in `BearerPayload` will be validated server-side. Ensure the server allows reasonable skew (e.g., ±5 minutes).
- The `validate_signed_challenge` function in the registry server may need review to confirm it handles the exact `BearerPayload` format. Read it carefully before assuming it works as-is.

## Definition of Done

1. No function in `registry.ts` accepts a `token: string` parameter for auth purposes
2. `AuthState` contains `{ did, publicKeyHex }` — no `token` field
3. Auth state persists across page reloads (`localStorage` for DID + publicKey, browser-local IndexedDB for private key)
4. Every authenticated request sends `Authorization: Bearer <signed-payload-json>` — not a UUID
5. The auth server session token is no longer stored or used after the initial challenge-response proof
6. All existing authenticated features (org creation, invites, policy management) continue to work
7. **The server never receives, stores, or has access to any user's private key**
