# Login Spec — Browser Auth + Org Flow

## Goal

Make the full org lifecycle work on the web:
1. `/try` asks if the user has an identity
2. CLI user proves ownership via challenge-response → browser becomes a delegated device
3. User creates an org
4. User views org settings as admin
5. User logs out

## What the Login Demo Proved

The standalone test harness at `/Users/bordumb/workspace/repositories/auths-base/auths-login-demo` validated:

- **WebCrypto Ed25519 works**: `crypto.subtle.generateKey('Ed25519')` generates keypairs in-browser
- **IndexedDB stores keys**: Private keys persist across page reloads, never leave the device
- **BearerPayload signing works**: Browser signs `"{did}\n{timestamp}"`, base64-encodes the signature, sends `Authorization: Bearer {"did":"...","timestamp":"...","signature":"..."}` — the registry middleware validates it without any roundtrip to the auth server
- **Auth gates work**: `POST /v1/orgs` returns 401 for anonymous, accepts authenticated requests

The demo used a shortcut (seeding identity directly into Postgres). The real flow needs the browser to become a proper delegated device.

## Architecture Decision: Browser as Device

The browser is treated as another **device** in the Auths model — same as an iPhone or a second laptop. It gets its own Ed25519 keypair, its own attestation from the controller identity, and can be revoked independently.

This reuses existing infrastructure:
- Pairing protocol (`POST /v1/pairing/sessions`)
- Device attestation (`Attestation` struct with capabilities, expiry, revocation)
- Device lookup (`GET /v1/devices/{did}`)

The browser's device key is what signs API requests. The controller identity's key stays in the platform keychain — it never touches the browser.

## User Journey

### Step 1: `/try` — "Do you have an identity?"

**Current state**: The `/try` page shows two buttons: "Individuals" and "Organizations". Both flows start from scratch.

**New state**: Before showing flow options, check if the user has a browser device key in IndexedDB.

```
┌─ Browser has device key in IndexedDB?
│
├─ YES → Load DID + device key → Show authenticated state
│        → Skip to org flow (create org, view settings, etc.)
│
└─ NO → "Do you already have an Auths identity?"
         │
         ├─ "Yes, I use auths-cli" → Browser Device Pairing flow (Step 2)
         │
         └─ "No, I'm new" → Individual flow (existing, unchanged)
```

### Step 2: Browser Device Pairing (CLI users)

This is the core new flow. The user has an identity via `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-cli` and wants to use the website.

```
┌─────────────────────────────────────────────────────────┐
│  Browser                         CLI                    │
│                                                         │
│  1. Generate Ed25519 keypair                            │
│     (WebCrypto, extractable:false)                      │
│     Store private key in IndexedDB                      │
│     Derive did:key:z6Mk... from public key              │
│                                                         │
│  2. Create pairing session                              │
│     POST /v1/pairing/sessions                           │
│     {                                                   │
│       session_id: <uuid>,                               │
│       controller_did: "",  ← filled by CLI              │
│       ephemeral_pubkey: <browser X25519>,                │
│       short_code: <6-char>,                             │
│       capabilities: ["sign_commit", "manage_members"],  │
│       expires_at: <now + 5min>                          │
│     }                                                   │
│     → Gets back session_id + short_code                 │
│                                                         │
│  3. Display to user:                                    │
│     "Run this command in your terminal:"                │
│     auths device pair --code <SHORT_CODE> \             │
│       --registry http://localhost:3100                   │
│                                                         │
│                                  4. CLI fetches session  │
│                                     by short code       │
│                                  5. CLI signs device key │
│                                     with identity key   │
│                                  6. CLI submits response │
│                                     with attestation    │
│                                                         │
│  7. Poll session status (or WebSocket)                  │
│     GET /v1/pairing/sessions/{id}                       │
│     Wait for status: "Completed"                        │
│                                                         │
│  8. Store auth state:                                   │
│     localStorage: { did: <controller_did>,              │
│                     deviceDid: <browser_device_did>,     │
│                     publicKeyHex: <browser_pubkey> }     │
│     IndexedDB: browser device private key               │
│                                                         │
│  9. All subsequent requests signed with browser         │
│     device key via BearerPayload                        │
└─────────────────────────────────────────────────────────┘
```

**Key detail**: The browser signs requests with its own device key (`did:key:z6Mk...`), but the `did` field in the BearerPayload is the **controller identity DID** (`did:keri:...`). The registry middleware resolves the controller DID, finds the browser's device key in the attestation chain, and validates the signature.

**Open question**: The current `validate_signed_challenge` in `identity_auth.rs` resolves the DID from `identity_state.current_keys` — these are the controller's keys, not device keys. The middleware may need to also check `device_bindings` for the signing key. Review `identity_auth.rs` to confirm whether device key signing is already supported or needs a new code path.

### Step 3: Create Org

Once authenticated, the user can create an org. This flow already exists in `auths-site` at `/try/org/org-flow.tsx`.

**Changes needed**: Replace `token` parameter with BearerPayload signing.

```
Current:  createOrg(name, auth.token)
New:      createOrg(name)  ← signing happens inside registryFetchAuth()
```

### Step 4: View Org Settings (Admin)

After creating an org, the user is the admin. Navigate to `/registry/org/{did}`.

**Current state**: The org page at `org-client.tsx` is read-only. It shows:
- Org header with trust tier
- Signing policy (read-only JSON)
- Members (scraped from activity feed — fragile)
- Namespaces
- Recent activity

**Changes needed**:
- Add admin detection: if `auth.did` matches an admin in `org_members`, show edit controls
- Add settings panel: editable signing policy, member management (add/remove/change role)
- Replace audit-feed member scraping with direct `GET /v1/orgs/{orgDid}/members` call
- Gate edit controls on auth state — logged out users see read-only view

### Step 5: Logout

**Current state**: No logout function exists. Auth state is in-memory only and lost on reload.

**New state**: Explicit logout that:
1. Clears `localStorage` (DID, device DID, public key)
2. Deletes private key from IndexedDB
3. Resets React auth context to null
4. Redirects to `/try`

The browser device key is destroyed locally. The attestation on the server side remains (it will expire or can be revoked from the CLI via `auths device revoke`).

Optional: call `DELETE /v1/devices/{browser_device_did}` or a revocation endpoint to invalidate server-side too. This is a nice-to-have — expiry handles it automatically.

---

## Changes Required

### 1. New: Auth Provider with Device Key Signing

**File**: `auths-site/apps/web/src/lib/auth/auth-context.tsx`

Replace token-based auth with device key signing.

```typescript
// Current
interface AuthState {
  token: string;
  did: string;
  expiresAt: string;
}

// New
interface AuthState {
  did: string;           // Controller identity DID (did:keri:...)
  deviceDid: string;     // Browser device DID (did:key:z6Mk...)
  publicKeyHex: string;  // Browser device public key
}

interface AuthContextValue {
  auth: AuthState | null;
  setAuth: (state: AuthState) => void;
  clearAuth: () => void;             // Logout: clear localStorage + IndexedDB
  isAuthenticated: boolean;
  signRequest: (data: string) => Promise<string>;  // Sign with device key
}
```

Persistence:
- `AuthState` → `localStorage` (all fields are public info)
- Device private key → `IndexedDB` (via WebCrypto, `extractable: false`)
- On init: load from `localStorage`, validate device key exists in IndexedDB

### 2. New: WebCrypto Signing Module

**File**: `auths-site/apps/web/src/lib/auth/signing.ts` (new)

Port from `auths-login-demo/src/crypto.ts`:

```typescript
export async function generateKeypair(): Promise<CryptoKeyPair>
export async function exportPublicKeyHex(publicKey: CryptoKey): Promise<string>
export async function storePrivateKey(deviceDid: string, key: CryptoKey): Promise<void>
export async function loadPrivateKey(deviceDid: string): Promise<CryptoKey>
export async function signData(privateKey: CryptoKey, data: string): Promise<string>
export async function deletePrivateKey(deviceDid: string): Promise<void>
export function deriveDeviceDid(publicKeyHex: string): string  // did:key:z6Mk... encoding
```

### 3. Modify: API Client — Remove Token, Add Signing

**File**: `auths-site/apps/web/src/lib/api/registry.ts`

```typescript
// Current
async function registryFetchAuth<T>(path, { token, ... }): Promise<T> {
  headers.Authorization = `Bearer ${token}`;
}

// New
async function registryFetchAuth<T>(path, { signal, ... }): Promise<T> {
  const { auth, signRequest } = getAuthFromContext();
  if (auth) {
    const timestamp = new Date().toISOString();
    const signature = await signRequest(`${auth.did}\n${timestamp}`);
    const payload = JSON.stringify({
      did: auth.did,
      timestamp,
      signature,
    });
    headers.Authorization = `Bearer ${payload}`;
  }
}
```

Remove `token` parameter from all functions:
- `createOrg(name, token)` → `createOrg(name)`
- `fetchOrgStatus(orgDid, token)` → `fetchOrgStatus(orgDid)`
- `createInvite(orgDid, role, expiresIn, token)` → `createInvite(orgDid, role, expiresIn)`
- `setOrgPolicy(orgDid, requireSigning, token)` → `setOrgPolicy(orgDid, requireSigning)`

### 4. New: Browser Pairing Component

**File**: `auths-site/apps/web/src/components/browser-pairing.tsx` (new)

Replaces `challenge-auth.tsx` for CLI users. Steps:

1. Generate browser device keypair (WebCrypto)
2. Create pairing session (`POST /v1/pairing/sessions`)
3. Show CLI command with short code
4. Poll session status (or connect via WebSocket at `/v1/pairing/sessions/{id}/ws`)
5. On completion: extract controller DID from session, store auth state
6. Call `setAuth({ did: controllerDid, deviceDid, publicKeyHex })`

### 5. Modify: `/try` Page — Identity Check

**File**: `auths-site/apps/web/src/app/try/try-client.tsx`

Add identity detection before showing flow options:

```typescript
// On mount: check localStorage for existing auth
const { auth, isAuthenticated } = useAuth();

if (isAuthenticated) {
  // Already paired — show org flow directly
  return <OrgFlow />;
}

// Not authenticated — ask
return (
  <div>
    <h2>Do you already have an Auths identity?</h2>
    <button onClick={() => setFlow('pair')}>
      Yes, I use auths-cli
    </button>
    <button onClick={() => setFlow('individual')}>
      No, I'm new
    </button>
  </div>
);
```

When `flow === 'pair'`: render `<BrowserPairing />` instead of `<ChallengeAuth />`.

### 6. Modify: Org Detail Page — Admin Controls

**File**: `auths-site/apps/web/src/app/registry/org/[did]/org-client.tsx`

Add admin detection and edit controls:

```typescript
const { auth } = useAuth();
const { data: members } = useOrgMembers(orgDid);

const currentUserRole = members?.find(m => m.member_did === auth?.did)?.role;
const isAdmin = currentUserRole === 'admin';

// In render:
{isAdmin && <OrgSettingsPanel orgDid={orgDid} />}
```

`OrgSettingsPanel` includes:
- Edit signing policy (`setOrgPolicy`)
- Member management table with add/remove/change role
- Invite generation

### 7. New: Logout

**File**: `auths-site/apps/web/src/components/logout-button.tsx` (new)

```typescript
function LogoutButton() {
  const { clearAuth, auth } = useAuth();

  const handleLogout = async () => {
    if (auth) {
      await deletePrivateKey(auth.deviceDid);
    }
    clearAuth();  // Clears localStorage + React state
    window.location.href = '/try';
  };

  return <button onClick={handleLogout}>Log out</button>;
}
```

Add to site nav (`components/site-nav.tsx`) when authenticated.

---

## Backend Changes

### Registry Middleware — Device Key Resolution

**File**: `auths-cloud/crates/auths-registry-server/src/middleware/identity_auth.rs`

**Open question to verify**: The current `validate_signed_challenge` resolves the signing key from `identity_state.current_keys` — these are the controller's KERI keys. When the browser signs with its device key, the middleware needs to:

1. Receive BearerPayload with `did: "did:keri:..."` and a signature from the browser device key
2. Look up `identity_state.current_keys` for `did:keri:...` → these are the controller keys, NOT the device key
3. Signature verification fails because the signing key doesn't match

**Two possible fixes**:

**Option A — Use device DID in BearerPayload**:
```json
{
  "did": "did:key:z6Mk...",
  "timestamp": "...",
  "signature": "..."
}
```
The middleware resolves the device DID → finds the attestation → gets the controller DID → authenticates as the controller. This requires `identity_auth.rs` to handle `did:key:` lookups in addition to `did:keri:`.

**Option B — Add device_did field to BearerPayload**:
```json
{
  "did": "did:keri:...",
  "device_did": "did:key:z6Mk...",
  "timestamp": "...",
  "signature": "..."
}
```
The middleware receives both. It looks up the device attestation to confirm `device_did` is attested by `did`, then verifies the signature against the device's public key.

**Recommendation**: Option B — it's explicit, doesn't break existing `did:keri:` flows, and maps cleanly to the attestation model. The middleware change is additive.

```rust
#[derive(Deserialize)]
struct BearerPayload {
    did: String,
    #[serde(default)]
    device_did: Option<String>,  // NEW — optional for backward compat
    timestamp: String,
    signature: String,
}

async fn validate_signed_challenge(
    state: &ServerState,
    payload: BearerPayload,
) -> Result<AuthenticatedIdentity, ApiError> {
    verify_timestamp(&payload.timestamp)?;

    let public_key_bytes = match &payload.device_did {
        Some(device_did) => {
            // Verify device is attested by the controller identity
            let device = lookup_device(pool, device_did).await?;
            if device.issuer != payload.did {
                return Err(ApiError::Unauthorized("device not attested by this identity"));
            }
            if device.revoked_at.is_some() {
                return Err(ApiError::Unauthorized("device attestation revoked"));
            }
            // Use device's public key for signature verification
            resolve_device_public_key(pool, device_did).await?
        }
        None => {
            // Existing path: controller key signing
            resolve_public_key(pool, &payload.did).await?
        }
    };

    verify_signature(&payload, &public_key_bytes)?;
    // ... rest unchanged
}
```

---

## Implementation Order

### Phase 1: Auth Foundation (no backend changes)

1. Port `signing.ts` from login demo → `auths-site`
2. Replace `AuthState` (token → did + deviceDid + publicKeyHex)
3. Add `localStorage` persistence to auth context
4. Add `clearAuth` / logout
5. Modify `registryFetchAuth` to sign with device key instead of passing token

**Test**: Use the login demo's seed approach (bypass pairing, inject key directly) to verify the org flow works with BearerPayload auth end-to-end.

### Phase 2: Browser Pairing

6. Build `BrowserPairing` component (WebCrypto keygen → pairing session → poll → store)
7. Update `/try` page with identity check
8. Test full flow: CLI user → browser pairing → org creation

### Phase 3: Backend — Device Key Auth

9. Add `device_did` field to `BearerPayload`
10. Add device attestation lookup in `validate_signed_challenge`
11. Test: browser device key → BearerPayload → middleware validates via attestation chain

### Phase 4: Org Admin Experience

12. Add admin detection to org detail page
13. Build `OrgSettingsPanel` (policy editor, member management)
14. Replace audit-feed member scraping with direct `GET /v1/orgs/{orgDid}/members`
15. Add `LogoutButton` to site nav

---

## Files Summary

| Action | Path | Description |
|--------|------|-------------|
| **New** | `auths-site/.../lib/auth/signing.ts` | WebCrypto + IndexedDB utilities |
| **Modify** | `auths-site/.../lib/auth/auth-context.tsx` | Token → device key auth state |
| **Modify** | `auths-site/.../lib/api/registry.ts` | Remove token params, add BearerPayload signing |
| **New** | `auths-site/.../components/browser-pairing.tsx` | Browser device pairing UI |
| **New** | `auths-site/.../components/logout-button.tsx` | Logout (clear keys + state) |
| **Modify** | `auths-site/.../app/try/try-client.tsx` | Identity check + flow routing |
| **Modify** | `auths-site/.../app/try/org/org-flow.tsx` | Remove token passing |
| **Modify** | `auths-site/.../app/try/org/create-org-card.tsx` | Remove token passing |
| **Modify** | `auths-site/.../app/try/org/invite-card.tsx` | Remove token passing |
| **Modify** | `auths-site/.../app/try/org/policy-card.tsx` | Remove token passing |
| **Modify** | `auths-site/.../app/try/org/summary-dashboard.tsx` | Remove token passing |
| **Modify** | `auths-site/.../app/registry/org/[did]/org-client.tsx` | Add admin controls |
| **Modify** | `auths-site/.../components/site-nav.tsx` | Add logout button when authenticated |
| **Modify** | `auths-cloud/.../middleware/identity_auth.rs` | Add device_did to BearerPayload |
| **Reference** | `auths-login-demo/src/crypto.ts` | Proven WebCrypto patterns to port |
| **Reference** | `auths-login-demo/src/api.ts` | Proven BearerPayload construction |
