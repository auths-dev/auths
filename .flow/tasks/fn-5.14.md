# fn-5.14 Add HttpdClient methods for delegates and identity endpoints

## Description
## Add HttpdClient methods for delegates and identity endpoints

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer`

### Context
`HttpdClient` at `http-client/index.ts:157-270` has no method to call `GET /delegates/{did}`, `GET /identity/{did}/kel`, or `GET /identity/{did}/attestations`. Currently only `getByDelegate()` exists, which calls `/delegates/{did}/repos`.

The client uses `Fetcher` with Zod schema validation — new methods must follow this pattern.

### What to do
1. Add Zod schemas for API responses:
   - `UserResponse`: `{ did, controllerDid?, isKeri, devices[] }` (camelCase from API)
   - `KelEvent[]`: Array of KEL event objects
   - `Attestation[]`: Array of attestation objects
2. Add methods to `HttpdClient`:
   - `getUser(did: string): Promise<UserResponse>` → `GET /delegates/{did}`
   - `getIdentityKel(did: string): Promise<KelEvent[]>` → `GET /identity/{did}/kel`
   - `getIdentityAttestations(did: string): Promise<Attestation[]>` → `GET /identity/{did}/attestations`
3. Follow existing `Fetcher` pattern: `this.fetcher.fetchOk(...)` with `.then(resp => resp.json()).then(schema.parse)`

### Key files
- `http-client/index.ts:157-270` — HttpdClient class
- `http-client/lib/fetcher.ts:103-180` — Fetcher class with Zod validation
- `http-client/lib/shared.ts` — shared Zod schemas
- `radicle-httpd/src/api/v1/delegates.rs` — UserResponse shape (API side)
- `radicle-httpd/src/api/v1/identity.rs` — KEL/attestation response shapes
## Acceptance
- [ ] `getUser(did)` method added to `HttpdClient`
- [ ] `getIdentityKel(did)` method added
- [ ] `getIdentityAttestations(did)` method added
- [ ] All methods use Zod schema validation
- [ ] Response types match radicle-httpd API output (camelCase)
## Done summary
- Added Zod schemas: `userResponseSchema` (camelCase), `kelEventSchema`, `attestationSchema`
- Added `getUser(did)` → `GET /delegates/{did}`
- Added `getIdentityKel(did)` → `GET /identity/{did}/kel`
- Added `getIdentityAttestations(did)` → `GET /identity/{did}/attestations`
- Exported `UserResponse`, `KelEvent`, `ApiAttestation` types

Why:
- Frontend needs typed HTTP client methods for the new identity endpoints
- Zod validation ensures runtime type safety at the API boundary

Verification:
- Code follows existing Fetcher pattern (same as getNodeIdentity, getStats, etc.)
## Evidence
- Commits: 11cbeae12a7b5bf65c8ea871f25a8dfa2f84eae1
- Tests: code review
- PRs:
