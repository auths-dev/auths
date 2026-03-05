# fn-4.4 Define cross-repo API contract for heartwood identity endpoints

## Description
## Define cross-repo API contract for heartwood identity endpoints

Create a specification document defining the exact JSON schemas that heartwood's radicle-httpd must implement for the frontend identity unification to work. This is a spec-only task — no code changes.

### What to do

1. Create `.flow/specs/fn-4.4-api-contract.md` with:

2. Define 3 endpoint schemas:

   **GET /v1/users/:did (extended)**
   - Input: `did:key:z6Mk...` or `did:keri:E...`
   - Response adds: `controller_did: string | null`, `is_keri: boolean`, `devices: DeviceInfo[]`
   - `DeviceInfo`: `{ did: string, status: "active" | "revoked", linked_at: string }`

   **GET /v1/identity/:did/kel**
   - Input: `did:keri:E...` prefix
   - **BRUTAL CLARITY**: Response MUST be the **raw JSON events** exactly as they appear in the Git blobs. NO re-serialization. NO whitespace/ordering changes. SAIDs will break if node "fixes" the JSON.
   - Response: JSON array of KEL events matching `KeriEvent` format from `auths-verifier/src/keri.rs`
   - Must match what `parse_kel_json()` accepts (fields: v, t, d, i, s, kt, k, nt, n, bt, b, a, p, x)
   - Content-Type: `application/json`

   **GET /v1/identity/:did/attestations**
   - Input: `did:key:z6Mk...` device DID
   - Response: JSON array of attestations matching `Attestation` struct from `auths-verifier/src/core.rs:332-363`
   - Fields: version, rid, issuer, subject, device_public_key, identity_signature, device_signature, capabilities, expires_at, etc.
   - Hex-encoded signatures (matching `serde(with = "hex::serde")`)

3. Document error responses (404, 400, 500 patterns)

4. Document the ref layout heartwood must read from:
   - KEL: `refs/keri/kel` (per `auths-radicle/src/refs.rs:45`)
   - **STRICT**: Follow `refs/keys/<nid>/signatures/` (per `refs.rs` helpers) exactly.
   - Attestations: `refs/keys/<did-key>/signatures/<did-keri>/` (per refs.rs helpers)

5. List open questions that heartwood team must answer:
   - Is `find_identity_for_device` scoped per project or global?
   - How does revocation propagate from auths CLI to the node?
   - Where does profile metadata (name/bio) live?

### Key references
- Existing radicle-httpd API: `GET /api/v1/repos`, `GET /api/v1/delegates/:did/repos` (axum-based)
- `Attestation` struct: `crates/auths-verifier/src/core.rs:332-363`
- KEL event types: `crates/auths-verifier/src/keri.rs:352-444`
- Ref layout: `crates/auths-radicle/src/refs.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] API contract spec exists in `.flow/specs/fn-4.4-api-contract.md`
- [ ] All 3 endpoints defined with request/response JSON schemas
- [ ] KEL event schema matches what `parse_kel_json()` accepts
- [ ] Attestation schema matches the `Attestation` struct serialization (hex-encoded sigs)
- [ ] Error response patterns documented
- [ ] Git ref layout documented for heartwood consumption
- [ ] Open questions listed for heartwood team
## Done summary
- Created API contract spec at .flow/specs/fn-4.4-api-contract.md
- Defined JSON schemas for 3 endpoints: GET /v1/identity/:did/kel, GET /v1/identity/:did/attestations, GET /v1/users/:did
- Documented field encodings (hex for signatures, base64url for keys, RFC 3339 for timestamps)
- Documented Git ref paths for data storage
- Listed 5 open questions for implementing nodes

- Schemas derived directly from auths-verifier Rust types to ensure compatibility
- Contract is implementation-agnostic — works with radicle-httpd or any HTTP server
## Evidence
- Commits:
- Tests:
- PRs:
