# fn-5.10 Implement GET /v1/identity/:did/attestations with 2-blob resolution

## Description
## Implement GET /v1/identity/:did/attestations with 2-blob resolution

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/identity.rs`

### Design Principle
The 2-blob attestation storage format (did-key blob + did-keri blob per device under RIP-X refs) is a Radicle implementation detail. **This endpoint is the correct place to hide that complexity** — the frontend must receive clean JSON attestation objects, never touching raw Git data or knowing about the blob structure.

### Context
`attestations_handler` at line 34-39 is a stub returning empty `Vec<String>`. Attestation data lives in Git as 2 separate blobs per device under RIP-X refs.

The `RadicleAuthsBridge` trait has `list_devices()` and the storage module has `load_attestation()` — these need to be composed into an API response.

### What to do
1. Use `RadicleIdentityResolver` to list all attested devices for the given DID
2. For each device, load the attestation blobs and compose them into the JSON `Attestation` format expected by `wasm_verify_device_link`
3. Return as JSON array of attestation objects — clean, structured, no Git internals exposed
4. Add proper error handling using the `IdentityError` variant
5. Document the response schema in a code comment

### Key files
- `radicle-httpd/src/api/v1/identity.rs:34-39` — attestations_handler stub
- `auths-radicle/src/storage.rs` — `list_devices()`, `load_attestation()`
- `auths-radicle/src/bridge.rs:193-232` — `RadicleAuthsBridge` trait
- `auths-verifier/src/wasm.rs:395` — expected `attestation_json` input format
- `packages/auths-verifier-ts/src/types.ts` — `Attestation` TypeScript interface
## Implement GET /v1/identity/:did/attestations with 2-blob resolution

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/identity.rs`

### Context
`attestations_handler` at line 34-39 is a stub returning empty `Vec<String>`. Attestation data lives in Git as 2 separate blobs per device (did-key blob + did-keri blob) under RIP-X refs.

The `RadicleAuthsBridge` trait has `list_devices()` and the storage module has `load_attestation()` — these need to be composed into an API response.

### What to do
1. Use `RadicleIdentityResolver` to list all attested devices for the given DID
2. For each device, load the attestation blobs and compose them into the JSON `Attestation` format expected by `wasm_verify_device_link`
3. Return as JSON array of attestation objects
4. Add proper error handling using the `IdentityError` variant
5. Document the response schema in a code comment

### Key files
- `radicle-httpd/src/api/v1/identity.rs:34-39` — attestations_handler stub
- `auths-radicle/src/storage.rs` — `list_devices()`, `load_attestation()`
- `auths-radicle/src/bridge.rs:193-232` — `RadicleAuthsBridge` trait
- `auths-verifier/src/wasm.rs:395` — expected `attestation_json` input format
- `packages/auths-verifier-ts/src/types.ts` — `Attestation` TypeScript interface
## Acceptance
- [ ] Returns actual attestation data (not empty array)
- [ ] Attestation JSON format matches what `verifyDeviceLink()` WASM expects
- [ ] Each attestation includes device DID, identity DID, and signature data
- [ ] Proper error handling for missing/corrupt attestations
- [ ] Unknown DID returns 404
## Done summary
- Implemented `attestations_handler` using `GitRadicleStorage` for 2-blob resolution
- Lists devices via `list_devices()`, loads attestation per device via `load_attestation()`
- Returns clean JSON attestation objects matching WASM `Attestation` interface
- Git 2-blob complexity fully hidden from frontend

Why:
- Frontend must receive clean attestation JSON, never touching raw Git data
- Format matches what `verifyDeviceLink()` WASM expects

Verification:
- `cargo build` shows only pre-existing auths-verifier edition errors
## Evidence
- Commits: fb105fcd7d05834eddd6beaa841be023b0458054
- Tests: cargo build (radicle-httpd)
- PRs:
