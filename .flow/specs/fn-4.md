# Frontend Identity Unification (did:keri) — auths repo

## Overview

Prepare the auths WASM verifier and TypeScript wrapper so the Radicle frontend can verify `did:keri` → `did:key` device links client-side. Phase 1.1 (`resolve_keri`) is already complete. This epic covers the remaining auths-repo work: new WASM bindings, TS wrapper updates, cross-repo API contract definition, and E2E test updates.

## Scope

**In scope (this repo):**
- New WASM binding: `verifyKelJson` — stateless KEL replay and validation
- New WASM binding: `verifyDeviceLink` — composed KEL verification + attestation + seal anchoring
- Update `auths-verifier-ts` with new TS exports, types, and tests
- Cross-repo API contract spec (JSON schema for heartwood endpoints)
- E2E script updates for controller_did assertions
- WASM binary size audit after new bindings

**Out of scope (separate repos/epics):**
- Heartwood API changes (Phase 2 — `radicle-httpd`)
- Svelte UI changes (Phase 3 — `radicle.xyz`)
- Profile metadata storage (name/bio/avatar — requires design decision)

## Approach

### WASM Bindings
Build on existing patterns in `crates/auths-verifier/src/wasm.rs`. Reuse:
- `verify_kel()` at `keri.rs:495` (async, stateless KEL verification)
- `parse_kel_json()` at `keri.rs:720` (JSON → Vec<KeriEvent>)
- `find_seal_in_kel()` at `keri.rs:706` (seal anchoring check)
- Existing `provider()` helper for `CryptoProvider`
- `console_log!` macro, JSON size validation pattern

New `verifyDeviceLink` composes: (1) parse + verify KEL → KeriKeyState, (2) parse attestation, (3) verify attestation signatures against KEL-derived key, (4) check seal anchoring in KEL, (5) check revocation/expiry.

### TS Wrapper
Follow existing pattern in `packages/auths-verifier-ts/src/index.ts`:
- Dynamic WASM import via `wasm.default()`
- JSON string crossing the FFI boundary (not serde-wasm-bindgen)
- Types in `types.ts`

### API Contract
Define the JSON schemas that heartwood must implement:
- `GET /v1/identity/:did/kel` response format
- `GET /v1/identity/:did/attestations` response format
- `GET /v1/users/:did` extended response with `controller_did`
Schemas must match what the WASM verifier accepts as input.

## Quick Commands

```bash
# Smoke test: WASM compilation check
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# Run verifier tests
cargo nextest run -p auths_verifier

# Run TS wrapper tests
cd packages/auths-verifier-ts && npm test

# Full workspace check
cargo clippy --all-targets --all-features -- -D warnings
```

## Acceptance

- [ ] `verifyKelJson` WASM binding compiles and passes unit tests
- [ ] `verifyDeviceLink` WASM binding compiles and passes unit tests
- [ ] `auths-verifier-ts` exports `verifyKel()` and `verifyDeviceLink()` with full TS types
- [ ] WASM target compiles: `cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] API contract spec exists with JSON schemas for all 3 heartwood endpoints
- [ ] E2E script has controller_did assertion after device linking
- [ ] WASM binary size is measured and documented (baseline + delta)
- [ ] All existing tests still pass

## Open Questions

1. **Profile metadata**: Where does name/bio/avatar live? KERI events don't carry it. Needs design decision before heartwood/frontend work.
2. **Trust anchor for controller_did**: If the same API serves both `controller_did` and KEL, verification is circular. Need OOBI or out-of-band trust path.
3. **`find_identity_for_device` scope**: Project-scoped (per repo_id) or global? Plan's API endpoint `GET /users/:did` has no repo_id param.
4. **Revocation propagation**: Mechanism for revocation flowing from auths CLI → heartwood node → frontend is unspecified.
5. **Stale KEL on client**: No equivalent of `min_kel_seq` for client-side WASM verification. Risk of verifying against old key state.

## References

- Plan doc: `docs/plans/frontend_identity_unification.md`
- Existing WASM bindings: `crates/auths-verifier/src/wasm.rs`
- KEL verification: `crates/auths-verifier/src/keri.rs:495-519`
- KEL JSON parsing: `crates/auths-verifier/src/keri.rs:720`
- Seal finder: `crates/auths-verifier/src/keri.rs:706`
- TS wrapper: `packages/auths-verifier-ts/src/index.ts`
- Bridge trait: `crates/auths-radicle/src/bridge.rs:191-229`
- Ref layout: `crates/auths-radicle/src/refs.rs`
- E2E script: `scripts/radicle-e2e.sh`
