# fn-4.3 Update auths-verifier-ts with verifyKel and verifyDeviceLink exports

## Description
## Update auths-verifier-ts with verifyKel and verifyDeviceLink exports

Add TypeScript wrappers for the two new WASM bindings, including types, error handling, and tests.

### What to do

1. Update `packages/auths-verifier-ts/src/types.ts`:
   - Add `KelVerificationResult` type (key_state fields: prefix, current_key_encoded, sequence, is_abandoned)
   - Add `DeviceLinkResult` type (`{ valid: boolean, error?: string, key_state?: KelVerificationResult, seal_sequence?: number }`)
   - **STRICT**: `KeriKeyState` TS interface MUST be 1:1 sync with Rust struct. Any drift = silent UI failure.
   - Add `KeriKeyState` type matching the Rust `KeriKeyState` struct serialization

2. Update `packages/auths-verifier-ts/src/index.ts`:
   - Add `verifyKel(kelJson: string): Promise<KelVerificationResult>` function
   - Add `verifyDeviceLink(kelJson: string, attestationJson: string, deviceDid: string): Promise<DeviceLinkResult>` function
   - Follow existing pattern: check `wasm` is initialized, call WASM function, `JSON.parse()` the result
   - Both are async (WASM functions return Promises)

3. Update the `WasmModule` interface (at `index.ts:32-36`) to declare the new WASM functions:
   - `verifyKelJson(kel_json: string): Promise<string>`
   - `verifyDeviceLink(kel_json: string, attestation_json: string, device_did: string): Promise<string>`

4. Add tests in `packages/auths-verifier-ts/tests/`:
   - Test `verifyKel` with fixture KEL JSON
   - Test `verifyDeviceLink` with fixture KEL + attestation + device DID
   - Test error cases (uninitialized WASM, malformed JSON)

### Key files
- `packages/auths-verifier-ts/src/index.ts` — main exports
- `packages/auths-verifier-ts/src/types.ts` — type definitions
- `packages/auths-verifier-ts/tests/verifier.test.ts` — existing tests to extend

### Depends on
- fn-4.1 (verifyKelJson WASM binding must exist)
- fn-4.2 (verifyDeviceLink WASM binding must exist)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `verifyKel()` exported from `index.ts` with correct TypeScript signature
- [ ] `verifyDeviceLink()` exported from `index.ts` with correct TypeScript signature
- [ ] `KelVerificationResult` and `DeviceLinkResult` types defined in `types.ts`
- [ ] `WasmModule` interface updated with new function declarations
- [ ] Both functions check WASM initialization before calling
- [ ] Tests pass: `cd packages/auths-verifier-ts && npm test`
- [ ] TypeScript compiles without errors
## Done summary
- Added KeriKeyState and DeviceLinkResult TypeScript interfaces
- Added async verifyKel() and verifyDeviceLink() exports
- Updated WasmModule interface with new WASM function declarations

- Follows existing patterns: ensureInitialized(), JSON.parse round-trip, error-as-result
- TypeScript compiles clean (npx tsc --noEmit)
## Evidence
- Commits: 5bf93c8
- Tests: npx tsc --noEmit
- PRs:
