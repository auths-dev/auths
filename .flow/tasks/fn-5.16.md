# fn-5.16 Implement auths.ts helper for local WASM verification

## Description
## Implement auths.ts helper for local WASM verification

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer`

### Context
The frontend needs a helper module that:
1. Fetches KEL and attestation data from the API
2. Initializes the WASM verifier
3. Runs `verifyDeviceLink()` and returns the result for UI display

This should be a standalone module importable by `View.svelte` and any future component that needs verification.

### What to do
1. Create `src/lib/auths.ts` with:
   - `initVerifier()` — lazy WASM initialization (call once, cache the module)
   - `verifyIdentity(baseUrl, did)` — fetches KEL + attestations via `HttpdClient`, runs WASM verification, returns structured result
   - `VerificationResult` type — `{ verified: boolean, devices: DeviceVerification[], error?: string }`
2. Handle WASM init failure gracefully (return `{ verified: false, error: "WASM not available" }`)
3. Handle API failures gracefully (return appropriate error, don't throw)
4. Use dynamic `import()` for WASM inside the init function
5. Wire into `View.svelte` (call `verifyIdentity()` in `onMount` when KERI profile detected)

### Key files
- NEW: `src/lib/auths.ts` — the helper
- `packages/auths-verifier-ts/src/index.ts` — WASM wrapper API
- `packages/auths-verifier-ts/src/types.ts` — TypeScript types
- `http-client/index.ts` — HttpdClient (getIdentityKel, getIdentityAttestations)
- `src/views/users/View.svelte` — consumer
## Acceptance
- [ ] `auths.ts` module created with `initVerifier()` and `verifyIdentity()`
- [ ] WASM initialized lazily (not at import time)
- [ ] WASM init failure returns graceful error (no throw)
- [ ] API failures return structured error (no throw)
- [ ] `verifyIdentity()` called in View.svelte onMount for KERI profiles
- [ ] Verification result drives UI badge state
## Done summary
- Created src/lib/auths.ts with initVerifier() and verifyIdentity()
- Lazy WASM init via dynamic import, cached after first call
- verifyIdentity fetches KEL + attestations, runs verifyDeviceLink per device
- All failures return structured errors, never throw
- Wired into View.svelte: onMount triggers verification for KERI profiles
- Badge shows Verifying/Verified/Unverified state

Verification:
- Code follows existing import patterns (@http-client, @auths/verifier)
- Graceful degradation when WASM unavailable or API fails
## Evidence
- Commits: 0d65747e
- Tests: code review
- PRs:
