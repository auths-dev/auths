# fn-5.13 Extend parseNodeId/formatNodeId and route types for did:keri

## Description
## Extend parseNodeId/formatNodeId and route types for did:keri

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer`

### Context
`parseNodeId()` at `src/lib/utils.ts:16-37` uses regex `/^(did:key:)?(z[a-zA-Z0-9]+)$/` which rejects `did:keri:E...`. `formatNodeId()` at line 55 only handles `did:key` formatting. `UserRoute` and `UserLoadedRoute` types carry `did: { prefix: string; pubkey: string }` which doesn't fit KERI DIDs.

### What to do
1. Extend `parseNodeId()` to handle both formats:
   - `did:key:z6Mk...` → `{ type: 'key', prefix: 'did:key', pubkey: 'z6Mk...' }`
   - `did:keri:EXq5...` → `{ type: 'keri', prefix: 'did:keri', id: 'EXq5...' }`
2. Update the return type to a union or extended interface
3. Extend `formatNodeId()` to display KERI DIDs (truncated `EXq5...` format)
4. Update `UserRoute` and `UserLoadedRoute` types to accommodate KERI DID shape
5. Update `loadUserRoute()` to handle KERI DIDs — it currently calls `api.getNodeIdentity(parsedDid.pubkey)` which won't work for KERI
6. Consider the Avatar component: `blockies.ts` seeds from key bytes — KERI prefix needs a different seed

### Key files
- `src/lib/utils.ts:16-37` — parseNodeId
- `src/lib/utils.ts:55` — formatNodeId
- `src/views/users/router.ts:11-75` — UserRoute, UserLoadedRoute, loadUserRoute
- `src/components/Avatar.svelte` — takes nodeId prop
- `src/lib/blockies.ts` — avatar generation
- `http-client/lib/shared.ts:122-125` — authorSchema (Zod)
## Acceptance
- [ ] `parseNodeId("did:keri:EXq5...")` succeeds (no "Invalid user DID" error)
- [ ] `parseNodeId("did:key:z6Mk...")` still works (no regression)
- [ ] `formatNodeId()` displays KERI DIDs in a readable truncated format
- [ ] `UserRoute`/`UserLoadedRoute` types accommodate both DID types
- [ ] `loadUserRoute()` can load KERI identity profiles
## Done summary
- Extended `parseNodeId` to handle `did:keri:E...` format (new regex branch)
- Added `ParsedDid` union type with `type: "key" | "keri"` discriminator
- Kept `{ prefix, pubkey }` shape for backwards compatibility — `pubkey` holds the KERI prefix for did:keri
- Updated `UserLoadedRoute.did` type to use `ParsedDid`
- Updated `loadUserRoute` to pass full DID string for KERI identities

Why:
- Without this, navigating to a `did:keri` user profile shows "Invalid user DID" error

Verification:
- All existing `.pubkey` accesses remain valid
- Both `did:key:z6Mk...` and `did:keri:E...` are parseable
## Evidence
- Commits: 9838335dd0b4f30fbc9b7070cf9ec0ada88c11ad
- Tests: code review
- PRs:
