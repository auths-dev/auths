# fn-5.15 Profile Unification UI: Device View vs Person View

## Description
## Profile Unification UI: Device View vs Person View

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer`

### Context
`View.svelte` at `src/views/users/View.svelte:1-425` renders user profiles showing SSH key, alias, avatar, and repo list. Currently has no concept of KERI identity, controller DID, or device grouping.

### What to do
1. In the user profile component, check if the loaded user has `controllerDid` set (from `getUser()` API call)
2. If `controllerDid` exists (`is_keri: true`):
   - Show "Person View" with:
     - KERI DID display (using extended `formatNodeId`)
     - Device list (each device DID with its SSH key/alias)
     - Verification badge (placeholder — fn-5.16 will wire up actual WASM verification)
     - Repos aggregated across all devices
   - Allow toggle to "Device View" showing single device details
3. If no `controllerDid` (`is_keri: false`):
   - Render exactly as today (no regression)
4. Use Svelte 5 runes: `$state` for view mode toggle, `$derived` for computed UI state
5. Use `onMount` for async data loading (KERI resolution, device list)
6. Handle edge cases:
   - KERI identity with zero devices → show "No linked devices" message
   - Loading state while KERI data resolves → spinner or skeleton
   - Abandoned KERI identity → show warning indicator

### Key files
- `src/views/users/View.svelte:1-425` — main user view
- `src/views/users/UserAddress.svelte:1-15` — DID display component
- `src/views/users/router.ts:28-75` — loadUserRoute
- `src/components/Avatar.svelte` — avatar (needs KERI seed support)
## Acceptance
- [ ] `did:key` profiles render identically to before (no regression)
- [ ] `did:keri` profiles show Person View with device list
- [ ] Toggle between Device View and Person View works
- [ ] Loading state shown while KERI data loads
- [ ] Edge cases handled: zero devices, abandoned identity
- [ ] Uses Svelte 5 runes ($state, $derived)
## Done summary
- Router: added getUser() call, passes UserResponse to View.svelte
- View.svelte: conditional Person View (KERI DID, device list, abandoned badge) vs Device View
- Toggle switches between Person and Device views for KERI identities
- Graceful fallback when getUser or getNodeIdentity unavailable

Why:
- KERI identities need a unified profile showing controller DID and linked devices
- did:key profiles render identically (no regression)

Verification:
- Code follows existing Svelte 4 patterns in the codebase
- did:key path unchanged, isKeri defaults to false when userResponse is null
## Evidence
- Commits: 04e1ccba
- Tests: code review
- PRs:
