# E2E Smoke Test Learnings

Accumulated knowledge from iterative development of the Radicle + Auths integration,
including the radicle-explorer frontend, radicle-httpd backend, and auths-radicle identity resolver.

## Storage Architecture

### Packed Registry (`refs/auths/registry`)

The auths CLI writes identity and device data to a **packed Git tree** at `refs/auths/registry`,
NOT to individual per-key Git refs.

```
refs/auths/registry (commit → tree)
└── v1/
    ├── identities/{s1}/{s2}/{prefix}/
    │   ├── events/00000000.json   ← KEL events
    │   ├── state.json             ← cached KeyState (CachedStateJson)
    │   └── tip.json               ← tip SAID for cache validation
    ├── devices/{s1}/{s2}/{sanitized_did}/
    │   └── attestation.json       ← device attestation
    └── metadata.json              ← aggregate counts
```

**Sharding**: 2-level directory sharding using first 4 characters of the key:
- KERI prefix `EXq5YqaL...` → `EX/q5/EXq5YqaL.../`
- Device DID `did_key_z6MkTest` → `z6/Mk/did_key_z6MkTest/`

**DID sanitization**: Colons replaced with underscores for filesystem safety.
`did:key:z6MkTest` → `did_key_z6MkTest`

### KEL Storage Locations

The KEL can live in two places depending on how the identity was provisioned:

1. **Git ref**: `refs/did/keri/{PREFIX}/kel` — written by `auths id create`
2. **Registry tree**: `v1/identities/{s1}/{s2}/{prefix}/events/*.json` — written by registry backend

The identity resolver must check BOTH locations. When the git ref is missing,
fall back to reading `state.json` from the registry tree.

### KERI Keys vs Device Keys

These are **different keypairs**:
- **KERI signing key**: The identity's own Ed25519 key, stored in the KEL. Appears in `KeyState.current_keys`.
  Converted to `did:key` format via `identity.keys`.
- **Device keys**: Separate Ed25519 keys for each device (Radicle node). Attested via attestations.
  Appear in `identity.devices`.

A repo's delegate list contains **device keys** (because Radicle nodes use `did:key` for delegation),
NOT the KERI signing key. This means matching repos for a KERI identity requires checking `identity.devices`,
not just `identity.keys`.

## radicle-httpd Integration

### Delegate Repos Handler (`GET /delegates/{did}/repos`)

When resolving repos for a DID, the handler must build a match set that includes:

1. The queried DID itself
2. `identity.keys` (KERI signing keys converted to did:key)
3. `identity.devices` (attested device keys)
4. If the DID has a `controller_did` (it's a device), also resolve the controller
   and include all sibling devices

Without step 4, querying repos for device 2 returns empty even though device 1
(a sibling) is the delegate.

### `show` Query Parameter

The repos endpoint defaults to `show=pinned`. In test/E2E environments with no
`web_config.json`, pinned repos is empty. Always pass `?show=all` to see repos.

### DID Type Bridge

Radicle has two DID types:
- `radicle::identity::Did` (struct, `did:key` only) — used in published repo docs
- `radicle_core::Did` (enum, `did:key` + `did:keri`) — used in auths integration

Both serialize `did:key` identically, so string comparison is safe for matching.

## Frontend (radicle-explorer)

### Route Structure

```
/users/did:keri:*    → User profile (controller identity)
/devices/did:key:*   → Device page
/users/did:key:*     → Redirects to /devices/did:key:*
```

### ParsedDid

`parseNodeId()` returns `{ prefix, pubkey, type }`:
- `did:keri:EPrefix...` → `{ prefix: "did:keri:", pubkey: "EPrefix...", type: "keri" }`
- `did:key:z6Mk...` → `{ prefix: "did:key:", pubkey: "z6Mk...", type: "key" }`

### NodeId Component (patches/issues author display)

The `NodeId.svelte` component resolves device DIDs to their controller identity asynchronously.
It uses a module-level cache to avoid repeated API calls. For `did:key` devices with a controller,
it shows the controller's `did:keri` instead of the device alias (e.g., "device-1").

### Device Page Repo Fetching

Device pages query repos by their own `did:key`. The httpd backend handles expansion
to include sibling device repos through the controller resolution logic.

## Radicle Gossip Sync

### Sigrefs Divergence

When two nodes independently modify a project (e.g., each device pushes a patch),
their `rad/sigrefs` refs diverge. This can cause fetch failures between nodes:

```
Fetch failed for rad:xxx from z6Mk...: delegate 'z6Mk...' has diverged 'rad/sigrefs'
```

**E2E workaround**: Rather than fighting gossip sync, device 2 pushes its patch
directly through node 1's working copy using device 2's signing key. This avoids
inter-node sync entirely while still proving that two different devices (different
signing keys) can contribute to the same project under a single KERI identity.

Gossip sync between two local nodes is unreliable because:
- `rad clone` from node 2 → node 1 can silently fail
- Even when clone succeeds, `rad sync --fetch` fails due to sigrefs divergence
- Retry loops with `--seed NID@addr:port` don't reliably resolve the divergence

The single-node approach is valid for this E2E because the test goal is identity
resolution (KERI → devices → repos), not Radicle replication.

## Test Infrastructure

### MockStorage (auths-radicle tests)

The `AuthsStorage` trait must be fully implemented on mocks. Common fields to remember
when updating the trait:
- `list_devices()` — added for KERI device discovery
- `KeyState` requires `threshold` and `next_threshold` fields (default: 1)
- `is_abandoned` field on `KeyState` (default: false)

### Integration Test Pattern

Each crate uses `tests/integration.rs` → `tests/cases/mod.rs` → `tests/cases/<topic>.rs`.
Shared helpers go in `tests/cases/helpers.rs`.
