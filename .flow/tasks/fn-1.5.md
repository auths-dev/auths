# fn-1.5 find_identity_for_device() implementation

## Description
Implement `find_identity_for_device()` in `RadicleAuthsStorage` — given a device's NodeId and a project repository, discover which KERI identity (if any) the device is attested under.

### What to implement

1. Implement the full `find_identity_for_device()` method on `RadicleAuthsStorage`:
   - Accept a device DID (`did:key:z6Mk...`) and a project repo path
   - Scan `refs/namespaces/did-keri-*/refs/rad/id` blobs to find identity repo RIDs
   - For each discovered identity repo, check `refs/keys/<nid>/signatures` for a matching attestation
   - Return the KERI DID (`did:keri:<prefix>`) of the matching identity, or `None`
2. Handle edge cases:
   - Device not attested under any identity -> return `None` (not an error)
   - Identity repo not locally available -> skip (return `None` for that identity, log warning)
   - Device attested under multiple identities -> return first match with warning log
3. Also update the `AuthsStorage` trait signature if needed — `find_identity_for_device()` may need `repo_id` parameter to know which project's namespaces to scan. Currently `repo_id` is unused in `verify_signer()` at `crates/auths-radicle/src/verify.rs:108` (prefixed with `_`).

### Performance consideration

Scanning all `refs/namespaces/did-keri-*/refs/rad/id` blobs on every verification could become a bottleneck as a project scales to hundreds of identities. **Design the trait signature so that `RadicleAuthsStorage` can eventually support a cache** (e.g., local SQLite index via `auths-index`, or a simple in-memory `HashMap<NodeId, Did>`) without changing the trait contract. The current impl does direct scanning, but the trait must not prevent a cached impl later.

### Key context

- Heartwood's `IdentityNamespace::from_ref_component()` at `namespace.rs:46-62` parses `did-keri-<prefix>` — our scanning must produce compatible ref prefix patterns.
- The `refs/rad/id` blob contains the RID (Radicle Repository ID) of the identity repo.
- The `refs/keys/<nid>/signatures` directory exists only if the device has been attested.
- Use refs constants from fn-1.1 for path construction.

### Affected files
- Modified: `crates/auths-radicle/src/storage.rs` (or wherever `RadicleAuthsStorage` lives)
- Possibly modified: `crates/auths-radicle/src/verify.rs` (trait signature if `repo_id` added)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Device attested under one identity -> returns that identity's DID
- [ ] Device not attested under any identity -> returns `None`
- [ ] Device attested under multiple identities -> returns first match with warning log
- [ ] Identity repo not locally available -> returns `None` (not error), logs warning
- [ ] `repo_id` is used for scoped identity lookup (no longer underscore-prefixed in `verify_signer()`)
- [ ] Trait signature does not prevent future cached implementations (no internal state assumptions leak)
- [ ] Uses ref constants from fn-1.1 for path construction
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- find_identity_for_device() on AuthsStorage trait accepts (device_did, repo_id)
- Returns Option<String> - None for not found (not an error)
- Trait signature designed for future caching without contract changes
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
