# Radicle Identity Bridge Integration

## Overview

Implement the auths-radicle bridge that enables KERI-based multi-device identity verification within Radicle's P2P code forge. The bridge reads identity state from locally-replicated Radicle repositories, evaluates device authorization, and returns verification decisions that Heartwood's fetch pipeline can act on.

This epic covers all **auths-side work** — the bridge crate (`auths-radicle`), verifier extensions, and `auths-id` adaptations. Heartwood-side changes (Did enum, fetch pipeline wiring) are tracked separately in the Heartwood repo's `.flow/` epics (fn-1 through fn-5).

## Scope

### In Scope
- RIP-X ref path constants and attestation format alignment
- Identity state loading from Radicle-replicated Git repos
- Full authorization pipeline (KEL validation, attestation verification, revocation/expiry/capability checks)
- Observe/enforce mode with quarantine support
- Gossip-informed staleness detection via `known_remote_tip`
- `min_kel_seq` binding integrity checks
- Multi-signer threshold verification with mixed `Did::Key` + `Did::Keri` delegates
- Bridge API alignment with Heartwood fn-3.2 (`CompositeAuthorityChecker`)
- End-to-end integration tests
- Migration of `identity.rs` from `anyhow` to `thiserror`

### Out of Scope
- Heartwood-side changes (Did enum, fetch pipeline, CLI commands) — tracked in Heartwood `.flow/`
- Proof-carrying authorization (Phase 2, deferred)
- Retroactive flagging UX (post-MVP)
- Quarantine timeout timer (post-MVP)

## Approach

### Architecture

```
Heartwood fetch pipeline
  └── CompositeAuthorityChecker (fn-3.2)
        ├── Fast path: Did::Key in Doc.delegates → accept (existing)
        └── Slow path: device not a direct delegate
              └── auths-radicle::DefaultBridge::verify_signer()
                    ├── DID translation: [u8;32] → did:key:z6Mk...
                    ├── Identity lookup: scan did-keri-* namespaces
                    ├── KEL loading: refs/keri/kel → validate_kel() → KeyState
                    ├── Attestation loading: refs/keys/<nid>/signatures
                    ├── 2-way signature verification (did-key + did-keri blobs)
                    ├── Policy evaluation: revocation, expiry, capabilities
                    ├── Staleness check: local tip vs known_remote_tip
                    └── Mode-dependent result: Verified/Rejected/Warn/Quarantine
```

### Key Design Decisions

1. **Byte boundary**: Bridge accepts `&[u8; 32]` (not Heartwood types) to avoid SQLite library conflict.
2. **Heartwood depends on auths-radicle** (not vice versa). The bridge has zero Heartwood dependencies.
3. **Two attestation formats**: Existing JSON format (auths-native) and RIP-X 2-blob format (Radicle). Bridge supports both via `AttestationFormat` enum.
4. **`VerifyResult` extended** with `Quarantine` variant for enforce mode.
5. **`verify_signer()` extended** with `enforcement_mode` and `known_remote_tip` parameters.
6. **Epics 1-4 can proceed without Heartwood fn-1.1** (Did enum). Only Epic 5 (API alignment) and Epic 6 (E2E tests) are hard-blocked on Heartwood readiness.

### Dependency Graph

```
Task 1.1 (ref constants) ──┐
Task 1.2 (2-blob format) ──┼──► Task 2.1 (AuthsStorage impl)
Task 1.3 (GitKel.with_ref) ┘         │
                                      ├──► Task 2.2 (find_identity_for_device)
                                      │         │
                                      └─────────┼──► Task 3.1 (full pipeline)
                                                │         │
                                                │    Task 3.2 (capabilities) ──┐
                                                │         │                    │
                                                │    Task 3.3 (threshold) ─────┤
                                                │                              │
                                                └──► Task 4.1 (modes) ────────┤
                                                     Task 4.2 (staleness) ─────┤
                                                     Task 4.3 (min_kel_seq) ───┤
                                                                               │
                                                     Task 4.4 (stale tests) ◄──┤
                                                     Task 5.1 (API align) ◄────┘
                                                          │
                                                     Task 6.1-6.3 (E2E) ◄──┘
                                                          │
                                                     Task 6.4 (CI)
```

## Quick Commands

```bash
# Smoke test: build auths-radicle
cargo build --package auths-radicle

# Run auths-radicle tests
cargo nextest run -p auths-radicle

# Run specific integration tests
cargo nextest run -p auths-radicle -E 'test(verify)'

# Check WASM compatibility of auths-verifier (must not break)
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# Lint
cargo clippy -p auths-radicle --all-targets -- -D warnings

# Full workspace test (regression check)
cargo nextest run --workspace
```

## Acceptance Criteria

- [ ] RIP-X ref path constants exist in `auths-radicle/src/refs.rs` and match spec exactly
- [ ] Bridge can read attestations in RIP-X 2-blob format (separate `did-key` + `did-keri` signature blobs)
- [ ] `GitKel` supports custom ref paths (`refs/keri/kel` for RIP-X repos)
- [ ] `AuthsStorage` impl loads `KeyState` and attestations from Radicle-replicated identity repos
- [ ] `find_identity_for_device()` scans `did-keri-*` namespaces to locate a device's identity
- [ ] Full authorization pipeline: DID translation → KEL validation → attestation verification → policy evaluation
- [ ] Revoked, expired, and unauthorized devices are correctly rejected
- [ ] Capability-scoped authorization works (`sign_commit` vs `sign_release`)
- [ ] M-of-N threshold verification works with mixed `Did::Key` + `Did::Keri` delegates
- [ ] Observe mode: never blocks updates, logs warnings for rejected/stale devices
- [ ] Enforce mode: rejects updates when identity state is unavailable or known-stale (quarantine)
- [ ] Gossip-informed staleness: warns/quarantines when local identity repo tip differs from announced tip
- [ ] `min_kel_seq` rejects identity state that predates the project binding
- [ ] Bridge API signature matches Heartwood fn-3.2 expectations
- [ ] E2E tests for authorization, revocation, and stale-node scenarios pass
- [ ] All tests pass on CI (Ubuntu, macOS, Windows)
- [ ] `anyhow` removed from `identity.rs` (migrated to `thiserror`)
- [ ] `auths-verifier` WASM target still compiles

## Open Questions

1. **RIP-X 2-blob canonical payload**: The existing `CanonicalAttestationData` has 14 fields. RIP-X specifies `(RID, other_did)` as the signing payload. Must decide: new canonical format for Radicle attestations only, or support both with a version discriminator? **Proposed**: New `RipXCanonicalPayload` type alongside existing format.
2. **Where is `min_kel_seq` stored?** Plan references it but doesn't specify storage. **Proposed**: Passed as parameter to `verify_signer()`, sourced from the `did-keri-` namespace blob on Heartwood side.
3. **Where is enforcement mode stored?** Per-project (Doc metadata) or per-node? **Proposed**: Passed as parameter to bridge, sourced from project Doc on Heartwood side.
4. **First-fetch bootstrapping**: On first fetch of a project with KERI delegate, identity repo isn't available yet. First update always quarantined in enforce mode. This is by design (fail-closed).
5. **Re-authorization after revocation**: Old attestation blobs under `refs/keys/<nid>/signatures` are overwritten by new attestation. The latest blob is authoritative.
6. **Cross-library Ed25519 compatibility**: `ring` (auths) vs `ec25519` (Heartwood) use identical wire format for Ed25519. Add explicit cross-library roundtrip test.

## References

- Plan document: `docs/plans/radicle_integration.md`
- Heartwood epics: `/Users/bordumb/workspace/repositories/heartwood/.flow/specs/fn-{1..5}.md`
- Cross-repo task map: `/Users/bordumb/workspace/repositories/heartwood/.flow/rad-auths.md`
- Bridge code: `crates/auths-radicle/src/{bridge,verify,identity}.rs`
- KEL validation: `crates/auths-id/src/keri/validate.rs:124-219`
- Attestation type: `crates/auths-verifier/src/core.rs:330-381`
- Git storage layout: `crates/auths-id/src/storage/layout.rs`
- Heartwood SignedRefs: `/Users/bordumb/workspace/repositories/heartwood/crates/radicle/src/storage/refs.rs:187-259`
- Heartwood IdentityNamespace: `/Users/bordumb/workspace/repositories/heartwood/crates/radicle/src/identity/namespace.rs:15-68`
