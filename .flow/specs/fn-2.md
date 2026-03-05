# Radicle + Auths Multi-Device Identity Integration

## Overview

Enable a single Auths identity (controller `did:keri:E...`) to be used across multiple Radicle nodes (devices, each `did:key:z6Mk...`), with verifiable proof that both devices belong to the same identity. Currently, the e2e script creates two Radicle nodes and links them as Auths devices, but never verifies the identity unification — each node appears as a separate user on Radicle.

## Scope

**Iteration 1 (this epic):** Prove the link exists at the Auths layer — the e2e test verifies both device DIDs resolve to the same controller DID, even though Radicle's UI doesn't render it yet.

**Future iterations (out of scope):**
- Real `AuthsStorage` implementation in `storage.rs` reading from Git refs
- Radicle hook integration for automatic verification on push/fetch
- `did:keri` support in `RadicleIdentityResolver`
- Radicle UI/CLI rendering of unified identity

## Approach

1. **Extract MockStorage** to a shared test helper module, eliminating 6-copy duplication across `auths-radicle` test files
2. **Add a `device resolve` CLI subcommand** that takes a device DID and returns the controller DID it's linked to (the "resolution primitive")
3. **Add identity resolution verification to the e2e shell script** — a new Phase 6b that calls `auths device resolve` for both device DIDs and asserts they return the same controller DID
4. **Add Rust integration tests** that explicitly verify `find_identity_for_device` returns the same controller DID for both device DIDs

## Key files

- `crates/auths-radicle/src/verify.rs` — `AuthsStorage` trait with `find_identity_for_device()` (line 67-91)
- `crates/auths-radicle/src/storage.rs` — Empty, future home of Git-backed implementation
- `crates/auths-radicle/tests/cases/multi_device_e2e.rs` — Existing multi-device lifecycle test (mock-based)
- `crates/auths-cli/src/commands/device/authorization.rs` — Device CLI subcommands (link, list, revoke)
- `crates/auths-sdk/src/device.rs` — SDK device operations (`link_device`, `extract_device_key`)
- `crates/auths-id/src/storage/layout.rs` — `StorageLayoutConfig::radicle()` defines ref paths (line 158-165)
- `scripts/radicle-e2e.sh` — Shell-based e2e test

## Reuse points

- `ed25519_to_did_key()` at `crates/auths-id/src/identity/resolve.rs:157-162`
- `DeviceDID::from_ed25519()` at `crates/auths-verifier/src/types.rs:254-260`
- `StorageLayoutConfig::radicle()` at `crates/auths-id/src/storage/layout.rs:158-165`
- `attestation_ref_for_device()` at `crates/auths-id/src/storage/layout.rs:317-324`
- Existing `MockStorage` pattern (to be extracted, not duplicated again)

## Quick commands

```bash
# Smoke test: run the e2e script
bash scripts/radicle-e2e.sh

# Run auths-radicle integration tests
cargo nextest run -p auths_radicle

# Run specific multi-device test
cargo nextest run -p auths_radicle -E 'test(multi_device)'

# Clippy + fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check --all
```

## Risks & dependencies

- **Ref layout ambiguity**: `StorageLayoutConfig::radicle()` uses `refs/rad/multidevice/nodes/` while `refs.rs` RIP-X helpers use `refs/keys/<nid>/signatures/`. Must consistently use `refs/rad/multidevice/nodes/` since that's what the CLI writes to.
- **`device resolve` needs attestation scanning**: The CLI currently doesn't have a command to look up a device's controller. Need to add one that reads attestations from the identity repo.
- **`rad` CLI required for shell e2e**: External dependency, must be installed.

## Acceptance criteria

- [ ] `MockStorage` extracted to one shared location, all 6 test files import from it
- [ ] `auths device resolve --device-did <did>` CLI command returns the controller DID
- [ ] E2e script Phase 6b asserts: `resolve(NODE1_DID) == resolve(NODE2_DID) == CONTROLLER_DID`
- [ ] Rust integration test: two devices linked to same identity, `find_identity_for_device` returns same controller for both
- [ ] All existing tests pass (`cargo nextest run --workspace`)
- [ ] Clippy and fmt clean

## References

- [Radicle Protocol Guide](https://radicle.xyz/guides/protocol)
- [KERI Security Q&A](https://identity.foundation/keri/docs/Q-and-A-Security.html)
- [did:key Spec](https://w3c-ccg.github.io/did-key-spec/)
- [RFC 8785 - JSON Canonicalization](https://www.rfc-editor.org/rfc/rfc8785)
