# fn-2.2 Add 'auths device resolve' CLI subcommand

## Description
Add a `device resolve` subcommand to the `auths` CLI that takes a device DID and returns the controller identity DID it's linked to.

## Purpose

Provides the "resolution primitive" — given a device `did:key:z6Mk...`, look up which controller `did:keri:E...` it belongs to. This enables the e2e script (fn-2.3) to verify identity unification.

## Implementation

Add a new variant to `DeviceSubcommand` in `crates/auths-cli/src/commands/device/authorization.rs`:

```rust
/// Resolve a device DID to its controller identity DID
Resolve {
    #[arg(long)]
    device_did: String,
}
```

Handler:
1. Open the identity repo (`--repo` flag, same as other device commands)
2. Use the `StorageLayoutConfig` (from `LAYOUT_ARGS`) to find the attestation ref for the given device DID
3. Read the attestation blob at `<attestation-prefix>/<sanitized-device-did>/signatures/<attestation-blob>`
4. Extract the issuer (controller) DID from the attestation
5. Print the controller DID to stdout

The attestation is stored by `auths device link` using `AttestationSink::persist_attestation()`. The lookup needs to reverse this: given the device DID, find the attestation, extract the issuer.

## Key files

- `crates/auths-cli/src/commands/device/authorization.rs` — Add `Resolve` variant
- `crates/auths-id/src/storage/layout.rs:317-324` — `attestation_ref_for_device()` constructs the ref path
- `crates/auths-id/src/attestation/` — Attestation deserialization
- `crates/auths-sdk/src/device.rs` — SDK device operations (may need a new `resolve_device()` function)

## Output format

```
did:keri:E<prefix>
```

Plain text, one line, suitable for shell script capture via `$()`.

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `auths device resolve --device-did did:key:z6Mk...` prints the controller DID to stdout
- [ ] Returns non-zero exit code if device DID is not found/linked
- [ ] Works with `--repo` and `LAYOUT_ARGS` (same as `device list`, `device link`)
- [ ] Reads attestation from the identity repo using the configured layout
- [ ] `cargo nextest run -p auths_cli` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
## Done summary
Added Resolve variant to DeviceSubcommand and resolve_device handler.
## Evidence
- Commits:
- Tests:
- PRs:
