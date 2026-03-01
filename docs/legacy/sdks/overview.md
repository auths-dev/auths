# SDKs Overview

Auths provides verification SDKs for multiple languages. All SDKs wrap the same Rust `auths-verifier` core.

## What SDKs do

SDKs are for **verification only**. They let your application verify attestation signatures and check device authorization without running the full `auths` CLI.

| SDK | Binding method | Package | Status |
|-----|---------------|---------|--------|
| [Python](python/quickstart.md) | PyO3 (native) | `pip install auths-verifier` | Beta |
| [JavaScript](javascript/quickstart.md) | WASM | `npm install @auths/verifier` | Beta |
| [Web Component](javascript/quickstart.md#web-component) | WASM (via JS SDK) | [`npm install auths-verify`](https://www.npmjs.com/package/auths-verify) | Beta |
| [Go](go/quickstart.md) | CGo (FFI) | `go get github.com/auths-dev/auths/packages/auths-verifier-go` | Alpha |
| [Swift](swift/mobile-identity.md) | UniFFI | Swift Package Manager | Alpha |

## Common API surface

All SDKs expose these core verification functions:

| Function | Description |
|----------|-------------|
| `verify_attestation` | Verify a single attestation against an issuer's Ed25519 public key |
| `verify_chain` | Verify a chain of attestations from root identity to leaf device |
| `is_device_listed` | Check if a device appears in the attestation list (no crypto verification) |
| `verify_device_authorization` | Full cryptographic verification that a device is authorized |

The Python SDK additionally provides:

| Function | Description |
|----------|-------------|
| `verify_commit_range` | Verify SSH signatures on git commits using an allowed_signers file or identity bundle |

## What SDKs don't do

- Create identities
- Manage keys
- Sign data
- Interact with Git (except Python's `verify_commit_range`)

For these operations, use the [CLI](../cli/overview.md) or the Rust `auths-core` / `auths-id` crates directly.

## Verification statuses

All SDKs return the same status types:

| Status | Meaning |
|--------|---------|
| `Valid` | All checks passed |
| `Expired` | Attestation past `expires_at` |
| `Revoked` | Attestation has `revoked: true` |
| `InvalidSignature` | Signature verification failed |
| `BrokenChain` | Chain has a gap |

## Building from source

All SDKs require the Rust toolchain to build from source. See each SDK's page for specific build instructions.
