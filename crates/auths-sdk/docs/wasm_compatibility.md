# WASM Compatibility

## Invariant

The `lan-pairing` feature must **never** be enabled for `wasm32` targets.

## Why

`lan-pairing` pulls in `auths-pairing-daemon`, which depends on Tokio, Axum, and `if-addrs` — none of which compile to WASM. These crates require OS-level networking primitives (TCP sockets, network interface enumeration) that don't exist in the WASM sandbox.

## How it's enforced

1. **Feature flag isolation**: `lan-pairing` is opt-in (not in `default`), so WASM consumers never accidentally pull it in.
2. **`dep:` syntax** (resolver "3"): Optional dependencies use `dep:auths-pairing-daemon`, preventing implicit feature activation from dependency names.
3. **CI check**: `cargo check -p auths-sdk --target wasm32-unknown-unknown --no-default-features` verifies the base crate compiles without native-only features.

## Before adding new features

If a new feature pulls in async runtime dependencies (Tokio, Hyper, Axum, reqwest with default features), ensure it:

- Uses `dep:` syntax for the optional dependency
- Is **not** added to `default` features
- Has a CI check confirming `--no-default-features` still compiles for `wasm32-unknown-unknown`
