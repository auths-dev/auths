# auths_verifier

## Overview

`auths_verifier` provides the core logic necessary to verify the cryptographic signatures and validity of [Auths](https://github.com/bordumb/mobile-ssh-agent) `Attestation` objects.

Its key characteristic is its **minimal dependency set**, intentionally excluding heavy libraries like `git2` or CLI frameworks like `clap`. This makes it suitable for use cases where the full `auths_id` context (including Git repository access) is unavailable or undesirable, such as:

* **FFI Integration:** Embedding verification logic into native mobile applications (iOS/Swift, Android/Kotlin) or other C-compatible environments.
* **WASM Integration:** Verifying attestations client-side in web browsers or other WebAssembly runtimes.
* **Backend Services:** Allowing servers to verify attestations without needing local Git checkouts.
* **CI/CD Pipelines & Tools:** Verifying attestations as part of automated checks.

## Core Functionality

The primary entry point is the `verify_with_keys` function:

```rust
pub fn verify_with_keys(
    att: &Attestation,
    issuer_pk_bytes: &[u8],
) -> Result<(), AttestationError>
```

This function takes:

1. An `Attestation` struct (deserialized from JSON or constructed otherwise).
2. The raw 32-byte Ed25519 public key of the **issuer** (the identity that created the attestation).

It performs the following checks:
1. Checks if the `att.revoked` flag is true.
2. Checks if `att.expires_at` is in the past.
3. (Optionally, can be extended for timestamp skew checks).
4. Verifies the `att.identity_signature` against a canonical representation of the attestation data using the provided `issuer_pk_bytes`.
5. Verifies the `att.device_signature` against the same canonical representation using the `att.device_public_key` stored within the attestation struct itself.
6. It returns `Ok(())` if all checks pass, or an `Err(AttestationError)` detailing the reason for failure.

### Architecture / Key Components
1. src/core.rs: Defines the core data structures (`Attestation`, `CanonicalAttestationData`) and the canonicalization logic (`canonicalize_attestation_data`) required for consistent signature verification.
2. `src/types.rs`: Defines common types like `DeviceDID`.
3. `src/error.rs`: Defines the AttestationError enum used for reporting verification failures.
4. `src/verify.rs`: Contains the main verify_with_keys verification logic.
5. `src/ffi.rs`: (If feature enabled) Contains the C-compatible Foreign Function Interface (`extern "C"` functions) for use by other languages.
6. `src/wasm.rs`: (If feature enabled) Contains the WebAssembly bindings (`#[wasm_bindgen]` functions) for browser/JS usage.

## Usage

```rust
use auths_verifier::{Attestation, AttestationError, verify_with_keys};
use std::fs;
use hex;

// 1. Load attestation (e.g., from file)
let att_bytes = fs::read("path/to/attestation.json")?;
let att: Attestation = Attestation::from_json(&att_bytes)?; // Use inherent method

// 2. Get issuer's public key bytes (e.g., from config, storage, or another source)
let issuer_pk_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
let issuer_pk_bytes = hex::decode(issuer_pk_hex)?;

// 3. Verify
match verify_with_keys(&att, &issuer_pk_bytes) {
    Ok(()) => println!("Attestation is valid!"),
    Err(e) => println!("Attestation verification failed: {}", e),
}
```

### FFI (C/Swift/Kotlin...)

(Requires building the crate as a `cdylib`)

1. **Include Header**: Include the generated `auths_verifier.h` header file.
2. **Prepare Data**: Get the attestation JSON as a byte array (`const uint8_t*`, `size_t len`) and the issuer's raw 32-byte public key (`const uint8_t*`, `size_t len`).

3. **Call Function**:
```rust
#include "auths_verifier.h"
#include <stdint.h>
#include <stddef.h>

// Assume att_json_bytes, att_json_len, issuer_pk_bytes, issuer_pk_len are populated

int32_t result = ffi_verify_attestation_json(
    att_json_bytes,
    att_json_len,
    issuer_pk_bytes,
    issuer_pk_len // Must be 32
);

if (result == VERIFY_SUCCESS) {
    // Verification successful
} else {
    // Verification failed, check result code for reason
    // e.g., if (result == ERR_VERIFY_EXPIRED) { ... }
}
```

4. **Error Codes**: Consult the `ERR_VERIFY_*` constants defined in `ffi.rs` and exported in the header for specific failure reasons.

### WASM (JavaScript/Web)

(Requires building with wasm-pack and the wasm feature enabled)

1. **Import**: Import the generated JavaScript module.
2. **Call Function**:
```js
import init, { verifyAttestationJson } from './pkg/auths_verifier.js'; // Adjust path

async function verify() {
  await init(); // Initialize the WASM module

  const attestationJsonString = '{"version":1,"rid":"...","issuer":"...",...}'; // Your attestation JSON
  const issuerPublicKeyHex = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

  try {
    verifyAttestationJson(attestationJsonString, issuerPublicKeyHex);
    console.log("Attestation verified successfully!");
  } catch (error) {
    console.error("Attestation verification failed:", error);
  }
}

verify();
```

3. **Error Handling**: The function throws a `JavaScript` error (derived from `JsValue`) containing the `AttestationError` message on failure.

## Building

###  🦀 Standard Rust Build

```bash
cargo build --release
```

This compiles the crate as a standard Rust library and binary for release.

⸻

### 🧩 FFI Build (Dynamic Library + Header)

1. Ensure cdylib Configuration

Make sure your Cargo.toml contains the correct crate type:
```
[lib]
crate-type = ["rlib", "cdylib"]
```
2. Install cbindgen
```bash
cargo install cbindgen
```
3. Configure cbindgen.toml

Create a `cbindgen.toml` in the crate root.

4. Generate Header File
```bash
cbindgen --config cbindgen.toml --crate auths_verifier --output include/auths_verifier.h
```
5. Build the Dynamic Library
```bash
cargo build --release
```
The `.dylib`, `.so`, or `.dll` will be output in target/release/.

⸻

### 🌐 WASM Build

1. Enable WASM Feature

Ensure your Cargo.toml includes:
```
[features]
default = []
wasm = ["wasm-bindgen"]
```
2. Install `wasm-pack`
```bash
cargo install wasm-pack
```
3. Build for Web or Node

Navigate to the `crates/auths-verifier` directory:

Web (for browser):
```bash
wasm-pack build . --target web --features wasm
```

Node.js (optional):
```bash
wasm-pack build . --target nodejs --features wasm
```
This will generate a pkg/ directory containing the `.wasm` binary and corresponding JavaScript bindings.

⸻

## 🚀 Future Ideas

* Achieve #![no_std] compatibility (potentially using alloc) for minimal WASM builds.
* Provide more granular error codes via FFI for easier debugging.
* Expose helper functions (e.g. canonicalization, DID parsing) via FFI/WASM.
* Add FFI/WASM support for verifying revocation data structures independently.
