# Adding a Language Binding

Auths language bindings wrap the `auths-verifier` crate for verification in other languages.

## Binding approaches

| Approach | Used by | How it works |
|----------|---------|-------------|
| **PyO3** | Python | Rust compiles to a native Python module |
| **WASM** | JavaScript | Rust compiles to WebAssembly via `wasm-pack` |
| **CGo (FFI)** | Go | Rust builds a C dynamic library, Go calls via CGo |
| **UniFFI** | Swift, Kotlin | Mozilla's UniFFI generates bindings from Rust |

## Steps to add a new binding

### 1. Create the package directory

```
packages/auths-verifier-<language>/
├── README.md
├── build.sh
├── src/           (or equivalent for the language)
└── tests/
```

### 2. Choose the binding method

- **If the language supports C FFI**: Use the `ffi` feature of `auths-verifier`. Build a `cdylib` and call `ffi_verify_attestation_json()`.
- **If targeting WASM**: Use the `wasm` feature of `auths-verifier`. Build with `wasm-pack`.
- **If using UniFFI**: Define a UDL file and generate bindings.

### 3. Wrap the core functions

Every binding should expose at minimum:

```
verifyAttestation(attestationJson, issuerPublicKeyHex) → result
verifyChain(attestationsJson[], rootPublicKeyHex) → report
isDeviceAuthorized(identityDid, deviceDid, attestationsJson[]) → bool
```

### 4. Map the types

| Rust type | What to map |
|-----------|-------------|
| `VerificationResult` | `{ valid: bool, error: string? }` |
| `VerificationReport` | `{ status, chain[], warnings[] }` |
| `VerificationStatus` | Enum/union with `Valid`, `Expired`, `Revoked`, `InvalidSignature`, `BrokenChain` |
| `ChainLink` | `{ issuer, subject, valid, error? }` |

### 5. Add tests

Test against known-good attestation JSON. The `auths-verifier` test fixtures provide valid and invalid attestation samples.

### 6. Add to CI

Add build and test steps for the new binding in `.github/workflows/`.

## FFI details

The FFI entry point in `auths-verifier`:

```c
int32_t ffi_verify_attestation_json(
    const uint8_t* att_json_bytes,
    size_t att_json_len,
    const uint8_t* issuer_pk_bytes,
    size_t issuer_pk_len  // Must be 32
);
```

Returns `VERIFY_SUCCESS` (0) or an `ERR_VERIFY_*` error code.

Generate the C header with:

```bash
cbindgen --config cbindgen.toml --crate auths_verifier --output include/auths_verifier.h
```

## WASM details

Build with:

```bash
cd crates/auths-verifier
wasm-pack build . --target web --features wasm
```

The generated `pkg/` directory contains `.wasm` and JavaScript bindings.
