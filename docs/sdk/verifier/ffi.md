# C FFI Embedding

The `auths-verifier` crate exposes a C-compatible FFI layer for embedding attestation verification into C, C++, Go (via CGo), or any language with a C foreign-function interface.

## Building the shared library

The FFI surface is behind the `ffi` feature flag. Build a release `cdylib` from the workspace root:

```bash
cd crates/auths-verifier
cargo build --release --features ffi
```

This produces a shared library in `target/release/`:

| Platform | File |
|----------|------|
| Linux | `libauths_verifier.so` |
| macOS | `libauths_verifier.dylib` |
| Windows | `auths_verifier.dll` |

## Header overview

There is no generated C header yet. Declare the symbols manually or use `cbindgen` to generate one. The FFI surface consists of four `extern "C"` functions and a set of integer return-code constants.

### Return codes

| Constant | Value | Meaning |
|----------|-------|---------|
| `VERIFY_SUCCESS` | `0` | Verification succeeded |
| `ERR_VERIFY_NULL_ARGUMENT` | `-1` | A required pointer argument was null |
| `ERR_VERIFY_JSON_PARSE` | `-2` | JSON deserialization failed |
| `ERR_VERIFY_INVALID_PK_LEN` | `-3` | Public key length was not 32 bytes |
| `ERR_VERIFY_ISSUER_SIG_FAIL` | `-4` | Issuer signature verification failed |
| `ERR_VERIFY_DEVICE_SIG_FAIL` | `-5` | Device signature verification failed |
| `ERR_VERIFY_EXPIRED` | `-6` | Attestation has expired |
| `ERR_VERIFY_REVOKED` | `-7` | Attestation has been revoked |
| `ERR_VERIFY_SERIALIZATION` | `-8` | Report serialization or output buffer error |
| `ERR_VERIFY_INSUFFICIENT_WITNESSES` | `-9` | Witness quorum not met |
| `ERR_VERIFY_WITNESS_PARSE` | `-10` | Witness receipt or key JSON parse error |
| `ERR_VERIFY_INPUT_TOO_LARGE` | `-11` | Input JSON exceeded size limit (64 KB single, 1 MB batch) |
| `ERR_VERIFY_OTHER` | `-99` | Unclassified verification error |
| `ERR_VERIFY_PANIC` | `-127` | Internal Rust panic (caught, never aborts) |

### Size limits

| Constant | Value | Applies to |
|----------|-------|------------|
| `MAX_ATTESTATION_JSON_SIZE` | 64 KB | Single attestation JSON |
| `MAX_JSON_BATCH_SIZE` | 1 MB | Chain JSON arrays, witness receipts, witness keys |

## Function signatures

### `ffi_verify_attestation_json`

Verify a single attestation against an issuer's Ed25519 public key.

```c
int ffi_verify_attestation_json(
    const uint8_t *attestation_json_ptr,
    size_t         attestation_json_len,
    const uint8_t *issuer_pk_ptr,
    size_t         issuer_pk_len       /* must be 32 */
);
```

Returns `0` on success, or a negative `ERR_VERIFY_*` code on failure.

### `ffi_verify_chain_json`

Verify an ordered chain of attestations from a root identity public key. Writes a JSON `VerificationReport` into the caller-provided buffer.

```c
int ffi_verify_chain_json(
    const uint8_t *chain_json_ptr,
    size_t         chain_json_len,
    const uint8_t *root_pk_ptr,
    size_t         root_pk_len,       /* must be 32 */
    uint8_t       *result_ptr,        /* output buffer */
    size_t        *result_len         /* in: capacity, out: bytes written */
);
```

On entry, `*result_len` must hold the buffer capacity. On success (`0`), `*result_len` is updated to the number of bytes written and `result_ptr` contains a JSON `VerificationReport`.

### `ffi_verify_chain_with_witnesses`

Verify an attestation chain plus witness quorum. Accepts additional witness receipt and key arrays.

```c
int ffi_verify_chain_with_witnesses(
    const uint8_t *chain_json_ptr,
    size_t         chain_json_len,
    const uint8_t *root_pk_ptr,
    size_t         root_pk_len,           /* must be 32 */
    const uint8_t *receipts_json_ptr,
    size_t         receipts_json_len,
    const uint8_t *witness_keys_json_ptr,
    size_t         witness_keys_json_len,
    uint32_t       threshold,
    uint8_t       *result_ptr,            /* output buffer */
    size_t        *result_len             /* in: capacity, out: bytes written */
);
```

The `witness_keys_json` parameter is a JSON array of objects with `did` and `pk_hex` fields:

```json
[
  {"did": "did:key:z6Mk...", "pk_hex": "abcdef0123456789..."}
]
```

### `ffi_verify_device_authorization_json`

Full cryptographic verification that a specific device is authorized under an identity.

```c
int ffi_verify_device_authorization_json(
    const uint8_t *identity_did_ptr,
    size_t         identity_did_len,     /* UTF-8 DID string */
    const uint8_t *device_did_ptr,
    size_t         device_did_len,       /* UTF-8 DID string */
    const uint8_t *chain_json_ptr,
    size_t         chain_json_len,
    const uint8_t *identity_pk_ptr,
    size_t         identity_pk_len,      /* must be 32 */
    uint8_t       *result_ptr,           /* output buffer */
    size_t        *result_len            /* in: capacity, out: bytes written */
);
```

## Memory management

All FFI functions follow a caller-owns-everything model:

- **Input buffers** are read-only (`const uint8_t *`). The library never frees or retains pointers after the function returns.
- **Output buffers** for report JSON are allocated by the caller. Set `*result_len` to the buffer capacity before calling. A 4 KB buffer is sufficient for most reports; 16 KB handles large chains.
- **No heap allocations cross the boundary.** All Rust allocations are internal and freed before the function returns.
- **Panic safety.** Every FFI entry point wraps its body in `panic::catch_unwind`. A Rust panic returns `ERR_VERIFY_PANIC` (-127) instead of unwinding into C.

## C usage example

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Declare FFI functions (or include a generated header) */
extern int ffi_verify_attestation_json(
    const uint8_t *att_json, size_t att_json_len,
    const uint8_t *pk,       size_t pk_len
);

extern int ffi_verify_chain_json(
    const uint8_t *chain_json, size_t chain_json_len,
    const uint8_t *root_pk,    size_t root_pk_len,
    uint8_t *result,           size_t *result_len
);

int main(void) {
    /* --- Single attestation verification --- */
    const char *att_json = "{...}";  /* attestation JSON */
    uint8_t issuer_pk[32] = { /* 32-byte Ed25519 public key */ };

    int rc = ffi_verify_attestation_json(
        (const uint8_t *)att_json, strlen(att_json),
        issuer_pk, 32
    );
    if (rc == 0) {
        printf("Attestation verified.\n");
    } else {
        printf("Verification failed: error code %d\n", rc);
    }

    /* --- Chain verification with report --- */
    const char *chain_json = "[...]";  /* JSON array of attestations */
    uint8_t root_pk[32] = { /* root identity public key */ };

    uint8_t report_buf[4096];
    size_t report_len = sizeof(report_buf);

    rc = ffi_verify_chain_json(
        (const uint8_t *)chain_json, strlen(chain_json),
        root_pk, 32,
        report_buf, &report_len
    );
    if (rc == 0) {
        /* report_buf contains report_len bytes of JSON */
        printf("Report: %.*s\n", (int)report_len, report_buf);
    }

    return 0;
}
```

Compile and link:

```bash
gcc -o verify_example verify_example.c -L target/release -lauths_verifier
```

## C++ usage

The same C interface works from C++. Wrap the extern declarations in `extern "C"`:

```cpp
extern "C" {
    int ffi_verify_attestation_json(
        const uint8_t *att_json, size_t att_json_len,
        const uint8_t *pk,       size_t pk_len
    );
}

#include <vector>
#include <string>

bool verify(const std::string& attestation_json,
            const std::vector<uint8_t>& issuer_pk) {
    return ffi_verify_attestation_json(
        reinterpret_cast<const uint8_t*>(attestation_json.data()),
        attestation_json.size(),
        issuer_pk.data(),
        issuer_pk.size()
    ) == 0;
}
```

## Report JSON format

Functions that write a report return a JSON `VerificationReport`:

```json
{
  "status": {"type": "Valid"},
  "chain": [
    {
      "issuer": "did:keri:Eabc...",
      "subject": "did:key:z6Mk...",
      "valid": true,
      "error": null
    }
  ],
  "warnings": [],
  "witness_quorum": {
    "required": 2,
    "verified": 2,
    "receipts": [...]
  }
}
```

The `status.type` field is one of: `Valid`, `Expired`, `Revoked`, `InvalidSignature`, `BrokenChain`, or `InsufficientWitnesses`.

## Thread safety

All FFI functions are stateless and thread-safe. Each call creates its own short-lived Tokio current-thread runtime to execute the async verification core. Multiple threads can call FFI functions concurrently without external synchronization.
