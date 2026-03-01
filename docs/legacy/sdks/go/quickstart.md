# Go SDK

Go bindings for the Auths attestation verification library, powered by Rust via CGo.

## Installation

```bash
go get github.com/auths/auths/packages/auths-verifier-go
```

Requirements: Go 1.21+, CGo enabled (`CGO_ENABLED=1`)

### Building the native library

Before using the package, build the Rust native library:

```bash
cd packages/auths-verifier-go
./build.sh
```

Set CGo environment variables:

=== "macOS"

    ```bash
    export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
    export DYLD_LIBRARY_PATH="/path/to/auths/target/release:$DYLD_LIBRARY_PATH"
    ```

=== "Linux"

    ```bash
    export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
    export LD_LIBRARY_PATH="/path/to/auths/target/release:$LD_LIBRARY_PATH"
    ```

## Quick start

```go
package main

import (
    "fmt"
    verifier "github.com/auths/auths/packages/auths-verifier-go"
)

func main() {
    result := verifier.VerifyAttestationHex(
        attestationJSON,
        "aabbccdd...", // 64-char hex public key
    )

    if result.Valid {
        fmt.Println("Attestation is valid!")
    } else {
        fmt.Printf("Verification failed: %v\n", result.Error)
    }
}
```

## Verify a chain

```go
report := verifier.VerifyChainHex(
    []string{att1JSON, att2JSON},
    rootPublicKeyHex,
)

switch report.Status {
case verifier.StatusValid:
    fmt.Println("Chain verified!")
case verifier.StatusExpired:
    fmt.Printf("Chain expired at: %v\n", report.ExpiredAt)
case verifier.StatusRevoked:
    fmt.Println("Chain revoked")
case verifier.StatusInvalidSignature:
    fmt.Printf("Invalid signature at step %d\n", report.FailedStep)
case verifier.StatusBrokenChain:
    fmt.Printf("Broken chain: %s\n", report.MissingLink)
}
```

## API reference

### Functions

| Function | Description |
|----------|-------------|
| `VerifyAttestation(json, pk []byte)` | Verify attestation with raw bytes |
| `VerifyAttestationHex(json, pkHex string)` | Verify attestation with hex key |
| `VerifyChain(jsons [][]byte, rootPK []byte)` | Verify chain with raw bytes |
| `VerifyChainHex(jsons []string, rootPKHex string)` | Verify chain with hex key |
| `IsDeviceAuthorized(idDID, devDID string, jsons [][]byte)` | Check authorization |

### Types

**`VerificationResult`**: `Valid bool`, `Error error`

**`VerificationStatus`** constants: `StatusValid`, `StatusExpired`, `StatusRevoked`, `StatusInvalidSignature`, `StatusBrokenChain`

**`VerificationReport`**: `Status`, `Chain []ChainLink`, `Warnings []string`, `ExpiredAt *time.Time`, `RevokedAt *time.Time`, `FailedStep int`, `MissingLink string`

**`ChainLink`**: `Issuer string`, `Subject string`, `Valid bool`, `Error string`

### Error constants

`ErrNullPointer`, `ErrInvalidJSON`, `ErrInvalidPublicKey`, `ErrIssuerSignature`, `ErrDeviceSignature`, `ErrAttestationExpired`, `ErrAttestationRevoked`, `ErrSerializationFailed`, `ErrVerificationFailed`

## Testing

```bash
./build.sh
go test -v
```
