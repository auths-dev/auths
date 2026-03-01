# auths-verifier-go

Go bindings for the Auths attestation verification library, powered by Rust via CGo.

## Installation

```bash
go get github.com/auths/auths/packages/auths-verifier-go
```

### Building the Native Library

Before using this package, you need to build the Rust native library:

```bash
cd packages/auths-verifier-go
./build.sh
```

Then set the CGo environment variables as instructed by the build script:

```bash
# macOS
export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
export DYLD_LIBRARY_PATH="/path/to/auths/target/release:$DYLD_LIBRARY_PATH"

# Linux
export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
export LD_LIBRARY_PATH="/path/to/auths/target/release:$LD_LIBRARY_PATH"
```

## Usage

```go
package main

import (
    "fmt"
    verifier "github.com/auths/auths/packages/auths-verifier-go"
)

func main() {
    // Verify a single attestation
    result := verifier.VerifyAttestationHex(
        attestationJSON,
        "abcd1234...", // 64-char hex public key
    )

    if result.Valid {
        fmt.Println("Attestation is valid!")
    } else {
        fmt.Printf("Verification failed: %v\n", result.Error)
    }

    // Verify a chain of attestations
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

    // Cryptographically verify device authorization
    authReport := verifier.VerifyDeviceAuthorization(
        "did:key:z6Mk...",
        "did:key:z6MK...",
        [][]byte{[]byte(attestationJSON)},
        rootPKBytes,
    )

    if authReport.IsValid() {
        fmt.Println("Device is cryptographically authorized!")
    }
}
```

## API Reference

### Functions

#### `VerifyAttestation(attestationJSON []byte, issuerPK []byte) VerificationResult`

Verify a single attestation against an issuer's public key.

- `attestationJSON`: The attestation as a JSON byte slice
- `issuerPK`: Ed25519 public key bytes (32 bytes)

Returns `VerificationResult` with `Valid` and `Error` fields.

#### `VerifyAttestationHex(attestationJSON string, issuerPKHex string) VerificationResult`

Convenience wrapper that accepts hex-encoded public key.

#### `VerifyChain(attestationsJSON [][]byte, rootPK []byte) VerificationReport`

Verify a chain of attestations from root identity to leaf device.

Returns `VerificationReport` with `Status`, `Chain`, and `Warnings` fields.

#### `VerifyChainHex(attestationsJSON []string, rootPKHex string) VerificationReport`

Convenience wrapper that accepts hex-encoded public key and string JSON slices.

#### `IsDeviceListed(identityDID, deviceDID string, attestationsJSON [][]byte) bool`

Check if a device appears in the attestation list (membership check only).

**Note:** This function does NOT verify cryptographic signatures. For security-critical checks, use `VerifyDeviceAuthorization()`.

#### `VerifyDeviceAuthorization(identityDID, deviceDID string, attestationsJSON [][]byte, identityPK []byte) VerificationReport`

Cryptographically verify that a device is authorized. Verifies Ed25519 signatures.

### Types

#### `VerificationResult`
- `Valid bool` - Whether verification succeeded
- `Error error` - Error if failed

#### `VerificationStatus`
Constants:
- `StatusValid` - Verification succeeded
- `StatusExpired` - Attestation expired
- `StatusRevoked` - Attestation revoked
- `StatusInvalidSignature` - Signature invalid
- `StatusBrokenChain` - Chain has missing link

#### `ChainLink`
- `Issuer string` - Issuer DID
- `Subject string` - Subject DID
- `Valid bool` - Whether this link verified
- `Error string` - Error message if failed

#### `VerificationReport`
- `Status VerificationStatus` - Overall status
- `Chain []ChainLink` - Per-link details
- `Warnings []string` - Non-fatal warnings
- `ExpiredAt *time.Time` - Set when Status == StatusExpired
- `RevokedAt *time.Time` - Set when Status == StatusRevoked
- `FailedStep int` - Set when Status == StatusInvalidSignature
- `MissingLink string` - Set when Status == StatusBrokenChain

### Error Constants

- `ErrNullPointer` - Null pointer argument
- `ErrInvalidJSON` - Invalid attestation JSON
- `ErrInvalidPublicKey` - Invalid public key length
- `ErrIssuerSignature` - Issuer signature verification failed
- `ErrDeviceSignature` - Device signature verification failed
- `ErrAttestationExpired` - Attestation has expired
- `ErrAttestationRevoked` - Attestation has been revoked
- `ErrSerializationFailed` - Serialization error
- `ErrVerificationFailed` - Generic verification failure

## Testing

```bash
# Build the library first
./build.sh

# Run tests (with CGo environment set)
go test -v
```

## Requirements

- Go 1.21+
- Rust toolchain (for building the native library)
- CGo enabled (`CGO_ENABLED=1`)

## License

MIT
