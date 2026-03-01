# Auths Mobile Swift

UniFFI bindings for Auths mobile identity creation on iOS.

## Overview

This package provides Swift bindings for creating KERI identities on iOS devices. It exposes the core cryptographic functions needed for:

- Creating a new self-sovereign identity
- Generating Ed25519 keypairs with pre-rotation support
- Producing signed KERI inception events for server registration

## Building

```bash
./build-xcframework.sh
```

This will:
1. Build the Rust library for all Apple platforms
2. Generate Swift bindings using UniFFI
3. Create static libraries for linking

## Integration

### Adding to Xcode Project

1. Copy `generated/auths_mobile_ffi.swift` to your Xcode project
2. Add the appropriate static library from `../../crates/auths-mobile-ffi/target/<arch>/release/libauths_mobile_ffi.a`
3. Configure linker settings

### Usage

```swift
import Foundation

// Create a new identity
do {
    let result = try createIdentity(deviceName: "My iPhone")

    print("Created DID: \(result.did)")
    print("Prefix: \(result.prefix)")

    // Store keys in iOS Keychain
    keychainService.saveCurrentKeyPkcs8(result.currentKeyPkcs8Hex)
    keychainService.saveNextKeyPkcs8(result.nextKeyPkcs8Hex)

    // POST inception event to server
    let response = try await apiService.postInceptionEvent(
        prefix: result.prefix,
        inceptionEventJson: result.inceptionEventJson
    )

} catch let error as MobileError {
    print("Failed to create identity: \(error)")
}
```

## API Reference

### `createIdentity(deviceName: String) -> IdentityResult`

Creates a new KERI identity with:
- Two Ed25519 keypairs (current + next for pre-rotation)
- A signed inception event

Returns `IdentityResult` containing:
- `prefix`: KERI identifier prefix
- `did`: Full DID (`did:keri:{prefix}`)
- `deviceName`: The provided device name
- `currentKeyPkcs8Hex`: Current signing key (PKCS8 DER, hex encoded)
- `nextKeyPkcs8Hex`: Next rotation key (PKCS8 DER, hex encoded)
- `currentPublicKeyHex`: Current public key (32 bytes, hex)
- `nextPublicKeyHex`: Next public key (32 bytes, hex)
- `inceptionEventJson`: Signed inception event to POST to server

### `signWithIdentity(currentKeyPkcs8Hex: String, dataToSign: [UInt8]) -> String`

Signs data with the identity's current key. Returns hex-encoded signature.

### `getPublicKeyFromPkcs8(pkcs8Hex: String) -> String`

Extracts the public key from a PKCS8-encoded private key.

### `generateDeviceDid(publicKeyHex: String) -> String`

Generates a `did:key` identifier from a public key.

### `validateInceptionEvent(inceptionEventJson: String) -> String`

Validates an inception event JSON and returns the prefix if valid.

## Architecture

```
Swift App
    │
    ▼ (UniFFI bindings)
auths_mobile_ffi.swift
    │
    ▼ (FFI calls)
libauths_mobile_ffi.a (Rust static library)
    │
    ├── ring (Ed25519 cryptography)
    ├── blake3 (SAID computation)
    └── serde_json (Event serialization)
```

## Security

- Keys are generated using `ring::rand::SystemRandom`
- Private keys are returned as hex-encoded PKCS8 DER for storage in iOS Keychain
- Inception events are self-authenticating (signed by the newly created key)
