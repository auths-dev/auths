# Swift SDK

Swift (and Kotlin) bindings for Auths, powered by Rust via UniFFI. Includes both verification and mobile identity creation.

## Verification

### Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/auths/auths", from: "0.1.0")
]
```

Requirements: Swift 5.5+, iOS 13.0+ / macOS 10.15+

### Quick start

```swift
import AuthsVerifier

// Verify a single attestation
let result = verifyAttestation(
    attestationJson: attestationJsonString,
    issuerPkHex: publicKeyHex
)

if result.valid {
    print("Attestation is valid!")
} else {
    print("Verification failed: \(result.error ?? "Unknown")")
}
```

### Verify a chain

```swift
do {
    let report = try verifyChain(
        attestationsJson: [att1Json, att2Json],
        rootPkHex: rootPublicKeyHex
    )

    switch report.status {
    case .valid:
        print("Chain verified!")
    case .expired(let at):
        print("Chain expired at: \(at)")
    case .revoked(let at):
        print("Chain revoked at: \(at ?? "unknown")")
    case .invalidSignature(let step):
        print("Invalid signature at step: \(step)")
    case .brokenChain(let missingLink):
        print("Broken chain: \(missingLink)")
    }
} catch {
    print("Error: \(error)")
}
```

## Mobile identity creation

The `auths-mobile-swift` package provides on-device identity creation for iOS apps -- a unique Auths advantage.

### What it does

- Generate Ed25519 keypairs with KERI pre-rotation support
- Produce signed inception events for server registration
- Create `did:keri` identities on-device

### Usage

```swift
import Foundation

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

### API

| Function | Returns | Description |
|----------|---------|-------------|
| `createIdentity(deviceName:)` | `IdentityResult` | Create a new KERI identity |
| `signWithIdentity(currentKeyPkcs8Hex:, dataToSign:)` | `String` | Sign data with identity key |
| `getPublicKeyFromPkcs8(pkcs8Hex:)` | `String` | Extract public key |
| `generateDeviceDid(publicKeyHex:)` | `String` | Generate `did:key` from public key |
| `validateInceptionEvent(json:)` | `String` | Validate inception event |

**`IdentityResult`** contains: `prefix`, `did`, `deviceName`, `currentKeyPkcs8Hex`, `nextKeyPkcs8Hex`, `currentPublicKeyHex`, `nextPublicKeyHex`, `inceptionEventJson`

### Security

- Keys are generated using `ring::rand::SystemRandom`
- Private keys are returned as hex-encoded PKCS8 DER for storage in iOS Keychain
- Inception events are self-authenticating (signed by the newly created key)

### Building

```bash
./build-xcframework.sh
```

This builds for all Apple platforms and generates UniFFI Swift bindings.

## Kotlin usage

The same UniFFI bindings work for Kotlin/Android:

```kotlin
import uniffi.auths_verifier_uniffi.*

val result = verifyAttestation(
    attestationJson = attestationJsonString,
    issuerPkHex = publicKeyHex
)

if (result.valid) {
    println("Attestation is valid!")
}
```

Requirements: Android SDK 21+ (Android 5.0), Kotlin 1.9+

### Android build

```bash
./build-android.sh
```

Targets: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`
