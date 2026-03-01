# AuthsVerifier (Swift & Kotlin)

Swift and Kotlin/Android bindings for the Auths attestation verification library, powered by Rust via UniFFI.

## Swift Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/auths/auths", from: "0.1.0")
]
```

### Manual Integration

1. Build the library:
   ```bash
   ./build-swift.sh
   ```

2. Copy the generated files to your Xcode project:
   - `generated/auths_verifier_uniffi.swift`
   - `target/release/libauths_verifier_uniffi.dylib` (or `.a` for static linking)

3. Add the library to your target's "Link Binary with Libraries" build phase.

## Kotlin/Android Installation

### Gradle

```kotlin
dependencies {
    implementation("com.auths:verifier-android:0.1.0")
}
```

### Manual Integration

1. Build the Android library:
   ```bash
   ./build-android.sh
   ```

2. Copy `android-lib/` to your project and add it as a module:
   ```kotlin
   // settings.gradle.kts
   include(":auths-verifier")

   // app/build.gradle.kts
   dependencies {
       implementation(project(":auths-verifier"))
   }
   ```

## Swift Usage

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
    print("Verification failed: \(result.error ?? "Unknown error")")
}

// Verify a chain of attestations
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
        print("Chain revoked at: \(at ?? "unknown time")")
    case .invalidSignature(let step):
        print("Invalid signature at step: \(step)")
    case .brokenChain(let missingLink):
        print("Broken chain: \(missingLink)")
    }
} catch {
    print("Error: \(error)")
}

// Check device authorization
do {
    let authorized = try isDeviceAuthorized(
        identityDid: "did:key:z6Mk...",
        deviceDid: "did:key:z6MK...",
        attestationsJson: attestationJsons
    )

    if authorized {
        print("Device is authorized!")
    }
} catch {
    print("Error: \(error)")
}
```

## Kotlin Usage

```kotlin
import uniffi.auths_verifier_uniffi.*

// Verify a single attestation
val result = verifyAttestation(
    attestationJson = attestationJsonString,
    issuerPkHex = publicKeyHex
)

if (result.valid) {
    println("Attestation is valid!")
} else {
    println("Verification failed: ${result.error}")
}

// Verify a chain of attestations
try {
    val report = verifyChain(
        attestationsJson = listOf(att1Json, att2Json),
        rootPkHex = rootPublicKeyHex
    )

    when (val status = report.status) {
        is VerificationStatus.Valid -> println("Chain verified!")
        is VerificationStatus.Expired -> println("Chain expired at: ${status.at}")
        is VerificationStatus.Revoked -> println("Chain revoked at: ${status.at}")
        is VerificationStatus.InvalidSignature -> println("Invalid signature at step: ${status.step}")
        is VerificationStatus.BrokenChain -> println("Broken chain: ${status.missingLink}")
    }
} catch (e: VerifierError) {
    println("Error: $e")
}

// Check device authorization
try {
    val authorized = isDeviceAuthorized(
        identityDid = "did:key:z6Mk...",
        deviceDid = "did:key:z6MK...",
        attestationsJson = attestationJsons
    )

    if (authorized) {
        println("Device is authorized!")
    }
} catch (e: VerifierError) {
    println("Error: $e")
}
```

## API Reference

### Functions

#### `verifyAttestation(attestationJson: String, issuerPkHex: String) -> VerificationResult`

Verify a single attestation against an issuer's public key.

- `attestationJson`: The attestation as a JSON string
- `issuerPkHex`: Ed25519 public key in hex format (64 characters)

Returns `VerificationResult` with `valid` and `error` properties.

#### `verifyChain(attestationsJson: [String], rootPkHex: String) throws -> VerificationReport`

Verify a chain of attestations from root identity to leaf device.

Returns `VerificationReport` with `status`, `chain`, and `warnings` properties.

#### `isDeviceAuthorized(identityDid: String, deviceDid: String, attestationsJson: [String]) throws -> Bool`

Check if a device is authorized for an identity based on attestations.

### Types

#### `VerificationResult`
- `valid: Bool` - Whether verification succeeded
- `error: String?` - Error message if failed

#### `VerificationStatus`
Enum with cases:
- `.valid` / `Valid` - Verification succeeded
- `.expired(at: String)` / `Expired(at)` - Attestation expired
- `.revoked(at: String?)` / `Revoked(at)` - Attestation revoked
- `.invalidSignature(step: UInt32)` / `InvalidSignature(step)` - Signature invalid at step
- `.brokenChain(missingLink: String)` / `BrokenChain(missingLink)` - Chain has missing link

#### `ChainLink`
- `issuer: String` - Issuer DID
- `subject: String` - Subject DID
- `valid: Bool` - Whether this link verified
- `error: String?` - Error message if failed

#### `VerificationReport`
- `status: VerificationStatus` - Overall status
- `chain: [ChainLink]` - Per-link details
- `warnings: [String]` - Non-fatal warnings

## Building from Source

### Prerequisites

- Rust toolchain (1.70+)
- For Swift: Xcode (for iOS/macOS targets)
- For Android: Android NDK

### Build Scripts

```bash
# Swift bindings (development)
./build-swift.sh

# Swift XCFramework for distribution
./build-xcframework.sh

# Kotlin bindings (development)
./build-kotlin.sh

# Android library with all ABIs
./build-android.sh
```

### Swift Targets

- macOS (Intel and Apple Silicon)
- iOS device
- iOS Simulator (Intel and Apple Silicon)

### Android Targets

- `arm64-v8a` (ARM64)
- `armeabi-v7a` (ARM32)
- `x86_64` (x86_64 emulator)
- `x86` (older emulators)

## Requirements

### Swift
- Swift 5.5+
- iOS 13.0+ / macOS 10.15+ / tvOS 13.0+ / watchOS 6.0+

### Android
- Android SDK 21+ (Android 5.0 Lollipop)
- Kotlin 1.9+

## License

MIT
