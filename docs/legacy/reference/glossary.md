# Glossary

| Term | Definition |
|------|-----------|
| **Attestation** | A signed JSON document binding a device to an identity. Contains two signatures (identity + device). |
| **Canonical JSON** | Deterministic JSON serialization with sorted keys and no whitespace. Used to produce consistent signing payloads. |
| **Capabilities** | Permissions granted in an attestation (e.g., `sign-commit`). Child attestations inherit the intersection of parent capabilities. |
| **Controller DID** | The identity's `did:keri:E...` identifier. "Controller" because this key controls the identity. |
| **Device** | Any machine holding a keypair that acts on behalf of an identity. Identified by a `did:key`. |
| **Device DID** | A `did:key:z6Mk...` identifier for a device. Derived directly from the device's Ed25519 public key. |
| **DID** | Decentralized Identifier. A URI scheme for self-sovereign identifiers (W3C spec). |
| **`did:keri`** | DID method using KERI (Key Event Receipt Infrastructure). Supports key rotation while preserving the identifier. |
| **`did:key`** | DID method where the public key is embedded in the identifier itself. Self-resolving, not rotatable. |
| **Ed25519** | An elliptic curve digital signature algorithm. Used for all Auths signing operations. |
| **FFI** | Foreign Function Interface. Mechanism for calling Rust code from C, Swift, Kotlin, etc. |
| **Identity** | A stable cryptographic identifier (`did:keri`) representing a person or entity. Survives key rotation. |
| **Inception event** | The first event in a KERI Key Event Log. Creates the identity and commits to the first rotation key. |
| **KEL** | Key Event Log. A hash-linked sequence of KERI events (inception, rotation, interaction) stored at `refs/keri/kel`. |
| **KERI** | Key Event Receipt Infrastructure. A protocol for decentralized key management with pre-rotation. |
| **Key alias** | A human-readable name for a key stored in the platform keychain (e.g., `my-key`, `laptop-key`). |
| **Multicodec** | A self-describing codec identifier. Ed25519 public keys use prefix `0xED01`. |
| **Platform keychain** | OS-native secure storage: macOS Keychain, Windows Credential Manager, Linux Secret Service. |
| **Pre-rotation** | A KERI feature where the hash of the next rotation key is committed in advance, preventing key hijacking. |
| **Revocation** | The act of disabling a device's attestation. Sets `revoked: true` in the attestation. |
| **Rotation** | Replacing the active signing key while preserving the identity DID. Recorded in the KEL. |
| **UniFFI** | Mozilla's tool for generating language bindings (Swift, Kotlin, Python) from Rust. |
| **WASM** | WebAssembly. Auths uses it to run `auths-verifier` in browsers and Node.js. |
