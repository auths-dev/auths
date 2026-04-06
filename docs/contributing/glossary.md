# Glossary

## Identity and cryptography

| Term | Definition |
|------|-----------|
| **AID** | Autonomic Identifier. A self-certifying identifier derived from the inception event's public key. In Auths, the AID is the KERI prefix embedded in the `did:keri:E...` identifier. |
| **Attestation** | A signed JSON document binding a device to an identity. Contains two signatures: one from the identity key (identity_signature) and one from the device key (device_signature). Fields include version, rid, issuer, subject, device_public_key, capabilities, and expires_at. |
| **Canonical JSON** | Deterministic JSON serialization with sorted keys and no whitespace (RFC 8785). Used to produce consistent signing payloads via the `json-canon` crate. |
| **Capabilities** | Permissions granted in an attestation (e.g., `sign-commit`). Child attestations inherit the intersection of parent capabilities. |
| **DID** | Decentralized Identifier. A URI scheme for self-sovereign identifiers defined by the W3C specification. Auths uses two DID methods: `did:keri` and `did:key`. |
| **Ed25519** | An elliptic curve digital signature algorithm over Curve25519. Used for all Auths signing operations. Produces 64-byte signatures from 32-byte keys. |
| **Inception event** | The first event in a KERI Key Event Log. Creates the identity, commits to the initial public key, and pre-commits to the first rotation key via a hash. The inception event's content hash becomes the permanent identity prefix (AID). |
| **KEL** | Key Event Log. A hash-linked, append-only sequence of KERI events (inception, rotation, interaction). Stored in Auths as a Git commit chain at `refs/did/keri/<prefix>/kel`. |
| **KERI** | Key Event Receipt Infrastructure. A protocol for decentralized key management with pre-rotation, enabling key rotation without changing the identifier. |
| **Key name** | A human-readable name for a key stored in the platform keychain (e.g., `my-key`, `laptop-key`). Maps to a `SecureSeed` in the OS-native credential store. Also referred to as "key alias" in internal API types. |
| **Pre-rotation** | A KERI mechanism where the hash of the next rotation key is committed in the current event. An attacker who compromises the current key cannot rotate the identity because they lack the pre-image of the next-key commitment. |
| **Rotation** | Replacing the active signing key while preserving the identity DID. Recorded as a rotation event in the KEL. The new key must match the previously committed next-key hash. |
| **SAID** | Self-Addressing Identifier. A content-addressed hash that uniquely identifies a KERI event. Computed over the canonicalized event data. |

## DID methods

| Term | Definition |
|------|-----------|
| **`did:keri`** | DID method using KERI. The identifier is derived from the inception event and remains stable across key rotations. Format: `did:keri:E<base64url-encoded-prefix>`. Used as the primary identity identifier (Controller DID). |
| **`did:key`** | DID method where the Ed25519 public key is directly embedded in the identifier using multicodec encoding. Format: `did:key:z6Mk<base58btc-encoded-key>`. Self-resolving but not rotatable. Used as the device identifier (Device DID). |
| **Controller DID** | The identity's `did:keri:E...` identifier. Called "controller" because this key controls the identity. |
| **Device DID** | A `did:key:z6Mk...` identifier for a device. Derived directly from the device's Ed25519 public key. |
| **Multicodec** | A self-describing codec identifier prefix. Ed25519 public keys use the `0xED01` prefix in multicodec encoding. |

## Devices and keys

| Term | Definition |
|------|-----------|
| **Device** | Any machine holding a keypair that acts on behalf of an identity. Each device is identified by a `did:key` derived from its Ed25519 public key. |
| **Identity** | A stable cryptographic identifier (`did:keri`) representing a person or entity. Survives key rotation because the DID is derived from the inception event, not from the current key. |
| **Platform keychain** | OS-native secure storage used to hold key material: macOS Keychain (Security Framework), Linux Secret Service, or Windows Credential Manager. |
| **Revocation** | The act of disabling a device's attestation. Sets `revoked_at` on the attestation record. Revoked devices can no longer sign on behalf of the identity. |
| **SecureSeed** | A newtype wrapping `[u8; 32]` with no `Debug`, `Display`, or `Clone` implementation. Prevents accidental logging or copying of raw key material. |
| **Witness** | A third-party node that observes and receipts KERI events. Witnesses provide an additional layer of accountability by independently recording event sequences, making it harder for an attacker to present different event histories to different parties. |

## Storage and architecture

| Term | Definition |
|------|-----------|
| **DLQ** | Dead Letter Queue. A Redis Stream (`auths:dlq:archival`) that stores KERI events whose Git write failed after all retry attempts. Preserves FIFO ordering for replay. |
| **Git ref** | A named pointer in a Git repository (e.g., `refs/auths/identity`, `refs/keri/kel`). Auths stores all identity data and attestations as Git refs in the `~/.auths` repository. |
| **`refs/auths/`** | Git ref namespace for identity data and attestations. |
| **`refs/keri/`** | Git ref namespace for KERI Key Event Logs. |

## Bindings and embedding

| Term | Definition |
|------|-----------|
| **FFI** | Foreign Function Interface. The C-ABI boundary exposed by `auths-verifier` (feature: `ffi`) for calling verification functions from C, Swift, Kotlin, and other languages. |
| **UniFFI** | Mozilla's tool for generating language bindings (Swift, Kotlin, Python) from Rust. Used by `auths-mobile-ffi` and `auths-verifier-swift`. |
| **WASM** | WebAssembly. `auths-verifier` compiles to WASM (feature: `wasm`) for use in browsers and Node.js via the `@auths/verifier` npm package. |
