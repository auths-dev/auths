# auths-keri

KERI CESR translation layer for Auths. Converts between Auths' internal JSON event representation and spec-compliant [CESR](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) streams (Trust over IP KERI v0.9).

## Why a separate crate?

The KERI specification is still a draft under active revision at Trust over IP. The core Auths crates (`auths-id`, `auths-verifier`, `auths-core`) use KERI-inspired concepts (key event logs, pre-rotation, SAIDs) but with a Git-native JSON storage format that prioritizes developer ergonomics over wire-level spec compliance.

This crate exists to isolate CESR-specific logic and dependencies (notably `cesride`) from the core stack:

- **Spec volatility**: KERI field names, counter codes, and serialization rules may change before the spec is finalized. Changes here don't ripple through the identity or verification layers.
- **Dependency isolation**: `cesride` (the Rust CESR code table implementation) is a substantial dependency. Crates like `auths-verifier` are designed for minimal-dependency embedding (FFI, WASM) and should not pull in CESR code tables.
- **Opt-in interoperability**: Most Auths users never need CESR. The translation layer is only needed when exchanging key event logs with external KERI implementations (keripy, keriox, etc.).

The core codebase remains untouched. Git-native JSON storage remains the primary format. This crate wraps existing types for export/import without replacing them.

## How it fits in the architecture

```
auths-cli / auths-sdk (unchanged)
  |
  +-- auths-id (unchanged -- internal JSON events, Git storage)
  |     |
  |     +-- KelPort trait (returns Vec<Event>)
  |
  +-- auths-keri (THIS CRATE -- opt-in translation layer)
        |
        +-- codec.rs     -- CesrCodec trait + CesrV1Codec backed by cesride
        +-- said.rs      -- Spec-compliant SAID with # placeholder
        +-- version.rs   -- Dynamic KERI10JSON{size}_ version strings
        +-- event.rs     -- Detached-signature event serialization
        +-- stream.rs    -- Full CESR stream assembly (events + attachments)
        +-- roundtrip.rs -- Export auths KEL -> CESR, import CESR -> auths types
```

**Dependency direction**: `auths-keri` depends on `auths-verifier` and `auths-crypto`. It never flows the other way. The core crates have no knowledge of this crate's existence.

## Usage

### Export a key event log as CESR

```rust
use auths_keri::{CesrV1Codec, export_kel_as_cesr};

let codec = CesrV1Codec::new();
let stream = export_kel_as_cesr(&codec, &events)?;
std::fs::write("identity.cesr", &stream.bytes)?;
```

### Import a CESR stream back to Auths events

```rust
use auths_keri::{CesrV1Codec, import_cesr_to_events};

let codec = CesrV1Codec::new();
let cesr_bytes = std::fs::read("identity.cesr")?;
let events = import_cesr_to_events(&codec, &cesr_bytes)?;
```

### Encode/decode individual CESR primitives

```rust
use auths_keri::{CesrV1Codec, CesrCodec, KeyType};

let codec = CesrV1Codec::new();
let qualified = codec.encode_pubkey(&key_bytes, KeyType::Ed25519)?;
// "D..." (44 chars)
```

## What this crate does differently from the internal format

| Aspect | Internal (auths-verifier) | Spec-compliant (auths-keri) |
|--------|--------------------------|----------------------------|
| `d` field during hashing | Empty string `""` | 44-char `#` placeholder |
| `x` field (signature) | Embedded in JSON body | Stripped; attached as CESR group after JSON |
| `i` field (inception) | Set independently | Self-certifying: `i == d` |
| Version string `v` | Static `KERI10JSON000000_` | Computed `KERI10JSON{hex_size}_` |
| Serialization field order | Struct declaration order | KERI spec order (v, t, d, i, s, ...) |

## Future directions

Once the KERI specification exits draft status and stabilizes, several extensions become viable:

- **Binary-domain CESR**: Currently text-domain only (`qb64`). Binary domain (`qb2`) is more compact for network transport and could be added as an alternative stream format.
- **CBOR/MessagePack serialization**: KERI supports multiple serialization formats beyond JSON. The version string protocol (`KERI10CBOR`, `KERI10MGPK`) already accommodates this.
- **Delegation events (`dip`/`drt`)**: Delegated inception and rotation for hierarchical identity structures.
- **Multi-sig support**: Weighted threshold signatures (`kt > 1`) with multiple indexed signatures per event.
- **OOBI generation**: Out-of-Band Introductions for discovering and bootstrapping trust with other KERI identities.
- **TEL/ACDC integration**: Transaction Event Logs and Authentic Chained Data Containers for verifiable credentials anchored to KERI identities.
- **Cross-implementation validation**: Automated test suite that validates output against keripy (Python reference implementation) and keriox (Rust alternative).
- **Native CESR storage**: If CESR stabilizes, a future option would be storing CESR streams directly in Git refs alongside (or instead of) JSON, reducing the translation overhead for interop-heavy deployments.
