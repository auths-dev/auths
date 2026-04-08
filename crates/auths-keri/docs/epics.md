# KERI Spec Compliance Epics

**Spec reference:** [Trust over IP KSWG KERI Specification](https://trustoverip.github.io/kswg-keri-specification/)
**Crate:** `crates/auths-keri/`
**Based on:** `docs/spec_compliance_audit.md`

This document contains implementation-ready epics and tasks to bring `auths-keri` into compliance with the KERI specification. Each task includes current code, spec requirement, and fix with code snippets.

**Downstream crates that will be affected:** auths-verifier, auths-core, auths-id, auths-storage, auths-infra-git, auths-infra-http, auths-index, auths-radicle, auths-cli, auths-sdk. All import from `auths_keri::` — any struct/type changes here cascade.

---

## Typing Discipline (applies to ALL epics)

Every change MUST follow "parse, don't validate." Never introduce a new `String` or `Vec<String>` field for structured KERI data. Use newtypes that validate at deserialization time.

**The test:** if you can assign a SAID to a key field, a threshold to a version string field, or a backer AID to a commitment field and it compiles — the types are wrong.

## Critical Dependency: `serde_json` `preserve_order` Feature

`auths-keri/Cargo.toml` enables `serde_json` with `preserve_order`. This uses `IndexMap` instead of `BTreeMap` for JSON objects, meaning **field insertion order is preserved during serialization and deserialization**. This is why the custom `Serialize` impls enforce field order — without `preserve_order`, `serde_json::Map` would alphabetize keys, breaking SAID computation and spec compliance. Every epic that touches serialization depends on this. Do not remove it.

---

## Epic 1: Strong Newtypes for Event Fields

Replace all `String` and `Vec<String>` fields on event structs with validated newtypes. This prevents invalid data from propagating past deserialization and eliminates ad-hoc parsing scattered across validation code.

### Task 1.1: Create `Threshold` enum for `kt`, `nt`, `bt`

**Spec:** Thresholds are hex-encoded non-negative integers (`"1"`, `"2"`, `"a"`) OR lists of fractional weight clauses (`[["1/2","1/2","1/2"]]`). Clauses are ANDed; each clause is satisfied when the sum of weights for verified signatures >= 1.

**Current code** (`events.rs:179`, `events.rs:250`, `events.rs:187`, `validate.rs:135-140`):
```rust
// events.rs — raw strings, no format enforcement
pub kt: String,
pub nt: String,
pub bt: String,

// validate.rs:135 — ad-hoc parse, WRONG base (decimal instead of hex)
fn parse_threshold(raw: &str) -> Result<u64, ValidationError> {
    raw.parse::<u64>()  // decimal parse — breaks for hex values >= "a"
        .map_err(|_| ValidationError::MalformedSequence {
            raw: raw.to_string(),
        })
}
```

**Fix:** Create `types.rs::Threshold` with hex parsing and weighted support:

```rust
// types.rs — add this enum

/// An exact rational fraction (numerator / denominator).
///
/// Used in weighted thresholds to avoid IEEE 754 precision issues.
/// 1/3 + 1/3 + 1/3 must equal exactly 1, which f64 cannot represent.
///
/// Usage:
/// ```ignore
/// let f: Fraction = "1/3".parse().unwrap();
/// assert_eq!(f.numerator, 1);
/// assert_eq!(f.denominator, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fraction {
    pub numerator: u64,
    pub denominator: u64,
}

impl Fraction {
    pub fn new(numerator: u64, denominator: u64) -> Self {
        assert!(denominator > 0, "denominator must be non-zero");
        Self { numerator, denominator }
    }

    /// Parse the numerator and denominator from a "n/d" string.
    pub fn parse_parts(&self) -> Result<(u64, u64), &'static str> {
        Ok((self.numerator, self.denominator))
    }
}

impl std::str::FromStr for Fraction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (num, den) = s.split_once('/')
            .ok_or_else(|| format!("invalid fraction: {s:?}, expected 'n/d'"))?;
        let n = num.parse::<u64>()
            .map_err(|_| format!("invalid numerator: {num:?}"))?;
        let d = den.parse::<u64>()
            .map_err(|_| format!("invalid denominator: {den:?}"))?;
        if d == 0 {
            return Err("denominator must be non-zero".into());
        }
        Ok(Self { numerator: n, denominator: d })
    }
}

impl Serialize for Fraction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}/{}", self.numerator, self.denominator))
    }
}

impl<'de> Deserialize<'de> for Fraction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// KERI signing/backer threshold.
///
/// Simple thresholds are hex-encoded integers ("1", "2", "a").
/// Weighted thresholds are clause lists of `Fraction` values.
/// Uses exact integer arithmetic to avoid IEEE 754 precision issues
/// (e.g., 1/3 + 1/3 + 1/3 must equal exactly 1).
///
/// Usage:
/// ```ignore
/// let t: Threshold = serde_json::from_str("\"2\"").unwrap();
/// assert_eq!(t, Threshold::Simple(2));
/// let w: Threshold = serde_json::from_str("[[\"1/3\",\"1/3\",\"1/3\"]]").unwrap();
/// // Verification uses cross-multiplication, not f64
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Threshold {
    /// M-of-N threshold (hex-encoded integer in JSON)
    Simple(u64),
    /// Fractionally weighted threshold (list of clause lists).
    /// Each clause is a list of rational fractions.
    /// Clauses are ANDed; each is satisfied when sum of weights >= 1.
    Weighted(Vec<Vec<Fraction>>),
}

impl Threshold {
    /// Get the simple threshold value, if this is a simple threshold.
    pub fn simple_value(&self) -> Option<u64> {
        match self {
            Threshold::Simple(v) => Some(*v),
            Threshold::Weighted(_) => None,
        }
    }
}

impl Serialize for Threshold {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Threshold::Simple(v) => serializer.serialize_str(&format!("{:x}", v)),
            Threshold::Weighted(clauses) => clauses.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Threshold {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => {
                let v = u64::from_str_radix(&s, 16)
                    .map_err(|_| serde::de::Error::custom(
                        format!("invalid hex threshold: {s:?}")
                    ))?;
                Ok(Threshold::Simple(v))
            }
            serde_json::Value::Array(arr) => {
                let clauses: Vec<Vec<Fraction>> = arr.into_iter().map(|clause| {
                    match clause {
                        serde_json::Value::Array(weights) => weights.into_iter().map(|w| {
                            match w {
                                serde_json::Value::String(s) => s.parse::<Fraction>()
                                    .map_err(serde::de::Error::custom),
                                _ => Err(serde::de::Error::custom("weight must be a fraction string"))
                            }
                        }).collect::<Result<Vec<_>, _>>(),
                        _ => Err(serde::de::Error::custom("clause must be an array"))
                    }
                }).collect::<Result<Vec<_>, _>>()?;
                Ok(Threshold::Weighted(clauses))
            }
            _ => Err(serde::de::Error::custom("threshold must be a hex string or array of clause arrays"))
        }
    }
}
```

Then update all event structs:
```rust
// events.rs — IcpEvent, RotEvent
pub kt: Threshold,  // was String
pub nt: Threshold,  // was String
pub bt: Threshold,  // was String
```

And update `state.rs`:
```rust
// state.rs — KeyState
pub threshold: Threshold,       // was u64
pub next_threshold: Threshold,  // was u64
```

Remove `parse_threshold()` from `validate.rs` — thresholds are now parsed at deserialization.

**Blast radius:** Every call site that constructs `IcpEvent`, `RotEvent`, or `KeyState` must change from `kt: "1".to_string()` to `kt: Threshold::Simple(1)`. Search for `kt:`, `nt:`, `bt:` across the workspace.

### Task 1.2: Create `CesrKey` newtype for `k` and `current_keys`

**Spec:** Keys in the `k` field are fully qualified CESR primitives (e.g., `D` + base64url for Ed25519). The `k` field MUST NOT be empty.

**Current code** (`events.rs:181`, `state.rs:24`):
```rust
// events.rs — raw strings
pub k: Vec<String>,

// state.rs — raw strings
pub current_keys: Vec<String>,

// validate.rs:194 — parsed on the fly, thrown away
let key_bytes = KeriPublicKey::parse(&rot.k[0])
    .map(|k| k.as_bytes().to_vec())
    .map_err(|_| ValidationError::CommitmentMismatch { sequence })?;
```

**Fix:** Create a `CesrKey` newtype in `types.rs`:

```rust
// types.rs — add CesrKey

/// A CESR-encoded public key (e.g., 'D' + base64url Ed25519).
///
/// Wraps the qualified string form. Use `parse_ed25519()` to extract
/// the raw 32-byte key for cryptographic operations.
///
/// Usage:
/// ```ignore
/// let key: CesrKey = serde_json::from_str("\"DBase64urlKey...\"").unwrap();
/// let pubkey = key.parse_ed25519()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CesrKey(String);

impl CesrKey {
    /// Wrap a qualified key string without validation.
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Parse the inner CESR string as an Ed25519 public key.
    pub fn parse_ed25519(&self) -> Result<KeriPublicKey, KeriDecodeError> {
        KeriPublicKey::parse(&self.0)
    }

    /// Get the raw CESR-qualified string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CesrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
```

Then update event structs and `KeyState`:
```rust
// events.rs
pub k: Vec<CesrKey>,  // was Vec<String>

// state.rs
pub current_keys: Vec<CesrKey>,  // was Vec<String>
```

Update `Event::keys()` return type from `Option<&[String]>` to `Option<&[CesrKey]>`.

**Blast radius:** All sites constructing events with `k: vec!["DKey...".to_string()]` must change to `k: vec![CesrKey::new_unchecked("DKey...".to_string())]`. Search for `.k =`, `.k.first()`, `.current_keys` across the workspace.

### Task 1.3: Type commitment fields (`n`, `next_commitment`) as `Vec<Said>`

**Spec:** Next key digests (`n`) are `E`-prefixed Blake3-256 digests, structurally identical to SAIDs.

**Current code** (`events.rs:185`, `state.rs:28`, `crypto.rs:29`):
```rust
// events.rs — raw strings
pub n: Vec<String>,

// state.rs — raw strings
pub next_commitment: Vec<String>,

// crypto.rs:29 — returns untyped String
pub fn compute_next_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}
```

**Fix:** Change return type and field types:

```rust
// crypto.rs — return Said instead of String
pub fn compute_next_commitment(public_key: &[u8]) -> Said {
    let hash = blake3::hash(public_key);
    Said::new_unchecked(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}

// verify_commitment — accept Said
pub fn verify_commitment(public_key: &[u8], commitment: &Said) -> bool {
    let computed = compute_next_commitment(public_key);
    computed.as_str().as_bytes().ct_eq(commitment.as_str().as_bytes()).into()
}
```

Update event structs and `KeyState`:
```rust
// events.rs
pub n: Vec<Said>,  // was Vec<String>

// state.rs
pub next_commitment: Vec<Said>,  // was Vec<String>
```

Update `Event::next_commitments()` return type from `Option<&[String]>` to `Option<&[Said]>`.

**Blast radius:** All sites constructing events with `n: vec!["ENext...".to_string()]` must use `Said`. All call sites of `compute_next_commitment` and `verify_commitment` change. Search for `.n =`, `.next_commitment`, `compute_next_commitment`, `verify_commitment` across the workspace.

### Task 1.4: Create `ConfigTrait` enum for `c` field

**Spec:** Configuration traits are a defined set: `EO` (EstablishmentOnly), `DND` (DoNotDelegate), `DID` (DelegateIsDelegator), `RB` (RegistrarBackers), `NRB` (NoRegistrarBackers). If two conflicting traits appear, the latter supersedes.

**Current code:** The `c` field does not exist on any event struct.

**Fix:** Add the enum and field:

```rust
// types.rs — add ConfigTrait enum

/// KERI configuration trait codes.
///
/// Usage:
/// ```ignore
/// let traits: Vec<ConfigTrait> = serde_json::from_str("[\"EO\",\"DND\"]").unwrap();
/// assert!(traits.contains(&ConfigTrait::EstablishmentOnly));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigTrait {
    /// Establishment-Only: only establishment events in KEL
    #[serde(rename = "EO")]
    EstablishmentOnly,
    /// Do-Not-Delegate: cannot act as delegator
    #[serde(rename = "DND")]
    DoNotDelegate,
    /// Delegate-Is-Delegator: delegated AID treated same as delegator
    #[serde(rename = "DID")]
    DelegateIsDelegator,
    /// Registrar Backers: backer list provides registrar backer AIDs
    #[serde(rename = "RB")]
    RegistrarBackers,
    /// No Registrar Backers: switch back to witnesses
    #[serde(rename = "NRB")]
    NoRegistrarBackers,
}
```

Add to event structs (between `b`/`br`/`ba` and `a`):
```rust
// events.rs — IcpEvent (between b and a)
/// Configuration traits (e.g., EstablishmentOnly, DoNotDelegate)
#[serde(default)]
pub c: Vec<ConfigTrait>,

// events.rs — RotEvent (between ba and a, after Task 2.1)
#[serde(default)]
pub c: Vec<ConfigTrait>,
```

Update the custom `Serialize` impls to always include `c`:
```rust
// IcpEvent Serialize — after "b", before "a"
map.serialize_entry("c", &self.c)?;

// RotEvent Serialize — after "ba", before "a"
map.serialize_entry("c", &self.c)?;
```

IXN events do NOT have a `c` field (spec: IXN fields are `[v, t, d, i, s, p, a]` only).

### Task 1.5: Type backer fields (`b`, `br`, `ba`) as `Vec<Prefix>`

**Spec:** Witness/backer AIDs are fully qualified CESR primitives. For non-transferable witnesses, these are public-key-derived AIDs (e.g., `D`-prefixed).

**Depends on:** Task 3.1 (relax `Prefix` validation to accept non-`E` codes).

**Current code** (`events.rs:189`, `events.rs:260`):
```rust
pub b: Vec<String>,
```

**Fix:**
```rust
// events.rs — IcpEvent
pub b: Vec<Prefix>,  // was Vec<String>

// events.rs — RotEvent (after Task 2.1)
pub br: Vec<Prefix>,  // replaces b
pub ba: Vec<Prefix>,  // replaces b
```

### Task 1.6: Create `VersionString` newtype for `v` field

**Spec:** Version string format is `KERIvvSSSShhhhhh_` (17 chars) for v1.x — protocol ID + hex version + serialization kind + 6 hex chars for byte count + terminator.

**Current code** (`events.rs:13`, `events.rs:170`):
```rust
pub const KERI_VERSION: &str = "KERI10JSON";  // only 10 chars, missing size + terminator
pub v: String,  // no format validation
```

**Fix:** Create a `VersionString` newtype:

```rust
// types.rs

/// KERI v1.x version string: "KERI10JSON{hhhhhh}_" (17 chars).
///
/// Usage:
/// ```ignore
/// let vs = VersionString::new("JSON", 256);
/// assert_eq!(vs.to_string(), "KERI10JSON000100_");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionString {
    /// Serialization kind (e.g., "JSON", "CBOR")
    pub kind: String,
    /// Serialized byte count
    pub size: u32,
}

impl VersionString {
    /// Create a version string for JSON serialization with the given byte count.
    pub fn json(size: u32) -> Self {
        Self { kind: "JSON".to_string(), size }
    }

    /// Create a placeholder version string (size = 0, to be updated after serialization).
    pub fn placeholder() -> Self {
        Self { kind: "JSON".to_string(), size: 0 }
    }
}

impl fmt::Display for VersionString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KERI10{}{:06x}_", self.kind, self.size)
    }
}

impl Serialize for VersionString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VersionString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Accept both full 17-char ("KERI10JSON000100_") and legacy 10-char ("KERI10JSON")
        if s.len() >= 17 && s.ends_with('_') {
            let size_hex = &s[10..16];
            let size = u32::from_str_radix(size_hex, 16)
                .map_err(|_| serde::de::Error::custom(
                    format!("invalid version string size: {size_hex:?}")
                ))?;
            let kind = s[6..10].to_string();
            Ok(Self { kind, size })
        } else if s.starts_with("KERI10") && s.len() >= 10 {
            // Legacy format without size — accept for backwards compat
            let kind = s[6..10].to_string();
            Ok(Self { kind, size: 0 })
        } else {
            Err(serde::de::Error::custom(format!("invalid KERI version string: {s:?}")))
        }
    }
}
```

Update event structs:
```rust
// events.rs
pub v: VersionString,  // was String
```

Replace `KERI_VERSION` constant:
```rust
pub const KERI_VERSION_PREFIX: &str = "KERI10JSON";
```

---

## Epic 2: Event Field Schema Compliance

Fix the field sets of each event type to match the spec exactly. No extra fields, no missing fields.

### Task 2.1: Replace `b` with `br`/`ba` on `RotEvent`

**Spec (ROT field order):** `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]` — ALL required. Rotation uses delta-based witness changes: `br` (remove first) then `ba` (add).

**Current code** (`events.rs:237-267`):
```rust
pub struct RotEvent {
    // ...
    pub bt: String,
    pub b: Vec<String>,   // NON-SPEC: full replacement list
    // MISSING: br, ba
    pub a: Vec<Seal>,
    pub x: String,
}
```

**Fix:** Replace `b` with `br` and `ba`:
```rust
// events.rs — RotEvent struct
/// Backer/witness threshold
pub bt: Threshold,  // already typed from Task 1.1
/// List of backers to remove (processed first)
#[serde(default)]
pub br: Vec<Prefix>,
/// List of backers to add (processed after removals)
#[serde(default)]
pub ba: Vec<Prefix>,
/// Configuration traits
#[serde(default)]
pub c: Vec<ConfigTrait>,
```

Update the custom `Serialize` impl:
```rust
// events.rs — RotEvent Serialize impl (replacing the b entry)
map.serialize_entry("bt", &self.bt)?;
map.serialize_entry("br", &self.br)?;
map.serialize_entry("ba", &self.ba)?;
map.serialize_entry("c", &self.c)?;
map.serialize_entry("a", &self.a)?;
// NO "x" — see Task 2.3
```

**Blast radius:** Every `RotEvent { ... b: vec![], ... }` construction must change to `br: vec![], ba: vec![]`. Search for `RotEvent {` and `.b =` on rot events across `auths-id`, `auths-sdk`, `auths-core`, `auths-verifier`.

### Task 2.2: Always serialize all required fields (remove conditional omission)

**Spec:** All fields listed in each event type schema are REQUIRED. They MUST be present even when empty.

**Current code** (`events.rs:199-226`):
```rust
// IcpEvent Serialize impl — conditionally omits d, a, x
if !self.d.is_empty() {
    map.serialize_entry("d", &self.d)?;
}
// ...
if !self.a.is_empty() {
    map.serialize_entry("a", &self.a)?;
}
```

Same pattern on `RotEvent` and `IxnEvent`.

**Fix:** Always serialize all spec-required fields. Remove all `if !self.X.is_empty()` guards:
```rust
// IcpEvent Serialize impl — always include all fields
let field_count = 13;  // v, t, d, i, s, kt, k, nt, n, bt, b, c, a
let mut map = serializer.serialize_map(Some(field_count))?;
map.serialize_entry("v", &self.v)?;
map.serialize_entry("t", "icp")?;
map.serialize_entry("d", &self.d)?;
map.serialize_entry("i", &self.i)?;
map.serialize_entry("s", &self.s)?;
map.serialize_entry("kt", &self.kt)?;
map.serialize_entry("k", &self.k)?;
map.serialize_entry("nt", &self.nt)?;
map.serialize_entry("n", &self.n)?;
map.serialize_entry("bt", &self.bt)?;
map.serialize_entry("b", &self.b)?;
map.serialize_entry("c", &self.c)?;
map.serialize_entry("a", &self.a)?;
map.end()
```

Same for `RotEvent` (15 fields: `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a`) and `IxnEvent` (7 fields: `v, t, d, i, s, p, a`).

**Note:** The `d` field for event construction will use a `Said::default()` (empty), which serializes as `""`. The `finalize_*` functions compute and set the real SAID. This is acceptable during construction; finalized events always have a proper SAID.

**Cleanup required in `compute_said` (`said.rs`):** After this task, `d` is always present in the serialized JSON (never conditionally omitted). The special logic in `compute_said` that injects `d` after `t` when the serializer omits it (`if k == "t" && !has_d { new_obj.insert("d", ...) }` at `said.rs:52-55`) becomes dead code. When implementing this task, simplify `compute_said` to remove the `has_d` check and the d-after-t injection branch — `d` will always be in the input object.

### Task 2.3: Externalize signatures (remove `x` field)

**Spec:** Signatures MUST be attached using CESR attachment codes. They are NOT part of the event body. The spec's event field lists do not include `x` or any signature field.

**Current code** (`events.rs:194-195`, `events.rs:265-266`, `events.rs:324-325`):
```rust
/// Event signature (Ed25519, base64url-no-pad)
#[serde(default)]
pub x: String,
```

The `x` field is serialized conditionally, `serialize_for_signing` zeros it, and `compute_said` removes it. This is a workaround for storing signatures inline.

**Fix (phased):**

**Phase A — struct change:** Remove `x` from all event structs. Create a wrapper:
```rust
// events.rs — new SignedEvent wrapper

/// An event paired with its detached signature(s).
///
/// Per the KERI spec, signatures are not part of the event body.
/// They are attached externally (CESR attachment codes or stored alongside).
///
/// Usage:
/// ```ignore
/// let signed = SignedEvent {
///     event: Event::Icp(icp),
///     signatures: vec![IndexedSignature { index: 0, sig: sig_bytes }],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    /// The event body (no signature data)
    pub event: Event,
    /// Controller-indexed signatures
    pub signatures: Vec<IndexedSignature>,
}

/// A single indexed controller signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedSignature {
    /// Index into the key list (which key signed)
    pub index: u32,
    /// Raw signature bytes (64 bytes for Ed25519)
    pub sig: Vec<u8>,
}
```

**Phase B — serialization simplification:** `serialize_for_signing` becomes trivial:
```rust
// validate.rs — simplified serialize_for_signing
pub fn serialize_for_signing(event: &Event) -> Result<Vec<u8>, ValidationError> {
    // With x removed, just serialize the event body with SAID placeholder
    match event {
        Event::Icp(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default();
            serde_json::to_vec(&Event::Icp(e))
        }
        Event::Rot(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            serde_json::to_vec(&Event::Rot(e))
        }
        Event::Ixn(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            serde_json::to_vec(&Event::Ixn(e))
        }
    }
    .map_err(|e| ValidationError::Serialization(e.to_string()))
}
```

`compute_said` no longer needs to strip `x` — the field simply doesn't exist.

**Phase C — storage migration:** KEL storage must be updated to store `(event_json, signatures_json)` separately. This affects `EventLogReader`/`EventLogWriter` traits in `kel_io.rs` and all implementations in `auths-storage` and `auths-infra-git`.

**Blast radius:** This is the largest change. Every crate that creates, stores, reads, or verifies events must migrate. The `Event::signature()` method is removed. Search for `.x =`, `.signature()`, `event.x`, `serialize_for_signing` across the workspace. Consider doing this as a separate PR after all other field changes stabilize.

### Task 2.4: Remove `Event::signature()` method and update accessor API

**Depends on:** Task 2.3

After removing `x`, remove the `signature()` method from the `Event` enum:
```rust
// events.rs — REMOVE this method
pub fn signature(&self) -> &str {
    match self {
        Event::Icp(e) => &e.x,
        Event::Rot(e) => &e.x,
        Event::Ixn(e) => &e.x,
    }
}
```

Callers should use `SignedEvent.signatures` instead.

---

## Epic 3: Prefix and AID Type Flexibility

The spec supports both self-addressing AIDs (`E`-prefixed, derived from SAID) and non-self-addressing AIDs (`D`-prefixed, derived from public key). Our `Prefix` type only accepts `E`.

### Task 3.1: Relax `Prefix` validation to accept any CESR derivation code

**Spec:** AIDs can be self-addressing (`E` for Blake3-256) or non-self-addressing (`D` for Ed25519, `1` for secp256k1, etc.). Non-transferable witness AIDs are public-key-derived (e.g., `D`-prefixed).

**Current code** (`types.rs:21-37`):
```rust
fn validate_keri_derivation_code(s: &str, type_label: &'static str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError { type_name: type_label, reason: "must not be empty".into() });
    }
    if !s.starts_with('E') {
        return Err(KeriTypeError {
            type_name: type_label,
            reason: format!("must start with 'E' (Blake3 derivation code), got '{}'", &s[..s.len().min(10)]),
        });
    }
    Ok(())
}
```

**Fix:** Split validation — `Prefix` accepts any valid CESR code, `Said` remains `E`-only:

```rust
// types.rs — separate validators

/// Validate a CESR derivation code for AIDs (Prefix).
/// Accepts any valid CESR primitive prefix character.
fn validate_prefix_derivation_code(s: &str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError {
            type_name: "Prefix",
            reason: "must not be empty".into(),
        });
    }
    let first = s.as_bytes()[0];
    // CESR codes start with uppercase letter or digit
    // D = Ed25519, E = Blake3-256, 1 = secp256k1, etc.
    if !first.is_ascii_uppercase() && !first.is_ascii_digit() {
        return Err(KeriTypeError {
            type_name: "Prefix",
            reason: format!(
                "must start with a CESR derivation code (uppercase letter or digit), got '{}'",
                &s[..s.len().min(10)]
            ),
        });
    }
    Ok(())
}

/// Validate a CESR derivation code for SAIDs (digest only).
fn validate_said_derivation_code(s: &str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError {
            type_name: "Said",
            reason: "must not be empty".into(),
        });
    }
    // SAIDs are always digests — currently only Blake3-256 ('E')
    if !s.starts_with('E') {
        return Err(KeriTypeError {
            type_name: "Said",
            reason: format!(
                "must start with 'E' (Blake3 derivation code), got '{}'",
                &s[..s.len().min(10)]
            ),
        });
    }
    Ok(())
}

// Update Prefix::new to use validate_prefix_derivation_code
impl Prefix {
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_prefix_derivation_code(&s)?;
        Ok(Self(s))
    }
}

// Update Said::new to use validate_said_derivation_code
impl Said {
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_said_derivation_code(&s)?;
        Ok(Self(s))
    }
}
```

### Task 3.2: Conditional `i == d` enforcement for self-addressing AIDs only

**Spec:** "When the AID is self-addressing, `d` and `i` MUST have the same value." Non-self-addressing AIDs have `i` derived from the public key, not from `d`.

**Current code** (`validate.rs:259-264`):
```rust
if icp.i.as_str() != icp.d.as_str() {
    return Err(ValidationError::InvalidSaid {
        expected: icp.d.clone(),
        actual: Said::new_unchecked(icp.i.as_str().to_string()),
    });
}
```

Always enforces `i == d`.

**Fix:**
```rust
// validate.rs — verify_event_crypto, ICP branch
let is_self_addressing = icp.i.as_str().starts_with('E');
if is_self_addressing && icp.i.as_str() != icp.d.as_str() {
    return Err(ValidationError::InvalidSaid {
        expected: icp.d.clone(),
        actual: Said::new_unchecked(icp.i.as_str().to_string()),
    });
}
// For non-self-addressing: i is derived from pubkey, no d comparison needed
```

Also update `finalize_icp_event`:
```rust
// validate.rs — finalize_icp_event
pub fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, ValidationError> {
    let value = serde_json::to_value(Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value)
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;

    icp.d = said.clone();
    // Only set i = d for self-addressing AIDs
    if icp.i.is_empty() || icp.i.as_str().starts_with('E') {
        icp.i = Prefix::new_unchecked(said.into_inner());
    }
    // For non-self-addressing, i was already set by caller (e.g., from public key)

    Ok(icp)
}
```

---

## Epic 4: Seal Format Compliance

Replace the non-spec seal structure with spec-compliant seal variants.

### Task 4.1: Replace `Seal` struct with spec-compliant enum

**Spec defines 7 seal types**, distinguished by field shape (not a type discriminator):
- Digest: `{"d": "<SAID>"}`
- Merkle Root: `{"rd": "<digest>"}`
- Source Event: `{"s": "<hex-sn>", "d": "<SAID>"}`
- Key Event: `{"i": "<AID>", "s": "<hex-sn>", "d": "<SAID>"}`
- Latest Establishment: `{"i": "<AID>"}`
- Registrar Backer: `{"bi": "<AID>", "d": "<SAID>"}`
- Typed: `{"t": "<type>", "d": "<SAID>"}`

**Current code** (`events.rs:111-119`):
```rust
pub struct Seal {
    pub d: Said,
    #[serde(rename = "type")]
    pub seal_type: SealType,  // NON-SPEC: adds "type" field to JSON
}
```

**Fix:** Replace with an untagged enum:

```rust
// events.rs — replace Seal struct and SealType enum

/// KERI seal — anchors external data in an event's `a` field.
///
/// Variants are distinguished by field shape (untagged), not by a "type" discriminator.
/// Per the spec, seal fields MUST appear in the specified order.
///
/// Usage:
/// ```ignore
/// let seal = Seal::Digest { d: Said::new_unchecked("ESAID...".into()) };
/// let json = serde_json::to_string(&seal).unwrap();
/// assert_eq!(json, r#"{"d":"ESAID..."}"#);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Seal {
    /// Digest seal: `{"d": "<SAID>"}`
    Digest { d: Said },
    /// Source event seal: `{"s": "<hex-sn>", "d": "<SAID>"}`
    SourceEvent { s: KeriSequence, d: Said },
    /// Key event seal: `{"i": "<AID>", "s": "<hex-sn>", "d": "<SAID>"}`
    KeyEvent { i: Prefix, s: KeriSequence, d: Said },
    /// Latest establishment event seal: `{"i": "<AID>"}`
    LatestEstablishment { i: Prefix },
    /// Merkle tree root digest seal: `{"rd": "<digest>"}`
    MerkleRoot { rd: Said },
    /// Registrar backer seal: `{"bi": "<AID>", "d": "<SAID>"}`
    RegistrarBacker { bi: Prefix, d: Said },
}

impl Seal {
    /// Create a digest seal from a SAID.
    pub fn digest(said: impl Into<String>) -> Self {
        Self::Digest { d: Said::new_unchecked(said.into()) }
    }

    /// Create a key event seal.
    pub fn key_event(prefix: Prefix, sequence: KeriSequence, said: Said) -> Self {
        Self::KeyEvent { i: prefix, s: sequence, d: said }
    }

    /// Get the digest from this seal, if it has one.
    pub fn digest_value(&self) -> Option<&Said> {
        match self {
            Seal::Digest { d } => Some(d),
            Seal::SourceEvent { d, .. } => Some(d),
            Seal::KeyEvent { d, .. } => Some(d),
            Seal::RegistrarBacker { d, .. } => Some(d),
            Seal::MerkleRoot { rd } => Some(rd),
            Seal::LatestEstablishment { .. } => None,
        }
    }
}
```

Custom `Serialize`/`Deserialize` to enforce field order and untagged discrimination:

```rust
impl Serialize for Seal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Seal::Digest { d } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("d", d)?;
                map.end()
            }
            Seal::SourceEvent { s, d } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("s", s)?;
                map.serialize_entry("d", d)?;
                map.end()
            }
            Seal::KeyEvent { i, s, d } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("i", i)?;
                map.serialize_entry("s", s)?;
                map.serialize_entry("d", d)?;
                map.end()
            }
            Seal::LatestEstablishment { i } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("i", i)?;
                map.end()
            }
            Seal::MerkleRoot { rd } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("rd", rd)?;
                map.end()
            }
            Seal::RegistrarBacker { bi, d } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("bi", bi)?;
                map.serialize_entry("d", d)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::Map::deserialize(deserializer)?;

        // Discriminate by field presence (spec-defined, unambiguous)
        if map.contains_key("rd") {
            let rd = map.get("rd")
                .and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("rd must be a string"))?;
            Ok(Seal::MerkleRoot { rd: Said::new_unchecked(rd.to_string()) })
        } else if map.contains_key("bi") {
            let bi = map.get("bi")
                .and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("bi must be a string"))?;
            let d = map.get("d")
                .and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("d required for registrar backer seal"))?;
            Ok(Seal::RegistrarBacker {
                bi: Prefix::new_unchecked(bi.to_string()),
                d: Said::new_unchecked(d.to_string()),
            })
        } else if map.contains_key("i") && map.contains_key("s") && map.contains_key("d") {
            let i = map.get("i").and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("i must be a string"))?;
            let s: KeriSequence = serde_json::from_value(map.get("s").cloned()
                .ok_or_else(|| serde::de::Error::custom("s required"))?)
                .map_err(serde::de::Error::custom)?;
            let d = map.get("d").and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("d must be a string"))?;
            Ok(Seal::KeyEvent {
                i: Prefix::new_unchecked(i.to_string()),
                s,
                d: Said::new_unchecked(d.to_string()),
            })
        } else if map.contains_key("i") {
            let i = map.get("i").and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("i must be a string"))?;
            Ok(Seal::LatestEstablishment {
                i: Prefix::new_unchecked(i.to_string()),
            })
        } else if map.contains_key("s") && map.contains_key("d") {
            let s: KeriSequence = serde_json::from_value(map.get("s").cloned()
                .ok_or_else(|| serde::de::Error::custom("s required"))?)
                .map_err(serde::de::Error::custom)?;
            let d = map.get("d").and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("d must be a string"))?;
            Ok(Seal::SourceEvent {
                s,
                d: Said::new_unchecked(d.to_string()),
            })
        } else if map.contains_key("d") {
            let d = map.get("d").and_then(|v| v.as_str())
                .ok_or_else(|| serde::de::Error::custom("d must be a string"))?;
            Ok(Seal::Digest { d: Said::new_unchecked(d.to_string()) })
        } else {
            Err(serde::de::Error::custom("unrecognized seal format"))
        }
    }
}
```

**Migration for existing code:** The current `SealType` enum (`DeviceAttestation`, `Revocation`, etc.) is an auths-specific extension. The "type" information should live in the anchored document (the thing the digest points to), not on the seal itself. All current seals become `Seal::Digest { d }`:

```rust
// Before:
Seal::device_attestation("EDigest123")
// After:
Seal::digest("EDigest123")
```

Remove `SealType` enum, `Seal::new()`, `Seal::device_attestation()`, `Seal::revocation()`, `Seal::delegation()`, `Seal::idp_binding()`.

**Blast radius:** Search for `Seal::device_attestation`, `Seal::revocation`, `Seal::delegation`, `Seal::idp_binding`, `Seal::new`, `seal_type`, `SealType` across the workspace.

### Task 4.2: Update `find_seal_in_kel` for new seal variants

**Current code** (`validate.rs:430-441`):
```rust
pub fn find_seal_in_kel(events: &[Event], digest: &str) -> Option<u64> {
    for event in events {
        if let Event::Ixn(ixn) = event {
            for seal in &ixn.a {
                if seal.d.as_str() == digest {
                    return Some(ixn.s.value());
                }
            }
        }
    }
    None
}
```

**Fix:** Use `digest_value()` on the new enum:
```rust
pub fn find_seal_in_kel(events: &[Event], digest: &str) -> Option<u64> {
    for event in events {
        if let Event::Ixn(ixn) = event {
            for seal in &ixn.a {
                if seal.digest_value().is_some_and(|d| d.as_str() == digest) {
                    return Some(ixn.s.value());
                }
            }
        }
    }
    None
}
```

---

## Epic 5: Version String and SAID Integration

The version string must include the serialized byte count, and SAID computation must use the correct version string.

### Task 5.1: Two-pass SAID computation with version string

**Spec:** The `v` field includes the total serialized byte count as 6 hex chars. SAID computation must use the correct `v` value.

**Current code** (`said.rs:22-71`): Computes SAID with whatever `v` value the event has (typically `"KERI10JSON"`, the truncated version without size).

The `compute_version_string()` in `version.rs` (behind `cesr` feature) already implements the correct two-pass pattern but is unused in the default event path.

**Fix:** Move the two-pass logic into `compute_said` (no feature gate):

```rust
// said.rs — updated compute_said

pub fn compute_said(event: &serde_json::Value) -> Result<Said, KeriTranslationError> {
    let obj = event.as_object().ok_or(KeriTranslationError::MissingField {
        field: "root object",
    })?;

    let placeholder = serde_json::Value::String(SAID_PLACEHOLDER.to_string());
    let event_type = obj.get("t").and_then(|v| v.as_str()).unwrap_or("");
    let has_d = obj.contains_key("d");

    // Build the map with placeholders
    let mut new_obj = serde_json::Map::new();
    let mut d_injected = false;

    for (k, v) in obj {
        if k == "x" {
            continue;  // legacy: skip x if present during migration
        } else if k == "d" {
            new_obj.insert("d".to_string(), placeholder.clone());
            d_injected = true;
        } else if k == "i" && event_type == "icp" {
            new_obj.insert("i".to_string(), placeholder.clone());
        } else {
            new_obj.insert(k.clone(), v.clone());
            if k == "t" && !has_d {
                new_obj.insert("d".to_string(), placeholder.clone());
                d_injected = true;
            }
        }
    }

    if !d_injected {
        new_obj.insert("d".to_string(), placeholder.clone());
    }

    // Pass 1: serialize with placeholder v to measure size
    // Insert a placeholder version string to get approximate size
    let version_placeholder = "KERI10JSON000000_";
    new_obj.insert("v".to_string(), serde_json::Value::String(version_placeholder.to_string()));

    let pass1 = serde_json::to_vec(&serde_json::Value::Object(new_obj.clone()))
        .map_err(KeriTranslationError::SerializationFailed)?;

    // Pass 2: compute correct version string with actual size and re-serialize
    let version_string = format!("KERI10JSON{:06x}_", pass1.len());
    new_obj.insert("v".to_string(), serde_json::Value::String(version_string));

    let serialized = serde_json::to_vec(&serde_json::Value::Object(new_obj))
        .map_err(KeriTranslationError::SerializationFailed)?;

    let hash = blake3::hash(&serialized);
    Ok(Said::new_unchecked(format!(
        "E{}",
        URL_SAFE_NO_PAD.encode(hash.as_bytes())
    )))
}
```

### Task 5.2: Update event finalization to set version string with byte count

**Current code** (`validate.rs:412-421`):
```rust
pub fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, ValidationError> {
    let value = serde_json::to_value(Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value)
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    icp.d = said.clone();
    icp.i = Prefix::new_unchecked(said.into_inner());
    Ok(icp)
}
```

**Fix:** After computing the SAID, re-serialize to get final byte count and update `v`:

```rust
pub fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, ValidationError> {
    let value = serde_json::to_value(Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value)
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;

    icp.d = said.clone();
    if icp.i.is_empty() || icp.i.as_str().starts_with('E') {
        icp.i = Prefix::new_unchecked(said.into_inner());
    }

    // Compute final serialized size for version string
    let final_bytes = serde_json::to_vec(&Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    icp.v = VersionString::json(final_bytes.len() as u32);

    Ok(icp)
}
```

Create analogous `finalize_rot_event` and `finalize_ixn_event` functions.

### Task 5.3: Fix receipt version string

**Current code** (`witness/receipt.rs:28`):
```rust
pub const KERI_VERSION: &str = "KERI10JSON000000_";  // hardcoded zeros — always wrong
```

**Fix:** Compute the receipt version string dynamically during `ReceiptBuilder::build()`:

```rust
impl ReceiptBuilder {
    pub fn build(self) -> Option<Receipt> {
        let mut receipt = Receipt {
            v: VersionString::placeholder(),  // temporary
            t: RECEIPT_TYPE.into(),
            d: self.d?,
            i: self.i?,
            s: self.s?,
        };
        // Compute actual serialized size and set v
        let bytes = serde_json::to_vec(&receipt).ok()?;
        receipt.v = VersionString::json(bytes.len() as u32);
        Some(receipt)
    }
}
```

---

## Epic 6: KEL Validation Gaps

Fix missing validation rules that the spec requires.

### Task 6.1: Reject events after identity abandonment

**Spec:** "When the `n` field value in a Rotation is an empty list, the AID MUST be deemed abandoned and no more key events MUST be allowed."

**Current code** (`validate.rs:107-133`): `KeyState.is_abandoned` is tracked but never checked in `validate_kel` before processing events.

**Fix:** Add check at the top of the event loop:
```rust
// validate.rs — validate_kel, inside the for loop, before match
for (idx, event) in events.iter().enumerate().skip(1) {
    let expected_seq = idx as u64;

    // Reject any event after abandonment
    if state.is_abandoned {
        return Err(ValidationError::AbandonedIdentity {
            sequence: expected_seq,
        });
    }

    verify_event_said(event)?;
    // ... rest of loop
}
```

Add the error variant:
```rust
// validate.rs — ValidationError
/// The identity has been abandoned (empty next commitment) and no more events are allowed.
#[error("Identity abandoned at sequence {sequence}, no more events allowed")]
AbandonedIdentity {
    /// The sequence number of the rejected event.
    sequence: u64,
},
```

### Task 6.2: Reject IXN events in establishment-only KELs

**Spec:** When `"EO"` is in the inception's `c` traits, only establishment events (ICP, ROT) may appear.

**Depends on:** Task 1.4 (adding `c` field).

**Fix:**
```rust
// validate.rs — validate_kel, after inception validation

let establishment_only = if let Event::Icp(icp) = &events[0] {
    icp.c.contains(&ConfigTrait::EstablishmentOnly)
} else {
    false
};

// ... in the event loop:
if establishment_only && matches!(event, Event::Ixn(_)) {
    return Err(ValidationError::EstablishmentOnly {
        sequence: expected_seq,
    });
}
```

Add the error variant:
```rust
/// An interaction event was found in an establishment-only KEL.
#[error("Interaction event at sequence {sequence} rejected: KEL is establishment-only (EO)")]
EstablishmentOnly {
    sequence: u64,
},
```

### Task 6.3: Enforce non-transferable identity rules

**Spec:** "When the `n` field value in an Inception is an empty list, the AID MUST be deemed non-transferable and no more key events MUST be allowed."

**Current code:** Not enforced. An inception with `n: []` followed by additional events would be accepted.

**Fix:**
```rust
// validate.rs — validate_kel, after inception validation
if icp.n.is_empty() && events.len() > 1 {
    return Err(ValidationError::NonTransferable);
}
```

Add the error variant:
```rust
/// The identity is non-transferable (inception had empty next commitments).
#[error("Non-transferable identity: inception had empty next key commitments, no subsequent events allowed")]
NonTransferable,
```

### Task 6.4: Verify all pre-rotation commitments (not just first key)

**Spec:** "The current public key list MUST include a satisfiable subset of the prior next key list with respect to the prior next threshold."

**Current code** (`validate.rs:193-201`):
```rust
if !state.next_commitment.is_empty() && !rot.k.is_empty() {
    let key_bytes = KeriPublicKey::parse(&rot.k[0])  // ONLY first key
        .map(|k| k.as_bytes().to_vec())
        .map_err(|_| ValidationError::CommitmentMismatch { sequence })?;
    if !verify_commitment(&key_bytes, &state.next_commitment[0]) {  // ONLY first commitment
        return Err(ValidationError::CommitmentMismatch { sequence });
    }
}
```

**Fix:** Check all commitments:
```rust
// validate.rs — validate_rotation, commitment verification

// For each commitment in state.next_commitment, at least one key in rot.k
// must match it. The total matched keys must satisfy the next threshold.
if !state.next_commitment.is_empty() {
    let mut matched_count = 0u64;
    for commitment in &state.next_commitment {
        let matched = rot.k.iter().any(|key| {
            key.parse_ed25519()
                .map(|pk| verify_commitment(pk.as_bytes(), commitment))
                .unwrap_or(false)
        });
        if matched {
            matched_count += 1;
        }
    }
    let required = state.next_threshold.simple_value().unwrap_or(1);
    if matched_count < required {
        return Err(ValidationError::CommitmentMismatch { sequence });
    }
}
```

### Task 6.5: Validate witness AID uniqueness

**Spec:** "A given AID MUST NOT appear more than once in any Backer list."

**Current code:** No uniqueness check.

**Fix:** Add validation helper and call it during inception and rotation validation:

```rust
// validate.rs — new helper

fn validate_backer_uniqueness(backers: &[Prefix]) -> Result<(), ValidationError> {
    let mut seen = std::collections::HashSet::new();
    for b in backers {
        if !seen.insert(b.as_str()) {
            return Err(ValidationError::DuplicateBacker {
                aid: b.as_str().to_string(),
            });
        }
    }
    Ok(())
}
```

Add error variant:
```rust
/// A backer AID appears more than once in the backer list.
#[error("Duplicate backer AID: {aid}")]
DuplicateBacker { aid: String },
```

Call in `validate_inception`:
```rust
validate_backer_uniqueness(&icp.b)?;
```

Call in `validate_rotation` (after Task 2.1):
```rust
// Validate no duplicates in br or ba individually
validate_backer_uniqueness(&rot.br)?;
validate_backer_uniqueness(&rot.ba)?;
// Validate no overlap between br and ba
for aid in &rot.ba {
    if rot.br.contains(aid) {
        return Err(ValidationError::DuplicateBacker {
            aid: aid.as_str().to_string(),
        });
    }
}
```

### Task 6.6: Validate `bt` consistency with backer list

**Spec:** "When `b` is empty, `bt` MUST be `"0"`."

**Fix:** In inception validation:
```rust
// validate.rs — validate_inception
let bt_val = icp.bt.simple_value().unwrap_or(0);
if icp.b.is_empty() && bt_val != 0 {
    return Err(ValidationError::InvalidBackerThreshold {
        bt: bt_val,
        backer_count: 0,
    });
}
```

Add error variant:
```rust
/// The backer threshold is inconsistent with the backer list size.
#[error("Invalid backer threshold: bt={bt} but backer_count={backer_count}")]
InvalidBackerThreshold { bt: u64, backer_count: usize },
```

---

## Epic 7: KeyState Completeness

Add missing state fields that the spec requires for full key state representation.

### Task 7.1: Add backer state and config traits to `KeyState`

**Spec:** Key state includes backer list, backer threshold, and configuration traits.

**Current code** (`state.rs:18-42`):
```rust
pub struct KeyState {
    pub prefix: Prefix,
    pub current_keys: Vec<String>,
    pub next_commitment: Vec<String>,
    pub sequence: u64,
    pub last_event_said: Said,
    pub is_abandoned: bool,
    pub threshold: u64,
    pub next_threshold: u64,
    // MISSING: backers, backer_threshold, config_traits, is_non_transferable
}
```

**Fix:**
```rust
// state.rs — updated KeyState (with new types from Epic 1)

pub struct KeyState {
    pub prefix: Prefix,
    pub current_keys: Vec<CesrKey>,
    pub next_commitment: Vec<Said>,
    pub sequence: u64,
    pub last_event_said: Said,
    pub is_abandoned: bool,
    pub threshold: Threshold,
    pub next_threshold: Threshold,
    /// Current backer/witness list
    pub backers: Vec<Prefix>,
    /// Current backer threshold
    pub backer_threshold: Threshold,
    /// Configuration traits from inception (and rotation for RB/NRB)
    pub config_traits: Vec<ConfigTrait>,
    /// Whether this identity is non-transferable (inception `n` was empty)
    pub is_non_transferable: bool,
}
```

Update `from_inception`:
```rust
pub fn from_inception(
    prefix: Prefix,
    keys: Vec<CesrKey>,
    next: Vec<Said>,
    threshold: Threshold,
    next_threshold: Threshold,
    said: Said,
    backers: Vec<Prefix>,
    backer_threshold: Threshold,
    config_traits: Vec<ConfigTrait>,
) -> Self {
    let is_non_transferable = next.is_empty();
    Self {
        prefix,
        current_keys: keys,
        next_commitment: next.clone(),
        sequence: 0,
        last_event_said: said,
        is_abandoned: next.is_empty(),
        threshold,
        next_threshold,
        backers,
        backer_threshold,
        config_traits,
        is_non_transferable,
    }
}
```

Update `apply_rotation` to handle `br`/`ba` deltas:
```rust
pub fn apply_rotation(
    &mut self,
    new_keys: Vec<CesrKey>,
    new_next: Vec<Said>,
    threshold: Threshold,
    next_threshold: Threshold,
    sequence: u64,
    said: Said,
    backers_to_remove: &[Prefix],
    backers_to_add: &[Prefix],
    backer_threshold: Threshold,
    config_traits: Vec<ConfigTrait>,
) {
    self.current_keys = new_keys;
    self.next_commitment = new_next.clone();
    self.threshold = threshold;
    self.next_threshold = next_threshold;
    self.sequence = sequence;
    self.last_event_said = said;
    self.is_abandoned = new_next.is_empty();

    // Apply backer deltas: remove first, then add
    self.backers.retain(|b| !backers_to_remove.contains(b));
    self.backers.extend(backers_to_add.iter().cloned());
    self.backer_threshold = backer_threshold;

    // Update config traits (RB/NRB can change in rotation)
    if !config_traits.is_empty() {
        self.config_traits = config_traits;
    }
}
```

**Blast radius:** All call sites of `from_inception` and `apply_rotation` across the workspace must be updated with the new parameters.

---

## Epic 8: Signature Verification (Multi-Key Threshold)

Support threshold-satisficing signature verification for multi-key identities.

### Task 8.1: Verify threshold-satisficing signatures

**Spec:** "Signed by a threshold-satisficing subset of the current set of private keys."

**Current code** (`validate.rs:385-406`): Only verifies ONE signature against the first key.

**Fix:** Replace `verify_event_signature` with threshold-aware version:

```rust
// validate.rs — new threshold-aware signature verification

/// Verify that signatures on an event satisfy the threshold.
///
/// Args:
/// * `event` - The event whose signatures to verify.
/// * `keys` - The ordered list of signing keys.
/// * `signatures` - The indexed signatures to verify.
/// * `threshold` - The required threshold.
fn verify_threshold_signatures(
    event: &Event,
    keys: &[CesrKey],
    signatures: &[IndexedSignature],
    threshold: &Threshold,
) -> Result<(), ValidationError> {
    let sequence = event.sequence().value();
    let canonical = serialize_for_signing(event)?;

    match threshold {
        Threshold::Simple(required) => {
            let mut verified_count = 0u64;
            for sig in signatures {
                let idx = sig.index as usize;
                if idx >= keys.len() {
                    continue;  // Invalid index, skip
                }
                let key = keys[idx].parse_ed25519()
                    .map_err(|_| ValidationError::SignatureFailed { sequence })?;
                let pk = UnparsedPublicKey::new(
                    &ring::signature::ED25519,
                    key.as_bytes(),
                );
                if pk.verify(&canonical, &sig.sig).is_ok() {
                    verified_count += 1;
                }
            }
            if verified_count < *required {
                return Err(ValidationError::SignatureFailed { sequence });
            }
        }
        Threshold::Weighted(clauses) => {
            // For each clause, sum the weights of verified signatures.
            // All clauses must be satisfied (ANDed).
            //
            // IMPORTANT: Use integer cross-multiplication, NOT f64.
            // IEEE 754 cannot represent 1/3 exactly, so
            // 1/3 + 1/3 + 1/3 != 1.0 in floating point.
            for clause in clauses {
                // Accumulate as a rational: acc_num / acc_den
                let mut acc_num: u128 = 0;
                let mut acc_den: u128 = 1;
                for (i, fraction) in clause.iter().enumerate() {
                    if i >= keys.len() { break; }
                    // Check if key[i] has a valid signature
                    let has_valid_sig = signatures.iter().any(|sig| {
                        sig.index as usize == i && {
                            keys[i].parse_ed25519().ok().map_or(false, |key| {
                                let pk = UnparsedPublicKey::new(
                                    &ring::signature::ED25519,
                                    key.as_bytes(),
                                );
                                pk.verify(&canonical, &sig.sig).is_ok()
                            })
                        }
                    });
                    if has_valid_sig {
                        let (n, d) = fraction.parse_parts()
                            .map_err(|_| ValidationError::SignatureFailed { sequence })?;
                        // acc_num/acc_den + n/d = (acc_num*d + n*acc_den) / (acc_den*d)
                        acc_num = acc_num * d as u128 + n as u128 * acc_den;
                        acc_den *= d as u128;
                    }
                }
                // Clause satisfied when acc_num/acc_den >= 1, i.e., acc_num >= acc_den
                if acc_num < acc_den {
                    return Err(ValidationError::SignatureFailed { sequence });
                }
            }
        }
    }
    Ok(())
}
```

### Task 8.2: Rotation dual-threshold verification

**Spec:** "A set of controller-indexed signatures MUST satisfy BOTH the current signing threshold AND the prior next rotation threshold."

**Fix:** During rotation validation, verify signatures against both thresholds:

```rust
// validate.rs — validate_rotation, signature verification

// Verify signatures satisfy BOTH:
// 1. The current signing threshold (using the new keys from rot.k)
// 2. The prior next rotation threshold (using state.next_threshold)
verify_threshold_signatures(
    event,
    &rot.k,
    &signed_event.signatures,  // from SignedEvent wrapper
    &rot.kt,  // current signing threshold
)?;

// Also verify against prior next threshold
verify_threshold_signatures(
    event,
    &rot.k,
    &signed_event.signatures,
    &state.next_threshold,
)?;
```

---

## Epic 9: Receipt Message Compliance

Fix the receipt format to match the spec.

### Task 9.1: Fix `Receipt` struct to match spec fields

**Spec (receipt fields):** `[v, t, d, i, s]` — ALL required, no others.
- `d` is the SAID of the **referenced key event** (not the receipt itself)
- Signatures are CESR attachments, not body fields

**Current code** (`witness/receipt.rs:63-86`):
```rust
pub struct Receipt {
    pub v: String,
    pub t: String,
    pub d: Said,            // receipt's own SAID — WRONG
    pub i: String,
    pub s: u64,
    pub a: Said,            // NON-SPEC field
    #[serde(with = "hex")]
    pub sig: Vec<u8>,       // NON-SPEC: should be CESR attachment
}
```

**Fix:**
```rust
// witness/receipt.rs — spec-compliant Receipt

/// A witness receipt for a KEL event (spec: `rct` message type).
///
/// Per the spec, the receipt body contains ONLY `[v, t, d, i, s]`.
/// `d` is the SAID of the referenced event (NOT the receipt itself).
/// Signatures are externalized as CESR attachments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Version string
    pub v: VersionString,
    /// Type identifier ("rct")
    pub t: String,
    /// SAID of the referenced key event (NOT the receipt's own SAID)
    pub d: Said,
    /// Controller AID of the KEL being receipted
    pub i: Prefix,
    /// Sequence number of the event being receipted
    pub s: KeriSequence,
}

/// A receipt paired with its detached witness signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    /// The receipt body
    pub receipt: Receipt,
    /// Witness signature (externalized, not in body)
    pub signature: Vec<u8>,
}
```

Update `ReceiptBuilder` accordingly:
```rust
impl ReceiptBuilder {
    pub fn build(self) -> Option<SignedReceipt> {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: RECEIPT_TYPE.into(),
            d: self.d?,              // event SAID (not receipt SAID)
            i: self.i?,
            s: self.s?,
        };
        // Compute actual serialized size
        let bytes = serde_json::to_vec(&receipt).ok()?;
        let mut receipt = receipt;
        receipt.v = VersionString::json(bytes.len() as u32);

        Some(SignedReceipt {
            receipt,
            signature: self.sig?,
        })
    }
}
```

Update builder field types:
```rust
pub struct ReceiptBuilder {
    d: Option<Said>,          // event SAID
    i: Option<Prefix>,        // was Option<String>
    s: Option<KeriSequence>,  // was Option<u64>
    sig: Option<Vec<u8>>,
}
```

**Blast radius:** All receipt construction and consumption in `auths-core`, `auths-cli`, `auths-verifier`, `auths-infra-http`. Search for `Receipt::builder()`, `receipt.a`, `receipt.sig`, `receipt.s` across the workspace.

---

## Epic 10: Sequence Number Width

Widen `KeriSequence` to `u128` per spec maximum.

### Task 10.1: Change `KeriSequence` inner type to `u128`

**Spec:** Maximum sequence number is `ffffffffffffffffffffffffffffffff` = 2^128 - 1.

**Current code** (`events.rs:28`):
```rust
pub struct KeriSequence(u64);
```

**Fix:**
```rust
// events.rs — KeriSequence
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeriSequence(u128);

impl KeriSequence {
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    pub fn value(self) -> u128 {
        self.0
    }
}

impl Serialize for KeriSequence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for KeriSequence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = u128::from_str_radix(&s, 16)
            .map_err(|_| serde::de::Error::custom(format!("invalid hex sequence: {s:?}")))?;
        Ok(KeriSequence(value))
    }
}
```

Update `KeyState.sequence` from `u64` to `u128`. Update all comparison sites.

**Priority:** LOW. No practical KEL will exceed u64. This is spec-correctness only.

**Blast radius:** All sites using `KeriSequence::new(n)` with u64 literals need explicit `u128` type or `.into()`. `state.sequence` comparisons change. Search for `KeriSequence::new`, `.sequence`, `.value()` across the workspace.

---

## Epic 11: Delegated Events (Future)

Add support for delegated inception and rotation events.

**Priority:** LOW. Not used in the current auths identity model.

### Task 11.1: Add `dip` (Delegated Inception) event type

**Spec field order:** `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di]`

```rust
// events.rs — new DipEvent

/// Delegated Inception event — creates a delegated KERI identity.
///
/// Same as ICP plus the `di` (delegator identifier prefix) field.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DipEvent {
    pub v: VersionString,
    #[serde(default)]
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub kt: Threshold,
    pub k: Vec<CesrKey>,
    pub nt: Threshold,
    pub n: Vec<Said>,
    pub bt: Threshold,
    pub b: Vec<Prefix>,
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Delegator identifier prefix
    pub di: Prefix,
}
```

Add to `Event` enum:
```rust
#[serde(rename = "dip")]
Dip(DipEvent),
```

### Task 11.2: Add `drt` (Delegated Rotation) event type

**Spec field order:** `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]`

Same fields as ROT but `t = "drt"`.

```rust
// events.rs — new DrtEvent

/// Delegated Rotation event — rotates keys for a delegated identity.
///
/// Same field set as ROT. Validation requires checking the delegator's
/// KEL for an anchoring seal.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DrtEvent {
    pub v: VersionString,
    #[serde(default)]
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub p: Said,
    pub kt: Threshold,
    pub k: Vec<CesrKey>,
    pub nt: Threshold,
    pub n: Vec<Said>,
    pub bt: Threshold,
    pub br: Vec<Prefix>,
    pub ba: Vec<Prefix>,
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    #[serde(default)]
    pub a: Vec<Seal>,
}
```

### Task 11.3: Implement delegated event validation

**Spec:** "A Validator MUST be given or find the delegating seal in the delegator's KEL before the delegated event may be accepted as valid."

This requires cross-KEL validation. The validator needs access to the delegator's KEL to find a key event seal `{"i": "<delegatee AID>", "s": "<delegatee event sn>", "d": "<delegatee event SAID>"}` in the delegator's IXN or ROT event.

```rust
// validate.rs — new function

/// Validate a delegated event against the delegator's KEL.
///
/// Args:
/// * `delegatee_event` - The delegated event (dip or drt) to validate.
/// * `delegator_kel` - The delegator's full KEL.
/// * `delegator_prefix` - The delegator's AID.
pub fn validate_delegation(
    delegatee_event: &Event,
    delegator_kel: &[Event],
    delegator_prefix: &Prefix,
) -> Result<(), ValidationError> {
    let (event_said, event_seq) = match delegatee_event {
        Event::Dip(dip) => (&dip.d, dip.s),
        Event::Drt(drt) => (&drt.d, drt.s),
        _ => return Err(ValidationError::NotDelegated),
    };

    // Search delegator's KEL for an anchoring seal
    let found = delegator_kel.iter().any(|event| {
        event.anchors().iter().any(|seal| {
            matches!(seal, Seal::KeyEvent { i, s, d }
                if i == delegatee_event.prefix()
                    && *s == event_seq
                    && d == event_said
            )
        })
    });

    if !found {
        return Err(ValidationError::MissingDelegationSeal {
            delegator: delegator_prefix.as_str().to_string(),
            delegatee_sequence: event_seq.value(),
        });
    }

    Ok(())
}
```

---

## Execution Order

The recommended order minimizes rework and respects dependencies:

```
Phase 1 (Foundation):
  Epic 1 (strong newtypes)  ─── do ALL tasks together
  Epic 3 (prefix flexibility) ─── enables typed backer fields

Phase 2 (Event Schema):
  Epic 2 (field schema) ─── depends on Epic 1 types
  Epic 4 (seal format) ─── independent, can parallel with Epic 2

Phase 3 (Serialization):
  Epic 5 (version string + SAID) ─── depends on VersionString from Epic 1

Phase 4 (Validation):
  Epic 6 (validation gaps) ─── depends on c field from Epic 2
  Epic 7 (KeyState completeness) ─── depends on new types
  Epic 8 (multi-sig) ─── depends on Threshold from Epic 1

Phase 5 (Messages):
  Epic 9 (receipt compliance) ─── depends on new types

Phase 6 (Low Priority):
  Epic 10 (u128 sequence)
  Epic 11 (delegation)
```

## Priority Matrix

| Epic | Priority | Reason |
|------|----------|--------|
| 1 (Strong Newtypes) | **CRITICAL** | Foundation for all other changes |
| 2 (Event Field Schema) | **HIGH** | Field schema is the spec's core |
| 3 (Prefix Flexibility) | **HIGH** | Enables typed backer fields |
| 4 (Seal Format) | **HIGH** | Current format is non-interoperable |
| 5 (Version String + SAID) | **HIGH** | Affects all serialized events |
| 6 (Validation Gaps) | **MEDIUM** | Edge cases; happy path works |
| 7 (KeyState Completeness) | **MEDIUM** | Missing state for full compliance |
| 8 (Multi-Sig Verification) | **MEDIUM** | Single-sig works; needed for multi-device |
| 9 (Receipt Compliance) | **MEDIUM** | Receipts work internally; interop requires fix |
| 10 (Sequence u128) | **LOW** | u64 is practically sufficient |
| 11 (Delegation) | **LOW** | Not in current identity model |
