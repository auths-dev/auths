//! Canonical KERI event types: Inception (ICP), Rotation (ROT), Interaction (IXN).
//!
//! These types are the single authoritative definition of KERI events for the
//! entire workspace. All other crates import from here.

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use crate::types::{CesrKey, ConfigTrait, Prefix, Said, Threshold, VersionString};

/// KERI protocol version prefix string.
pub const KERI_VERSION_PREFIX: &str = "KERI10JSON";

// ── KeriSequence ─────────────────────────────────────────────────────────────

/// A KERI sequence number, stored internally as u64 and serialized as a hex string.
///
/// Sequence numbers are spec-compliant hex strings: "0", "1", "a", "ff", etc.
///
/// Usage:
/// ```ignore
/// let seq = KeriSequence::new(10);
/// assert_eq!(seq.value(), 10);
/// assert_eq!(serde_json::to_string(&seq).unwrap(), "\"a\"");
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeriSequence(u128);

#[cfg(feature = "schema")]
impl schemars::JsonSchema for KeriSequence {
    fn schema_name() -> String {
        "KeriSequence".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        }
        .into()
    }
}

impl KeriSequence {
    /// Create a new sequence number.
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// Return the full u128 value.
    pub fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for KeriSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
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

// ── Seal ─────────────────────────────────────────────────────────────────────

/// KERI seal — anchors external data in an event's `a` field.
///
/// Variants are distinguished by field shape (untagged), not by a "type" discriminator.
/// Per the spec, seal fields MUST appear in the specified order.
///
/// Usage:
/// ```
/// use auths_keri::Seal;
/// let seal = Seal::digest("EDigest123");
/// assert!(seal.digest_value().is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Seal {
    /// Digest seal: `{"d": "<SAID>"}`
    Digest {
        /// SAID of the anchored data.
        d: Said,
    },
    /// Source event seal: `{"s": "<hex-sn>", "d": "<SAID>"}`
    SourceEvent {
        /// Sequence number.
        s: KeriSequence,
        /// Event SAID.
        d: Said,
    },
    /// Key event seal: `{"i": "<AID>", "s": "<hex-sn>", "d": "<SAID>"}`
    KeyEvent {
        /// AID.
        i: Prefix,
        /// Sequence number.
        s: KeriSequence,
        /// Event SAID.
        d: Said,
    },
    /// Event-location seal (KERI v1.1 §7): `{"i","s","p","t","d"}`.
    EventLocation {
        /// AID.
        i: Prefix,
        /// Sequence number.
        s: KeriSequence,
        /// Prior event SAID.
        p: Said,
        /// Event type (ilk).
        t: String,
        /// Event SAID.
        d: Said,
    },
    /// Latest establishment event seal: `{"i": "<AID>"}`
    LatestEstablishment {
        /// AID.
        i: Prefix,
    },
    /// Merkle tree root digest seal: `{"rd": "<digest>"}` (non-spec extension).
    #[cfg(feature = "seal-extensions")]
    MerkleRoot {
        /// Root digest.
        rd: Said,
    },
    /// Registrar backer seal: `{"bi": "<AID>", "d": "<SAID>"}` (non-spec extension).
    #[cfg(feature = "seal-extensions")]
    RegistrarBacker {
        /// Backer AID.
        bi: Prefix,
        /// Metadata SAID.
        d: Said,
    },
}

impl Seal {
    /// Create a digest seal from a SAID.
    pub fn digest(said: impl Into<String>) -> Self {
        Self::Digest {
            d: Said::new_unchecked(said.into()),
        }
    }

    /// Create a key event seal.
    pub fn key_event(prefix: Prefix, sequence: KeriSequence, said: Said) -> Self {
        Self::KeyEvent {
            i: prefix,
            s: sequence,
            d: said,
        }
    }

    /// Get the digest from this seal, if it has one.
    pub fn digest_value(&self) -> Option<&Said> {
        match self {
            Seal::Digest { d } => Some(d),
            Seal::SourceEvent { d, .. } => Some(d),
            Seal::KeyEvent { d, .. } => Some(d),
            Seal::EventLocation { d, .. } => Some(d),
            Seal::LatestEstablishment { .. } => None,
            #[cfg(feature = "seal-extensions")]
            Seal::RegistrarBacker { d, .. } => Some(d),
            #[cfg(feature = "seal-extensions")]
            Seal::MerkleRoot { rd } => Some(rd),
        }
    }
}

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
            Seal::EventLocation { i, s, p, t, d } => {
                let mut map = serializer.serialize_map(Some(5))?;
                map.serialize_entry("i", i)?;
                map.serialize_entry("s", s)?;
                map.serialize_entry("p", p)?;
                map.serialize_entry("t", t)?;
                map.serialize_entry("d", d)?;
                map.end()
            }
            Seal::LatestEstablishment { i } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("i", i)?;
                map.end()
            }
            #[cfg(feature = "seal-extensions")]
            Seal::MerkleRoot { rd } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("rd", rd)?;
                map.end()
            }
            #[cfg(feature = "seal-extensions")]
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

        let want_str = |k: &str| -> Result<String, D::Error> {
            map.get(k)
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
                .ok_or_else(|| {
                    serde::de::Error::custom(format!("seal field `{k}` must be a string"))
                })
        };
        let want_seq =
            |k: &str| -> Result<KeriSequence, D::Error> {
                serde_json::from_value(map.get(k).cloned().ok_or_else(|| {
                    serde::de::Error::custom(format!("seal field `{k}` required"))
                })?)
                .map_err(serde::de::Error::custom)
            };

        // Match on the EXACT sorted field set — no silent field-dropping (F-37).
        let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
        keys.sort_unstable();

        match keys.as_slice() {
            ["d"] => Ok(Seal::Digest {
                d: Said::new_unchecked(want_str("d")?),
            }),
            ["d", "s"] => Ok(Seal::SourceEvent {
                s: want_seq("s")?,
                d: Said::new_unchecked(want_str("d")?),
            }),
            ["d", "i", "s"] => Ok(Seal::KeyEvent {
                i: Prefix::new_unchecked(want_str("i")?),
                s: want_seq("s")?,
                d: Said::new_unchecked(want_str("d")?),
            }),
            ["d", "i", "p", "s", "t"] => Ok(Seal::EventLocation {
                i: Prefix::new_unchecked(want_str("i")?),
                s: want_seq("s")?,
                p: Said::new_unchecked(want_str("p")?),
                t: want_str("t")?,
                d: Said::new_unchecked(want_str("d")?),
            }),
            ["i"] => Ok(Seal::LatestEstablishment {
                i: Prefix::new_unchecked(want_str("i")?),
            }),
            #[cfg(feature = "seal-extensions")]
            ["rd"] => Ok(Seal::MerkleRoot {
                rd: Said::new_unchecked(want_str("rd")?),
            }),
            #[cfg(feature = "seal-extensions")]
            ["bi", "d"] => Ok(Seal::RegistrarBacker {
                bi: Prefix::new_unchecked(want_str("bi")?),
                d: Said::new_unchecked(want_str("d")?),
            }),
            other => Err(serde::de::Error::custom(format!(
                "unrecognized seal field set: {other:?}"
            ))),
        }
    }
}

// ── Event Types ───────────────────────────────────────────────────────────────

/// Inception event — creates a new KERI identity.
///
/// The inception event establishes the identifier prefix and commits
/// to the first rotation key via the `n` (next) field.
///
/// Spec field order: `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IcpEvent {
    /// Version string
    pub v: VersionString,
    /// SAID (Self-Addressing Identifier) — Blake3 hash of event
    pub d: Said,
    /// Identifier prefix (same as `d` for self-addressing inception)
    pub i: Prefix,
    /// Sequence number (always 0 for inception)
    pub s: KeriSequence,
    /// Key signing threshold (hex integer or fractional weight list)
    pub kt: Threshold,
    /// Current public key(s), CESR-encoded
    pub k: Vec<CesrKey>,
    /// Next key signing threshold
    pub nt: Threshold,
    /// Next key commitment(s) — Blake3 digests of next public key(s)
    pub n: Vec<Said>,
    /// Witness/backer threshold
    pub bt: Threshold,
    /// Witness/backer list (ordered AIDs)
    #[serde(default)]
    pub b: Vec<Prefix>,
    /// Configuration traits (e.g., EstablishmentOnly, DoNotDelegate)
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
}

/// Parameter struct for [`IcpEvent::new`]. Mirrors the existing
/// field set 1-for-1 so call-site migration is a mechanical prefix/
/// suffix wrap. Future wire-format additions land on `IcpEvent` via
/// a `with_*` method, not by widening this `Init` struct — that's
/// what makes the pattern future-proof.
pub struct IcpEventInit {
    pub v: VersionString,
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub kt: Threshold,
    pub k: Vec<CesrKey>,
    pub nt: Threshold,
    pub n: Vec<Said>,
    pub bt: Threshold,
    pub b: Vec<Prefix>,
    pub c: Vec<ConfigTrait>,
    pub a: Vec<Seal>,
}

impl IcpEvent {
    /// Construct an `IcpEvent` from its required fields.
    pub fn new(init: IcpEventInit) -> Self {
        Self {
            v: init.v,
            d: init.d,
            i: init.i,
            s: init.s,
            kt: init.kt,
            k: init.k,
            nt: init.nt,
            n: init.n,
            bt: init.bt,
            b: init.b,
            c: init.c,
            a: init.a,
        }
    }
}

/// Spec field order: v, t, d, i, s, kt, k, nt, n, bt, b, c, a
impl Serialize for IcpEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 13;
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
    }
}

/// Rotation event — rotates to pre-committed key.
///
/// Spec field order: `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a]`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RotEvent {
    /// Version string
    pub v: VersionString,
    /// SAID of this event
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number (increments with each event)
    pub s: KeriSequence,
    /// Previous event SAID (creates the hash chain)
    pub p: Said,
    /// Key signing threshold
    pub kt: Threshold,
    /// New current key(s), CESR-encoded
    pub k: Vec<CesrKey>,
    /// Next key signing threshold
    pub nt: Threshold,
    /// New next key commitment(s) — Blake3 digests
    pub n: Vec<Said>,
    /// Witness/backer threshold
    pub bt: Threshold,
    /// List of backers to remove (processed first)
    #[serde(default)]
    pub br: Vec<Prefix>,
    /// List of backers to add (processed after removals)
    #[serde(default)]
    pub ba: Vec<Prefix>,
    /// Configuration traits
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
}

/// Parameter struct for [`RotEvent::new`]. See [`IcpEventInit`] for
/// the pattern rationale.
pub struct RotEventInit {
    pub v: VersionString,
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
    pub c: Vec<ConfigTrait>,
    pub a: Vec<Seal>,
}

impl RotEvent {
    /// Construct a `RotEvent` from its required fields.
    pub fn new(init: RotEventInit) -> Self {
        Self {
            v: init.v,
            d: init.d,
            i: init.i,
            s: init.s,
            p: init.p,
            kt: init.kt,
            k: init.k,
            nt: init.nt,
            n: init.n,
            bt: init.bt,
            br: init.br,
            ba: init.ba,
            c: init.c,
            a: init.a,
        }
    }
}

/// Spec field order: v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a
impl Serialize for RotEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 14;
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "rot")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("kt", &self.kt)?;
        map.serialize_entry("k", &self.k)?;
        map.serialize_entry("nt", &self.nt)?;
        map.serialize_entry("n", &self.n)?;
        map.serialize_entry("bt", &self.bt)?;
        map.serialize_entry("br", &self.br)?;
        map.serialize_entry("ba", &self.ba)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

/// Interaction event — anchors data without key rotation.
///
/// Spec field order: `[v, t, d, i, s, p, a]`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IxnEvent {
    /// Version string
    pub v: VersionString,
    /// SAID of this event
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number
    pub s: KeriSequence,
    /// Previous event SAID
    pub p: Said,
    /// Anchored seals (the main purpose of IXN events)
    pub a: Vec<Seal>,
}

/// Parameter struct for [`IxnEvent::new`].
pub struct IxnEventInit {
    pub v: VersionString,
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub p: Said,
    pub a: Vec<Seal>,
}

impl IxnEvent {
    /// Construct an `IxnEvent` from its required fields.
    pub fn new(init: IxnEventInit) -> Self {
        Self {
            v: init.v,
            d: init.d,
            i: init.i,
            s: init.s,
            p: init.p,
            a: init.a,
        }
    }
}

/// Spec field order: v, t, d, i, s, p, a
impl Serialize for IxnEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 7;
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "ixn")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

/// Unified event enum for processing any KERI event type.
///
/// Uses serde's tagged enum feature to deserialize based on the `t` field.
///
/// Usage:
/// ```ignore
/// let event: Event = serde_json::from_str(json)?;
/// match event {
///     Event::Icp(icp) => { /* inception */ }
///     Event::Rot(rot) => { /* rotation */ }
///     Event::Ixn(ixn) => { /* interaction */ }
/// }
/// ```
/// Delegated inception event — creates a delegated KERI identity.
///
/// Same as ICP plus the `di` (delegator identifier prefix) field.
/// Spec field order: `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di]`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DipEvent {
    /// Version string
    pub v: VersionString,
    /// SAID
    pub d: Said,
    /// Identifier prefix (same as `d` for self-addressing)
    pub i: Prefix,
    /// Sequence number (always 0)
    pub s: KeriSequence,
    /// Key signing threshold
    pub kt: Threshold,
    /// Current public key(s)
    pub k: Vec<CesrKey>,
    /// Next key signing threshold
    pub nt: Threshold,
    /// Next key commitment(s)
    pub n: Vec<Said>,
    /// Witness/backer threshold
    pub bt: Threshold,
    /// Witness/backer list
    #[serde(default)]
    pub b: Vec<Prefix>,
    /// Configuration traits
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Delegator identifier prefix
    pub di: Prefix,
}

/// Parameter struct for [`DipEvent::new`].
pub struct DipEventInit {
    pub v: VersionString,
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub kt: Threshold,
    pub k: Vec<CesrKey>,
    pub nt: Threshold,
    pub n: Vec<Said>,
    pub bt: Threshold,
    pub b: Vec<Prefix>,
    pub c: Vec<ConfigTrait>,
    pub a: Vec<Seal>,
    pub di: Prefix,
}

impl DipEvent {
    /// Construct a `DipEvent` from its required fields.
    pub fn new(init: DipEventInit) -> Self {
        Self {
            v: init.v,
            d: init.d,
            i: init.i,
            s: init.s,
            kt: init.kt,
            k: init.k,
            nt: init.nt,
            n: init.n,
            bt: init.bt,
            b: init.b,
            c: init.c,
            a: init.a,
            di: init.di,
        }
    }
}

/// Spec field order: v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di
impl Serialize for DipEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 14;
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "dip")?;
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
        map.serialize_entry("di", &self.di)?;
        map.end()
    }
}

/// Delegated rotation event — rotates keys for a delegated identity.
///
/// Same field set as ROT but type `drt`. Validation requires checking the
/// delegator's KEL for an anchoring seal.
/// Spec field order: `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a]`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DrtEvent {
    /// Version string
    pub v: VersionString,
    /// SAID
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number
    pub s: KeriSequence,
    /// Previous event SAID
    pub p: Said,
    /// Key signing threshold
    pub kt: Threshold,
    /// New current key(s)
    pub k: Vec<CesrKey>,
    /// Next key signing threshold
    pub nt: Threshold,
    /// New next key commitment(s)
    pub n: Vec<Said>,
    /// Witness/backer threshold
    pub bt: Threshold,
    /// Backers to remove
    #[serde(default)]
    pub br: Vec<Prefix>,
    /// Backers to add
    #[serde(default)]
    pub ba: Vec<Prefix>,
    /// Configuration traits
    #[serde(default)]
    pub c: Vec<ConfigTrait>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Delegator identifier prefix (KERI §11).
    pub di: Prefix,
}

/// Parameter struct for [`DrtEvent::new`].
pub struct DrtEventInit {
    pub v: VersionString,
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
    pub c: Vec<ConfigTrait>,
    pub a: Vec<Seal>,
    pub di: Prefix,
}

impl DrtEvent {
    /// Construct a `DrtEvent` from its required fields.
    pub fn new(init: DrtEventInit) -> Self {
        Self {
            v: init.v,
            d: init.d,
            i: init.i,
            s: init.s,
            p: init.p,
            kt: init.kt,
            k: init.k,
            nt: init.nt,
            n: init.n,
            bt: init.bt,
            br: init.br,
            ba: init.ba,
            c: init.c,
            a: init.a,
            di: init.di,
        }
    }
}

/// Spec field order (KERI §11): v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a, di
impl Serialize for DrtEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 15;
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "drt")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("kt", &self.kt)?;
        map.serialize_entry("k", &self.k)?;
        map.serialize_entry("nt", &self.nt)?;
        map.serialize_entry("n", &self.n)?;
        map.serialize_entry("bt", &self.bt)?;
        map.serialize_entry("br", &self.br)?;
        map.serialize_entry("ba", &self.ba)?;
        map.serialize_entry("a", &self.a)?;
        map.serialize_entry("di", &self.di)?;
        map.end()
    }
}

/// Unified event enum for processing any KERI event type.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "t")]
pub enum Event {
    /// Inception event
    #[serde(rename = "icp")]
    Icp(IcpEvent),
    /// Rotation event
    #[serde(rename = "rot")]
    Rot(RotEvent),
    /// Interaction event
    #[serde(rename = "ixn")]
    Ixn(IxnEvent),
    /// Delegated inception event
    #[serde(rename = "dip")]
    Dip(DipEvent),
    /// Delegated rotation event
    #[serde(rename = "drt")]
    Drt(DrtEvent),
}

impl Serialize for Event {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Event::Icp(e) => e.serialize(serializer),
            Event::Rot(e) => e.serialize(serializer),
            Event::Ixn(e) => e.serialize(serializer),
            Event::Dip(e) => e.serialize(serializer),
            Event::Drt(e) => e.serialize(serializer),
        }
    }
}

impl Event {
    /// Get the SAID of this event.
    pub fn said(&self) -> &Said {
        match self {
            Event::Icp(e) => &e.d,
            Event::Rot(e) => &e.d,
            Event::Ixn(e) => &e.d,
            Event::Dip(e) => &e.d,
            Event::Drt(e) => &e.d,
        }
    }

    /// Get the sequence number of this event.
    pub fn sequence(&self) -> KeriSequence {
        match self {
            Event::Icp(e) => e.s,
            Event::Rot(e) => e.s,
            Event::Ixn(e) => e.s,
            Event::Dip(e) => e.s,
            Event::Drt(e) => e.s,
        }
    }

    /// Get the identifier prefix.
    pub fn prefix(&self) -> &Prefix {
        match self {
            Event::Icp(e) => &e.i,
            Event::Rot(e) => &e.i,
            Event::Ixn(e) => &e.i,
            Event::Dip(e) => &e.i,
            Event::Drt(e) => &e.i,
        }
    }

    /// Get the previous event SAID (None for inception/delegated inception).
    pub fn previous(&self) -> Option<&Said> {
        match self {
            Event::Icp(_) | Event::Dip(_) => None,
            Event::Rot(e) => Some(&e.p),
            Event::Ixn(e) => Some(&e.p),
            Event::Drt(e) => Some(&e.p),
        }
    }

    /// Get the current keys (only for establishment events).
    pub fn keys(&self) -> Option<&[CesrKey]> {
        match self {
            Event::Icp(e) => Some(&e.k),
            Event::Rot(e) => Some(&e.k),
            Event::Dip(e) => Some(&e.k),
            Event::Drt(e) => Some(&e.k),
            Event::Ixn(_) => None,
        }
    }

    /// Get the next key commitments (only for establishment events).
    pub fn next_commitments(&self) -> Option<&[Said]> {
        match self {
            Event::Icp(e) => Some(&e.n),
            Event::Rot(e) => Some(&e.n),
            Event::Dip(e) => Some(&e.n),
            Event::Drt(e) => Some(&e.n),
            Event::Ixn(_) => None,
        }
    }

    /// Get the anchored seals.
    pub fn anchors(&self) -> &[Seal] {
        match self {
            Event::Icp(e) => &e.a,
            Event::Rot(e) => &e.a,
            Event::Ixn(e) => &e.a,
            Event::Dip(e) => &e.a,
            Event::Drt(e) => &e.a,
        }
    }

    /// Get the delegator AID (only for delegated inception).
    pub fn delegator(&self) -> Option<&Prefix> {
        match self {
            Event::Dip(e) => Some(&e.di),
            _ => None,
        }
    }

    /// Check if this is an inception event (including delegated).
    pub fn is_inception(&self) -> bool {
        matches!(self, Event::Icp(_) | Event::Dip(_))
    }

    /// Check if this is a rotation event (including delegated).
    pub fn is_rotation(&self) -> bool {
        matches!(self, Event::Rot(_) | Event::Drt(_))
    }

    /// Check if this is an interaction event.
    pub fn is_interaction(&self) -> bool {
        matches!(self, Event::Ixn(_))
    }

    /// Check if this is a delegated event.
    pub fn is_delegated(&self) -> bool {
        matches!(self, Event::Dip(_) | Event::Drt(_))
    }
}

// ── Signed Event (externalized signatures) ──────────────────────────────────

/// A single indexed controller signature.
///
/// The `index` maps to the position in the key list (`k` field) of the
/// signing key. Per the CESR spec, indexed signatures carry their key
/// index in the derivation code.
///
/// Usage:
/// ```
/// use auths_keri::IndexedSignature;
/// let sig = IndexedSignature { index: 0, sig: vec![0u8; 64] };
/// assert_eq!(sig.index, 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedSignature {
    /// Index into the new key list `k[]` (which current key signed).
    pub index: u32,
    /// For a rotation signature, the index into the prior event's next-key
    /// commitment list `n[]` that this signature reveals (CESR *ondex*).
    ///
    /// `Some(j)` emits a dual-index ("Big", `2A`) siger; `None` emits the
    /// single-index code (`A`) with ondex == index — preserving the wire
    /// bytes of every single-index signer (inception, symmetric rotation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_index: Option<u32>,
    /// Raw signature bytes (64 bytes for Ed25519).
    #[serde(with = "hex::serde")]
    pub sig: Vec<u8>,
}

/// An event paired with its detached signature(s).
///
/// Per the KERI spec, signatures are NOT part of the event body. They are
/// attached externally (CESR attachment codes in streams, or stored alongside
/// in databases). The event body is what gets hashed for the SAID.
///
/// Usage:
/// ```ignore
/// use auths_keri::{SignedEvent, IndexedSignature, Event};
///
/// // After creating and finalizing an event:
/// let signed = SignedEvent::new(event, vec![IndexedSignature { index: 0, sig: sig_bytes }]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    /// The event body (no signature data).
    pub event: Event,
    /// Controller-indexed signatures (detached from body).
    pub signatures: Vec<IndexedSignature>,
}

impl SignedEvent {
    /// Create a new signed event from an event and its signatures.
    pub fn new(event: Event, signatures: Vec<IndexedSignature>) -> Self {
        Self { event, signatures }
    }

    /// Get the SAID of the inner event.
    pub fn said(&self) -> &Said {
        self.event.said()
    }

    /// Get the sequence number of the inner event.
    pub fn sequence(&self) -> KeriSequence {
        self.event.sequence()
    }

    /// Get the identifier prefix of the inner event.
    pub fn prefix(&self) -> &Prefix {
        self.event.prefix()
    }
}

/// Serialize a list of externalized signatures to CESR text-domain
/// `-A##<siger1><siger2>…` indexed-signature group bytes.
///
/// Wire format: `-A` prefix + 2-char base64url count + each signature as
/// a CESR `Siger` (qb64). Reads back via `parse_attachment`.
pub fn serialize_attachment(signatures: &[IndexedSignature]) -> Result<Vec<u8>, AttachmentError> {
    use cesride::{Indexer, Siger, indexer};

    let mut out = String::new();
    out.push_str("-A");
    out.push_str(&encode_count_b64(signatures.len())?);

    for sig in signatures {
        // Ed25519 indexed signature (auths' sign paths produce Ed25519). A
        // distinct prior-commitment index (`prior_index != index`) needs the
        // dual-index "Big" code `2A`, which carries both indices; otherwise the
        // single-index `A` (ondex == index) keeps the legacy 88-char bytes.
        let (code, ondex) = if sig.prior_index.is_some_and(|j| j != sig.index) {
            (indexer::Codex::Ed25519_Big, sig.prior_index)
        } else {
            (indexer::Codex::Ed25519, None)
        };
        let siger = Siger::new(
            None,
            Some(sig.index),
            ondex,
            Some(code),
            Some(&sig.sig),
            None,
            None,
            None,
        )
        .map_err(|e| AttachmentError::Encode(e.to_string()))?;
        let qb64 = siger
            .qb64()
            .map_err(|e| AttachmentError::Encode(e.to_string()))?;
        out.push_str(&qb64);
    }

    Ok(out.into_bytes())
}

/// CESR Indexer hard-code length: codes whose first char is a digit (`0`–`4`)
/// are multi-char selectors; all others are single-char. Mirrors cesride's
/// `indexer` hardage (whose tables are `pub(crate)`).
fn indexer_hard_len(first: u8) -> usize {
    if first.is_ascii_digit() { 2 } else { 1 }
}

/// `(full qb64 size, ondex size)` for a CESR Indexer signature code, mirroring
/// cesride `indexer/tables.rs` (its `sizage` is `pub(crate)`, not callable here).
///
/// `os > 0` marks a dual-index ("Big") code carrying a *distinct* prior-commitment
/// index (ondex); single-index codes have `os == 0` (ondex echoes index).
fn indexer_sizage(code: &str) -> Option<(usize, usize)> {
    Some(match code {
        // single-index: Ed25519 A/B, secp256k1 C/D, P-256 E/F (+ Crt variants)
        "A" | "B" | "C" | "D" | "E" | "F" => (88, 0),
        // dual-index ("Big"): Ed25519 2A/2B, secp256k1 2C/2D, P-256 2E/2F
        "2A" | "2B" | "2C" | "2D" | "2E" | "2F" => (92, 2),
        // large/huge index variants (completeness; not emitted by auths)
        "0A" | "0B" => (156, 1),
        "3A" | "3B" => (160, 3),
        _ => return None,
    })
}

/// Parse a CESR `-A##` indexed-signature group into the constituent
/// `IndexedSignature`s.
///
/// Code-directed: each siger's width is read from its CESR hard code (so a group
/// may mix single-index `A` (88 ch) and dual-index `2A` (92 ch), or curves). A
/// signature under a dual-index code populates `prior_index` from its ondex.
pub fn parse_attachment(bytes: &[u8]) -> Result<Vec<IndexedSignature>, AttachmentError> {
    use cesride::{Indexer, Siger};

    let s = std::str::from_utf8(bytes)
        .map_err(|e| AttachmentError::Decode(format!("non-utf8 attachment: {e}")))?;

    if s.is_empty() {
        return Ok(vec![]);
    }

    let rest = s.strip_prefix("-A").ok_or_else(|| {
        AttachmentError::Decode("attachment must start with -A counter code".into())
    })?;
    if rest.len() < 2 {
        return Err(AttachmentError::Decode("truncated counter header".into()));
    }
    let (count_b64, body) = rest.split_at(2);
    let count = decode_count_b64(count_b64)?;

    let mut out = Vec::with_capacity(count);
    let mut cursor = body;
    for _ in 0..count {
        let first = *cursor.as_bytes().first().ok_or_else(|| {
            AttachmentError::Decode("truncated group: expected another signature".into())
        })?;
        let hs = indexer_hard_len(first);
        if cursor.len() < hs {
            return Err(AttachmentError::Decode("truncated siger hard code".into()));
        }
        let code = &cursor[..hs];
        let (fs, os) = indexer_sizage(code)
            .ok_or_else(|| AttachmentError::Decode(format!("unknown indexer code {code:?}")))?;
        if cursor.len() < fs {
            return Err(AttachmentError::Decode(format!(
                "insufficient bytes for {code} siger: need {fs}, have {}",
                cursor.len()
            )));
        }
        let (siger_qb64, remainder) = cursor.split_at(fs);
        cursor = remainder;

        let siger = Siger::new(None, None, None, None, None, None, Some(siger_qb64), None)
            .map_err(|e| AttachmentError::Decode(format!("Siger: {e}")))?;
        // A distinct prior-commitment index is carried only by dual-index codes
        // (os > 0); single-index codes report ondex == index, which is not a binding.
        let prior_index = (os > 0).then(|| siger.ondex());

        out.push(IndexedSignature {
            index: siger.index(),
            prior_index,
            sig: siger.raw(),
        });
    }

    Ok(out)
}

/// Error shape for attachment encode/decode.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttachmentError {
    /// Encoding an indexed signature into CESR failed.
    #[error("attachment encode: {0}")]
    Encode(String),
    /// Decoding a CESR attachment stream failed (bad counter, malformed Siger, etc.).
    #[error("attachment decode: {0}")]
    Decode(String),
}

/// CESR base64url alphabet, ordered so `B64_ALPHA[n]` is the char for n.
const B64_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_count_b64(count: usize) -> Result<String, AttachmentError> {
    if count >= 64 * 64 {
        return Err(AttachmentError::Encode(format!(
            "count {count} exceeds 2-char base64url max (4095)"
        )));
    }
    let hi = B64_ALPHA[(count >> 6) & 0x3f] as char;
    let lo = B64_ALPHA[count & 0x3f] as char;
    Ok(format!("{hi}{lo}"))
}

fn decode_count_b64(s: &str) -> Result<usize, AttachmentError> {
    let mut it = s.chars();
    let hi = it
        .next()
        .and_then(b64_index)
        .ok_or_else(|| AttachmentError::Decode(format!("invalid count hi char: {s:?}")))?;
    let lo = it
        .next()
        .and_then(b64_index)
        .ok_or_else(|| AttachmentError::Decode(format!("invalid count lo char: {s:?}")))?;
    Ok((hi << 6) | lo)
}

fn b64_index(c: char) -> Option<usize> {
    B64_ALPHA.iter().position(|&b| b as char == c)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn attachment_roundtrip_single_sig() {
        let sigs = vec![IndexedSignature {
            index: 0,
            prior_index: None,
            sig: vec![0x42u8; 64],
        }];
        let bytes = serialize_attachment(&sigs).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("-AAB"), "expected -AAB prefix, got {s:?}");
        let back = parse_attachment(&bytes).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].index, 0);
        assert_eq!(back[0].sig, vec![0x42u8; 64]);
    }

    #[test]
    fn attachment_roundtrip_three_sigs() {
        let sigs = vec![
            IndexedSignature {
                index: 0,
                prior_index: None,
                sig: vec![0x01u8; 64],
            },
            IndexedSignature {
                index: 1,
                prior_index: None,
                sig: vec![0x02u8; 64],
            },
            IndexedSignature {
                index: 2,
                prior_index: None,
                sig: vec![0x03u8; 64],
            },
        ];
        let bytes = serialize_attachment(&sigs).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("-AAD"), "expected -AAD prefix, got {s:?}");
        let back = parse_attachment(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        for (i, sig) in back.iter().enumerate() {
            assert_eq!(sig.index, i as u32);
        }
    }

    #[test]
    fn attachment_empty() {
        let bytes = serialize_attachment(&[]).unwrap();
        assert_eq!(bytes, b"-AAA");
        let back = parse_attachment(&bytes).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn keri_sequence_serializes_as_hex() {
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(0)).unwrap(),
            "\"0\""
        );
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(10)).unwrap(),
            "\"a\""
        );
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(255)).unwrap(),
            "\"ff\""
        );
    }

    #[test]
    fn keri_sequence_deserializes_from_hex() {
        let s: KeriSequence = serde_json::from_str("\"0\"").unwrap();
        assert_eq!(s.value(), 0);
        let s: KeriSequence = serde_json::from_str("\"a\"").unwrap();
        assert_eq!(s.value(), 10);
        let s: KeriSequence = serde_json::from_str("\"ff\"").unwrap();
        assert_eq!(s.value(), 255);
    }

    #[test]
    fn keri_sequence_rejects_invalid_hex() {
        assert!(serde_json::from_str::<KeriSequence>("\"not_hex\"").is_err());
    }

    #[test]
    fn icp_event_always_serializes_d_a_c() {
        use crate::types::{CesrKey, Threshold, VersionString};
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest123".to_string()),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey123".to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENext456".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let json = serde_json::to_string(&icp).unwrap();
        // d, a, c are always serialized (spec requires all fields)
        assert!(json.contains("\"d\":"), "d must always be present");
        assert!(json.contains("\"a\":"), "a must always be present");
        assert!(json.contains("\"c\":"), "c must always be present");
        // x is still conditionally omitted (empty)
        assert!(!json.contains("\"x\":"), "empty x must be omitted");
        assert!(json.contains("\"s\":\"0\""), "s must serialize as hex");
    }

    #[test]
    fn event_enum_deserializes_by_t_field() {
        let json = r#"{"v":"KERI10JSON000000_","t":"icp","d":"ETestSaid","i":"E123","s":"0","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_inception());
        assert_eq!(event.sequence().value(), 0);
    }

    #[test]
    fn digest_seal_roundtrips() {
        let seal = Seal::digest("EDigest123");
        let json = serde_json::to_string(&seal).unwrap();
        assert_eq!(json, r#"{"d":"EDigest123"}"#);
        let parsed: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(seal, parsed);
    }

    #[test]
    fn seal_event_location_roundtrips() {
        // A.8 (F-36): the KERI §7 event-location seal {i,s,p,t,d} round-trips.
        let seal = Seal::EventLocation {
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(3),
            p: Said::new_unchecked("EPrior".to_string()),
            t: "ixn".to_string(),
            d: Said::new_unchecked("EDigest".to_string()),
        };
        let json = serde_json::to_string(&seal).unwrap();
        let parsed: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(seal, parsed);
        assert_eq!(parsed.digest_value().map(|d| d.as_str()), Some("EDigest"));
    }

    #[test]
    fn seal_rejects_malformed_i_s() {
        // A.8 (F-37): a malformed {i,s} seal (no d) must error, not silently
        // collapse to a LatestEstablishment {i} that drops `s`.
        let r: Result<Seal, _> = serde_json::from_str(r#"{"i":"EPrefix","s":"3"}"#);
        assert!(r.is_err(), "malformed {{i,s}} seal must be rejected");
        // and an entirely unknown field set errors too.
        let r2: Result<Seal, _> = serde_json::from_str(r#"{"zz":"x"}"#);
        assert!(r2.is_err());
    }

    #[test]
    fn key_event_seal_roundtrips() {
        let seal = Seal::key_event(
            Prefix::new_unchecked("EPrefix".to_string()),
            KeriSequence::new(1),
            Said::new_unchecked("ESaid".to_string()),
        );
        let json = serde_json::to_string(&seal).unwrap();
        let parsed: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(seal, parsed);
    }

    #[test]
    fn indexed_signature_serde_roundtrip() {
        let sig = IndexedSignature {
            index: 2,
            prior_index: None,
            sig: vec![0xab; 64],
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("\"index\":2"));
        assert!(
            !json.contains("prior_index"),
            "a None prior_index must be omitted from the wire: {json}"
        );
        let parsed: IndexedSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn signed_event_accessors() {
        use crate::types::{CesrKey, Threshold, VersionString};
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked("ESAID123".to_string()),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey".to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENext".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let signed = SignedEvent::new(
            Event::Icp(icp),
            vec![IndexedSignature {
                index: 0,
                prior_index: None,
                sig: vec![0u8; 64],
            }],
        );
        assert_eq!(signed.said().as_str(), "ESAID123");
        assert_eq!(signed.sequence().value(), 0);
        assert_eq!(signed.prefix().as_str(), "EPrefix");
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].index, 0);
    }

    #[test]
    fn seal_digest_value() {
        let seal = Seal::digest("ETest123");
        assert_eq!(seal.digest_value().unwrap().as_str(), "ETest123");
        let latest = Seal::LatestEstablishment {
            i: Prefix::new_unchecked("EPrefix".to_string()),
        };
        assert!(latest.digest_value().is_none());
    }
}
