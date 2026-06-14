//! IPEX — the Issuance & Presentation EXchange protocol.
//!
//! IPEX is KERI's standard peer-to-peer handshake for handing over an ACDC
//! credential. Where a credential *is* an ACDC and its *status* lives in a TEL,
//! IPEX is the *exchange envelope*: a pair of signed `exn` (peer exchange)
//! messages that carry the credential from a discloser to a holder and record
//! the holder's acceptance — the standard way two KERI controllers move a
//! credential between them, instead of each inventing a bespoke presentation
//! wire.
//!
//! Two messages, mirroring the two roles in a disclosure:
//!
//! * **Grant** (discloser → holder): *"here is a credential for you."* An
//!   [`IpexGrant`] is an `exn` routed `/ipex/grant` whose attributes name the
//!   recipient and whose embeds block carries the full ACDC. It opens the
//!   exchange, so it has no prior (`p` is empty).
//! * **Admit** (holder → discloser): *"I accept it."* An [`IpexAdmit`] is an
//!   `exn` routed `/ipex/admit` whose prior (`p`) is the grant's SAID, closing
//!   the loop. It carries no embeds.
//!
//! The wire records are byte-exact with keripy 1.3.4's `keri.vc.protocoling`
//! (`ipexGrantExn` / `ipexAdmitExn` over `keri.peer.exchanging.exchange`). An
//! `exn` serializes in field order `{v, t:"exn", d, i, rp, p, dt, r, q, a, e}`,
//! SAID-ified over the whole record (the top-level `d`), and — for a grant — the
//! embeds block `e` carries its own section SAID (`e.d`) over `{acdc, d}`,
//! exactly as `exchanging.exchange` saidifies `e` under the `d` label. The
//! version string is sized `KERI10JSON{size:06x}_` like every KERI record.
//!
//! This module is I/O-free: it builds and parses the `exn` wire records and
//! pulls the embedded ACDC back out, verifying its SAID. Signing the `exn` and
//! putting it on a transport sit behind ports in the caller (the CLI's IPEX
//! adapter), so the exchange logic never imports a signer or a socket.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::acdc::{Acdc, AcdcError};
use crate::error::KeriTranslationError;
use crate::events::KERI_VERSION_PREFIX;
use crate::said::{Protocol, compute_said_with_protocol, compute_section_said};
use crate::types::{Prefix, Said};

/// Placeholder version string filled in during saidify (17 chars, like every
/// KERI record's `v`).
const KERI_VERSION_PLACEHOLDER: &str = "KERI10JSON000000_";

/// The keripy `exn` ilk — IPEX rides peer exchange messages, not key events.
const EXN_ILK: &str = "exn";

/// Sizes the version string `KERI10JSON{size:06x}_` to a serialized record — the
/// same single-pass machinery the OOBI/TEL records use (the `v` field width is
/// constant, so re-serializing with the placeholder gives the final byte length).
fn recompute_version_string<T: Serialize>(event: &T) -> Result<String, IpexError> {
    let bytes = serde_json::to_vec(event).map_err(KeriTranslationError::SerializationFailed)?;
    Ok(format!("{KERI_VERSION_PREFIX}{:06x}_", bytes.len()))
}

/// An IPEX grant `exn` — *"discloser `i` grants the embedded ACDC to holder `rcp`."*
///
/// Byte-exact with keripy 1.3.4's `ipexGrantExn`: serializes as
/// `{v, t:"exn", d, i, rp:"", p:"", dt, r:"/ipex/grant", q:{},
/// a:{m, i:<recipient>}, e:{acdc:<ACDC>, d:<embeds SAID>}}`. The grant opens an
/// exchange, so `rp` and `p` are empty (keripy's `exchange` leaves them `""` when
/// no recipient/prior is threaded through `exchange`). Build via
/// [`IpexGrant::new`] (which saidifies the embeds block then the whole record),
/// then serialize for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpexGrant {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// SAID of this grant `exn` (Blake3-256 over the saidified record).
    pub d: Said,
    /// Discloser (sender) AID — the controller granting the credential.
    pub i: Prefix,
    /// Human-readable disclosure message (`a.m`); empty by default.
    pub m: String,
    /// Recipient (holder) AID the credential is granted to (`a.i`).
    pub recipient: Prefix,
    /// ISO-8601 datetime stamp (RFC-3339 profile, microsecond precision).
    pub dt: String,
    /// The ACDC being disclosed, carried in the `e.acdc` embeds slot.
    pub acdc: Acdc,
    /// SAID of the embeds block `e` (`e.d`), over `{acdc, d}`.
    pub embeds_said: Said,
}

impl IpexGrant {
    /// The keripy route for an IPEX grant `exn`.
    pub const ROUTE: &'static str = "/ipex/grant";

    /// Builds a saidified IPEX grant `exn` disclosing `acdc` to `recipient`.
    ///
    /// The ACDC must already be saidified (its own `d`/`a.d` filled) — a grant
    /// discloses an existing credential, it does not mint one. `message` is the
    /// optional human-readable note (`a.m`); pass `""` for keripy's default.
    pub fn new(
        sender: Prefix,
        recipient: Prefix,
        acdc: Acdc,
        message: impl Into<String>,
        dt: impl Into<String>,
    ) -> Result<Self, IpexError> {
        let mut grant = Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            d: Said::default(),
            i: sender,
            m: message.into(),
            recipient,
            dt: dt.into(),
            acdc,
            embeds_said: Said::default(),
        };
        grant.saidify()?;
        Ok(grant)
    }

    /// Computes the embeds-block SAID (`e.d`) then the top-level grant SAID, in
    /// place — the two-stage order keripy's `exchange` uses (saidify `e` first,
    /// substitute `e.d`, then saidify the whole `exn`).
    fn saidify(&mut self) -> Result<(), IpexError> {
        // `e.d` is a section SAID over `{acdc, d}` (the embeds block keripy
        // saidifies under the `d` label), with the ACDC carrying its own SAID.
        let embeds = self.embeds_value()?;
        self.embeds_said = compute_section_said(&embeds)?;

        // The top-level `d` is a plain KERI-protocol SAID over the whole record
        // (`exn` is not an inception, so `i` is kept during hashing).
        let body =
            serde_json::to_value(&*self).map_err(KeriTranslationError::SerializationFailed)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        self.v = recompute_version_string(&*self)?;
        Ok(())
    }

    /// The `e` embeds block as JSON: `{acdc:<ACDC>, d:<embeds SAID>}` (the SAID is
    /// placeholder-filled by [`compute_section_said`] when it is recomputed).
    fn embeds_value(&self) -> Result<serde_json::Value, IpexError> {
        let acdc =
            serde_json::to_value(&self.acdc).map_err(KeriTranslationError::SerializationFailed)?;
        let mut e = serde_json::Map::new();
        e.insert("acdc".to_string(), acdc);
        e.insert(
            "d".to_string(),
            serde_json::Value::String(self.embeds_said.as_str().to_string()),
        );
        Ok(serde_json::Value::Object(e))
    }

    /// Parses a peer's grant `exn` JSON into a typed [`IpexGrant`], verifying both
    /// the record SAID and the embedded ACDC SAID at the boundary.
    ///
    /// Total at the boundary: a record whose route is not `/ipex/grant`, whose
    /// `d`/`e.d` SAIDs don't recompute, or whose embedded ACDC fails its own SAID
    /// check never becomes an `IpexGrant`.
    pub fn parse(json: &str) -> Result<Self, IpexError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(KeriTranslationError::SerializationFailed)?;
        let obj = value.as_object().ok_or(IpexError::NotAnObject)?;

        expect_ilk(obj)?;
        expect_route(obj, Self::ROUTE)?;

        let sender = parse_prefix(obj, "i")?;
        let dt = parse_str(obj, "dt")?;

        let a = obj
            .get("a")
            .and_then(|v| v.as_object())
            .ok_or(IpexError::MissingField { field: "a" })?;
        let message = a
            .get("m")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let recipient = a
            .get("i")
            .and_then(|v| v.as_str())
            .ok_or(IpexError::MissingField { field: "a.i" })
            .and_then(|s| {
                Prefix::new(s.to_string()).map_err(|source| IpexError::Prefix {
                    field: "a.i",
                    source,
                })
            })?;

        let e = obj
            .get("e")
            .and_then(|v| v.as_object())
            .ok_or(IpexError::MissingField { field: "e" })?;
        let acdc_value = e
            .get("acdc")
            .ok_or(IpexError::MissingField { field: "e.acdc" })?;
        let acdc: Acdc = serde_json::from_value(acdc_value.clone())
            .map_err(KeriTranslationError::SerializationFailed)?;
        // The embedded credential must stand on its own SAID — a grant cannot
        // launder a tampered ACDC behind the exchange envelope.
        acdc.verify_said()?;

        let grant = Self::new(sender, recipient, acdc, message, dt)?;
        verify_said(obj, &grant.d)?;
        Ok(grant)
    }
}

impl Serialize for IpexGrant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(11))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", EXN_ILK)?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("rp", "")?;
        map.serialize_entry("p", "")?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", IpexGrant::ROUTE)?;
        map.serialize_entry("q", &serde_json::Map::<String, serde_json::Value>::new())?;
        let mut a = serde_json::Map::new();
        a.insert("m".into(), serde_json::Value::String(self.m.clone()));
        a.insert(
            "i".into(),
            serde_json::Value::String(self.recipient.to_string()),
        );
        map.serialize_entry("a", &serde_json::Value::Object(a))?;
        let mut e = serde_json::Map::new();
        e.insert(
            "acdc".into(),
            serde_json::to_value(&self.acdc).map_err(serde::ser::Error::custom)?,
        );
        e.insert(
            "d".into(),
            serde_json::Value::String(self.embeds_said.as_str().to_string()),
        );
        map.serialize_entry("e", &serde_json::Value::Object(e))?;
        map.end()
    }
}

/// An IPEX admit `exn` — *"holder `i` admits the grant `p`."*
///
/// Byte-exact with keripy 1.3.4's `ipexAdmitExn`: serializes as
/// `{v, t:"exn", d, i, rp:"", p:<grant SAID>, dt, r:"/ipex/admit", q:{},
/// a:{m}, e:{}}`. The admit responds to a grant, so its prior (`p`) is the grant
/// SAID and its embeds block `e` is empty (no `e.d`, since there is nothing to
/// saidify). Build via [`IpexAdmit::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpexAdmit {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// SAID of this admit `exn`.
    pub d: Said,
    /// Holder (sender) AID admitting the disclosure.
    pub i: Prefix,
    /// Human-readable admission message (`a.m`); empty by default.
    pub m: String,
    /// Prior (`p`) — the SAID of the grant this admit responds to.
    pub prior: Said,
    /// ISO-8601 datetime stamp.
    pub dt: String,
}

impl IpexAdmit {
    /// The keripy route for an IPEX admit `exn`.
    pub const ROUTE: &'static str = "/ipex/admit";

    /// Builds a saidified IPEX admit `exn` accepting the grant identified by
    /// `grant_said`.
    pub fn new(
        sender: Prefix,
        grant_said: Said,
        message: impl Into<String>,
        dt: impl Into<String>,
    ) -> Result<Self, IpexError> {
        let mut admit = Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            d: Said::default(),
            i: sender,
            m: message.into(),
            prior: grant_said,
            dt: dt.into(),
        };
        admit.saidify()?;
        Ok(admit)
    }

    fn saidify(&mut self) -> Result<(), IpexError> {
        let body =
            serde_json::to_value(&*self).map_err(KeriTranslationError::SerializationFailed)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        self.v = recompute_version_string(&*self)?;
        Ok(())
    }

    /// Parses a peer's admit `exn` JSON into a typed [`IpexAdmit`], verifying the
    /// record SAID and that it threads a prior grant SAID at the boundary.
    pub fn parse(json: &str) -> Result<Self, IpexError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(KeriTranslationError::SerializationFailed)?;
        let obj = value.as_object().ok_or(IpexError::NotAnObject)?;

        expect_ilk(obj)?;
        expect_route(obj, Self::ROUTE)?;

        let sender = parse_prefix(obj, "i")?;
        let dt = parse_str(obj, "dt")?;
        let prior_str = parse_str(obj, "p")?;
        if prior_str.is_empty() {
            // An admit with no prior is not threading any grant — it cannot open
            // an IPEX exchange (keripy's IpexHandler rejects the same way).
            return Err(IpexError::MissingPrior);
        }
        let prior =
            Said::new(prior_str).map_err(|source| IpexError::Prefix { field: "p", source })?;

        let admit = Self::new(sender, prior, message_of(obj), dt)?;
        verify_said(obj, &admit.d)?;
        Ok(admit)
    }
}

impl Serialize for IpexAdmit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", EXN_ILK)?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("rp", "")?;
        map.serialize_entry("p", &self.prior)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", IpexAdmit::ROUTE)?;
        map.serialize_entry("q", &serde_json::Map::<String, serde_json::Value>::new())?;
        let mut a = serde_json::Map::new();
        a.insert("m".into(), serde_json::Value::String(self.m.clone()));
        map.serialize_entry("a", &serde_json::Value::Object(a))?;
        map.serialize_entry("e", &serde_json::Map::<String, serde_json::Value>::new())?;
        map.end()
    }
}

/// Reads the `a.m` message field of an `exn`, defaulting to `""`.
fn message_of(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    obj.get("a")
        .and_then(|v| v.as_object())
        .and_then(|a| a.get("m"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Rejects a record whose ilk (`t`) is not `exn` at the boundary.
fn expect_ilk(obj: &serde_json::Map<String, serde_json::Value>) -> Result<(), IpexError> {
    match obj.get("t").and_then(|v| v.as_str()) {
        Some(EXN_ILK) => Ok(()),
        other => Err(IpexError::WrongIlk(other.unwrap_or("").to_string())),
    }
}

/// Rejects a record whose route (`r`) is not the expected IPEX route.
fn expect_route(
    obj: &serde_json::Map<String, serde_json::Value>,
    route: &'static str,
) -> Result<(), IpexError> {
    match obj.get("r").and_then(|v| v.as_str()) {
        Some(r) if r == route => Ok(()),
        other => Err(IpexError::WrongRoute {
            expected: route,
            found: other.unwrap_or("").to_string(),
        }),
    }
}

/// Reads a required string field, or errors with its name.
fn parse_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<String, IpexError> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or(IpexError::MissingField { field })
}

/// Reads a required prefix field, validating its CESR coding at the boundary.
fn parse_prefix(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<Prefix, IpexError> {
    let s = parse_str(obj, field)?;
    Prefix::new(s).map_err(|source| IpexError::Prefix { field, source })
}

/// Verifies a parsed record's carried `d` matches the SAID we recomputed.
fn verify_said(
    obj: &serde_json::Map<String, serde_json::Value>,
    computed: &Said,
) -> Result<(), IpexError> {
    let found = obj
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(IpexError::MissingField { field: "d" })?;
    if found != computed.as_str() {
        return Err(IpexError::SaidMismatch {
            computed: computed.as_str().to_string(),
            found: found.to_string(),
        });
    }
    Ok(())
}

/// Errors raised while building or parsing an IPEX `exn`.
#[derive(Debug, thiserror::Error)]
pub enum IpexError {
    /// The record was not a JSON object.
    #[error("IPEX record is not a JSON object")]
    NotAnObject,
    /// The record's ilk (`t`) was not `exn`.
    #[error("IPEX record is not an exn (t = {0:?})")]
    WrongIlk(String),
    /// The record's route (`r`) was not the expected IPEX route.
    #[error("IPEX record route is {found:?}, expected {expected:?}")]
    WrongRoute {
        /// The route the parser required.
        expected: &'static str,
        /// The route the record actually carried.
        found: String,
    },
    /// A required field was absent.
    #[error("IPEX record missing field {field}")]
    MissingField {
        /// The absent field's path.
        field: &'static str,
    },
    /// An admit carried no prior grant SAID, so it threads no exchange.
    #[error("IPEX admit has no prior grant (p is empty)")]
    MissingPrior,
    /// A prefix/SAID field was not a CESR-valid value.
    #[error("invalid {field} in IPEX record: {source}")]
    Prefix {
        /// Which field failed.
        field: &'static str,
        /// The underlying CESR/derivation-code error.
        source: crate::types::KeriTypeError,
    },
    /// The carried `d` SAID did not match the one recomputed from the record.
    #[error("IPEX record SAID mismatch: computed {computed}, found {found}")]
    SaidMismatch {
        /// The SAID recomputed from the record.
        computed: String,
        /// The SAID the record carried.
        found: String,
    },
    /// The embedded ACDC failed to build/verify.
    #[error("IPEX embedded ACDC failed: {0}")]
    Acdc(#[from] AcdcError),
    /// A wire record failed to saidify/serialize.
    #[error("KERI record build failed: {0}")]
    Record(#[from] KeriTranslationError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::acdc::Acdc;

    const SENDER: &str = "EOoC9Auw5kgKLi0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM";
    const RECP: &str = "EBHnCvYya3Udo4SEGo82HeOPt7WkVDEC0KWfKYnZpupF";
    const REGISTRY: &str = "EO0_SHla5Gnzc-T3jkTNAclpA1iv1L9k3lQZw5cFOe9o";
    const SCHEMA: &str = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC";
    const DT: &str = "2024-01-01T00:00:00.000000+00:00";
    /// The grant `exn` SAID keripy 1.3.4 computes for the [`fixture_acdc`] grant.
    const GRANT_SAID: &str = "EGTOcVx8ghSFYwMQT_q4YMjEzlUIh93kKfvnIzgtfgkS";

    /// Builds the same ACDC keripy embedded in the reference grant vector.
    fn fixture_acdc() -> Acdc {
        Acdc::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Said::new(REGISTRY.to_string()).unwrap(),
            Said::new(SCHEMA.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            DT.to_string(),
            serde_json::Map::new(),
        )
        .saidify()
        .unwrap()
    }

    // The grant `exn` must be byte-exact with keripy 1.3.4's `ipexGrantExn`. This
    // vector was generated from keripy itself (the oracle):
    //   exchanging.exchange(route="/ipex/grant", payload={m:"", i:RECP},
    //                       sender=SENDER, embeds={acdc:<ACDC>}, date=DT)
    #[test]
    fn grant_exn_byte_exact_keripy() {
        let grant = IpexGrant::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            fixture_acdc(),
            "",
            DT,
        )
        .unwrap();
        let json = serde_json::to_string(&grant).unwrap();
        let expected = r#"{"v":"KERI10JSON0002d4_","t":"exn","d":"EGTOcVx8ghSFYwMQT_q4YMjEzlUIh93kKfvnIzgtfgkS","i":"EOoC9Auw5kgKLi0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","rp":"","p":"","dt":"2024-01-01T00:00:00.000000+00:00","r":"/ipex/grant","q":{},"a":{"m":"","i":"EBHnCvYya3Udo4SEGo82HeOPt7WkVDEC0KWfKYnZpupF"},"e":{"acdc":{"v":"ACDC10JSON00017a_","d":"ECK0Ep4HfnszjMpQDgovp19ioPdn1jwxGdnEtNHCN2Sy","i":"EOoC9Auw5kgKLi0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","ri":"EO0_SHla5Gnzc-T3jkTNAclpA1iv1L9k3lQZw5cFOe9o","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EKP_MEtpMtJfInZdMOiivHrYtz3zyObVfjDySEGxGT-V","i":"EBHnCvYya3Udo4SEGo82HeOPt7WkVDEC0KWfKYnZpupF","dt":"2024-01-01T00:00:00.000000+00:00"}},"d":"EOXgGpKt_2f6rr_JyxVwEBT1z6xbACKW0PLDhoULb0ag"}}"#;
        assert_eq!(json, expected);
    }

    // The admit `exn` must be byte-exact with keripy 1.3.4's `ipexAdmitExn`:
    //   exchanging.exchange(route="/ipex/admit", payload={m:""}, sender=RECP,
    //                       dig=grant.said, date=DT)
    #[test]
    fn admit_exn_byte_exact_keripy() {
        let admit = IpexAdmit::new(
            Prefix::new(RECP.to_string()).unwrap(),
            Said::new(GRANT_SAID.to_string()).unwrap(),
            "",
            DT,
        )
        .unwrap();
        let json = serde_json::to_string(&admit).unwrap();
        let expected = r#"{"v":"KERI10JSON000119_","t":"exn","d":"EEAwH5LPMA4bkj5ceowBjGDnpe7aWW1BQ530djvBp1kv","i":"EBHnCvYya3Udo4SEGo82HeOPt7WkVDEC0KWfKYnZpupF","rp":"","p":"EGTOcVx8ghSFYwMQT_q4YMjEzlUIh93kKfvnIzgtfgkS","dt":"2024-01-01T00:00:00.000000+00:00","r":"/ipex/admit","q":{},"a":{"m":""},"e":{}}"#;
        assert_eq!(json, expected);
    }

    #[test]
    fn grant_round_trips_through_parse() {
        let grant = IpexGrant::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            fixture_acdc(),
            "",
            DT,
        )
        .unwrap();
        let json = serde_json::to_string(&grant).unwrap();
        let parsed = IpexGrant::parse(&json).unwrap();
        assert_eq!(parsed, grant);
        // The embedded ACDC came back out intact and self-verifying.
        assert_eq!(parsed.acdc.d, grant.acdc.d);
        parsed.acdc.verify_said().unwrap();
    }

    #[test]
    fn admit_round_trips_through_parse() {
        let admit = IpexAdmit::new(
            Prefix::new(RECP.to_string()).unwrap(),
            Said::new(GRANT_SAID.to_string()).unwrap(),
            "",
            DT,
        )
        .unwrap();
        let json = serde_json::to_string(&admit).unwrap();
        let parsed = IpexAdmit::parse(&json).unwrap();
        assert_eq!(parsed, admit);
    }

    #[test]
    fn parse_rejects_tampered_grant_said() {
        let grant = IpexGrant::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            fixture_acdc(),
            "",
            DT,
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&grant).unwrap()).unwrap();
        value["dt"] = serde_json::Value::String("2099-01-01T00:00:00.000000+00:00".into());
        let tampered = serde_json::to_string(&value).unwrap();
        let err = IpexGrant::parse(&tampered).unwrap_err();
        assert!(matches!(err, IpexError::SaidMismatch { .. }));
    }

    #[test]
    fn parse_rejects_tampered_embedded_acdc() {
        let grant = IpexGrant::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            fixture_acdc(),
            "",
            DT,
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&grant).unwrap()).unwrap();
        // Tamper a credential claim without fixing its SAID — must be rejected.
        value["e"]["acdc"]["a"]["dt"] =
            serde_json::Value::String("2099-01-01T00:00:00.000000+00:00".into());
        let tampered = serde_json::to_string(&value).unwrap();
        let err = IpexGrant::parse(&tampered).unwrap_err();
        assert!(matches!(err, IpexError::Acdc(_)));
    }

    #[test]
    fn parse_rejects_wrong_route() {
        let grant = IpexGrant::new(
            Prefix::new(SENDER.to_string()).unwrap(),
            Prefix::new(RECP.to_string()).unwrap(),
            fixture_acdc(),
            "",
            DT,
        )
        .unwrap();
        let json = serde_json::to_string(&grant).unwrap();
        // A grant body is not an admit.
        let err = IpexAdmit::parse(&json).unwrap_err();
        assert!(matches!(err, IpexError::WrongRoute { .. }));
    }

    #[test]
    fn admit_parse_rejects_missing_prior() {
        let admit = IpexAdmit::new(
            Prefix::new(RECP.to_string()).unwrap(),
            Said::new(GRANT_SAID.to_string()).unwrap(),
            "",
            DT,
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&admit).unwrap()).unwrap();
        value["p"] = serde_json::Value::String(String::new());
        let stripped = serde_json::to_string(&value).unwrap();
        let err = IpexAdmit::parse(&stripped).unwrap_err();
        assert!(matches!(err, IpexError::MissingPrior));
    }
}
