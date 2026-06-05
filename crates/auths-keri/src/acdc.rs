//! ACDC (Authentic Chained Data Container) credential type for Auths.
//!
//! An ACDC is a SAID'd JSON credential anchored to a KEL — the same SAID-ification
//! machinery as KEL events, under the `ACDC10JSON` protocol tag instead of
//! `KERI10JSON`. The v1 shape is `{v, d, i, ri, s, a}`:
//!
//! - `v` — version string `ACDC10JSON{size:06x}_`.
//! - `d` — credential SAID (Blake3-256, CESR `E…`).
//! - `i` — issuer AID (a KERI `did:keri:` prefix; curve-tagged via its inception keys).
//! - `ri` — registry (status) SAID, anchoring revocation state.
//! - `s` — schema SAID (the immutable [`CAPABILITY_SCHEMA`] SAID).
//! - `a` — attributes block with its own nested SAID `a.d` and a holder-bindable
//!   subject `a.i` that is a KERI AID (F.8 enforces holder control).
//!
//! ## Forward-compatibility (honest)
//!
//! The SAID is computed with keripy 1.3.4's ACDC algorithm. A future **top-level
//! `e` (edges)** block re-runs the same algorithm over the larger body: a v1
//! credential that has no `e` keeps its SAID, and an edged credential's `a.d` is
//! unchanged because `a` is untouched. Adding `e` does change the *top-level* `d`
//! (the digest covers the whole body) — so edges are an additive *layout*, not a
//! SAID-preserving mutation.
//!
//! **Selective disclosure (`u`/`A`) is NOT additive.** The blinding nonce `u` lives
//! *inside* the attributes block, changing `a.d` (hence the top-level `d`). SD is
//! therefore a SAID-breaking **v2** (new schema SAID / version), not a drop-in. This
//! module makes no SD forward-compat claim.

use serde::{Deserialize, Serialize};

use crate::said::{Protocol, compute_said_with_protocol, compute_section_said};
use crate::types::{Prefix, Said};

/// Pinned keripy revision whose ACDC SAID algorithm these types reproduce byte-for-byte.
pub const ACDC_KERIPY_REVISION: &str = "keripy 1.3.4";

/// The 17-char ACDC version-string prefix family (`ACDC10JSON…`).
pub const ACDC_VERSION_PREFIX: &str = "ACDC10JSON";

/// The pinned v1 capability schema document (JSON-Schema-2020-12), with its
/// immutable schema SAID already substituted into `$id`.
///
/// This is the document `s` pins and that F.5 embeds for offline/WASM validation.
/// Its SAID is computed by SAID-ifying the *schema document* under the `$id` label
/// (distinct from credential SAID-ification under `d`) — see
/// [`compute_capability_schema_said`].
pub const CAPABILITY_SCHEMA: &str = include_str!("acdc_capability_schema.json");

/// Errors raised while constructing, SAID-ifying, or verifying an [`Acdc`].
#[derive(Debug, thiserror::Error)]
pub enum AcdcError {
    /// The credential body could not be serialized to JSON.
    #[error("ACDC serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// SAID computation failed at the credential or attributes layer.
    #[error("ACDC SAID computation failed: {0}")]
    Said(#[from] crate::error::KeriTranslationError),

    /// A computed SAID did not match the one carried in the credential.
    #[error("ACDC {layer} SAID mismatch: computed {computed}, found {found}")]
    SaidMismatch {
        /// Which layer mismatched (`credential` or `attributes`).
        layer: &'static str,
        /// The SAID recomputed from the body.
        computed: String,
        /// The SAID carried in the credential.
        found: String,
    },
}

/// The attributes (`a`) block of an ACDC — the holder-bound subject claims.
///
/// Serializes in strict insertion order `{d, i, dt, <data…>}` to match keripy.
/// `d` is the nested section SAID; `i` is the subject (holder) AID; `dt` is the
/// issuance datetime; any further claim fields ride in `data` (insertion-ordered).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attributes {
    /// Nested attributes SAID (Blake3-256 over this block with `d` placeholder-filled).
    pub d: Said,
    /// Subject (holder) AID — a curve-tagged KERI prefix; holder-bindable for F.8.
    pub i: Prefix,
    /// ISO-8601 issuance datetime.
    pub dt: String,
    /// Remaining subject claim fields, serialized in insertion order after `dt`.
    #[serde(flatten)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

/// An Authentic Chained Data Container credential (`{v, d, i, ri, s, a}`).
///
/// Construct unsaided fields via [`Acdc::new`], then [`Acdc::saidify`] to compute
/// `a.d` and `d`. Strict field order `v, d, i, ri, s, a` is preserved on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acdc {
    /// Version string `ACDC10JSON{size:06x}_`.
    pub v: String,
    /// Credential SAID (Blake3-256, CESR `E…`).
    pub d: Said,
    /// Issuer AID (a KERI `did:keri:` prefix).
    pub i: Prefix,
    /// Registry (status) SAID.
    pub ri: Said,
    /// Schema SAID.
    pub s: Said,
    /// Attributes block (subject claims) with its own nested SAID `a.d`.
    pub a: Attributes,
}

/// The placeholder version string used before the two-pass size computation.
const ACDC_VERSION_PLACEHOLDER: &str = "ACDC10JSON000000_";

impl Acdc {
    /// Builds an un-SAID'd ACDC; call [`Acdc::saidify`] to fill `a.d` then `d`.
    ///
    /// Args:
    /// * `issuer`: Issuer AID (`i`).
    /// * `registry`: Registry/status SAID (`ri`).
    /// * `schema`: Schema SAID (`s`).
    /// * `subject`: Subject (holder) AID (`a.i`), a curve-tagged KERI prefix.
    /// * `dt`: ISO-8601 issuance datetime (`a.dt`).
    /// * `data`: Additional subject claim fields, appended after `dt` in order.
    ///
    /// Usage:
    /// ```ignore
    /// let acdc = Acdc::new(issuer, registry, schema, subject, dt, data).saidify()?;
    /// ```
    pub fn new(
        issuer: Prefix,
        registry: Said,
        schema: Said,
        subject: Prefix,
        dt: String,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            v: ACDC_VERSION_PLACEHOLDER.to_string(),
            d: Said::default(),
            i: issuer,
            ri: registry,
            s: schema,
            a: Attributes {
                d: Said::default(),
                i: subject,
                dt,
                data,
            },
        }
    }

    /// Computes the nested `a.d` and top-level `d` SAIDs and the `v` size, in place.
    ///
    /// Two-stage, matching keripy: SAID-ify the attributes section first (no version
    /// string), substitute `a.d`, then SAID-ify the whole credential under
    /// [`Protocol::Acdc`] (`ACDC10JSON…`) and substitute `d` and the sized `v`.
    ///
    /// Usage:
    /// ```ignore
    /// let acdc = Acdc::new(/* … */).saidify()?;
    /// assert!(acdc.verify_said().is_ok());
    /// ```
    pub fn saidify(mut self) -> Result<Self, AcdcError> {
        let attr_value = serde_json::to_value(&self.a)?;
        self.a.d = compute_section_said(&attr_value)?;

        let body = serde_json::to_value(&self)?;
        self.d = compute_said_with_protocol(&body, Protocol::Acdc)?;
        self.v = self.recompute_version_string()?;
        Ok(self)
    }

    /// Re-derives the `ACDC10JSON{size}_` version string for the current body.
    fn recompute_version_string(&self) -> Result<String, AcdcError> {
        let mut probe = self.clone();
        probe.v = ACDC_VERSION_PLACEHOLDER.to_string();
        let bytes = serde_json::to_vec(&probe)?;
        Ok(format!("{ACDC_VERSION_PREFIX}{:06x}_", bytes.len()))
    }

    /// Verifies the carried `a.d` and `d` SAIDs against a fresh recomputation.
    ///
    /// Usage:
    /// ```ignore
    /// acdc.verify_said()?; // Err(AcdcError::SaidMismatch) if tampered.
    /// ```
    pub fn verify_said(&self) -> Result<(), AcdcError> {
        let attr_value = serde_json::to_value(&self.a)?;
        let attr_computed = compute_section_said(&attr_value)?;
        if attr_computed != self.a.d {
            return Err(AcdcError::SaidMismatch {
                layer: "attributes",
                computed: attr_computed.into_inner(),
                found: self.a.d.as_str().to_string(),
            });
        }

        let body = serde_json::to_value(self)?;
        let computed = compute_said_with_protocol(&body, Protocol::Acdc)?;
        if computed != self.d {
            return Err(AcdcError::SaidMismatch {
                layer: "credential",
                computed: computed.into_inner(),
                found: self.d.as_str().to_string(),
            });
        }
        Ok(())
    }

    /// Serializes the credential to its canonical insertion-order JSON bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let wire = acdc.to_wire_bytes()?;
    /// ```
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, AcdcError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// Computes the immutable SAID of the pinned capability schema document.
///
/// Schema SAID-ification SAID-ifies the *schema document* under the `$id` label
/// (not the `d` label used for credentials/events): blank `$id` with the 44-char
/// placeholder, serialize the document in insertion order, Blake3-256, CESR `E…`.
/// keripy's `coring.Saider(sad=schema, label="$id")` is the oracle.
///
/// Usage:
/// ```ignore
/// let said = compute_capability_schema_said()?;
/// ```
pub fn compute_capability_schema_said() -> Result<Said, AcdcError> {
    let doc: serde_json::Value = serde_json::from_str(CAPABILITY_SCHEMA)?;
    compute_schema_said(&doc)
}

/// Computes a schema SAID (SAID-ification under the `$id` label).
///
/// Args:
/// * `schema`: The schema document as JSON; its `$id` is placeholder-filled before hashing.
///
/// Usage:
/// ```ignore
/// let said = compute_schema_said(&schema_json)?;
/// ```
pub fn compute_schema_said(schema: &serde_json::Value) -> Result<Said, AcdcError> {
    let obj = schema
        .as_object()
        .ok_or(crate::error::KeriTranslationError::MissingField { field: "schema" })?;

    let placeholder = serde_json::Value::String(crate::said::SAID_PLACEHOLDER.to_string());
    let mut probe = serde_json::Map::new();
    for (k, v) in obj {
        if k == "$id" {
            probe.insert("$id".to_string(), placeholder.clone());
        } else {
            probe.insert(k.clone(), v.clone());
        }
    }
    if !probe.contains_key("$id") {
        probe.insert("$id".to_string(), placeholder.clone());
    }

    let serialized = serde_json::to_vec(&serde_json::Value::Object(probe))
        .map_err(crate::error::KeriTranslationError::SerializationFailed)?;
    let hash = blake3::hash(&serialized);
    #[allow(clippy::expect_used)] // INVARIANT: a 32-byte Blake3 digest always CESR-encodes
    let said = crate::cesr_encode::encode_blake3_digest(hash.as_bytes())
        .expect("32-byte Blake3 digest always encodes as a CESR Blake3_256 SAID");
    Ok(Said::new_unchecked(said))
}
