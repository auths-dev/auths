//! Backerless TEL (Transaction Event Log) events for Auths credential status.
//!
//! A TEL is the KERI-native revocation registry. A *backerless* (`NB`) registry
//! derives all of its trust from the issuer's KEL — there is no separate backer
//! quorum (which would map onto witness infrastructure not run here). Three event
//! types form the log, all SAID'd under the KERI protocol family (`KERI10JSON…`),
//! matching keripy 1.3.4's `keri.vdr.eventing` byte-for-byte:
//!
//! - [`Vcp`] — registry inception. Self-addressing: `i` (registry SAID) equals
//!   `d` and both are blanked during SAID-ification (same rule as KEL `icp`/`dip`).
//!   Carries `c = ["NB"]`, `bt = "0"`, `b = []`, and a nonce `n`.
//! - [`Iss`] — credential issuance. `i` is the *credential* SAID (an external
//!   reference, never blanked); `s = "0"`; `ri` links the registry.
//! - [`Rev`] — credential revocation. `i` is the credential SAID; `s = "1"`;
//!   `ri` links the registry; `p` back-links the prior `iss` SAID (the chain).
//!
//! [`validate_tel`] is a pure function over an ordered event slice that enforces
//! the `vcp → iss → rev` chain (back-link `p` + monotonic `s`) and returns a
//! [`TelState`] of issued/revoked credentials, or a typed [`TelError`].
//!
//! ## `dt` is informational
//!
//! Both `iss` and `rev` carry an ISO-8601 `dt`. Per the clock-injection rule it is
//! never branched on for correctness — it is preserved on the wire and committed by
//! the SAID, but [`validate_tel`] does not compare or order by it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::TelError;
use crate::events::KeriSequence;
use crate::said::{Protocol, compute_said_with_protocol};
use crate::types::{Prefix, Said};

/// Pinned keripy revision whose TEL event SAID algorithm these types reproduce byte-for-byte.
pub const TEL_KERIPY_REVISION: &str = "keripy 1.3.4";

/// The backerless registry config trait code (`NoBackers`), as emitted in `vcp.c`.
pub const TRAIT_NO_BACKERS: &str = "NB";

/// The 17-char placeholder version string used before the two-pass size computation.
const KERI_VERSION_PLACEHOLDER: &str = "KERI10JSON000000_";

/// The 10-char KERI version-string prefix family (`KERI10JSON…`).
const KERI_VERSION_PREFIX: &str = "KERI10JSON";

/// Recomputes the `KERI10JSON{size:06x}_` version string for a serializable TEL event.
///
/// Two-pass, matching keripy: serialize the body with a zeroed-size placeholder
/// `v`, measure the byte count, then format the real version string (identical
/// length, so the size is stable).
fn recompute_version_string<T: Serialize>(event: &T) -> Result<String, TelError> {
    let bytes = serde_json::to_vec(event)?;
    Ok(format!("{KERI_VERSION_PREFIX}{:06x}_", bytes.len()))
}

/// Registry inception event (`vcp`) for a backerless (`NB`) TEL.
///
/// Strict insertion order `{v, t, d, i, ii, s, c, bt, b, n}` matches keripy 1.3.4.
/// `i` (the registry SAID) is self-addressing: it equals `d`, and both are blanked
/// during SAID-ification. Construct via [`Vcp::new`] then [`Vcp::saidify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vcp {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// Event type — always `"vcp"`.
    pub t: String,
    /// Registry SAID (Blake3-256, CESR `E…`). Self-addressing: equals `i`.
    pub d: Said,
    /// Registry SAID again (self-addressing identifier of the registry).
    pub i: Said,
    /// Issuing AID — the issuer's KERI prefix that controls this registry.
    pub ii: Prefix,
    /// Sequence number — always `"0"` for the inception event.
    pub s: KeriSequence,
    /// Config traits — `["NB"]` for a backerless registry.
    pub c: Vec<String>,
    /// Backer threshold — `"0"` for a backerless registry.
    pub bt: KeriSequence,
    /// Backer AID list — empty for a backerless registry.
    pub b: Vec<Prefix>,
    /// Registry nonce (CESR salt), making each registry SAID unique.
    pub n: String,
}

impl Vcp {
    /// Builds an un-SAID'd backerless `vcp`; call [`Vcp::saidify`] to fill `i`/`d`.
    ///
    /// Args:
    /// * `issuer`: The issuing AID (`ii`) that controls the registry via its KEL.
    /// * `nonce`: A CESR-encoded nonce (`n`) making the registry SAID unique.
    ///
    /// Usage:
    /// ```ignore
    /// let vcp = Vcp::new(issuer, nonce).saidify()?;
    /// ```
    pub fn new(issuer: Prefix, nonce: String) -> Self {
        Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            t: "vcp".to_string(),
            d: Said::default(),
            i: Said::default(),
            ii: issuer,
            s: KeriSequence::new(0),
            c: vec![TRAIT_NO_BACKERS.to_string()],
            bt: KeriSequence::new(0),
            b: Vec::new(),
            n: nonce,
        }
    }

    /// Computes the self-addressing registry SAID, filling `d`, `i`, and the sized `v`.
    ///
    /// Usage:
    /// ```ignore
    /// let vcp = Vcp::new(issuer, nonce).saidify()?;
    /// assert!(vcp.verify_said().is_ok());
    /// ```
    pub fn saidify(mut self) -> Result<Self, TelError> {
        let body = serde_json::to_value(&self)?;
        let said = compute_said_with_protocol(&body, Protocol::Keri)?;
        self.d = said.clone();
        self.i = said;
        self.v = recompute_version_string(&self.probe())?;
        Ok(self)
    }

    /// A clone with `v` reset to the placeholder, for the two-pass size measurement.
    fn probe(&self) -> Self {
        let mut probe = self.clone();
        probe.v = KERI_VERSION_PLACEHOLDER.to_string();
        probe
    }

    /// The registry SAID this inception establishes (the value carried in `iss`/`rev` `ri`).
    pub fn registry(&self) -> &Said {
        &self.d
    }

    /// Verifies the carried `d` (and self-addressing `i`) against a fresh recomputation.
    ///
    /// Usage:
    /// ```ignore
    /// vcp.verify_said()?; // Err(TelError::SaidMismatch) if tampered.
    /// ```
    pub fn verify_said(&self) -> Result<(), TelError> {
        verify_event_said(self, &self.d, "vcp")?;
        if self.i != self.d {
            return Err(TelError::SaidMismatch {
                event_type: "vcp",
                computed: self.d.as_str().to_string(),
                found: self.i.as_str().to_string(),
            });
        }
        Ok(())
    }
}

/// Credential issuance event (`iss`).
///
/// Strict insertion order `{v, t, d, i, s, ri, dt}` matches keripy 1.3.4. `i` is
/// the *credential* SAID (an external reference, never blanked); `s` is always
/// `"0"`; `ri` links the registry SAID. Construct via [`Iss::new`] then [`Iss::saidify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iss {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// Event type — always `"iss"`.
    pub t: String,
    /// Event SAID (Blake3-256, CESR `E…`).
    pub d: Said,
    /// Credential SAID being issued.
    pub i: Said,
    /// Sequence number — always `"0"` for issuance.
    pub s: KeriSequence,
    /// Registry SAID this issuance belongs to.
    pub ri: Said,
    /// ISO-8601 issuance datetime (informational; never branched on for correctness).
    pub dt: String,
}

impl Iss {
    /// Builds an un-SAID'd `iss`; call [`Iss::saidify`] to fill `d`.
    ///
    /// Args:
    /// * `credential`: The credential SAID being issued (`i`).
    /// * `registry`: The registry SAID (`ri`) from a [`Vcp`].
    /// * `dt`: ISO-8601 issuance datetime (`dt`).
    ///
    /// Usage:
    /// ```ignore
    /// let iss = Iss::new(credential, registry, dt).saidify()?;
    /// ```
    pub fn new(credential: Said, registry: Said, dt: String) -> Self {
        Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            t: "iss".to_string(),
            d: Said::default(),
            i: credential,
            s: KeriSequence::new(0),
            ri: registry,
            dt,
        }
    }

    /// Computes the event SAID, filling `d` and the sized `v`.
    pub fn saidify(mut self) -> Result<Self, TelError> {
        let body = serde_json::to_value(&self)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        let mut probe = self.clone();
        probe.v = KERI_VERSION_PLACEHOLDER.to_string();
        self.v = recompute_version_string(&probe)?;
        Ok(self)
    }

    /// Verifies the carried `d` against a fresh recomputation.
    pub fn verify_said(&self) -> Result<(), TelError> {
        verify_event_said(self, &self.d, "iss")
    }
}

/// Credential revocation event (`rev`).
///
/// Strict insertion order `{v, t, d, i, s, ri, p, dt}` matches keripy 1.3.4. `i`
/// is the *credential* SAID; `s` is always `"1"`; `ri` links the registry; `p`
/// back-links the prior `iss` SAID (the chain). Construct via [`Rev::new`] then
/// [`Rev::saidify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rev {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// Event type — always `"rev"`.
    pub t: String,
    /// Event SAID (Blake3-256, CESR `E…`).
    pub d: Said,
    /// Credential SAID being revoked.
    pub i: Said,
    /// Sequence number — always `"1"` for revocation.
    pub s: KeriSequence,
    /// Registry SAID this revocation belongs to.
    pub ri: Said,
    /// Prior event SAID — the `iss` event's `d` (the chain back-link).
    pub p: Said,
    /// ISO-8601 revocation datetime (informational; never branched on for correctness).
    pub dt: String,
}

impl Rev {
    /// Builds an un-SAID'd `rev`; call [`Rev::saidify`] to fill `d`.
    ///
    /// Args:
    /// * `credential`: The credential SAID being revoked (`i`).
    /// * `registry`: The registry SAID (`ri`) from a [`Vcp`].
    /// * `prior`: The prior `iss` event SAID (`p`, the chain back-link).
    /// * `dt`: ISO-8601 revocation datetime (`dt`).
    ///
    /// Usage:
    /// ```ignore
    /// let rev = Rev::new(credential, registry, iss.d.clone(), dt).saidify()?;
    /// ```
    pub fn new(credential: Said, registry: Said, prior: Said, dt: String) -> Self {
        Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            t: "rev".to_string(),
            d: Said::default(),
            i: credential,
            s: KeriSequence::new(1),
            ri: registry,
            p: prior,
            dt,
        }
    }

    /// Computes the event SAID, filling `d` and the sized `v`.
    pub fn saidify(mut self) -> Result<Self, TelError> {
        let body = serde_json::to_value(&self)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        let mut probe = self.clone();
        probe.v = KERI_VERSION_PLACEHOLDER.to_string();
        self.v = recompute_version_string(&probe)?;
        Ok(self)
    }

    /// Verifies the carried `d` against a fresh recomputation.
    pub fn verify_said(&self) -> Result<(), TelError> {
        verify_event_said(self, &self.d, "rev")
    }
}

/// Recomputes a TEL event's SAID and checks it against the carried `d`.
fn verify_event_said<T: Serialize>(
    event: &T,
    carried: &Said,
    event_type: &'static str,
) -> Result<(), TelError> {
    let body = serde_json::to_value(event)?;
    let computed = compute_said_with_protocol(&body, Protocol::Keri)?;
    if &computed != carried {
        return Err(TelError::SaidMismatch {
            event_type,
            computed: computed.into_inner(),
            found: carried.as_str().to_string(),
        });
    }
    Ok(())
}

/// The TEL→KEL anchor seal — a key-event seal carried in the issuer KEL `ixn`'s `a[]`.
///
/// keripy 1.3.4 anchors a TEL event into the issuer's KEL with a `SealEvent`
/// (`{i, s, d}`): the registry/credential AID, the TEL event sequence number, and
/// the TEL event SAID. The verifier (F.5) checks the issuer KEL `ixn` carries this
/// exact shape. This is the `{i, s, d}` source-seal — not the bare `{s, d}` form.
///
/// Usage:
/// ```ignore
/// let seal = TelAnchorSeal::for_event(registry.clone(), iss.s, iss.d.clone());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelAnchorSeal {
    /// The registry/credential AID the TEL event belongs to.
    pub i: Prefix,
    /// The TEL event sequence number (`s`).
    pub s: KeriSequence,
    /// The TEL event SAID (`d`).
    pub d: Said,
}

impl TelAnchorSeal {
    /// Builds the `{i, s, d}` anchor seal for a TEL event.
    ///
    /// Args:
    /// * `aid`: The registry/credential AID the TEL event belongs to (`i`).
    /// * `sequence`: The TEL event sequence number (`s`).
    /// * `said`: The TEL event SAID (`d`).
    ///
    /// Usage:
    /// ```ignore
    /// let seal = TelAnchorSeal::for_event(registry, iss.s, iss.d.clone());
    /// ```
    pub fn for_event(aid: Prefix, sequence: KeriSequence, said: Said) -> Self {
        Self {
            i: aid,
            s: sequence,
            d: said,
        }
    }
}

/// The resolved status of a TEL after replaying its events in order.
///
/// `issued` holds every credential SAID a valid `iss` introduced; `revoked` holds
/// those a valid `rev` subsequently revoked. A credential present in `issued` but
/// absent from `revoked` is *currently valid*.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelState {
    /// Credential SAIDs introduced by an `iss` event.
    pub issued: Vec<Said>,
    /// Credential SAIDs revoked by a `rev` event.
    pub revoked: Vec<Said>,
}

impl TelState {
    /// Returns true if `credential` was issued and not subsequently revoked.
    ///
    /// Args:
    /// * `credential`: The credential SAID to check.
    pub fn is_valid(&self, credential: &Said) -> bool {
        self.issued.contains(credential) && !self.revoked.contains(credential)
    }
}

/// A single backerless TEL event, tagged by its event type.
///
/// `validate_tel` consumes an ordered slice of these. Deserializes from the wire
/// by dispatching on the `t` field — never on byte length or field count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelEvent {
    /// Registry inception.
    Vcp(Vcp),
    /// Credential issuance.
    Iss(Iss),
    /// Credential revocation.
    Rev(Rev),
}

impl TelEvent {
    /// Parses a single TEL event from its wire JSON bytes, dispatching on `t`.
    ///
    /// Args:
    /// * `bytes`: The insertion-order JSON serialization of one TEL event.
    ///
    /// Usage:
    /// ```ignore
    /// let event = TelEvent::from_wire_bytes(&iss.to_wire_bytes()?)?;
    /// ```
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, TelError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let event_type = value
            .get("t")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TelError::Said("TEL event missing required field 't'".to_string()))?;
        match event_type {
            "vcp" => Ok(TelEvent::Vcp(serde_json::from_value(value)?)),
            "iss" => Ok(TelEvent::Iss(serde_json::from_value(value)?)),
            "rev" => Ok(TelEvent::Rev(serde_json::from_value(value)?)),
            other => Err(TelError::BrokenChain {
                credential: String::new(),
                detail: format!("unknown TEL event type '{other}'"),
            }),
        }
    }
}

/// Validates an ordered backerless TEL and resolves its issued/revoked state.
///
/// The events must form a valid `vcp → iss… → rev…` log:
/// - The first event MUST be a `vcp` registry inception.
/// - Every `iss` MUST name the inceptioned registry (`ri == vcp.d`) and introduce a
///   credential exactly once (no double-issue).
/// - Every `rev` MUST reference a previously-issued credential, name the same
///   registry, back-link the credential's `iss` SAID via `p`, carry a strictly
///   greater `s` than that `iss`, and revoke exactly once (no double-revoke).
/// - Every event's carried `d` SAID MUST match a fresh recomputation.
///
/// `dt` is informational and is never compared or ordered on (clock-injection rule).
///
/// Args:
/// * `events`: The TEL events in insertion order, starting with the `vcp`.
///
/// Usage:
/// ```ignore
/// let state = validate_tel(&[TelEvent::Vcp(vcp), TelEvent::Iss(iss)])?;
/// assert!(state.is_valid(&credential));
/// ```
pub fn validate_tel(events: &[TelEvent]) -> Result<TelState, TelError> {
    let mut iter = events.iter();
    let registry = match iter.next() {
        Some(TelEvent::Vcp(vcp)) => {
            vcp.verify_said()?;
            vcp.registry().clone()
        }
        _ => return Err(TelError::MissingInception),
    };

    let mut state = TelState::default();
    let mut issuances: HashMap<String, Issuance> = HashMap::new();

    for event in iter {
        match event {
            TelEvent::Vcp(_) => {
                return Err(TelError::BrokenChain {
                    credential: registry.as_str().to_string(),
                    detail: "a second vcp inception is not allowed in one TEL".to_string(),
                });
            }
            TelEvent::Iss(iss) => apply_iss(iss, &registry, &mut state, &mut issuances)?,
            TelEvent::Rev(rev) => apply_rev(rev, &registry, &mut state, &issuances)?,
        }
    }

    Ok(state)
}

/// The recorded issuance of a credential — its `iss` SAID and sequence number, for
/// the `rev` chain check (`p` back-link + monotonic `s`).
struct Issuance {
    said: Said,
    sequence: u128,
}

/// Applies one `iss` event to the running TEL state.
fn apply_iss(
    iss: &Iss,
    registry: &Said,
    state: &mut TelState,
    issuances: &mut HashMap<String, Issuance>,
) -> Result<(), TelError> {
    iss.verify_said()?;
    if &iss.ri != registry {
        return Err(TelError::IssWithoutRegistry {
            registry: iss.ri.as_str().to_string(),
        });
    }
    if state.issued.contains(&iss.i) {
        return Err(TelError::DoubleIss {
            credential: iss.i.as_str().to_string(),
        });
    }
    issuances.insert(
        iss.i.as_str().to_string(),
        Issuance {
            said: iss.d.clone(),
            sequence: iss.s.value(),
        },
    );
    state.issued.push(iss.i.clone());
    Ok(())
}

/// Applies one `rev` event to the running TEL state.
fn apply_rev(
    rev: &Rev,
    registry: &Said,
    state: &mut TelState,
    issuances: &HashMap<String, Issuance>,
) -> Result<(), TelError> {
    rev.verify_said()?;
    if &rev.ri != registry {
        return Err(TelError::IssWithoutRegistry {
            registry: rev.ri.as_str().to_string(),
        });
    }
    let prior = issuances
        .get(rev.i.as_str())
        .ok_or_else(|| TelError::RevWithoutIss {
            credential: rev.i.as_str().to_string(),
        })?;
    if state.revoked.contains(&rev.i) {
        return Err(TelError::DoubleRev {
            credential: rev.i.as_str().to_string(),
        });
    }
    if rev.p != prior.said {
        return Err(TelError::BrokenChain {
            credential: rev.i.as_str().to_string(),
            detail: format!(
                "rev back-link p={} does not match issuance SAID {}",
                rev.p, prior.said
            ),
        });
    }
    if rev.s.value() <= prior.sequence {
        return Err(TelError::BrokenChain {
            credential: rev.i.as_str().to_string(),
            detail: format!(
                "rev sequence {} must exceed the issuance sequence {}",
                rev.s, prior.sequence
            ),
        });
    }
    state.revoked.push(rev.i.clone());
    Ok(())
}

/// Serializes a serializable TEL event to its canonical insertion-order JSON bytes.
///
/// Args:
/// * `event`: Any SAID'd TEL event (`Vcp`/`Iss`/`Rev`).
///
/// Usage:
/// ```ignore
/// let wire = to_wire_bytes(&iss)?;
/// ```
pub fn to_wire_bytes<T: Serialize>(event: &T) -> Result<Vec<u8>, TelError> {
    Ok(serde_json::to_vec(event)?)
}
