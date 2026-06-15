//! Validated KEL merge between registries — the trust core of registry
//! propagation (`registry push` / `registry pull`).
//!
//! Transport-free: both sides are [`RegistryBackend`] ports; the git fetch /
//! push that produces the source snapshot lives in the storage adapter. The
//! destination registry is the **trusted floor** (local-first): a source KEL
//! may only *advance* it, never rewrite it. Per identity in the source:
//!
//! - **prefix-binding guard** — the served inception must re-derive the
//!   claimed prefix ([`verify_prefix_binding`]), so a source cannot
//!   substitute a different identity's KEL;
//! - **authenticated replay** — every event must carry a valid signature from
//!   the in-force key-state ([`validate_signed_kel`]); delegated (`dip`/`drt`)
//!   events resolve their anchoring seal from the source, then the
//!   destination. A KEL the source cannot prove it signed is refused whole;
//! - **rollback floor** — a source tip at-or-behind the destination's changes
//!   nothing (prefer local; an older remote is never an instruction to
//!   forget);
//! - **fork refusal** — a same-sequence SAID divergence between source and
//!   destination fails the merge loudly ([`RegistryMergeError::Forked`])
//!   rather than silently picking a side.
//!
//! Only after all four hold is the strictly-newer suffix appended —
//! signature attachments included, so the destination's KELs remain
//! authenticatable (never merely structurally replayable).

use std::collections::{BTreeSet, HashSet};
use std::ops::ControlFlow;

use auths_keri::{
    Acdc, DelegatorKelLookup, KelSealIndex, Prefix, Said, SignedEvent, SourceSeal, TelEvent,
    parse_delegated_attachment, validate_signed_kel, validate_tel,
};

use super::kel_resolver::{KelResolveError, collect_kel_capped, verify_prefix_binding};
use crate::ports::registry::{RegistryBackend, RegistryError};

/// DoS bounds applied when reading a KEL out of an untrusted source registry.
#[derive(Debug, Clone, Copy)]
pub struct KelCaps {
    /// Hard cap on event count per KEL.
    pub max_events: usize,
    /// Hard cap on total serialized size per KEL, in bytes.
    pub max_bytes: usize,
}

/// What the merge did for one identity's KEL.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum MergeOutcome {
    /// The destination had no KEL for this prefix — the full authenticated
    /// KEL was imported.
    Imported {
        /// Number of events written.
        events: usize,
    },
    /// The destination's KEL was behind — the strictly-newer authenticated
    /// suffix was appended.
    Advanced {
        /// Number of events appended.
        events: usize,
    },
    /// The destination already holds everything the source offered
    /// (equal or newer). Nothing was written.
    AlreadyCurrent,
}

/// Per-identity merge report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MergedKel {
    /// The identity prefix.
    pub prefix: Prefix,
    /// What happened to its KEL in the destination.
    #[serde(flatten)]
    pub outcome: MergeOutcome,
}

/// Why a registry merge was refused. Any error aborts the whole merge — a
/// pull never partially trusts a source that failed one identity's checks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryMergeError {
    /// The source listed an identity whose id is not a valid prefix.
    #[error("source registry lists an invalid identity prefix '{id}': {reason}")]
    InvalidPrefix {
        /// The offending identity id.
        id: String,
        /// Why it failed to parse.
        reason: String,
    },

    /// Reading the source KEL failed the untrusted-read guards
    /// (not-found / oversized / truncated / prefix-binding).
    #[error("source KEL for {prefix} was refused: {source}")]
    SourceKel {
        /// The identity prefix.
        prefix: Prefix,
        /// The guard that refused it.
        #[source]
        source: KelResolveError,
    },

    /// An event in the source KEL has no signature attachment — it cannot be
    /// authenticated, so it is never persisted.
    #[error("source KEL for {prefix} has no signature attachment at sequence {sequence}")]
    MissingSignature {
        /// The identity prefix.
        prefix: Prefix,
        /// The unsigned event's sequence.
        sequence: u128,
    },

    /// The source KEL failed authenticated replay (bad signature, broken
    /// chain, unauthorized delegation, …).
    #[error("source KEL for {prefix} failed authentication: {reason}")]
    Unauthenticated {
        /// The identity prefix.
        prefix: Prefix,
        /// The validation failure.
        reason: String,
    },

    /// Source and destination disagree at a shared sequence — a fork.
    /// Refused outright; a merge never picks a side of a fork.
    #[error(
        "KEL fork for {prefix} at sequence {sequence}: \
         destination has {destination}, source has {incoming}"
    )]
    Forked {
        /// The identity prefix.
        prefix: Prefix,
        /// The diverging sequence number.
        sequence: u128,
        /// The destination's event SAID at that sequence.
        destination: Said,
        /// The source's event SAID at that sequence.
        incoming: Said,
    },

    /// A backend read/write failed.
    #[error("registry backend error: {0}")]
    Storage(#[from] RegistryError),

    /// A source credential blob did not parse as a stored ACDC envelope, or its
    /// recomputed SAID did not match the SAID it was filed under — a tampered or
    /// malformed credential body is refused rather than copied onto the cold
    /// machine.
    #[error("source credential {credential} under {issuer} was refused: {reason}")]
    CredentialRefused {
        /// The issuer the credential was filed under.
        issuer: Prefix,
        /// The credential SAID (the on-disk filename).
        credential: Said,
        /// Why it was refused.
        reason: String,
    },

    /// A source credential names an issuer whose KEL was not authenticated in
    /// this merge — a credential with no anchoring identity is never imported.
    #[error("source credential {credential} names unknown issuer {issuer} (no authenticated KEL)")]
    CredentialOrphan {
        /// The unanchored issuer.
        issuer: Prefix,
        /// The orphaned credential SAID.
        credential: Said,
    },

    /// A source TEL chain failed structural validation (a recomputed event SAID
    /// did not match, or the `vcp → iss… → rev…` shape was broken) — a tampered
    /// TEL is refused rather than copied.
    #[error("source TEL {credential} under {issuer}/{registry} was refused: {reason}")]
    TelRefused {
        /// The issuer the TEL was filed under.
        issuer: Prefix,
        /// The registry SAID.
        registry: Said,
        /// The credential SAID the TEL belongs to.
        credential: Said,
        /// Why it was refused.
        reason: String,
    },
}

/// Merge every identity's KEL from `source` into `dest` under the guards
/// documented at the module level.
///
/// `source` is untrusted (a fetched snapshot); `dest` is the local trusted
/// floor. Returns one [`MergedKel`] per source identity, in prefix order.
/// Any guard failure aborts the whole merge with the first error.
///
/// Args:
/// * `source`: The untrusted registry to read from.
/// * `dest`: The trusted local registry to advance.
/// * `caps`: DoS bounds for reading the source.
///
/// Usage:
/// ```ignore
/// let report = merge_registries(snapshot.backend(), &local, &caps)?;
/// ```
pub fn merge_registries(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    caps: &KelCaps,
) -> Result<Vec<MergedKel>, RegistryMergeError> {
    let mut ids: Vec<String> = Vec::new();
    source.visit_identities(&mut |id| {
        ids.push(id.to_string());
        ControlFlow::Continue(())
    })?;
    ids.sort();
    ids.dedup();

    let mut report = Vec::with_capacity(ids.len());
    for id in ids {
        let prefix = Prefix::new(id.clone()).map_err(|e| RegistryMergeError::InvalidPrefix {
            id,
            reason: e.to_string(),
        })?;
        let outcome = merge_kel(source, dest, &prefix, caps)?;
        report.push(MergedKel { prefix, outcome });
    }
    Ok(report)
}

/// Merge one identity's KEL from `source` into `dest`.
fn merge_kel(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    prefix: &Prefix,
    caps: &KelCaps,
) -> Result<MergeOutcome, RegistryMergeError> {
    let refused = |source: KelResolveError| RegistryMergeError::SourceKel {
        prefix: prefix.clone(),
        source,
    };

    let events =
        collect_kel_capped(source, prefix, caps.max_events, caps.max_bytes).map_err(refused)?;
    verify_prefix_binding(prefix, &events).map_err(refused)?;

    // Pair every event with its signature attachment; an unsigned event is
    // unauthenticatable and refused before any validation work.
    let mut attachments = Vec::with_capacity(events.len());
    let mut signed = Vec::with_capacity(events.len());
    for event in &events {
        let sequence = event.sequence().value();
        let attachment = source.get_attachment(prefix, sequence)?.ok_or_else(|| {
            RegistryMergeError::MissingSignature {
                prefix: prefix.clone(),
                sequence,
            }
        })?;
        let (sigs, _seals) = parse_delegated_attachment(&attachment).map_err(|e| {
            RegistryMergeError::Unauthenticated {
                prefix: prefix.clone(),
                reason: format!("unparseable attachment at sequence {sequence}: {e}"),
            }
        })?;
        // Delegated events read from a registry backend already carry their
        // rehydrated source seal; the attachment's `-G` group is redundant here.
        signed.push(SignedEvent::new(event.clone(), sigs));
        attachments.push(attachment);
    }

    let lookup = BackendSealLookup {
        backends: [source, dest],
        caps: *caps,
    };
    validate_signed_kel(&signed, Some(&lookup)).map_err(|e| {
        RegistryMergeError::Unauthenticated {
            prefix: prefix.clone(),
            reason: e.to_string(),
        }
    })?;

    let dest_tip = match dest.get_tip(prefix) {
        Ok(tip) => Some(tip.sequence),
        Err(RegistryError::NotFound { .. }) => None,
        Err(e) => return Err(e.into()),
    };

    match dest_tip {
        None => {
            for (event, attachment) in events.iter().zip(&attachments) {
                dest.append_signed_event(prefix, event, attachment)?;
            }
            Ok(MergeOutcome::Imported {
                events: events.len(),
            })
        }
        Some(dest_tip) => {
            // Fork refusal: every event in the shared range must agree by SAID.
            for event in events.iter().filter(|e| e.sequence().value() <= dest_tip) {
                let sequence = event.sequence().value();
                let local = dest.get_event(prefix, sequence)?;
                if local.said() != event.said() {
                    return Err(RegistryMergeError::Forked {
                        prefix: prefix.clone(),
                        sequence,
                        destination: local.said().clone(),
                        incoming: event.said().clone(),
                    });
                }
            }
            let newer: Vec<_> = events
                .iter()
                .zip(&attachments)
                .filter(|(event, _)| event.sequence().value() > dest_tip)
                .collect();
            if newer.is_empty() {
                return Ok(MergeOutcome::AlreadyCurrent);
            }
            let appended = newer.len();
            for (event, attachment) in newer {
                dest.append_signed_event(prefix, event, attachment)?;
            }
            Ok(MergeOutcome::Advanced { events: appended })
        }
    }
}

/// What the credential + TEL merge did, counted over the whole registry.
///
/// The KEL merge ([`merge_registries`]) is the trust core — it authenticates
/// every imported event. This report covers the *artifact* layer that rides on
/// top of those authenticated KELs: the ACDC credential bodies and their TEL
/// chains, which a cold machine needs to re-verify a credential end-to-end.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct MergedCredentials {
    /// Credential bodies newly written to the destination.
    pub credentials_imported: usize,
    /// Credential bodies the destination already held (idempotent skip).
    pub credentials_already_present: usize,
    /// TEL events newly written to the destination.
    pub tel_events_imported: usize,
    /// TEL events the destination already held (idempotent skip).
    pub tel_events_already_present: usize,
}

/// Merge every credential body and TEL chain from `source` into `dest`.
///
/// Runs AFTER [`merge_registries`] has authenticated the KELs: the credential
/// and TEL artifacts ride on those KELs and are re-verified at
/// `credential verify` time (the issuer's detached signature is checked against
/// the authenticated key-state; the TEL anchors are checked against the KEL).
/// This step only *materializes* the bodies so a cold machine has them to verify.
///
/// It is still fail-closed, mirroring the KEL merge's discipline:
///
/// - **anchored-issuer only** — a credential whose issuer has no authenticated
///   KEL (not in `authenticated_issuers`) is refused
///   ([`RegistryMergeError::CredentialOrphan`]); a dangling credential is never
///   imported;
/// - **content-address consistency** — a credential body must parse and
///   recompute to the SAID it is filed under, and name that issuer
///   ([`RegistryMergeError::CredentialRefused`]); a byte-flipped credential is
///   refused, not copied;
/// - **TEL structural validity** — a TEL chain must pass [`validate_tel`]
///   (every event's recomputed SAID matches; the `vcp → iss… → rev…` shape
///   holds) before any event is written ([`RegistryMergeError::TelRefused`]); a
///   byte-flipped TEL event is refused.
///
/// Writes are idempotent: a credential body / TEL event the destination already
/// holds (by SAID-addressed path) is skipped, so a re-pull changes nothing.
/// Any refusal aborts the whole step — a pull never partially trusts a source.
///
/// Args:
/// * `source`: The untrusted registry snapshot to read artifacts from.
/// * `dest`: The trusted local registry to import into.
/// * `authenticated_issuers`: Prefixes whose KELs `merge_registries` authenticated.
///
/// Usage:
/// ```ignore
/// let kels = merge_registries(src, dst, &caps)?;
/// let issuers = kels.iter().map(|m| m.prefix.clone()).collect();
/// let creds = merge_credentials_and_tel(src, dst, &issuers)?;
/// ```
pub fn merge_credentials_and_tel(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    authenticated_issuers: &HashSet<Prefix>,
) -> Result<MergedCredentials, RegistryMergeError> {
    let mut report = MergedCredentials::default();
    merge_credential_bodies(source, dest, authenticated_issuers, &mut report)?;
    merge_tel_chains(source, dest, authenticated_issuers, &mut report)?;
    Ok(report)
}

/// Import every source credential body for an authenticated issuer (the first
/// leg of [`merge_credentials_and_tel`]).
fn merge_credential_bodies(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    authenticated_issuers: &HashSet<Prefix>,
    report: &mut MergedCredentials,
) -> Result<(), RegistryMergeError> {
    let mut credentials: Vec<(Prefix, Said, Vec<u8>)> = Vec::new();
    source.visit_credentials(&mut |issuer, credential, bytes| {
        credentials.push((issuer.clone(), credential.clone(), bytes.to_vec()));
        ControlFlow::Continue(())
    })?;

    for (issuer, credential, bytes) in credentials {
        if !authenticated_issuers.contains(&issuer) {
            return Err(RegistryMergeError::CredentialOrphan { issuer, credential });
        }
        verify_credential_body(&issuer, &credential, &bytes)?;

        if dest.load_credential(&issuer, &credential)?.is_some() {
            report.credentials_already_present += 1;
            continue;
        }
        dest.store_credential(&issuer, &credential, &bytes)?;
        report.credentials_imported += 1;
    }
    Ok(())
}

/// Import every source TEL chain for an authenticated issuer (the second leg of
/// [`merge_credentials_and_tel`]).
fn merge_tel_chains(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    authenticated_issuers: &HashSet<Prefix>,
    report: &mut MergedCredentials,
) -> Result<(), RegistryMergeError> {
    let mut coordinates: Vec<(Prefix, Said, Said)> = Vec::new();
    source.visit_tel_registries(&mut |issuer, registry, credential| {
        coordinates.push((issuer.clone(), registry.clone(), credential.clone()));
        ControlFlow::Continue(())
    })?;

    for (issuer, registry, credential) in coordinates {
        if !authenticated_issuers.contains(&issuer) {
            return Err(RegistryMergeError::CredentialOrphan { issuer, credential });
        }
        merge_one_tel(source, dest, &issuer, &registry, &credential, report)?;
    }
    Ok(())
}

/// Validate and import one TEL coordinate's events, idempotently.
fn merge_one_tel(
    source: &dyn RegistryBackend,
    dest: &dyn RegistryBackend,
    issuer: &Prefix,
    registry: &Said,
    credential: &Said,
    report: &mut MergedCredentials,
) -> Result<(), RegistryMergeError> {
    let refused = |reason: String| RegistryMergeError::TelRefused {
        issuer: issuer.clone(),
        registry: registry.clone(),
        credential: credential.clone(),
        reason,
    };

    // Read the source TEL events (raw bytes + each event's own sequence, which is
    // the storage key — not the iteration position).
    let mut raw: Vec<(u128, Vec<u8>)> = Vec::new();
    read_tel_raw(source, issuer, registry, credential, &mut raw).map_err(&refused)?;
    if raw.is_empty() {
        return Ok(());
    }

    // Structural validation BEFORE any write: a byte-flipped TEL event fails its
    // own SAID recomputation inside validate_tel and is refused whole. An
    // `iss`/`rev` coordinate carries only that chain's suffix, which validate_tel
    // rejects as missing its inception — so prepend the registry's `vcp` slot for
    // the check (the `vcp` coordinate is itself credential == registry).
    let mut chain: Vec<TelEvent> = Vec::new();
    if credential != registry {
        collect_tel(source, issuer, registry, registry, &mut chain).map_err(&refused)?;
    }
    collect_tel(source, issuer, registry, credential, &mut chain).map_err(&refused)?;
    validate_tel(&chain).map_err(|e| refused(e.to_string()))?;

    // Persist verbatim, idempotently (skip an sn the destination already has).
    let mut present: BTreeSet<u128> = BTreeSet::new();
    read_tel_sns(dest, issuer, registry, credential, &mut present)
        .map_err(|reason| refused(format!("local TEL event did not parse: {reason}")))?;
    for (sn, bytes) in raw {
        if present.contains(&sn) {
            report.tel_events_already_present += 1;
            continue;
        }
        dest.append_tel_event(issuer, registry, credential, sn, &bytes)?;
        report.tel_events_imported += 1;
    }
    Ok(())
}

/// Read one coordinate's TEL events into `(sn, bytes)` pairs, surfacing a parse
/// failure as a reason string.
fn read_tel_raw(
    source: &dyn RegistryBackend,
    issuer: &Prefix,
    registry: &Said,
    credential: &Said,
    raw: &mut Vec<(u128, Vec<u8>)>,
) -> Result<(), String> {
    let mut parse_err: Option<String> = None;
    source
        .visit_tel_events(
            issuer,
            registry,
            credential,
            &mut |bytes| match TelEvent::from_wire_bytes(bytes) {
                Ok(event) => {
                    raw.push((tel_event_sn(&event), bytes.to_vec()));
                    ControlFlow::Continue(())
                }
                Err(e) => {
                    parse_err = Some(format!("TEL event did not parse: {e}"));
                    ControlFlow::Break(())
                }
            },
        )
        .map_err(|e| e.to_string())?;
    match parse_err {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// Collect the destination coordinate's already-present TEL sequence numbers.
fn read_tel_sns(
    dest: &dyn RegistryBackend,
    issuer: &Prefix,
    registry: &Said,
    credential: &Said,
    present: &mut BTreeSet<u128>,
) -> Result<(), String> {
    let mut parse_err: Option<String> = None;
    dest.visit_tel_events(
        issuer,
        registry,
        credential,
        &mut |bytes| match TelEvent::from_wire_bytes(bytes) {
            Ok(event) => {
                present.insert(tel_event_sn(&event));
                ControlFlow::Continue(())
            }
            Err(e) => {
                parse_err = Some(e.to_string());
                ControlFlow::Break(())
            }
        },
    )
    .map_err(|e| e.to_string())?;
    match parse_err {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// The storage sequence key for a TEL event (its own `s` field).
fn tel_event_sn(event: &TelEvent) -> u128 {
    match event {
        TelEvent::Vcp(vcp) => vcp.s.value(),
        TelEvent::Iss(iss) => iss.s.value(),
        TelEvent::Rev(rev) => rev.s.value(),
    }
}

/// Refuse a credential body whose recomputed SAID or issuer disagrees with the
/// SAID-addressed path it was served under.
fn verify_credential_body(
    issuer: &Prefix,
    credential: &Said,
    bytes: &[u8],
) -> Result<(), RegistryMergeError> {
    let refused = |reason: String| RegistryMergeError::CredentialRefused {
        issuer: issuer.clone(),
        credential: credential.clone(),
        reason,
    };

    // The stored envelope is `{ "acdc": {…}, "signature": [...] }`; the trust
    // core here is the ACDC body's content-addressing. The detached issuer
    // signature is re-checked against the authenticated KEL at verify time.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| refused(format!("blob is not JSON: {e}")))?;
    let acdc_value = value
        .get("acdc")
        .ok_or_else(|| refused("blob has no `acdc` body".to_string()))?;
    let acdc: Acdc = serde_json::from_value(acdc_value.clone())
        .map_err(|e| refused(format!("acdc body did not parse: {e}")))?;

    acdc.verify_said()
        .map_err(|e| refused(format!("acdc SAID does not recompute: {e}")))?;
    if acdc.d.as_str() != credential.as_str() {
        return Err(refused(format!(
            "acdc SAID {} does not match the path SAID {}",
            acdc.d.as_str(),
            credential.as_str()
        )));
    }
    if acdc.i.as_str() != issuer.as_str() {
        return Err(refused(format!(
            "acdc issuer {} does not match the path issuer {}",
            acdc.i.as_str(),
            issuer.as_str()
        )));
    }
    Ok(())
}

/// Append one coordinate's parsed TEL events onto `chain`, surfacing a parse
/// failure as the refusal reason string.
fn collect_tel(
    source: &dyn RegistryBackend,
    issuer: &Prefix,
    registry: &Said,
    credential: &Said,
    chain: &mut Vec<TelEvent>,
) -> Result<(), String> {
    let mut parse_err: Option<String> = None;
    source
        .visit_tel_events(
            issuer,
            registry,
            credential,
            &mut |bytes| match TelEvent::from_wire_bytes(bytes) {
                Ok(event) => {
                    chain.push(event);
                    ControlFlow::Continue(())
                }
                Err(e) => {
                    parse_err = Some(format!("TEL event did not parse: {e}"));
                    ControlFlow::Break(())
                }
            },
        )
        .map_err(|e| e.to_string())?;
    if let Some(reason) = parse_err {
        return Err(reason);
    }
    Ok(())
}

/// Resolves a delegated event's anchoring seal from the merge's registries —
/// source first (a pushed registry carries the delegator's KEL alongside the
/// delegate's), then the destination (the delegator may already be local).
struct BackendSealLookup<'a> {
    backends: [&'a dyn RegistryBackend; 2],
    caps: KelCaps,
}

impl DelegatorKelLookup for BackendSealLookup<'_> {
    fn find_seal(&self, delegator_aid: &Prefix, seal_said: &Said) -> Option<SourceSeal> {
        for backend in self.backends {
            let Ok(events) = collect_kel_capped(
                backend,
                delegator_aid,
                self.caps.max_events,
                self.caps.max_bytes,
            ) else {
                continue;
            };
            if let Some(seal) =
                KelSealIndex::from_events(&events).find_seal(delegator_aid, seal_said)
            {
                return Some(seal);
            }
        }
        None
    }
}
