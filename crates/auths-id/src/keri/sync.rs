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

use std::ops::ControlFlow;

use auths_keri::{
    DelegatorKelLookup, KelSealIndex, Prefix, Said, SignedEvent, SourceSeal,
    parse_delegated_attachment, validate_signed_kel,
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
