//! Offline verification of an air-gapped org bundle — a pure, zero-network function
//! of the bundle's contents.
//!
//! Reproduces the live org/member provenance verdict from an
//! [`AirGappedOrgBundle`] with the network cable unplugged: it recomputes every
//! bundled event's SAID (tamper-evident), authenticates every event's signature
//! against the controlling key-state (RT-002), confirms the org is a **pinned**
//! root, flags KEL duplicity, and classifies a member's authority at a signing
//! position **by KEL position, never wall-clock**.
//!
//! Fail-closed: a tampered event (SAID mismatch), a delegated member whose KEL is
//! missing, or a queried member with no delegation seal each yield a **named hard
//! error**, never "valid." A wrong/non-delegating pinned root is reported as
//! `root_pinned = false` (unauthorized), not an error.

use auths_keri::{Event, Prefix, Seal, verify_event_said};
use serde::Serialize;

use super::bundle::{AirGappedOrgBundle, BundledKel};
use super::error::OrgBundleError;
use super::record::find_revocation_event;
use crate::duplicity::{KelEventRef, detect_duplicity};
use crate::types::IdentityDID;

/// Maximum accepted JSON input for the JSON/WASM surface (16 MiB) — a bundle
/// carries whole KELs, so the ceiling is higher than the attestation contract's.
pub const MAX_BUNDLE_JSON_BYTES: usize = 16 * 1024 * 1024;

/// A member's authority at the moment an artifact was signed — a closed sum ordered
/// strictly by **KEL position** (never wall-clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(tag = "authority_at_signing", rename_all = "snake_case")]
pub enum AuthorityAtSigning {
    /// The member's authority was live at the signing position — the artifact was
    /// signed strictly before the revocation, or the member was never revoked.
    AuthorizedBeforeRevocation,
    /// The artifact was signed at or after the org revoked the member, by KEL
    /// position. Carries the exact revocation position.
    RejectedAfterRevocation {
        /// The KEL position at which the org anchored the revocation.
        #[serde(with = "u128_str")]
        revoked_at: u128,
    },
    /// The org revoked the member but the artifact carries no in-band signing
    /// position, so it cannot be ordered — conservatively rejected (mirrors the
    /// verifier's no-position default).
    RejectedRevokedPositionUnknown {
        /// The KEL position at which the org anchored the revocation.
        #[serde(with = "u128_str")]
        revoked_at: u128,
    },
    /// The org never delegated this member — there is no authority to classify.
    NeverDelegated,
}

/// (De)serialize a `u128` KEL position as a decimal string.
///
/// JSON numbers lose precision above 2^53, and serde's internally-tagged-enum
/// buffer cannot round-trip 128-bit integers — so KEL positions travel as strings
/// (the same convention [`auths_keri::KeriSequence`] uses for its hex form).
mod u128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The result of verifying an air-gapped org bundle offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineVerifyReport {
    /// The org the bundle is for.
    pub org_did: IdentityDID,
    /// The org KEL position the bundle (and therefore this verdict) is verified
    /// as-of — "verified as-of KEL position X."
    pub as_of_org_seq: u128,
    /// Whether the org is in the caller's pinned trust roots. `false` =
    /// unauthorized (the verdict cannot be trusted), not an error.
    pub root_pinned: bool,
    /// Whether the org KEL shows duplicity (same seq, divergent SAIDs). Flagged,
    /// never silently accepted.
    pub duplicity_detected: bool,
    /// The queried member's authority at the signing position, when a member +
    /// position were supplied. Ordered by KEL position, never wall-clock.
    pub authority: Option<AuthorityAtSigning>,
}

/// Recompute and check every event's SAID in a bundled KEL (tamper detection).
fn check_kel_integrity(kel: &BundledKel) -> Result<(), OrgBundleError> {
    for event in &kel.events {
        verify_event_said(event).map_err(|e| OrgBundleError::Integrity {
            id: kel.prefix.as_str().to_string(),
            reason: e.to_string(),
        })?;
    }
    Ok(())
}

/// Authenticate a bundled KEL (RT-002): verify every event is SIGNED by the
/// controlling key-state, not just SAID-correct. Reconstructs `SignedEvent`s from
/// the parallel `events` × hex `attachments` and replays them through
/// `validate_signed_kel`. Fails closed on a length mismatch, an unparseable
/// attachment, or a signature that doesn't verify.
///
/// Returns the authenticated [`auths_keri::KeyState`] — the only trust-rooted
/// source of the controller's *current* verkey available offline (e.g. to verify
/// a DSSE envelope signed by the org whose KEL the evidence embeds).
///
/// This is the shared ecosystem primitive: a downstream verifier (CI gate,
/// browser widget, third-party audit tool) holding a [`BundledKel`] gets the
/// controller's authenticated key state from evidence alone in one call, rather
/// than reconstructing `SignedEvent`s and replaying `validate_signed_kel` itself.
/// For an [`AirGappedOrgBundle`], prefer
/// [`AirGappedOrgBundle::authenticated_org_state`].
pub fn authenticate_bundled_kel(
    kel: &BundledKel,
    lookup: Option<&dyn auths_keri::DelegatorKelLookup>,
) -> Result<auths_keri::KeyState, OrgBundleError> {
    let integrity_err = |reason: String| OrgBundleError::Integrity {
        id: kel.prefix.as_str().to_string(),
        reason,
    };
    if kel.attachments.len() != kel.events.len() {
        return Err(integrity_err(format!(
            "{} events but {} signature attachments — cannot authenticate",
            kel.events.len(),
            kel.attachments.len()
        )));
    }
    let mut signed = Vec::with_capacity(kel.events.len());
    for (event, att_hex) in kel.events.iter().zip(kel.attachments.iter()) {
        let bytes =
            hex::decode(att_hex).map_err(|e| integrity_err(format!("non-hex attachment: {e}")))?;
        // A delegated (dip/drt) event's attachment is `-A <sig> ++ -G <source seal>`;
        // a plain event's is just `-A <sig>`. `parse_delegated_attachment` handles both.
        let (sigs, seals) = auths_keri::parse_delegated_attachment(&bytes)
            .map_err(|e| integrity_err(format!("unparseable attachment: {e}")))?;
        // A dip/drt JSON body carries no source seal (it lives in the attachment);
        // restore it so the delegation binding can be authenticated.
        let event = rehydrate_event_source_seal(event.clone(), seals.into_iter().next());
        signed.push(auths_keri::SignedEvent::new(event, sigs));
    }
    auths_keri::validate_signed_kel(&signed, lookup)
        .map_err(|e| integrity_err(format!("KEL signature authentication failed (RT-002): {e}")))
}

/// Re-attach a delegated event's source seal from its parsed attachment — the JSON
/// body of a `dip`/`drt` carries none (it lives in the `-G` group). Mirrors the
/// storage layer's `rehydrate_source_seal`.
fn rehydrate_event_source_seal(event: Event, seal: Option<auths_keri::SourceSeal>) -> Event {
    let Some(seal) = seal else {
        return event;
    };
    match event {
        Event::Dip(mut e) => {
            e.source_seal = Some(seal);
            Event::Dip(e)
        }
        Event::Drt(mut e) => {
            e.source_seal = Some(seal);
            Event::Drt(e)
        }
        other => other,
    }
}

/// Does the org KEL anchor a delegation `KeyEvent` seal for `member_prefix`?
fn is_delegated(org_kel: &[Event], member_prefix: &Prefix) -> bool {
    org_kel.iter().any(|event| {
        event.anchors().iter().any(
            |seal| matches!(seal, Seal::KeyEvent { i, .. } if i.as_str() == member_prefix.as_str()),
        )
    })
}

/// Classify a member's authority at `signed_at` from an air-gapped bundle's org KEL —
/// the offline mirror of the live registry classifier, for re-deriving compliance
/// evidence-pack rows with zero network.
///
/// Args:
/// * `bundle`: The air-gapped org bundle (its org KEL is the authority source).
/// * `member_prefix`: The member to classify.
/// * `signed_at`: The artifact's in-band signing position, if any.
///
/// Usage:
/// ```ignore
/// let verdict = classify_authority_in_bundle(&bundle, &member, Some(41));
/// ```
pub fn classify_authority_in_bundle(
    bundle: &AirGappedOrgBundle,
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> AuthorityAtSigning {
    classify_from_bundle(&bundle.org_kel.events, member_prefix, signed_at)
}

/// Classify a member's authority at `signed_at`, read purely from the bundle's org
/// KEL.
fn classify_from_bundle(
    org_kel: &[Event],
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> AuthorityAtSigning {
    if !is_delegated(org_kel, member_prefix) {
        return AuthorityAtSigning::NeverDelegated;
    }
    match find_revocation_event(org_kel, member_prefix) {
        None => AuthorityAtSigning::AuthorizedBeforeRevocation,
        Some((_, revoked_at)) => match signed_at {
            None => AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at },
            Some(seq) if seq < revoked_at => AuthorityAtSigning::AuthorizedBeforeRevocation,
            Some(_) => AuthorityAtSigning::RejectedAfterRevocation { revoked_at },
        },
    }
}

/// Verify an air-gapped org bundle offline.
///
/// Pure and network-free. Checks bundle integrity (every event's SAID),
/// authenticates every event's signature (RT-002), confirms the org is pinned,
/// flags org-KEL duplicity, and — when `query` supplies a member and optional
/// signing position — classifies that member's authority by KEL position.
///
/// Fail-closed errors (never "valid"): [`OrgBundleError::Integrity`] (a tampered
/// event), [`OrgBundleError::MissingMemberKel`] (a delegated member's KEL is
/// absent), [`OrgBundleError::MissingDelegatorSeal`] (a queried member was never
/// delegated).
///
/// Args:
/// * `bundle`: The air-gapped bundle to verify.
/// * `pinned_roots`: The caller's pinned trust roots (e.g. from `.auths/roots`).
/// * `query`: Optional `(member_prefix, signed_at)` to classify a specific artifact.
///
/// Usage:
/// ```ignore
/// let report = verify_org_bundle(&bundle, &roots, Some((&member, Some(41))))?;
/// assert!(report.root_pinned);
/// ```
pub fn verify_org_bundle(
    bundle: &AirGappedOrgBundle,
    pinned_roots: &[IdentityDID],
    query: Option<(&Prefix, Option<u128>)>,
) -> Result<OfflineVerifyReport, OrgBundleError> {
    // 1. Integrity + AUTHENTICATION (RT-002): every bundled event must self-address
    //    (SAID) AND be signed by the controlling key-state — not just structurally
    //    valid. The org KEL is the root of trust (no delegator); member KELs are
    //    authenticated against the org as delegator.
    check_kel_integrity(&bundle.org_kel)?;
    authenticate_bundled_kel(&bundle.org_kel, None)?;
    let org_lookup = auths_keri::KelSealIndex::from_events(&bundle.org_kel.events);
    for member_kel in &bundle.member_kels {
        check_kel_integrity(member_kel)?;
        authenticate_bundled_kel(member_kel, Some(&org_lookup))?;
    }

    // 2. Completeness: every member the org delegated must ship its own KEL.
    for event in &bundle.org_kel.events {
        for seal in event.anchors() {
            if let Seal::KeyEvent { i, .. } = seal {
                let present = bundle
                    .member_kels
                    .iter()
                    .any(|m| m.prefix.as_str() == i.as_str());
                if !present {
                    return Err(OrgBundleError::MissingMemberKel {
                        member: format!("did:keri:{}", i.as_str()),
                    });
                }
            }
        }
    }

    // 3. Trust: is the org a pinned root? (false = unauthorized, not an error.)
    let root_pinned = pinned_roots
        .iter()
        .any(|r| r.as_str() == bundle.org_did.as_str());

    // 4. Duplicity: same-seq divergent SAIDs on the org KEL — flag, never accept.
    let org_did_str = bundle.org_did.as_str().to_string();
    let refs: Vec<KelEventRef<'_>> = bundle
        .org_kel
        .events
        .iter()
        .map(|e| KelEventRef {
            prefix: org_did_str.as_str(),
            seq: e.sequence().value() as u64,
            said: e.said().as_str(),
        })
        .collect();
    let duplicity_detected = detect_duplicity(&refs).is_diverging();

    // 5. Authority classification for the queried member, by KEL position.
    let authority = match query {
        Some((member_prefix, signed_at)) => {
            if !is_delegated(&bundle.org_kel.events, member_prefix) {
                return Err(OrgBundleError::MissingDelegatorSeal {
                    member: format!("did:keri:{}", member_prefix.as_str()),
                });
            }
            Some(classify_from_bundle(
                &bundle.org_kel.events,
                member_prefix,
                signed_at,
            ))
        }
        None => None,
    };

    Ok(OfflineVerifyReport {
        org_did: bundle.org_did.clone(),
        as_of_org_seq: bundle.built_at_org_seq,
        root_pinned,
        duplicity_detected,
        authority,
    })
}

// ── JSON contract (the WASM/FFI-facing form) ───────────────────────────────

/// The tagged verdict envelope for [`verify_org_bundle_json`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum BundleVerdictJson {
    /// Verification ran to completion; the report carries the verdict axes.
    #[serde(rename = "report")]
    Report {
        /// The offline verification report.
        report: OfflineVerifyReport,
    },
    /// Verification failed closed (tampered bundle, incomplete bundle, bad input).
    #[serde(rename = "error")]
    Error {
        /// The stable `AUTHS-Exxxx` code.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

/// A last-resort verdict used only if envelope serialization itself fails.
const SERIALIZE_FALLBACK: &str =
    r#"{"kind":"error","code":"AUTHS-E2204","message":"verdict serialization failed"}"#;

fn envelope_to_string(envelope: &BundleVerdictJson) -> String {
    serde_json::to_string(envelope).unwrap_or_else(|_| SERIALIZE_FALLBACK.to_string())
}

fn error_envelope(e: &OrgBundleError) -> String {
    use auths_crypto::AuthsErrorInfo;
    envelope_to_string(&BundleVerdictJson::Error {
        code: e.error_code().to_string(),
        message: e.to_string(),
    })
}

/// Verify an air-gapped org bundle from its JSON wire forms — the
/// string-in/string-out contract the WASM surface exposes.
///
/// Panic-free and synchronous: malformed or oversize input returns a tagged
/// `error` envelope, never an exception. The verdict is a discriminated union
/// (`kind`: `"report"` | `"error"`), never a bare bool.
///
/// Args:
/// * `bundle_json`: The [`AirGappedOrgBundle`] JSON (the `.auths-offline` file).
/// * `pinned_roots_json`: JSON array of the verifier's pinned `did:keri:` roots.
/// * `member_did`: Optional member to classify (`did:keri:` or bare prefix).
/// * `signed_at`: Optional in-band signing KEL position, as a decimal string.
///
/// Usage:
/// ```ignore
/// let verdict = verify_org_bundle_json(&bundle, r#"["did:keri:EOrg"]"#, None, None);
/// ```
pub fn verify_org_bundle_json(
    bundle_json: &str,
    pinned_roots_json: &str,
    member_did: Option<&str>,
    signed_at: Option<&str>,
) -> String {
    match verify_org_bundle_json_inner(bundle_json, pinned_roots_json, member_did, signed_at) {
        Ok(report) => envelope_to_string(&BundleVerdictJson::Report { report }),
        Err(e) => error_envelope(&e),
    }
}

fn verify_org_bundle_json_inner(
    bundle_json: &str,
    pinned_roots_json: &str,
    member_did: Option<&str>,
    signed_at: Option<&str>,
) -> Result<OfflineVerifyReport, OrgBundleError> {
    if bundle_json.len() > MAX_BUNDLE_JSON_BYTES {
        return Err(OrgBundleError::Parse(format!(
            "bundle JSON too large: {} bytes, max {}",
            bundle_json.len(),
            MAX_BUNDLE_JSON_BYTES
        )));
    }
    let bundle = AirGappedOrgBundle::from_json(bundle_json)?;
    let pinned_roots: Vec<IdentityDID> = serde_json::from_str(pinned_roots_json)
        .map_err(|e| OrgBundleError::Parse(format!("pinned roots: {e}")))?;

    let member_prefix = member_did
        .map(|m| {
            Prefix::new(m.strip_prefix("did:keri:").unwrap_or(m).to_string())
                .map_err(|e| OrgBundleError::Parse(format!("member prefix: {e}")))
        })
        .transpose()?;
    let signed_at = signed_at
        .map(|s| {
            s.parse::<u128>()
                .map_err(|e| OrgBundleError::Parse(format!("signed_at: {e}")))
        })
        .transpose()?;

    let query = member_prefix.as_ref().map(|p| (p, signed_at));
    verify_org_bundle(&bundle, &pinned_roots, query)
}
