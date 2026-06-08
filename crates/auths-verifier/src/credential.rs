//! Pure ACDC credential verification — report facts, never resolve (Epic F.5).
//!
//! [`verify_credential`] decides whether an issued capability credential is
//! authentic **purely by replaying its inputs**: it recomputes the ACDC SAID,
//! validates the attributes against the compiled-in F.1 capability schema,
//! replays the issuer KEL to confirm the issuance is anchored and signed by the
//! signing-time key, runs the lifecycle witness-quorum math (KAWA) over the
//! receipts it is handed, and reads TEL status by KEL anchor position.
//!
//! It is WASM-safe: no git, no network, no clock of its own. It never resolves
//! KEL tips or judges freshness — that is the SDK resolution layer's job (F.4),
//! which is why [`CredentialVerdict`] has no `StaleOrUnresolvable` variant. F.5
//! reports the `as_of` position of exactly the KEL it was given.
//!
//! ## Composed claim
//!
//! Under [`VerifierWitnessPolicy::RequireWitnesses`] a credential is `Valid` only
//! if its `vcp` *and* `iss` anchoring `ixn`s reached witness quorum and no
//! quorum-reaching `rev` is anchored at/before the presentation position. Under
//! [`VerifierWitnessPolicy::Warn`] (the default) under-quorum is a non-fatal
//! trust-on-first-sight acceptance and any seen `rev` revokes (conservative).
//! `detect_duplicity` flags issuer-KEL forks in both modes.

use auths_crypto::CryptoProvider;
use auths_keri::witness::StoredReceipt;
use auths_keri::witness::agreement::WitnessAgreement;

use crate::software_verify::verify_with_key_sync;
use crate::{CanonicalDid, Capability, IdentityDID};
use auths_keri::{
    Acdc, CesrKey, Event, KeriPublicKey, KeyState, Prefix, Said, TelEvent, Threshold,
    compute_capability_schema_said, validate_kel,
};
use chrono::{DateTime, Utc};

use crate::commit_kel::VerifierWitnessPolicy;
use crate::duplicity::{KelEventRef, detect_duplicity};

/// The capability claim field required by the F.1 capability schema (`a.capability`).
const CAPABILITY_FIELD: &str = "capability";

/// Optional ISO-8601 expiry claim in the attributes block (`a.expiry`). Absent
/// means the credential never expires; the verifier compares it against the
/// injected `now` (it never consults a wall clock of its own).
const EXPIRY_FIELD: &str = "expiry";

/// Names which lifecycle anchor missed witness quorum, for [`CredentialVerdict::WitnessQuorumNotMet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// The registry inception (`vcp`) anchoring `ixn`.
    Vcp,
    /// The credential issuance (`iss`) anchoring `ixn`.
    Iss,
    /// A credential revocation (`rev`) anchoring `ixn`.
    Rev,
}

impl LifecycleEvent {
    /// The lowercase TEL event tag (`vcp`/`iss`/`rev`).
    fn tag(self) -> &'static str {
        match self {
            LifecycleEvent::Vcp => "vcp",
            LifecycleEvent::Iss => "iss",
            LifecycleEvent::Rev => "rev",
        }
    }
}

impl std::fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

/// The distinguishable outcome of [`verify_credential`].
///
/// Every failure is a named variant so a consumer can explain *why* a credential
/// did not verify, never a generic "invalid".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVerdict {
    /// The credential is authentic, anchored, witnessed (per policy), unexpired,
    /// and not revoked at/before the presentation position.
    Valid {
        /// Issuer AID (`did:keri:`), parsed once at construction.
        issuer: IdentityDID,
        /// Subject (holder) AID (`did:keri:`), parsed once at construction.
        subject: CanonicalDid,
        /// The capabilities the credential grants (`a.capability`), parsed once — a
        /// capability that does not parse fails the verdict closed (never silently dropped).
        caps: Vec<Capability>,
        /// The KEL position the verdict is as-of: the tip `(seq)` of the given issuer KEL.
        as_of: u128,
    },
    /// The recomputed ACDC `d` (or nested `a.d`) did not match the embedded SAID.
    SaidMismatch,
    /// The attributes failed validation against the embedded capability schema, or
    /// the schema SAID `s` is not the pinned one.
    SchemaInvalid,
    /// The issuance was not anchored, or its issuer signature did not verify against
    /// the signing-time key.
    IssuerSignatureInvalid,
    /// The registry (`vcp`) was never anchored in the issuer KEL, so status is unknown.
    RegistryNotEstablished,
    /// A revocation reached the policy bar and is anchored at/before the presentation.
    CredentialRevoked {
        /// The KEL position at which the revocation was anchored.
        revoked_at: u128,
    },
    /// The credential expired at `expired_at`, checked against the injected `now`.
    Expired {
        /// The expiry instant declared in `a.expiry`.
        expired_at: DateTime<Utc>,
        /// The injected verification time it was checked against.
        now: DateTime<Utc>,
    },
    /// Under [`VerifierWitnessPolicy::RequireWitnesses`] a lifecycle anchor did not
    /// reach witness quorum (fail-closed). Names which anchor missed.
    WitnessQuorumNotMet {
        /// Which lifecycle anchor (vcp/iss/rev) missed quorum.
        event: LifecycleEvent,
        /// Distinct valid designated-witness receipts collected for that anchor.
        collected: usize,
        /// Receipts required by the in-force backer threshold at that anchor.
        required: usize,
    },
    /// The issuer KEL forks (two events at one seq with different SAIDs) — fail-closed
    /// in both witness policies.
    IssuerKelDuplicitous,
}

impl CredentialVerdict {
    /// Whether the credential verified (`Valid`).
    pub fn is_valid(&self) -> bool {
        matches!(self, CredentialVerdict::Valid { .. })
    }
}

/// An ACDC paired with the issuer's detached signature over its canonical wire bytes.
///
/// The ACDC body itself carries no signature; the issuer signs
/// [`Acdc::to_wire_bytes`] with the KEL signing key in force when the issuance was
/// anchored. The verifier recovers that signing-time key by KEL replay and checks
/// this signature against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAcdc {
    /// The credential body.
    pub acdc: Acdc,
    /// The issuer's signature over `acdc.to_wire_bytes()`.
    pub signature: Vec<u8>,
}

/// Verify an issued capability credential — the thin `async` wrapper over
/// [`verify_credential_sync`].
///
/// Kept so native Rust async callers (`auths-sdk`, `auths-rp`, `auths-mcp-server`)
/// compile unchanged. Signature verification is deterministic and backend-independent,
/// so this returns exactly the same verdict as the executor-free
/// [`verify_credential_sync`]; the `_provider` argument is retained only for
/// source-compatibility of this signature (verification runs through the in-crate
/// pure-Rust `software_verify`, not the injected provider).
///
/// Args: identical to [`verify_credential_sync`], plus a trailing `_provider` that is
/// accepted but unused.
///
/// Usage:
/// ```ignore
/// let verdict = verify_credential(&signed, &issuer_kel, &tel, &receipts, policy, now, &provider).await;
/// assert!(verdict.is_valid());
/// ```
pub async fn verify_credential(
    signed: &SignedAcdc,
    issuer_kel: &[Event],
    tel_events: &[TelEvent],
    receipts: &[StoredReceipt],
    witness_policy: VerifierWitnessPolicy,
    now: DateTime<Utc>,
    _provider: &dyn CryptoProvider,
) -> CredentialVerdict {
    verify_credential_sync(
        signed,
        issuer_kel,
        tel_events,
        receipts,
        witness_policy,
        now,
    )
}

/// Verify an issued capability credential purely by replaying its inputs — synchronously,
/// with no executor.
///
/// This is the executor-free core every non-Rust binding target (C-ABI, WASM, Node,
/// Python, Go) calls directly: `block_on` is impossible in browser WASM, so signature
/// checks run through the synchronous pure-Rust `software_verify` rather than the async
/// [`CryptoProvider`]. It reports facts and does the lifecycle witness-quorum math; it
/// never resolves KEL tips, fetches, or judges freshness (that is the SDK resolution
/// layer's job, F.4).
///
/// Args:
/// * `signed`: The credential plus the issuer's detached signature over its wire bytes.
/// * `issuer_kel`: The issuer identity's KEL events, in sequence order.
/// * `tel_events`: The credential registry's TEL (`vcp`, `iss`, optional `rev…`).
/// * `receipts`: Witness receipts (witness-attributed) handed in for the quorum math.
/// * `witness_policy`: `Warn` (default, TOFS) or `RequireWitnesses` (fail-closed).
/// * `now`: The verification time, injected at the boundary (no wall clock here).
///
/// Usage:
/// ```ignore
/// let verdict = verify_credential_sync(&signed, &issuer_kel, &tel, &receipts, policy, now);
/// assert!(verdict.is_valid());
/// ```
pub fn verify_credential_sync(
    signed: &SignedAcdc,
    issuer_kel: &[Event],
    tel_events: &[TelEvent],
    receipts: &[StoredReceipt],
    witness_policy: VerifierWitnessPolicy,
    now: DateTime<Utc>,
) -> CredentialVerdict {
    let acdc = &signed.acdc;

    if acdc.verify_said().is_err() {
        return CredentialVerdict::SaidMismatch;
    }

    if validate_against_schema(acdc).is_err() {
        return CredentialVerdict::SchemaInvalid;
    }

    if let Some(verdict) = check_expiry(acdc, now) {
        return verdict;
    }

    // Duplicity is diagnosed on the raw event stream first: a fork makes the KEL
    // un-replayable, so this must precede `validate_kel` to surface the specific
    // `IssuerKelDuplicitous` rather than a generic replay failure.
    if let Some(prefix) = issuer_kel.first().map(|e| e.prefix())
        && detect_duplicity(&kel_refs(issuer_kel, prefix)).is_diverging()
    {
        return CredentialVerdict::IssuerKelDuplicitous;
    }

    let issuer_state = match validate_kel(issuer_kel) {
        Ok(state) => state,
        Err(_) => return CredentialVerdict::RegistryNotEstablished,
    };

    let lifecycle = match locate_lifecycle(tel_events, issuer_kel) {
        Some(lifecycle) => lifecycle,
        None => return CredentialVerdict::RegistryNotEstablished,
    };

    // Step 4: resolve the witness-quorum of every lifecycle anchor once, against
    // the backer set in force at each anchor's KEL position. Under
    // RequireWitnesses an under-quorum vcp/iss is fatal; the per-rev outcomes feed
    // the revocation decision below.
    let quorum = resolve_quorum(&lifecycle, issuer_kel, &issuer_state.prefix, receipts);
    if let VerifierWitnessPolicy::RequireWitnesses = witness_policy
        && let Some(verdict) = quorum.fatal_under_quorum()
    {
        return verdict;
    }

    if !verify_issuer_signature(signed, issuer_kel, lifecycle.iss_anchor_seq) {
        return CredentialVerdict::IssuerSignatureInvalid;
    }

    if let Some(revoked_at) =
        effective_revocation(&lifecycle, &quorum, witness_policy, issuer_state.sequence)
    {
        return CredentialVerdict::CredentialRevoked { revoked_at };
    }

    // Parse the validated identity/capability claims into their typed forms once, here.
    // These are derived from already-replayed prefixes and schema-checked attributes, so a
    // parse failure is a data-integrity violation — fail closed rather than carry a bad
    // value or silently drop it.
    let (Ok(issuer), Ok(subject)) = (
        IdentityDID::parse(&format!("did:keri:{}", acdc.i)),
        CanonicalDid::parse(&format!("did:keri:{}", acdc.a.i)),
    ) else {
        return CredentialVerdict::SchemaInvalid;
    };
    let Ok(caps) = capability_claims(acdc)
        .iter()
        .map(|c| Capability::parse(c))
        .collect::<Result<Vec<_>, _>>()
    else {
        return CredentialVerdict::SchemaInvalid;
    };

    CredentialVerdict::Valid {
        issuer,
        subject,
        caps,
        as_of: issuer_state.sequence,
    }
}

/// Validate the ACDC attributes against the compiled-in F.1 capability schema.
///
/// Offline/WASM: pins `s` to the embedded schema SAID and structurally checks the
/// schema's required fields (JSON-Schema-2020-12-lite). An unknown `s` is rejected.
fn validate_against_schema(acdc: &Acdc) -> Result<(), ()> {
    let pinned = compute_capability_schema_said().map_err(|_| ())?;
    if acdc.s != pinned {
        return Err(());
    }
    if !acdc.a.data.contains_key(CAPABILITY_FIELD) {
        return Err(());
    }
    let capability = acdc.a.data.get(CAPABILITY_FIELD).and_then(|v| v.as_str());
    match capability {
        Some(c) if !c.is_empty() => Ok(()),
        _ => Err(()),
    }
}

/// The capability claims granted by the credential (`a.capability`).
fn capability_claims(acdc: &Acdc) -> Vec<String> {
    acdc.a
        .data
        .get(CAPABILITY_FIELD)
        .and_then(|v| v.as_str())
        .map(|c| vec![c.to_string()])
        .unwrap_or_default()
}

/// Reject an expired credential by comparing the optional `a.expiry` to `now`.
fn check_expiry(acdc: &Acdc, now: DateTime<Utc>) -> Option<CredentialVerdict> {
    let raw = acdc.a.data.get(EXPIRY_FIELD).and_then(|v| v.as_str())?;
    let expired_at = DateTime::parse_from_rfc3339(raw).ok()?.with_timezone(&Utc);
    (now >= expired_at).then_some(CredentialVerdict::Expired { expired_at, now })
}

/// The TEL lifecycle events resolved to their issuer-KEL anchor positions.
struct Lifecycle {
    /// KEL position of the `iss`-anchoring `ixn`.
    iss_anchor_seq: u128,
    /// The `vcp`-anchoring `ixn` (KEL position + TEL SAID).
    vcp_anchor: AnchoredTelEvent,
    /// The `iss`-anchoring `ixn` (KEL position + TEL SAID).
    iss_anchor: AnchoredTelEvent,
    /// Each `rev`-anchoring `ixn` (KEL position + TEL SAID), in TEL order.
    rev_anchors: Vec<AnchoredTelEvent>,
}

/// One TEL event located by its issuer-KEL anchor (`ixn`) position and SAID.
struct AnchoredTelEvent {
    /// The TEL event SAID the `ixn` anchored.
    tel_said: Said,
    /// The KEL position (`ixn` sequence) the seal was found at.
    kel_seq: u128,
}

/// Locate the `vcp`, `iss`, and any `rev` TEL events by their issuer-KEL anchors.
///
/// Returns `None` (⇒ `RegistryNotEstablished`) when the TEL has no `vcp`/`iss` or
/// either is not anchored by an `ixn` seal in the issuer KEL.
fn locate_lifecycle(tel_events: &[TelEvent], issuer_kel: &[Event]) -> Option<Lifecycle> {
    let vcp_said = tel_events.iter().find_map(|e| match e {
        TelEvent::Vcp(vcp) => Some(vcp.d.clone()),
        _ => None,
    })?;
    let iss_said = tel_events.iter().find_map(|e| match e {
        TelEvent::Iss(iss) => Some(iss.d.clone()),
        _ => None,
    })?;

    let vcp_anchor = anchor_position(issuer_kel, &vcp_said)?;
    let iss_anchor = anchor_position(issuer_kel, &iss_said)?;

    let rev_anchors = tel_events
        .iter()
        .filter_map(|e| match e {
            TelEvent::Rev(rev) => anchor_position(issuer_kel, &rev.d),
            _ => None,
        })
        .collect();

    Some(Lifecycle {
        iss_anchor_seq: iss_anchor.kel_seq,
        vcp_anchor,
        iss_anchor,
        rev_anchors,
    })
}

/// Find the issuer-KEL `ixn` whose anchor seal carries `tel_said`, returning its position.
fn anchor_position(issuer_kel: &[Event], tel_said: &Said) -> Option<AnchoredTelEvent> {
    for event in issuer_kel {
        if event.is_interaction()
            && event
                .anchors()
                .iter()
                .any(|seal| seal.digest_value().is_some_and(|d| d == tel_said))
        {
            return Some(AnchoredTelEvent {
                tel_said: tel_said.clone(),
                kel_seq: event.sequence().value(),
            });
        }
    }
    None
}

/// The per-anchor witness-quorum outcomes for one credential's lifecycle (step 4).
///
/// Computed once over the given receipts; consumed both by the fatal `vcp`/`iss`
/// check (`RequireWitnesses`) and by the revocation decision (a `rev` revokes only
/// if it reached quorum under `RequireWitnesses`, or was simply seen under `Warn`).
struct QuorumResolution {
    /// Quorum outcome of the `vcp` anchor.
    vcp: QuorumOutcome,
    /// Quorum outcome of the `iss` anchor.
    iss: QuorumOutcome,
    /// `(kel_seq, outcome)` for each `rev` anchor, in TEL order.
    revs: Vec<(u128, QuorumOutcome)>,
}

impl QuorumResolution {
    /// The fatal `WitnessQuorumNotMet` verdict if `vcp` or `iss` is under-quorum.
    fn fatal_under_quorum(&self) -> Option<CredentialVerdict> {
        for (event, outcome) in [
            (LifecycleEvent::Vcp, &self.vcp),
            (LifecycleEvent::Iss, &self.iss),
        ] {
            if let QuorumOutcome::UnderQuorum {
                collected,
                required,
            } = outcome
            {
                return Some(CredentialVerdict::WitnessQuorumNotMet {
                    event,
                    collected: *collected,
                    required: *required,
                });
            }
        }
        None
    }
}

/// Resolve the witness-quorum of every lifecycle anchor over the given receipts.
///
/// For the `vcp`, `iss`, and each `rev` anchoring `ixn`, run KAWA over the backer
/// set in force at that `ixn`'s KEL position.
fn resolve_quorum(
    lifecycle: &Lifecycle,
    issuer_kel: &[Event],
    issuer_prefix: &Prefix,
    receipts: &[StoredReceipt],
) -> QuorumResolution {
    let vcp = anchor_quorum(&lifecycle.vcp_anchor, issuer_kel, issuer_prefix, receipts);
    let iss = anchor_quorum(&lifecycle.iss_anchor, issuer_kel, issuer_prefix, receipts);
    let mut revs = Vec::with_capacity(lifecycle.rev_anchors.len());
    for anchor in &lifecycle.rev_anchors {
        let outcome = anchor_quorum(anchor, issuer_kel, issuer_prefix, receipts);
        revs.push((anchor.kel_seq, outcome));
    }
    QuorumResolution { vcp, iss, revs }
}

/// The composed revocation decision for the presentation position.
///
/// A `rev` counts iff anchored at/before the presentation position AND (under
/// `RequireWitnesses`) reached quorum, or (under `Warn`) was simply seen
/// (conservative TOFS). Returns the earliest qualifying revocation position.
fn effective_revocation(
    lifecycle: &Lifecycle,
    quorum: &QuorumResolution,
    policy: VerifierWitnessPolicy,
    presentation_seq: u128,
) -> Option<u128> {
    lifecycle
        .rev_anchors
        .iter()
        .filter(|rev| rev.kel_seq <= presentation_seq)
        .filter(|rev| rev_counts(rev.kel_seq, quorum, policy))
        .map(|rev| rev.kel_seq)
        .min()
}

/// Whether a `rev` at `kel_seq` counts as a revocation under the policy.
fn rev_counts(kel_seq: u128, quorum: &QuorumResolution, policy: VerifierWitnessPolicy) -> bool {
    match policy {
        VerifierWitnessPolicy::Warn => true,
        VerifierWitnessPolicy::RequireWitnesses => quorum
            .revs
            .iter()
            .find(|(seq, _)| *seq == kel_seq)
            .is_some_and(|(_, outcome)| matches!(outcome, QuorumOutcome::Met)),
    }
}

/// The witness-quorum outcome of one lifecycle anchor under the given receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QuorumOutcome {
    /// Quorum reached (including the `bt=0` backerless path).
    Met,
    /// Quorum not reached: `collected` distinct valid receipts vs `required`.
    UnderQuorum {
        /// Distinct valid designated-witness receipts collected.
        collected: usize,
        /// Receipts required by the in-force backer threshold.
        required: usize,
    },
}

/// Compute the KAWA witness-quorum outcome of one TEL anchor.
///
/// The backer set in force is the issuer key-state replayed up to and including
/// the anchoring `ixn`'s position (`take_while ≤ anchor_seq`). KAWA does the
/// M-of-N math over the receipts whose signature verifies against their declared
/// witness key and whose witness AID is in that backer set.
fn anchor_quorum(
    anchor: &AnchoredTelEvent,
    issuer_kel: &[Event],
    issuer_prefix: &Prefix,
    receipts: &[StoredReceipt],
) -> QuorumOutcome {
    let backer_state = match replay_to_seq(issuer_kel, anchor.kel_seq) {
        Some(state) => state,
        None => {
            return QuorumOutcome::UnderQuorum {
                collected: 0,
                required: 0,
            };
        }
    };
    let backers = &backer_state.backers;
    let bt = &backer_state.backer_threshold;
    if backers.is_empty() {
        return QuorumOutcome::Met;
    }

    let agreement = WitnessAgreement::new(1);
    let sn = anchor.kel_seq as u64;
    agreement.submit_event(issuer_prefix, sn, &anchor.tel_said, bt, backers);
    if agreement.is_accepted(issuer_prefix, sn, &anchor.tel_said) {
        return QuorumOutcome::Met;
    }

    let mut collected = 0usize;
    for receipt in receipts {
        if receipt.signed.receipt.d != anchor.tel_said {
            continue;
        }
        if !backers.contains(&receipt.witness) {
            continue;
        }
        if !verify_receipt(receipt) {
            continue;
        }
        collected += 1;
        agreement.add_receipt(
            issuer_prefix,
            sn,
            &anchor.tel_said,
            receipt.witness.as_str(),
        );
    }

    if agreement.is_accepted(issuer_prefix, sn, &anchor.tel_said) {
        QuorumOutcome::Met
    } else {
        QuorumOutcome::UnderQuorum {
            collected,
            required: required_count(bt, backers.len()),
        }
    }
}

/// The required-receipt count for display, from the typed backer threshold.
fn required_count(bt: &Threshold, backer_count: usize) -> usize {
    bt.simple_value()
        .map(|v| v as usize)
        .unwrap_or(backer_count)
}

/// Verify a witness receipt's detached signature against its declared witness key.
///
/// The witness AID is a CESR-qualified verkey, so the key travels in-band; the
/// curve is dispatched on the parsed key, never on byte length.
fn verify_receipt(receipt: &StoredReceipt) -> bool {
    let Ok(payload) = serde_json::to_vec(&receipt.signed.receipt) else {
        return false;
    };
    let Ok(key) = KeriPublicKey::parse(receipt.witness.as_str()) else {
        return false;
    };
    verify_with_key_sync(&key, &payload, &receipt.signed.signature)
}

/// Verify the issuer's signature over the ACDC wire bytes against the signing-time key.
///
/// The signing-time key is recovered by replaying the issuer KEL up to and
/// including the `iss`-anchoring position (`take_while ≤ iss_anchor_seq`) — a
/// rotation *after* issuance does not invalidate the credential.
fn verify_issuer_signature(
    signed: &SignedAcdc,
    issuer_kel: &[Event],
    iss_anchor_seq: u128,
) -> bool {
    let Some(state) = replay_to_seq(issuer_kel, iss_anchor_seq) else {
        return false;
    };
    let Ok(wire) = signed.acdc.to_wire_bytes() else {
        return false;
    };
    for cesr in &state.current_keys {
        if let Some(key) = parse_cesr_key(cesr)
            && verify_with_key_sync(&key, &wire, &signed.signature)
        {
            return true;
        }
    }
    false
}

/// Replay the issuer KEL up to and including `seq`, returning the key-state at that
/// position (the take-while-≤-anchor-seq key recovery shared with the commit path).
fn replay_to_seq(issuer_kel: &[Event], seq: u128) -> Option<KeyState> {
    let subset: Vec<Event> = issuer_kel
        .iter()
        .take_while(|e| e.sequence().value() <= seq)
        .cloned()
        .collect();
    validate_kel(&subset).ok()
}

/// Decode a CESR verkey into a curve-tagged key, or `None` if it is undecodable.
fn parse_cesr_key(cesr: &CesrKey) -> Option<KeriPublicKey> {
    KeriPublicKey::parse(cesr.as_str()).ok()
}

/// Project an issuer KEL onto duplicity-detection refs (prefix, seq, SAID).
fn kel_refs<'a>(issuer_kel: &'a [Event], prefix: &'a Prefix) -> Vec<KelEventRef<'a>> {
    issuer_kel
        .iter()
        .map(|e| KelEventRef {
            prefix: prefix.as_str(),
            seq: e.sequence().value() as u64,
            said: e.said().as_str(),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_keri::{KeriSequence, Vcp};

    fn lifecycle_with_revs(revs: Vec<u128>) -> Lifecycle {
        Lifecycle {
            iss_anchor_seq: 1,
            vcp_anchor: AnchoredTelEvent {
                tel_said: Said::new_unchecked("Evcp".into()),
                kel_seq: 0,
            },
            iss_anchor: AnchoredTelEvent {
                tel_said: Said::new_unchecked("Eiss".into()),
                kel_seq: 1,
            },
            rev_anchors: revs
                .into_iter()
                .map(|s| AnchoredTelEvent {
                    tel_said: Said::new_unchecked(format!("Erev{s}")),
                    kel_seq: s,
                })
                .collect(),
        }
    }

    fn warn_quorum(rev_seqs: &[u128]) -> QuorumResolution {
        QuorumResolution {
            vcp: QuorumOutcome::Met,
            iss: QuorumOutcome::Met,
            revs: rev_seqs.iter().map(|s| (*s, QuorumOutcome::Met)).collect(),
        }
    }

    #[test]
    fn revocation_ordered_by_kel_position() {
        let lc = lifecycle_with_revs(vec![3]);
        let q = warn_quorum(&[3]);
        // Presented before the rev → not revoked.
        assert_eq!(
            effective_revocation(&lc, &q, VerifierWitnessPolicy::Warn, 2),
            None
        );
        // Presented at/after the rev → revoked.
        assert_eq!(
            effective_revocation(&lc, &q, VerifierWitnessPolicy::Warn, 3),
            Some(3)
        );
    }

    #[test]
    fn under_quorum_rev_skipped_under_require_witnesses() {
        let lc = lifecycle_with_revs(vec![3]);
        let q = QuorumResolution {
            vcp: QuorumOutcome::Met,
            iss: QuorumOutcome::Met,
            revs: vec![(
                3,
                QuorumOutcome::UnderQuorum {
                    collected: 0,
                    required: 1,
                },
            )],
        };
        // Under RequireWitnesses a sub-quorum rev does NOT revoke.
        assert_eq!(
            effective_revocation(&lc, &q, VerifierWitnessPolicy::RequireWitnesses, 9),
            None
        );
        // But under Warn the same seen rev revokes (conservative).
        assert_eq!(
            effective_revocation(&lc, &q, VerifierWitnessPolicy::Warn, 9),
            Some(3)
        );
    }

    #[test]
    fn lifecycle_event_display_names_anchor() {
        assert_eq!(LifecycleEvent::Vcp.to_string(), "vcp");
        assert_eq!(LifecycleEvent::Iss.to_string(), "iss");
        assert_eq!(LifecycleEvent::Rev.to_string(), "rev");
    }

    #[test]
    fn required_count_from_simple_threshold() {
        assert_eq!(required_count(&Threshold::Simple(2), 3), 2);
    }

    #[test]
    fn vcp_registry_accessor_is_reused() {
        // Compile-time proof the Vcp type is wired (registry SAID == d).
        let vcp = Vcp::new(Prefix::new_unchecked("Eissuer".into()), "0Anonce".into());
        let _ = vcp.s.value();
        let _ = KeriSequence::new(0);
    }
}
