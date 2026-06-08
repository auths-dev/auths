//! Holder-binding + presentation verification — credentials are not bearer tokens (Epic F.8).
//!
//! An issuer-signature-only ACDC that anyone who *possesses* it can present as
//! authority is a **bearer token** — the red flag this project bans. Authority
//! derived from a credential is honored only on **proof of current control of the
//! subject AID** (`a.i`), established by replaying the subject's KEL and checking a
//! fresh **presentation signature** against the signing-time key. A possessed-but-
//! unbound ACDC grants nothing.
//!
//! [`verify_presentation`] is pure and WASM-safe: no git, no network, no clock of its
//! own (the verification time is injected). It chains F.5's [`verify_credential`] so a
//! revoked/invalid credential never binds, then enforces the holder proof.
//!
//! ## Replay model
//!
//! The signed message is always `(credential-SAID || audience || nonce)`. Two binding
//! modes select how the `nonce` is judged:
//!
//! - **Interactive challenge-response (the v1 default):** the verifier issues a fresh
//!   random nonce as its own ephemeral per-session state (see the SDK
//!   `credentials::present` challenge session), the subject signs over it, and the
//!   verifier accepts the **matching** nonce exactly once. One-shot consumption is the
//!   calling session's job — the pure verifier only confirms the presented nonce equals
//!   the challenge it is handed. A replayed/mismatched/consumed nonce is rejected with
//!   [`PresentationVerdict::NonceMismatchOrConsumed`]. This is genuine replay protection
//!   without any global seen-cache, which is what keeps it WASM-compatible.
//! - **Non-interactive TTL (`expected_challenge == None`):** no fresh challenge is
//!   possible, so the presentation binds to `(audience, purpose, short-TTL)` carried in
//!   the envelope and is judged against the injected `now`. **Residual (documented
//!   honestly):** within the TTL window, the *same* presentation can be replayed to the
//!   *same audience* — there is no per-use nonce to consume. This is acceptable only for
//!   low-stakes / idempotent audiences; it is NOT a replacement for the challenge path
//!   where genuine single-use is required. The verdict surfaces [`PresentationVerdict::Expired`]
//!   once `now` passes `not_after`.

use auths_crypto::CryptoProvider;
use auths_keri::{
    CesrKey, DelegatorKelLookup, Event, KeriPublicKey, KeyState, Prefix, Said, Seal, SourceSeal,
    validate_kel_with_lookup,
};
use chrono::{DateTime, Utc};

use crate::credential::{CredentialVerdict, SignedAcdc, verify_credential_sync};
use crate::software_verify::verify_with_key_sync;
use crate::{CanonicalDid, Capability, IdentityDID};

/// The optional informational role claim in the ACDC attributes (`a.role`),
/// written by the F.4 issuance path. Surfaced on a `Valid` verdict for the F.6 bridge.
const ROLE_FIELD: &str = "role";

/// The optional ISO-8601 expiry claim in the ACDC attributes (`a.expiry`), written by
/// the F.4 issuance path. Surfaced on a `Valid` verdict for the F.6 bridge.
const EXPIRY_FIELD: &str = "expiry";

/// `DelegatorKelLookup` over an in-memory delegator KEL slice — answers "did the
/// delegator anchor a seal for this delegated subject event?" by scanning its seals.
///
/// A credential subject (`a.i`) is typically a delegated device/agent whose `dip`/`drt`
/// events are anchored in its delegator's KEL. Replaying the subject KEL to recover its
/// *current* signing key therefore needs the delegator's anchoring seals; this provides
/// them purely (no git/network), keeping the verify path WASM-safe.
struct DelegatorSeals<'a> {
    delegator_kel: &'a [Event],
}

impl DelegatorKelLookup for DelegatorSeals<'_> {
    fn find_seal(&self, _delegator_aid: &Prefix, seal_said: &Said) -> Option<SourceSeal> {
        for event in self.delegator_kel {
            for seal in event.anchors() {
                if let Seal::KeyEvent { d, .. } = seal
                    && d == seal_said
                {
                    return Some(SourceSeal {
                        s: event.sequence(),
                        d: event.said().clone(),
                    });
                }
            }
        }
        None
    }
}

/// Replay the subject KEL to its current key-state, supplying delegator seals if needed.
///
/// A non-delegated subject KEL (only `icp`/`rot`/`ixn`) replays with no lookup; a
/// delegated subject (`dip`/`drt`) needs its delegator's anchoring seals, taken from
/// `subject_delegator_kel`. An empty delegator KEL with a delegated subject yields a
/// replay error (`SubjectKelInvalid`), which is the correct fail-closed outcome.
fn replay_subject(subject_kel: &[Event], subject_delegator_kel: &[Event]) -> Option<KeyState> {
    let lookup = DelegatorSeals {
        delegator_kel: subject_delegator_kel,
    };
    validate_kel_with_lookup(subject_kel, Some(&lookup)).ok()
}

/// The presentation binding mode carried in a [`PresentationEnvelope`].
///
/// Selects how the `nonce` in the signed `(cred-SAID || audience || nonce)` is judged:
/// a verifier-issued challenge (single-use, interactive) or a self-asserted TTL window
/// (non-interactive, with the documented within-TTL same-audience replay residual).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationBinding {
    /// Interactive challenge-response: the `nonce` is the verifier-issued challenge the
    /// subject signed over. The verifier accepts it once (the session consumes it).
    Challenge {
        /// The verifier-issued nonce the subject signed.
        nonce: Vec<u8>,
    },
    /// Non-interactive: the `nonce` is a subject-chosen value bound to a short TTL.
    /// Valid while `now < not_after`. Carries the within-TTL replay residual.
    Ttl {
        /// The subject-chosen nonce the subject signed (uniqueness, not single-use).
        nonce: Vec<u8>,
        /// The presentation's expiry; `now >= not_after` → [`PresentationVerdict::Expired`].
        not_after: DateTime<Utc>,
    },
}

/// A minimal presentation envelope: the subject's proof of current control of `a.i`.
///
/// This is the binding + a minimal envelope, **not** the IPEX grant/admit protocol
/// (deferred, tracked in F.7). The subject signs `(credential-SAID || audience || nonce)`
/// with its signing-time key; the verifier recovers that key by replaying the subject
/// KEL and checks this signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationEnvelope {
    /// The SAID (`acdc.d`) of the credential being presented.
    pub credential_said: String,
    /// The audience this presentation is bound to (the relying party / verifier id).
    pub audience: String,
    /// The binding mode (interactive challenge or non-interactive TTL).
    pub binding: PresentationBinding,
    /// The subject's signature over `(credential-SAID || audience || nonce)`.
    pub signature: Vec<u8>,
}

impl PresentationEnvelope {
    /// The canonical bytes the subject signs: `credential-SAID || audience || nonce`.
    ///
    /// Length-prefix-free concatenation is unambiguous here because the SAID and the
    /// audience are length-fixed by their domains at the call site, and the nonce is the
    /// trailing field — but to avoid any cross-field ambiguity we separate fields with a
    /// NUL byte that cannot occur in a SAID or a UTF-8 audience identifier boundary.
    fn signed_message(credential_said: &str, audience: &str, nonce: &[u8]) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(credential_said.len() + audience.len() + nonce.len() + 2);
        message.extend_from_slice(credential_said.as_bytes());
        message.push(0);
        message.extend_from_slice(audience.as_bytes());
        message.push(0);
        message.extend_from_slice(nonce);
        message
    }

    /// The nonce carried by this envelope's binding (challenge or TTL).
    fn nonce(&self) -> &[u8] {
        match &self.binding {
            PresentationBinding::Challenge { nonce } => nonce,
            PresentationBinding::Ttl { nonce, .. } => nonce,
        }
    }
}

/// The distinguishable outcome of [`verify_presentation`].
///
/// Every failure names *why* the presentation was not honored. A possessed credential
/// alone never yields [`PresentationVerdict::Valid`]; current-control proof is mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationVerdict {
    /// Holder-binding proven: the credential is valid (F.5) AND the presentation was
    /// signed by the subject AID's current signing-time key for the expected audience
    /// and nonce/TTL. Carries the grant facts so the F.6 authority bridge can build a
    /// policy context from the *verified presentation*, never from a raw ACDC.
    Valid {
        /// The issuer AID (`did:keri:`) that granted the now-bound credential.
        issuer: IdentityDID,
        /// The subject (holder) AID (`did:keri:`) whose current key signed the presentation.
        subject: CanonicalDid,
        /// The capabilities the now-bound credential grants (`a.capability`).
        caps: Vec<Capability>,
        /// The optional informational role claim (`a.role`).
        role: Option<String>,
        /// The optional credential expiry (`a.expiry`), as carried in the ACDC attributes.
        expires_at: Option<DateTime<Utc>>,
    },
    /// The presentation signature did not verify against the subject KEL's current key —
    /// the presenter does not currently control `a.i` (bearer / stale-key rejection).
    HolderNotCurrentKey,
    /// The presentation was bound to a different audience than expected.
    WrongAudience,
    /// Challenge path: the presented nonce did not match the verifier's challenge, or the
    /// challenge was already consumed (single-use replay protection).
    NonceMismatchOrConsumed,
    /// TTL path: the non-interactive presentation's `not_after` has passed (`now >= not_after`).
    Expired,
    /// The subject's KEL could not be replayed (missing/forked/invalid) — no current key
    /// to bind against.
    SubjectKelInvalid,
    /// The credential itself is not valid (chains F.5): revoked, expired, unanchored,
    /// schema/SAID mismatch, etc. A presentation of an invalid credential binds nothing.
    CredentialNotValid(CredentialVerdict),
}

impl PresentationVerdict {
    /// Whether the presentation is honored (`Valid`).
    pub fn is_honored(&self) -> bool {
        matches!(self, PresentationVerdict::Valid { .. })
    }
}

/// Verify a credential presentation — F.5 credential validity AND holder-binding proof.
///
/// This is the pure, WASM-safe authority gate. It refuses to honor a possessed-but-
/// unbound ACDC: the presentation MUST be signed by the subject AID's current signing-
/// time key (recovered by replaying `subject_kel`), bound to `expected_audience`, and
/// (challenge path) carry the verifier's one-shot nonce or (TTL path) be within its TTL.
///
/// The credential check is delegated to F.5's [`verify_credential`] unchanged; a
/// non-`Valid` inner verdict short-circuits to [`PresentationVerdict::CredentialNotValid`]
/// so a revoked/expired credential never binds.
///
/// Args:
/// * `envelope`: The subject's presentation (audience, binding, signature).
/// * `signed`: The credential body + the issuer's detached signature (the F.5 input).
/// * `issuer_kel`: The issuer identity's KEL (for the F.5 credential check), in sequence order.
/// * `tel_events`: The credential registry's TEL (`vcp`/`iss`/optional `rev`), for F.5.
/// * `receipts`: Witness receipts handed to F.5's quorum math.
/// * `witness_policy`: F.5 witness policy (`Warn` / `RequireWitnesses`).
/// * `subject_kel`: The subject (holder) AID's KEL, replayed to recover its current key.
/// * `subject_delegator_kel`: The subject's delegator KEL (its anchoring seals), needed
///   only when the subject is a delegated identifier (`dip`/`drt`). Pass `&[]` for a
///   non-delegated subject.
/// * `expected_audience`: The audience the verifier requires the presentation to be bound to.
/// * `expected_challenge`: `Some(nonce)` for the interactive challenge path (one-shot,
///   session-consumed); `None` for the non-interactive TTL path.
/// * `now`: Verification time, injected at the boundary (no wall clock here).
/// * `_provider`: Accepted but unused — see [`verify_presentation_sync`]. Signature
///   verification runs through the in-crate pure-Rust `software_verify`; the parameter
///   is retained only for source-compatibility of this async signature.
///
/// Usage:
/// ```ignore
/// let verdict = verify_presentation(
///     &envelope, &signed, &issuer_kel, &tel, &receipts, policy,
///     &subject_kel, &subject_delegator_kel, "audience.example", Some(&nonce), now, &provider,
/// ).await;
/// assert!(verdict.is_honored());
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn verify_presentation(
    envelope: &PresentationEnvelope,
    signed: &SignedAcdc,
    issuer_kel: &[Event],
    tel_events: &[auths_keri::TelEvent],
    receipts: &[auths_keri::witness::StoredReceipt],
    witness_policy: crate::commit_kel::VerifierWitnessPolicy,
    subject_kel: &[Event],
    subject_delegator_kel: &[Event],
    expected_audience: &str,
    expected_challenge: Option<&[u8]>,
    now: DateTime<Utc>,
    _provider: &dyn CryptoProvider,
) -> PresentationVerdict {
    verify_presentation_sync(
        envelope,
        signed,
        issuer_kel,
        tel_events,
        receipts,
        witness_policy,
        subject_kel,
        subject_delegator_kel,
        expected_audience,
        expected_challenge,
        now,
    )
}

/// Verify a credential presentation synchronously, with no executor — the WASM-safe
/// core behind [`verify_presentation`].
///
/// Identical contract to [`verify_presentation`] but executor-free: `block_on` is
/// impossible in browser WASM, so every non-Rust binding target (C-ABI, WASM, Node,
/// Python, Go) calls this directly. It chains F.5's [`verify_credential_sync`] so a
/// revoked/invalid credential never binds, then enforces the holder proof through the
/// synchronous pure-Rust `software_verify`.
///
/// Args: identical to [`verify_presentation`] minus the trailing provider.
///
/// Usage:
/// ```ignore
/// let verdict = verify_presentation_sync(
///     &envelope, &signed, &issuer_kel, &tel, &receipts, policy,
///     &subject_kel, &subject_delegator_kel, "audience.example", Some(&nonce), now,
/// );
/// assert!(verdict.is_honored());
/// ```
#[allow(clippy::too_many_arguments)]
pub fn verify_presentation_sync(
    envelope: &PresentationEnvelope,
    signed: &SignedAcdc,
    issuer_kel: &[Event],
    tel_events: &[auths_keri::TelEvent],
    receipts: &[auths_keri::witness::StoredReceipt],
    witness_policy: crate::commit_kel::VerifierWitnessPolicy,
    subject_kel: &[Event],
    subject_delegator_kel: &[Event],
    expected_audience: &str,
    expected_challenge: Option<&[u8]>,
    now: DateTime<Utc>,
) -> PresentationVerdict {
    let credential_verdict = verify_credential_sync(
        signed,
        issuer_kel,
        tel_events,
        receipts,
        witness_policy,
        now,
    );
    if !credential_verdict.is_valid() {
        return PresentationVerdict::CredentialNotValid(credential_verdict);
    }

    if envelope.credential_said != signed.acdc.d.as_str() {
        return PresentationVerdict::CredentialNotValid(CredentialVerdict::SaidMismatch);
    }

    if envelope.audience != expected_audience {
        return PresentationVerdict::WrongAudience;
    }

    if let Some(verdict) = check_binding(&envelope.binding, expected_challenge, now) {
        return verdict;
    }

    let (issuer, caps) = match credential_verdict {
        CredentialVerdict::Valid { issuer, caps, .. } => (issuer, caps),
        // `is_valid()` above guarantees `Valid`; on the impossible arm return a credential
        // failure rather than panicking or fabricating an identity (keeps this WASM/FFI-safe).
        other => return PresentationVerdict::CredentialNotValid(other),
    };

    let grant = GrantFacts {
        issuer,
        caps,
        role: read_attribute(signed, ROLE_FIELD),
        expires_at: read_expiry(signed),
    };

    verify_holder_signature(envelope, signed, subject_kel, subject_delegator_kel, grant)
}

/// The credential grant facts surfaced on a `Valid` presentation verdict.
///
/// Assembled from the inner F.5 [`CredentialVerdict::Valid`] (`issuer`/`caps`) and the
/// verified `acdc.a` (`role`/`expiry`) once both the credential and the holder proof
/// have passed, so they can never be read off an un-presented ACDC.
struct GrantFacts {
    issuer: IdentityDID,
    caps: Vec<Capability>,
    role: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

/// Read an optional string claim from the verified ACDC attributes (`a.<field>`).
fn read_attribute(signed: &SignedAcdc, field: &str) -> Option<String> {
    signed
        .acdc
        .a
        .data
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Read and parse the optional `a.expiry` claim into a UTC instant (RFC-3339), as F.4 wrote it.
fn read_expiry(signed: &SignedAcdc) -> Option<DateTime<Utc>> {
    let raw = read_attribute(signed, EXPIRY_FIELD)?;
    DateTime::parse_from_rfc3339(&raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Enforce the nonce/TTL binding; `None` means the binding passed.
///
/// Challenge path: `expected_challenge` must be present and equal the envelope nonce
/// (mismatch / already-consumed → [`PresentationVerdict::NonceMismatchOrConsumed`]).
/// TTL path: the envelope must be the TTL variant and unexpired against `now`. A
/// challenge/TTL-mode disagreement between the verifier and the envelope is treated as a
/// nonce mismatch (the verifier asked for a challenge it did not get, or vice versa).
fn check_binding(
    binding: &PresentationBinding,
    expected_challenge: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Option<PresentationVerdict> {
    match (binding, expected_challenge) {
        (PresentationBinding::Challenge { nonce }, Some(expected)) => {
            (nonce.as_slice() != expected).then_some(PresentationVerdict::NonceMismatchOrConsumed)
        }
        (PresentationBinding::Ttl { not_after, .. }, None) => {
            (now >= *not_after).then_some(PresentationVerdict::Expired)
        }
        // Mode disagreement: a challenge was expected but the envelope is TTL-bound (or
        // the reverse). The interactive path treats a missing/extra challenge as a
        // nonce failure; there is no honoring without the agreed binding.
        (PresentationBinding::Challenge { .. }, None)
        | (PresentationBinding::Ttl { .. }, Some(_)) => {
            Some(PresentationVerdict::NonceMismatchOrConsumed)
        }
    }
}

/// Check the presentation signature against the subject KEL's current signing key.
///
/// The subject KEL is replayed (`validate_kel`) to recover the *current* key-state; the
/// presentation must verify against one of those current keys. A rotation that advanced
/// the subject's key invalidates a presentation signed by the old key — that is the
/// "current control" requirement (distinct from F.5's signing-*time* issuer key).
fn verify_holder_signature(
    envelope: &PresentationEnvelope,
    signed: &SignedAcdc,
    subject_kel: &[Event],
    subject_delegator_kel: &[Event],
    grant: GrantFacts,
) -> PresentationVerdict {
    let Some(state) = replay_subject(subject_kel, subject_delegator_kel) else {
        return PresentationVerdict::SubjectKelInvalid;
    };
    // The subject AID is the holder we just replayed; a DID that fails to parse means the
    // subject is unusable as an identity (treated as an invalid subject KEL).
    let Ok(subject) = CanonicalDid::parse(&format!("did:keri:{}", signed.acdc.a.i)) else {
        return PresentationVerdict::SubjectKelInvalid;
    };

    let message = PresentationEnvelope::signed_message(
        &envelope.credential_said,
        &envelope.audience,
        envelope.nonce(),
    );

    for cesr in &state.current_keys {
        if let Some(key) = parse_cesr_key(cesr)
            && verify_with_key_sync(&key, &message, &envelope.signature)
        {
            return PresentationVerdict::Valid {
                issuer: grant.issuer,
                subject,
                caps: grant.caps,
                role: grant.role,
                expires_at: grant.expires_at,
            };
        }
    }
    PresentationVerdict::HolderNotCurrentKey
}

/// Decode a CESR verkey into a curve-tagged key, or `None` if it is undecodable.
fn parse_cesr_key(cesr: &CesrKey) -> Option<KeriPublicKey> {
    KeriPublicKey::parse(cesr.as_str()).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ttl_envelope(not_after: DateTime<Utc>) -> PresentationEnvelope {
        PresentationEnvelope {
            credential_said: "ECred".to_string(),
            audience: "aud".to_string(),
            binding: PresentationBinding::Ttl {
                nonce: vec![1, 2, 3],
                not_after,
            },
            signature: vec![],
        }
    }

    fn challenge_envelope(nonce: Vec<u8>) -> PresentationEnvelope {
        PresentationEnvelope {
            credential_said: "ECred".to_string(),
            audience: "aud".to_string(),
            binding: PresentationBinding::Challenge { nonce },
            signature: vec![],
        }
    }

    #[test]
    fn signed_message_separates_fields() {
        let a = PresentationEnvelope::signed_message("E1", "aud", &[9]);
        let b = PresentationEnvelope::signed_message("E1a", "ud", &[9]);
        assert_ne!(a, b, "field boundaries must be unambiguous");
    }

    #[test]
    fn challenge_match_passes_binding() {
        let env = challenge_envelope(vec![7, 7, 7]);
        let now = chrono::Utc::now();
        assert_eq!(check_binding(&env.binding, Some(&[7, 7, 7]), now), None);
    }

    #[test]
    fn challenge_mismatch_rejected() {
        let env = challenge_envelope(vec![7, 7, 7]);
        let now = chrono::Utc::now();
        assert_eq!(
            check_binding(&env.binding, Some(&[1, 2, 3]), now),
            Some(PresentationVerdict::NonceMismatchOrConsumed)
        );
    }

    #[test]
    fn consumed_challenge_is_none_expected() {
        // A consumed challenge is represented by the session no longer offering it:
        // expected becomes None, which the challenge envelope cannot satisfy.
        let env = challenge_envelope(vec![7, 7, 7]);
        let now = chrono::Utc::now();
        assert_eq!(
            check_binding(&env.binding, None, now),
            Some(PresentationVerdict::NonceMismatchOrConsumed)
        );
    }

    #[test]
    fn ttl_unexpired_passes_binding() {
        let now = chrono::Utc::now();
        let env = ttl_envelope(now + chrono::Duration::seconds(60));
        assert_eq!(check_binding(&env.binding, None, now), None);
    }

    #[test]
    fn ttl_expired_rejected() {
        let now = chrono::Utc::now();
        let env = ttl_envelope(now - chrono::Duration::seconds(1));
        assert_eq!(
            check_binding(&env.binding, None, now),
            Some(PresentationVerdict::Expired)
        );
    }
}
