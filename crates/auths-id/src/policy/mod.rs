//! Policy engine for authorization decisions.
//!
//! This module provides pure functions for evaluating authorization policies.
//! It centralizes all "should this be trusted?" logic.
//!
//! ## Core Entrypoints (Pure Functions)
//!
//! - [`evaluate_compiled`]: Evaluates a compiled policy against an attestation
//! - [`evaluate_with_witness`]: Adds witness consistency checks before evaluation
//!
//! **What "pure" means for these functions:**
//! - **Deterministic**: Same inputs always produce same outputs
//! - **No side effects**: No filesystem, network, or global state access
//! - **No storage assumptions**: All state passed as parameters
//! - **Time is injected**: `DateTime<Utc>` passed in, never `Utc::now()`
//! - **Errors are values**: Returns `Decision`, never panics
//!
//! ## Design Principle
//!
//! The policy engine consumes identity state and attestations but never
//! accesses storage directly. All inputs are passed explicitly.
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │  Attestation │────▶│  context_    │     │              │
//! │  (device)    │     │  from_       │────▶│  EvalContext │
//! │              │     │  attestation │     │              │
//! └──────────────┘     └──────────────┘     └──────────────┘
//!                                                  │
//!                                                  ▼
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │  Compiled    │────▶│  evaluate_   │────▶│   Decision   │
//! │  Policy      │     │  compiled    │     │              │
//! │              │     │              │     │ Allow/Deny/  │
//! └──────────────┘     └──────────────┘     │ Indeterminate│
//!                                           └──────────────┘
//! ```

use auths_core::witness::{EventHash, WitnessProvider};
use auths_policy::{CanonicalCapability, DidParseError};
use auths_verifier::PresentationVerdict;
use auths_verifier::core::Attestation;
use auths_verifier::types::CanonicalDid;
use chrono::{DateTime, Utc};

use crate::keri::KeyState;
use crate::keri::event::EventReceipts;
use crate::keri::types::Said;
#[cfg(feature = "git-storage")]
use crate::storage::receipts::{check_receipt_consistency, verify_receipt_signature};

// Re-export policy types for convenience
pub use auths_policy::{
    CompileError, CompiledPolicy, Decision, EvalContext, Expr, Outcome, PolicyBuilder,
    PolicyLimits, ReasonCode, compile, compile_from_json, evaluate_strict,
};

/// Convert an attestation to an evaluation context.
///
/// This is the bridge between the attestation data model and the
/// policy engine's typed context.
///
/// # Authority source (fail-closed)
///
/// This context carries identity facts only — issuer, subject, revocation,
/// expiry, timestamp, delegator, and signer type. It does **not** read
/// `capabilities`/`role` from the attestation: credential-grade authority
/// flows exclusively through [`context_from_credential`] (holder-verified ACDC),
/// and org-membership role/caps through [`context_from_delegated_member`]
/// (delegator-anchored scope seal). An attestation alone therefore yields an
/// empty capability set and no role, so any caps/role policy condition fails
/// closed unless a credential/membership context supplies them.
///
/// # Arguments
///
/// * `att` - The device attestation to convert
/// * `now` - The current time (injected for determinism)
///
/// # Returns
///
/// An `EvalContext` populated with the attestation's identity facts.
///
pub fn context_from_attestation(
    att: &Attestation,
    now: DateTime<Utc>,
) -> Result<EvalContext, DidParseError> {
    let mut ctx = EvalContext::try_from_strings(now, &att.issuer, att.subject.as_ref())?;

    ctx = ctx.revoked(att.is_revoked());

    if let Some(expires_at) = att.expires_at {
        ctx = ctx.expires_at(expires_at);
    }

    if let Some(ref delegated_by) = att.delegated_by {
        // Parse delegated_by DID, ignoring if invalid
        if let Ok(did) = auths_policy::CanonicalDid::parse(delegated_by) {
            ctx = ctx.delegated_by(did);
        }
    }

    // Bridge signer_type from verifier to policy domain
    if let Some(ref st) = att.signer_type {
        let policy_st = match st {
            auths_verifier::core::SignerType::Human => auths_policy::SignerType::Human,
            auths_verifier::core::SignerType::Agent => auths_policy::SignerType::Agent,
            auths_verifier::core::SignerType::Workload => auths_policy::SignerType::Workload,
            _ => auths_policy::SignerType::Workload,
        };
        ctx = ctx.signer_type(policy_st);
    }

    Ok(ctx)
}

/// Build an evaluation context from a delegator-anchored (KEL-authoritative) org
/// membership, fail-closed.
///
/// This is the KERI-native counterpart to [`context_from_attestation`]: org
/// authority is read from the org's KEL (the member is a `dip` the org anchored;
/// role/capabilities ride a delegator-anchored scope seal), **never** from an
/// attestation `delegated_by` field. The caller resolves the membership against the
/// KEL — a revoked-on-KEL member yields `revoked = true` here, so policy denies it
/// even if a stale attestation says otherwise.
///
/// Args:
/// * `org_did`: The delegating org's `did:keri:` — populates both `issuer` and `delegated_by`.
/// * `member_did`: The member's `did:keri:` (derived from its `dip` SAID).
/// * `revoked`: Whether the org has revoked the member on its KEL.
/// * `role`: The member's role string from the scope seal (if any).
/// * `capabilities`: Capability strings granted by the scope seal.
/// * `expires_at`: Optional delegator-anchored expiry.
/// * `now`: The current time (injected for determinism).
///
/// Usage:
/// ```ignore
/// let ctx = context_from_delegated_member(&org_did, &member_did, revoked, role, &caps, expires, now)?;
/// let decision = evaluate_strict(&policy, &ctx);
/// ```
#[allow(clippy::too_many_arguments)]
pub fn context_from_delegated_member(
    org_did: &str,
    member_did: &str,
    revoked: bool,
    role: Option<&str>,
    capabilities: &[String],
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<EvalContext, DidParseError> {
    let mut ctx = EvalContext::try_from_strings(now, org_did, member_did)?;
    ctx = ctx.revoked(revoked);

    let caps: Vec<CanonicalCapability> = capabilities
        .iter()
        .filter_map(|c| CanonicalCapability::parse(c).ok())
        .collect();
    ctx = ctx.capabilities(caps);

    if let Some(role) = role {
        ctx = ctx.role(role.to_string());
    }
    if let Some(expires_at) = expires_at {
        ctx = ctx.expires_at(expires_at);
    }
    if let Ok(did) = auths_policy::CanonicalDid::parse(org_did) {
        ctx = ctx.delegated_by(did);
    }

    Ok(ctx)
}

/// The authoritative source of a grant's capabilities + role for a policy decision.
///
/// There are two on-chain encodings of a capability/role grant, and they serve
/// different decision grades:
///
/// - [`CapsSource::AgentScopeSeal`] — the Epic-E `agentscope:` `Seal::Digest` anchored in
///   the delegator's `ixn`. It is **commit-time advisory**: the offline fast path a
///   verifier can read straight off the KEL without a live presentation. It is the
///   low-latency convenience source, not an authority of record.
/// - [`CapsSource::Acdc`] — the F.4 capability credential. It is the **authoritative**
///   caps/role source for credential-grade decisions, and authority derived from it is
///   honored only through a *holder-verified presentation* (F.8) at the policy seam
///   ([`context_from_credential`]).
///
/// **Anti-divergence rule:** the same grant MUST NOT be authored into both encodings with
/// diverging caps/role. When both exist for one grant, [`CapsSource::governing`] selects
/// the ACDC — the credential governs the credential-grade decision. The agentscope seal
/// remains valid only as the advisory commit-time fast path. (Full ADR text is F.7.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsSource {
    /// The Epic-E `agentscope:` delegator-anchored scope seal (commit-time advisory).
    AgentScopeSeal,
    /// The F.4 ACDC capability credential (authoritative for credential-grade decisions).
    Acdc,
}

impl CapsSource {
    /// Select the source that governs a credential-grade decision when both encodings
    /// exist for one grant: the ACDC always wins.
    ///
    /// Args:
    /// * `agentscope_present`: Whether an `agentscope:` seal exists for the grant.
    /// * `acdc_present`: Whether an F.4 ACDC credential exists for the grant.
    ///
    /// Usage:
    /// ```ignore
    /// assert_eq!(CapsSource::governing(true, true), CapsSource::Acdc);
    /// ```
    pub fn governing(agentscope_present: bool, acdc_present: bool) -> Option<CapsSource> {
        match (acdc_present, agentscope_present) {
            (true, _) => Some(CapsSource::Acdc),
            (false, true) => Some(CapsSource::AgentScopeSeal),
            (false, false) => None,
        }
    }
}

/// Failure to build an authority-bearing policy context from a credential presentation.
///
/// The bearer hole is closed at this seam: only a holder-verified presentation
/// ([`PresentationVerdict::Valid`]) yields authority. Every other verdict — and mere
/// possession of a raw ACDC, which is not even an accepted input — fails closed here, so
/// capabilities can never enter a decision without proof the presenter controls the
/// subject AID.
#[derive(Debug, thiserror::Error)]
pub enum PolicyBridgeError {
    /// The presentation did not carry holder proof: it was not [`PresentationVerdict::Valid`],
    /// so no authority-bearing context is produced (fail-closed).
    #[error("no holder proof: presentation is not Valid, refusing to grant authority")]
    NoHolderProof,
    /// The verified presentation's issuer/subject DID failed to parse into the policy domain.
    #[error("credential DID parse failed: {0}")]
    Did(#[from] DidParseError),
}

/// Build a policy [`EvalContext`] from a **holder-verified credential presentation** (F.8),
/// fail-closed.
///
/// This is the credential-grade counterpart to [`context_from_delegated_member`]: it is the
/// single seam where ACDC-borne capabilities/role enter a policy decision, and it closes the
/// bearer hole by construction. It consumes a [`PresentationVerdict`], **never a raw `Acdc`** —
/// so authority cannot flow from mere *possession* of a credential. Only
/// [`PresentationVerdict::Valid`] (the credential is valid per F.5 AND the presenter proved
/// current control of the subject AID) yields a context; every other verdict returns
/// [`PolicyBridgeError::NoHolderProof`].
///
/// Caps-source precedence: see [`CapsSource`] — the ACDC behind a `Valid` presentation is the
/// authoritative caps/role source, governing over any commit-time advisory `agentscope:` seal.
///
/// The spec's vestigial `tel_state` parameter is intentionally dropped: a `Valid`
/// presentation is by construction not-revoked at the verified `as_of` (F.5 already ran the
/// TEL revocation math), so this maps `revoked = false` unconditionally.
///
/// Args:
/// * `presentation`: The holder-binding verdict from `auths_verifier::verify_presentation`.
/// * `now`: The current time (injected for determinism; no wall clock here).
///
/// Usage:
/// ```ignore
/// let ctx = context_from_credential(&verdict, now)?;
/// let decision = evaluate_strict(&policy, &ctx);
/// ```
pub fn context_from_credential(
    presentation: &PresentationVerdict,
    now: DateTime<Utc>,
) -> Result<EvalContext, PolicyBridgeError> {
    let PresentationVerdict::Valid {
        issuer,
        subject,
        caps,
        role,
        expires_at,
    } = presentation
    else {
        return Err(PolicyBridgeError::NoHolderProof);
    };

    let mut ctx = EvalContext::try_from_strings(now, issuer, subject)?;
    ctx = ctx.revoked(false);

    let caps: Vec<CanonicalCapability> = caps
        .iter()
        .filter_map(|c| CanonicalCapability::parse(c).ok())
        .collect();
    ctx = ctx.capabilities(caps);

    if let Some(role) = role {
        ctx = ctx.role(role.clone());
    }
    if let Some(expires_at) = expires_at {
        ctx = ctx.expires_at(*expires_at);
    }
    if let Ok(did) = CanonicalDid::parse(issuer) {
        ctx = ctx.delegated_by(did);
    }

    Ok(ctx)
}

/// Evaluate a compiled policy against an attestation.
///
/// This is a **pure function** with no side effects.
///
/// # Pure Function Guarantees
///
/// - **Deterministic**: Same inputs always produce same `Decision`
/// - **No I/O**: No filesystem, network, or global state access
/// - **Time is injected**: `now` parameter, never `Utc::now()`
/// - **No storage assumptions**: All state passed as parameters
///
/// # Arguments
///
/// * `att` - The device attestation being evaluated
/// * `policy` - The compiled policy to evaluate
/// * `now` - The current time (injected for determinism)
///
/// # Returns
///
/// A `Decision` indicating whether the action is allowed, denied, or indeterminate.
///
/// # Example
///
/// ```rust,ignore
/// use auths_id::policy::{evaluate_compiled, PolicyBuilder};
/// use chrono::Utc;
///
/// let policy = PolicyBuilder::new()
///     .not_revoked()
///     .not_expired()
///     .require_capability("sign_commit")
///     .build();
///
/// let decision = evaluate_compiled(&device_attestation, &policy, Utc::now());
///
/// if decision.outcome == Outcome::Allow {
///     println!("Access granted");
/// }
/// ```
pub fn evaluate_compiled(
    att: &Attestation,
    policy: &CompiledPolicy,
    now: DateTime<Utc>,
) -> Result<Decision, DidParseError> {
    let ctx = context_from_attestation(att, now)?;
    Ok(evaluate_strict(policy, &ctx))
}

/// Evaluate policy with optional witness consistency checks.
///
/// This function extends [`evaluate_compiled`] by first checking that the
/// local identity head matches what witnesses have observed. This helps
/// detect split-view attacks where a malicious node shows different KELs
/// to different peers.
///
/// # Witness Checking
///
/// 1. If no witnesses are provided or all return `None`, proceed with normal policy evaluation
/// 2. If witnesses have opinions, count how many agree with local_head
/// 3. If quorum is not met, return `Indeterminate`
/// 4. If quorum is met, proceed with normal policy evaluation
///
/// # Arguments
///
/// * `identity` - The identity's current key state
/// * `att` - The device attestation being evaluated
/// * `policy` - The compiled policy to evaluate
/// * `now` - Current time (injected for determinism)
/// * `local_head` - The local identity KEL head (from our storage)
/// * `witnesses` - Witness providers to check for consistency
///
/// # Returns
///
/// - `Indeterminate` if witness quorum not met
/// - Otherwise, result of `evaluate_compiled`
pub fn evaluate_with_witness(
    identity: &KeyState,
    att: &Attestation,
    policy: &CompiledPolicy,
    now: DateTime<Utc>,
    local_head: EventHash,
    witnesses: &[&dyn WitnessProvider],
) -> Result<Decision, DidParseError> {
    if witnesses.is_empty() {
        return evaluate_compiled(att, policy, now);
    }

    let required_quorum = witnesses.first().map(|w| w.quorum()).unwrap_or(1);

    if required_quorum == 0 {
        return evaluate_compiled(att, policy, now);
    }

    let mut matching = 0;
    let mut total_opinions = 0;

    for witness in witnesses {
        if let Some(head) = witness.observe_identity_head(&identity.prefix) {
            total_opinions += 1;
            if head == local_head {
                matching += 1;
            }
        }
    }

    if total_opinions == 0 {
        return evaluate_compiled(att, policy, now);
    }

    if matching < required_quorum {
        return Ok(Decision::deny(
            ReasonCode::WitnessQuorumNotMet,
            format!(
                "Witness quorum not met: {}/{} matching, {} required",
                matching, total_opinions, required_quorum
            ),
        ));
    }

    evaluate_compiled(att, policy, now)
}

/// Result of receipt verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerificationResult {
    /// Receipts are valid and meet threshold
    Valid,
    /// Not enough receipts to meet threshold
    InsufficientReceipts { required: usize, got: usize },
    /// Duplicity detected (conflicting SAIDs)
    Duplicity { event_a: Said, event_b: Said },
    /// Invalid receipt signature
    InvalidSignature { witness_did: CanonicalDid },
}

/// Witness public key resolver.
///
/// Implementations provide public keys for witnesses by their DID.
pub trait WitnessKeyResolver: Send + Sync {
    /// Get the Ed25519 public key (32 bytes) for a witness DID.
    fn get_public_key(&self, witness_did: &str) -> Option<Vec<u8>>;
}

/// Evaluate policy with receipt verification.
///
/// This function extends [`evaluate_compiled`] by verifying that:
/// 1. Sufficient receipts are present (meets threshold from event's `bt` field)
/// 2. All receipts are for the same event SAID (no duplicity)
/// 3. Optionally, all receipt signatures are valid
///
/// # Arguments
///
/// * `att` - The device attestation being evaluated
/// * `policy` - The compiled policy to evaluate
/// * `now` - Current time (injected for determinism)
/// * `receipts` - The collected receipts for the event
/// * `threshold` - Required number of receipts (from event's `bt` field)
/// * `key_resolver` - Optional resolver for verifying receipt signatures
///
/// # Returns
///
/// - `ReceiptVerificationResult::InsufficientReceipts` if threshold not met
/// - `ReceiptVerificationResult::Duplicity` if conflicting SAIDs detected
/// - `ReceiptVerificationResult::InvalidSignature` if signature verification fails
/// - Otherwise, proceeds to policy evaluation and returns `ReceiptVerificationResult::Valid`
///   if policy allows, or the policy's `Decision` otherwise
#[cfg(feature = "git-storage")]
pub fn verify_receipts(
    receipts: &EventReceipts,
    threshold: usize,
    key_resolver: Option<&dyn WitnessKeyResolver>,
) -> ReceiptVerificationResult {
    // 1. Check threshold met (using unique witness count, not raw receipt count)
    let unique = receipts.unique_witness_count();
    if unique < threshold {
        return ReceiptVerificationResult::InsufficientReceipts {
            required: threshold,
            got: unique,
        };
    }

    // 2. Check for duplicity (all receipts should have same SAID)
    if let Err(e) = check_receipt_consistency(&receipts.receipts) {
        return ReceiptVerificationResult::Duplicity {
            event_a: receipts.event_said.clone(),
            event_b: Said::new_unchecked(format!("conflicting: {}", e)),
        };
    }

    // 3. Verify receipt signatures if key resolver provided.
    //    Provenance comes from the stored witness AID, not the receipt body's
    //    controller `i`. Collection-time verification (witness_integration) is
    //    the authoritative gate; this resolver path is verifier-side scaffolding.
    if let Some(resolver) = key_resolver {
        for stored in &receipts.receipts {
            let witness = stored.witness.as_str();
            if let Some(public_key) = resolver.get_public_key(witness) {
                let witness_curve = auths_crypto::did_key_decode(witness)
                    .map(|d| d.curve())
                    .unwrap_or_default();
                let typed_pk =
                    match auths_verifier::decode_public_key_bytes(&public_key, witness_curve) {
                        Ok(pk) => pk,
                        Err(_) => {
                            #[allow(clippy::disallowed_methods)]
                            // INVARIANT: witness is a CESR AID from a deserialized stored receipt
                            return ReceiptVerificationResult::InvalidSignature {
                                witness_did: CanonicalDid::new_unchecked(witness),
                            };
                        }
                    };
                match verify_receipt_signature(&stored.signed.receipt, &typed_pk) {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => {
                        return ReceiptVerificationResult::InvalidSignature {
                            #[allow(clippy::disallowed_methods)] // INVARIANT: witness is a CESR AID from a deserialized stored receipt
                            witness_did: CanonicalDid::new_unchecked(witness),
                        };
                    }
                }
            }
            // If no key found for witness, skip signature verification for that receipt
            // (In production, you might want to fail instead)
        }
    }

    ReceiptVerificationResult::Valid
}

/// Evaluate policy with both witness head checks and receipt verification.
///
/// This is the most comprehensive policy evaluation function, combining:
/// - Witness head consistency checks (split-view detection)
/// - Receipt threshold verification
/// - Receipt signature verification
/// - Standard policy evaluation
///
/// # Arguments
///
/// * `identity` - The identity's current key state
/// * `att` - The device attestation being evaluated
/// * `policy` - The compiled policy to evaluate
/// * `now` - Current time (injected for determinism)
/// * `local_head` - The local identity KEL head
/// * `witnesses` - Witness providers for head consistency checks
/// * `receipts` - The collected receipts for the event
/// * `threshold` - Required number of receipts
/// * `key_resolver` - Optional resolver for verifying receipt signatures
///
/// # Returns
///
/// - `Deny` with appropriate reason if any verification fails
/// - Otherwise, result of `evaluate_compiled`
#[cfg(feature = "git-storage")]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_receipts(
    identity: &KeyState,
    att: &Attestation,
    policy: &CompiledPolicy,
    now: DateTime<Utc>,
    local_head: EventHash,
    witnesses: &[&dyn WitnessProvider],
    receipts: &EventReceipts,
    threshold: usize,
    key_resolver: Option<&dyn WitnessKeyResolver>,
) -> Result<Decision, DidParseError> {
    match verify_receipts(receipts, threshold, key_resolver) {
        ReceiptVerificationResult::Valid => {}
        ReceiptVerificationResult::InsufficientReceipts { required, got } => {
            return Ok(Decision::deny(
                ReasonCode::WitnessQuorumNotMet,
                format!(
                    "Insufficient receipts: {} required, {} present",
                    required, got
                ),
            ));
        }
        ReceiptVerificationResult::Duplicity { event_a, event_b } => {
            return Ok(Decision::deny(
                ReasonCode::WitnessQuorumNotMet,
                format!("Duplicity detected: {} vs {}", event_a, event_b),
            ));
        }
        ReceiptVerificationResult::InvalidSignature { witness_did } => {
            return Ok(Decision::deny(
                ReasonCode::WitnessQuorumNotMet,
                format!("Invalid receipt signature from witness: {}", witness_did),
            ));
        }
    }

    evaluate_with_witness(identity, att, policy, now, local_head, witnesses)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_core::witness::NoOpWitness;
    use auths_keri::{CesrKey, Prefix, Said, Threshold};
    use auths_verifier::AttestationBuilder;
    use auths_verifier::core::Capability;
    use chrono::Duration;

    /// Mock witness for testing
    struct MockWitness {
        head: Option<EventHash>,
        quorum: usize,
    }

    impl WitnessProvider for MockWitness {
        fn observe_identity_head(&self, _prefix: &Prefix) -> Option<EventHash> {
            self.head
        }

        fn quorum(&self) -> usize {
            self.quorum
        }
    }

    fn make_key_state(prefix: &str) -> KeyState {
        KeyState::from_inception(
            Prefix::new_unchecked(prefix.to_string()),
            vec![CesrKey::new_unchecked("DTestKey".to_string())],
            vec![Said::new_unchecked("ENextCommitment".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ETestSaid".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        )
    }

    fn make_attestation(
        issuer: &str,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        AttestationBuilder::default()
            .rid("test")
            .issuer(issuer)
            .subject("did:key:zSubject")
            .revoked_at(revoked_at)
            .expires_at(expires_at)
            .build()
    }

    fn default_policy() -> CompiledPolicy {
        PolicyBuilder::new().not_revoked().not_expired().build()
    }

    #[test]
    fn context_from_attestation_basic() {
        let att = make_attestation("did:keri:ETest", None, None);
        let now = Utc::now();
        let ctx = context_from_attestation(&att, now).unwrap();

        assert_eq!(ctx.issuer.as_str(), "did:keri:ETest");
        assert_eq!(ctx.subject.as_str(), "did:key:zSubject");
        assert!(!ctx.revoked);
    }

    #[test]
    fn context_from_attestation_ignores_capabilities() {
        // Caps no longer flow from the attestation — credential-grade authority comes
        // only from `context_from_credential` (a holder-verified ACDC presentation).
        let mut att = make_attestation("did:keri:ETest", None, None);
        att.capabilities = vec![Capability::sign_commit()];
        let now = Utc::now();
        let ctx = context_from_attestation(&att, now).unwrap();

        assert!(
            ctx.capabilities.is_empty(),
            "attestation caps must not enter the policy context"
        );
    }

    #[test]
    fn context_from_attestation_ignores_role() {
        // Role no longer flows from the attestation — org role comes from the
        // delegator-anchored scope seal (`context_from_delegated_member`).
        let mut att = make_attestation("did:keri:ETest", None, None);
        att.role = Some(auths_verifier::core::Role::Member);
        let now = Utc::now();
        let ctx = context_from_attestation(&att, now).unwrap();

        assert_eq!(
            ctx.role, None,
            "attestation role must not enter the policy context"
        );
    }

    #[test]
    fn caps_absent_without_valid_credential() {
        // Fail-closed: an attestation that names capabilities yields NO caps in the
        // policy context, so a capability-gated policy denies — authority can only
        // arrive via a holder-verified credential.
        let mut att = make_attestation("did:keri:ETestPrefix", None, None);
        att.capabilities = vec![Capability::sign_commit()];
        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_capability("sign_commit")
            .build();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::CapabilityMissing);
    }

    // =========================================================================
    // F.6 — context_from_credential holder-proof bridge
    // =========================================================================

    const CRED_ISSUER: &str = "did:keri:EIssuerCredential";
    const CRED_SUBJECT: &str = "did:keri:ESubjectCredential";

    /// A holder-verified `Valid` presentation carrying the given grant facts.
    fn valid_presentation(
        caps: &[&str],
        role: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> PresentationVerdict {
        PresentationVerdict::Valid {
            issuer: CRED_ISSUER.to_string(),
            subject: CRED_SUBJECT.to_string(),
            caps: caps.iter().map(|c| c.to_string()).collect(),
            role: role.map(str::to_string),
            expires_at,
        }
    }

    #[test]
    fn policy_reads_caps_from_credential() {
        let presentation = valid_presentation(&["sign_commit"], Some("deployer"), None);
        let now = Utc::now();

        let ctx = context_from_credential(&presentation, now).unwrap();
        assert_eq!(ctx.issuer.as_str(), CRED_ISSUER);
        assert_eq!(ctx.subject.as_str(), CRED_SUBJECT);
        assert!(!ctx.revoked);
        assert_eq!(ctx.capabilities.len(), 1);
        assert_eq!(ctx.capabilities[0].as_str(), "sign_commit");
        assert_eq!(ctx.role.as_deref(), Some("deployer"));

        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_capability("sign_commit")
            .build();
        assert_eq!(evaluate_strict(&policy, &ctx).outcome, Outcome::Allow);
    }

    #[test]
    fn raw_acdc_without_presentation_yields_no_authority() {
        // The bridge takes a verdict, not an ACDC: a non-`Valid` verdict (here a possessed
        // credential that failed the holder-proof gate) yields NO authority-bearing
        // context. Mere possession of a raw ACDC cannot even be passed in.
        let now = Utc::now();
        for verdict in [
            PresentationVerdict::HolderNotCurrentKey,
            PresentationVerdict::WrongAudience,
            PresentationVerdict::NonceMismatchOrConsumed,
            PresentationVerdict::Expired,
            PresentationVerdict::SubjectKelInvalid,
            PresentationVerdict::CredentialNotValid(
                auths_verifier::CredentialVerdict::SaidMismatch,
            ),
        ] {
            let result = context_from_credential(&verdict, now);
            assert!(
                matches!(result, Err(PolicyBridgeError::NoHolderProof)),
                "non-Valid verdict {verdict:?} must fail closed, got {result:?}"
            );
        }
    }

    #[test]
    fn capability_round_trips_into_acdc() {
        use auths_keri::{AgentScope, decode_agent_scope, encode_agent_scope};
        use auths_verifier::Capability;

        // A capability that exercises the `:`-allowed constraint (forbidden: `,`).
        let raw = "repo:foo-bar_baz";

        // 1. Legacy agentscope: CSV seal → decode back → unchanged.
        let scope = AgentScope {
            capabilities: vec![raw.to_string()],
            expires_at: Some(99),
        };
        let encoded = encode_agent_scope("Eagent", &scope);
        let (prefix, decoded) = decode_agent_scope(&encoded).unwrap();
        assert_eq!(prefix, "Eagent");
        assert_eq!(decoded.capabilities, vec![raw.to_string()]);

        // 2. agentscope CSV → ACDC `a.capability` JSON (the F.4 `,`-join encoding).
        let acdc_capability_json = decoded.capabilities.join(",");
        assert!(
            !acdc_capability_json.contains(','),
            "single cap stays comma-free; the join separator must not appear inside a cap"
        );

        // 3. ACDC `a.capability` (split back on `,`) → CanonicalCapability::parse, lossless.
        for cap in acdc_capability_json.split(',') {
            let canonical = CanonicalCapability::parse(cap).unwrap();
            assert_eq!(canonical.as_str(), raw);
        }

        // 4. The attestation `Capability` encoding round-trips through the same parse.
        let att_cap = Capability::parse(raw).unwrap();
        let canonical = CanonicalCapability::parse(&att_cap.to_string()).unwrap();
        assert_eq!(canonical.as_str(), raw);

        // The `,` separator is forbidden inside a single capability (CanonicalCapability rejects it).
        assert!(CanonicalCapability::parse("a,b").is_err());
    }

    #[test]
    fn agentscope_seal_vs_acdc_precedence_documented() {
        // The ACDC is the authoritative caps/role source; the agentscope: seal is
        // commit-time advisory. When both exist for one grant, the ACDC governs.
        assert_eq!(CapsSource::governing(true, true), Some(CapsSource::Acdc));
        assert_eq!(CapsSource::governing(false, true), Some(CapsSource::Acdc));
        assert_eq!(
            CapsSource::governing(true, false),
            Some(CapsSource::AgentScopeSeal)
        );
        assert_eq!(CapsSource::governing(false, false), None);
    }

    #[test]
    fn evaluate_compiled_allows_valid_attestation() {
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_compiled_denies_revoked() {
        let att = make_attestation("did:keri:ETestPrefix", Some(Utc::now()), None);
        let policy = default_policy();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::Revoked);
    }

    #[test]
    fn evaluate_compiled_denies_expired() {
        let past = Utc::now() - Duration::hours(1);
        let att = make_attestation("did:keri:ETestPrefix", None, Some(past));
        let policy = default_policy();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::Expired);
    }

    #[test]
    fn evaluate_compiled_allows_not_yet_expired() {
        let future = Utc::now() + Duration::hours(1);
        let att = make_attestation("did:keri:ETestPrefix", None, Some(future));
        let policy = default_policy();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_compiled_denies_issuer_mismatch() {
        let att = make_attestation("did:keri:EWrongPrefix", None, None);
        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_issuer("did:keri:ETestPrefix")
            .build();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::IssuerMismatch);
    }

    #[test]
    fn evaluate_compiled_denies_missing_capability() {
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_capability("sign_commit")
            .build();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::CapabilityMissing);
    }

    #[test]
    fn evaluate_compiled_allows_with_capability_from_credential() {
        // Capability authority now arrives only via a holder-verified credential
        // presentation: the same require-capability policy that an attestation can no
        // longer satisfy is allowed once the credential context supplies the cap.
        let presentation = valid_presentation(&["sign_commit"], None, None);
        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_capability("sign_commit")
            .build();
        let now = Utc::now();

        let ctx = context_from_credential(&presentation, now).unwrap();
        assert_eq!(evaluate_strict(&policy, &ctx).outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_compiled_is_deterministic() {
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();

        let decision1 = evaluate_compiled(&att, &policy, now).unwrap();
        let decision2 = evaluate_compiled(&att, &policy, now).unwrap();

        assert_eq!(decision1, decision2);
    }

    // =========================================================================
    // Tests for evaluate_with_witness
    // =========================================================================

    #[test]
    fn evaluate_with_witness_no_witnesses_delegates() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, &[]).unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_with_witness_noop_delegates() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();

        let noop = NoOpWitness;
        let witnesses: &[&dyn WitnessProvider] = &[&noop];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_with_witness_mismatch_denies() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let different_head =
            EventHash::from_hex("0000000000000000000000000000000000000002").unwrap();

        let witness = MockWitness {
            head: Some(different_head),
            quorum: 1,
        };
        let witnesses: &[&dyn WitnessProvider] = &[&witness];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::WitnessQuorumNotMet);
    }

    #[test]
    fn evaluate_with_witness_quorum_met_allows() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();

        let witness = MockWitness {
            head: Some(local_head),
            quorum: 1,
        };
        let witnesses: &[&dyn WitnessProvider] = &[&witness];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_with_witness_quorum_met_denies_when_policy_denies() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", Some(Utc::now()), None); // revoked
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();

        let witness = MockWitness {
            head: Some(local_head),
            quorum: 1,
        };
        let witnesses: &[&dyn WitnessProvider] = &[&witness];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::Revoked);
    }

    #[test]
    fn evaluate_with_witness_multiple_witnesses_quorum() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let different_head =
            EventHash::from_hex("0000000000000000000000000000000000000002").unwrap();

        let w1 = MockWitness {
            head: Some(local_head),
            quorum: 2,
        };
        let w2 = MockWitness {
            head: Some(local_head),
            quorum: 2,
        };
        let w3 = MockWitness {
            head: Some(different_head),
            quorum: 2,
        };
        let witnesses: &[&dyn WitnessProvider] = &[&w1, &w2, &w3];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_with_witness_no_opinions_delegates() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();

        let witness = MockWitness {
            head: None,
            quorum: 1,
        };
        let witnesses: &[&dyn WitnessProvider] = &[&witness];

        let decision =
            evaluate_with_witness(&identity, &att, &policy, now, local_head, witnesses).unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    // =========================================================================
    // Tests for receipt verification
    // =========================================================================

    fn make_test_receipt(
        event_said: &str,
        witness_did: &str,
        seq: u128,
    ) -> auths_core::witness::StoredReceipt {
        auths_core::witness::StoredReceipt {
            signed: auths_core::witness::SignedReceipt {
                receipt: auths_core::witness::Receipt {
                    v: auths_keri::VersionString::placeholder(),
                    t: auths_core::witness::ReceiptTag,
                    d: Said::new_unchecked(event_said.to_string()),
                    i: Prefix::new_unchecked("EController".to_string()),
                    s: auths_keri::KeriSequence::new(seq),
                },
                signature: vec![],
            },
            witness: Prefix::new_unchecked(witness_did.to_string()),
        }
    }

    #[test]
    fn verify_receipts_meets_threshold() {
        let receipts = EventReceipts::new(
            "ESAID123",
            vec![
                make_test_receipt("ESAID123", "did:key:w1", 0),
                make_test_receipt("ESAID123", "did:key:w2", 0),
            ],
        );

        let result = verify_receipts(&receipts, 2, None);
        assert_eq!(result, ReceiptVerificationResult::Valid);
    }

    #[test]
    fn verify_receipts_insufficient() {
        let receipts = EventReceipts::new(
            "ESAID123",
            vec![make_test_receipt("ESAID123", "did:key:w1", 0)],
        );

        let result = verify_receipts(&receipts, 2, None);
        assert!(matches!(
            result,
            ReceiptVerificationResult::InsufficientReceipts {
                required: 2,
                got: 1
            }
        ));
    }

    #[test]
    fn verify_receipts_duplicity() {
        let receipts = EventReceipts {
            event_said: Said::new_unchecked("ESAID_A".to_string()),
            receipts: vec![
                make_test_receipt("ESAID_A", "did:key:w1", 0),
                make_test_receipt("ESAID_B", "did:key:w2", 0), // Different SAID!
            ],
        };

        let result = verify_receipts(&receipts, 1, None);
        assert!(matches!(
            result,
            ReceiptVerificationResult::Duplicity { .. }
        ));
    }

    #[test]
    fn evaluate_with_receipts_valid() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let receipts = EventReceipts::new(
            "ESAID",
            vec![
                make_test_receipt("ESAID", "did:key:w1", 0),
                make_test_receipt("ESAID", "did:key:w2", 0),
            ],
        );

        let decision = evaluate_with_receipts(
            &identity,
            &att,
            &policy,
            now,
            local_head,
            &[],
            &receipts,
            2,
            None,
        )
        .unwrap();

        assert_eq!(decision.outcome, Outcome::Allow);
    }

    #[test]
    fn evaluate_with_receipts_insufficient_denies() {
        let identity = make_key_state("ETestPrefix");
        let att = make_attestation("did:keri:ETestPrefix", None, None);
        let policy = default_policy();
        let now = Utc::now();
        let local_head = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let receipts =
            EventReceipts::new("ESAID", vec![make_test_receipt("ESAID", "did:key:w1", 0)]);

        let decision = evaluate_with_receipts(
            &identity,
            &att,
            &policy,
            now,
            local_head,
            &[],
            &receipts,
            2, // Threshold 2, but only 1 receipt
            None,
        )
        .unwrap();

        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::WitnessQuorumNotMet);
    }
}
