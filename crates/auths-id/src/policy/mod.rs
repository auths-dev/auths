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
use auths_policy::{CanonicalCapability, DidParseError, evaluate_strict};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};

use crate::keri::KeyState;
use crate::keri::event::EventReceipts;
use crate::keri::types::Said;
#[cfg(feature = "git-storage")]
use crate::storage::receipts::{check_receipt_consistency, verify_receipt_signature};

// Re-export policy types for convenience
pub use auths_policy::{
    CompileError, CompiledPolicy, Decision, EvalContext, Expr, Outcome, PolicyBuilder,
    PolicyLimits, ReasonCode, compile, compile_from_json,
};

/// Convert an attestation to an evaluation context.
///
/// This is the bridge between the attestation data model and the
/// policy engine's typed context.
///
/// # Arguments
///
/// * `att` - The device attestation to convert
/// * `now` - The current time (injected for determinism)
///
/// # Returns
///
/// An `EvalContext` populated with the attestation's fields.
///
pub fn context_from_attestation(
    att: &Attestation,
    now: DateTime<Utc>,
) -> Result<EvalContext, DidParseError> {
    let mut ctx = EvalContext::try_from_strings(now, &att.issuer, &att.subject.to_string())?;

    ctx = ctx.revoked(att.is_revoked());

    // Parse capabilities, silently ignoring invalid ones
    let caps: Vec<CanonicalCapability> = att
        .capabilities
        .iter()
        .filter_map(|c| CanonicalCapability::parse(&c.to_string()).ok())
        .collect();
    ctx = ctx.capabilities(caps);

    if let Some(expires_at) = att.expires_at {
        ctx = ctx.expires_at(expires_at);
    }

    if let Some(ref role) = att.role {
        ctx = ctx.role(role.to_string());
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
    InvalidSignature { witness_did: DeviceDID },
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

    // 3. Verify receipt signatures if key resolver provided
    if let Some(resolver) = key_resolver {
        for receipt in &receipts.receipts {
            if let Some(public_key) = resolver.get_public_key(&receipt.i) {
                match verify_receipt_signature(receipt, &public_key) {
                    Ok(true) => continue,
                    Ok(false) => {
                        return ReceiptVerificationResult::InvalidSignature {
                            witness_did: DeviceDID::new_unchecked(&receipt.i),
                        };
                    }
                    Err(_) => {
                        return ReceiptVerificationResult::InvalidSignature {
                            witness_did: DeviceDID::new_unchecked(&receipt.i),
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
    use auths_core::storage::keychain::IdentityDID;
    use auths_core::witness::NoOpWitness;
    use auths_verifier::core::{Capability, Ed25519PublicKey, Ed25519Signature, ResourceId};
    use auths_verifier::keri::{Prefix, Said};
    use auths_verifier::types::DeviceDID;
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
        KeyState {
            prefix: Prefix::new_unchecked(prefix.to_string()),
            sequence: 0,
            current_keys: vec!["DTestKey".to_string()],
            next_commitment: vec![],
            last_event_said: Said::new_unchecked("ETestSaid".to_string()),
            is_abandoned: false,
            threshold: 1,
            next_threshold: 1,
        }
    }

    fn make_attestation(
        issuer: &str,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        Attestation {
            version: 1,
            rid: ResourceId::new("test"),
            issuer: IdentityDID::new_unchecked(issuer),
            subject: DeviceDID::new_unchecked("did:key:zSubject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at,
            expires_at,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
            environment_claim: None,
        }
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
        assert_eq!(ctx.subject.as_str(), "did:key:subject");
        assert!(!ctx.revoked);
    }

    #[test]
    fn context_from_attestation_with_capabilities() {
        let mut att = make_attestation("did:keri:ETest", None, None);
        att.capabilities = vec![Capability::sign_commit()];
        let now = Utc::now();
        let ctx = context_from_attestation(&att, now).unwrap();

        assert_eq!(ctx.capabilities.len(), 1);
        assert_eq!(ctx.capabilities[0].as_str(), "sign_commit");
    }

    #[test]
    fn context_from_attestation_with_role() {
        let mut att = make_attestation("did:keri:ETest", None, None);
        att.role = Some(auths_verifier::core::Role::Member);
        let now = Utc::now();
        let ctx = context_from_attestation(&att, now).unwrap();

        assert_eq!(ctx.role.as_deref(), Some("member"));
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
    fn evaluate_compiled_allows_with_capability() {
        let mut att = make_attestation("did:keri:ETestPrefix", None, None);
        att.capabilities = vec![Capability::sign_commit()];
        let policy = PolicyBuilder::new()
            .not_revoked()
            .require_capability("sign_commit")
            .build();
        let now = Utc::now();

        let decision = evaluate_compiled(&att, &policy, now).unwrap();
        assert_eq!(decision.outcome, Outcome::Allow);
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
        seq: u64,
    ) -> auths_core::witness::Receipt {
        auths_core::witness::Receipt {
            v: auths_core::witness::KERI_VERSION.into(),
            t: auths_core::witness::RECEIPT_TYPE.into(),
            d: Said::new_unchecked(format!(
                "E{}",
                &event_said.chars().skip(1).take(10).collect::<String>()
            )),
            i: witness_did.to_string(),
            s: seq,
            a: Said::new_unchecked(event_said.to_string()),
            sig: vec![0; 64],
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
