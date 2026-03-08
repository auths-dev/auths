//! Authorization decision types.
//!
//! Decisions carry structured evidence, not just reason strings. Every decision
//! includes a machine-readable reason code for stable logging and alerting.

use serde::{Deserialize, Serialize};

/// Three-valued authorization decision.
///
/// Contains the outcome, a machine-readable reason code, a human-readable message,
/// and an optional policy hash for audit pinning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The authorization outcome.
    pub outcome: Outcome,
    /// Machine-readable reason code for logging and alerting.
    pub reason: ReasonCode,
    /// Human-readable explanation of the decision.
    pub message: String,
    /// Blake3 hash of the policy that produced this decision.
    /// Used for audit pinning.
    pub policy_hash: Option<[u8; 32]>,
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Outcome {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
    /// The decision could not be made due to missing information.
    /// In strict mode, this is treated as Deny.
    Indeterminate,
    /// The action requires human approval before proceeding.
    /// Propagated through `evaluate_strict` (NOT collapsed to Deny).
    RequiresApproval,
}

/// Machine-readable reason code for stable logging and alerting.
///
/// These codes are designed to be stable across versions for use in
/// monitoring dashboards, alerting rules, and audit queries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReasonCode {
    /// Unconditional allow/deny (True/False expressions).
    Unconditional,
    /// All checks in a policy passed.
    AllChecksPassed,
    /// Required capability is present.
    CapabilityPresent,
    /// Required capability is missing.
    CapabilityMissing,
    /// Issuer matches expected value.
    IssuerMatch,
    /// Issuer does not match expected value.
    IssuerMismatch,
    /// Attestation has been revoked.
    Revoked,
    /// Attestation has expired.
    Expired,
    /// Remaining TTL is below required threshold.
    InsufficientTtl,
    /// Attestation was issued too long ago.
    IssuedTooLongAgo,
    /// Role does not match expected value.
    RoleMismatch,
    /// Scope (repo, ref, path, env) does not match.
    ScopeMismatch,
    /// Delegation chain exceeds maximum depth.
    ChainTooDeep,
    /// Delegator does not match expected value.
    DelegationMismatch,
    /// Custom attribute does not match expected value.
    AttrMismatch,
    /// Required field is missing from context.
    MissingField,
    /// Expression recursion limit exceeded.
    RecursionExceeded,
    /// Short-circuit evaluation in And/Or.
    ShortCircuit,
    /// Result from And/Or/Not combinator.
    CombinatorResult,
    /// Workload claim does not match expected value.
    WorkloadMismatch,
    /// Witness quorum was not met.
    WitnessQuorumNotMet,
    /// Signer type matches expected value.
    SignerTypeMatch,
    /// Signer type does not match expected value.
    SignerTypeMismatch,
    /// Policy ApprovalGate determined human approval is needed.
    ApprovalRequired,
    /// Approval attestation was valid and matched.
    ApprovalGranted,
    /// Approval request TTL expired.
    ApprovalExpired,
    /// Approval JTI already used (replay attempt).
    ApprovalAlreadyUsed,
    /// Approval scope hash doesn't match the current request.
    ApprovalRequestMismatch,
}

impl Decision {
    /// Create an Allow decision with the given reason and message.
    pub fn allow(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Allow,
            reason,
            message: message.into(),
            policy_hash: None,
        }
    }

    /// Create a Deny decision with the given reason and message.
    pub fn deny(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Deny,
            reason,
            message: message.into(),
            policy_hash: None,
        }
    }

    /// Create an Indeterminate decision with the given reason and message.
    pub fn indeterminate(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Indeterminate,
            reason,
            message: message.into(),
            policy_hash: None,
        }
    }

    /// Create a RequiresApproval decision with the given reason and message.
    pub fn requires_approval(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::RequiresApproval,
            reason,
            message: message.into(),
            policy_hash: None,
        }
    }

    /// Attach a policy hash to this decision for audit pinning.
    pub fn with_policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Returns true if the outcome is Allow.
    pub fn is_allowed(&self) -> bool {
        self.outcome == Outcome::Allow
    }

    /// Returns true if the outcome is Deny.
    pub fn is_denied(&self) -> bool {
        self.outcome == Outcome::Deny
    }

    /// Returns true if the outcome is Indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.outcome == Outcome::Indeterminate
    }

    /// Returns true if the outcome is RequiresApproval.
    pub fn is_approval_required(&self) -> bool {
        self.outcome == Outcome::RequiresApproval
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Allow => write!(f, "ALLOW"),
            Outcome::Deny => write!(f, "DENY"),
            Outcome::Indeterminate => write!(f, "INDETERMINATE"),
            Outcome::RequiresApproval => write!(f, "REQUIRES_APPROVAL"),
        }
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.outcome, self.reason, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_decision() {
        let d = Decision::allow(ReasonCode::CapabilityPresent, "has 'sign_commit'");
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(!d.is_indeterminate());
        assert_eq!(d.outcome, Outcome::Allow);
        assert_eq!(d.reason, ReasonCode::CapabilityPresent);
        assert!(d.policy_hash.is_none());
    }

    #[test]
    fn deny_decision() {
        let d = Decision::deny(ReasonCode::Revoked, "attestation revoked");
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert!(!d.is_indeterminate());
        assert_eq!(d.outcome, Outcome::Deny);
    }

    #[test]
    fn indeterminate_decision() {
        let d = Decision::indeterminate(ReasonCode::MissingField, "no repo in context");
        assert!(!d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.is_indeterminate());
        assert_eq!(d.outcome, Outcome::Indeterminate);
    }

    #[test]
    fn with_policy_hash() {
        let hash = [0u8; 32];
        let d = Decision::allow(ReasonCode::AllChecksPassed, "ok").with_policy_hash(hash);
        assert_eq!(d.policy_hash, Some(hash));
    }

    #[test]
    fn display_outcome() {
        assert_eq!(Outcome::Allow.to_string(), "ALLOW");
        assert_eq!(Outcome::Deny.to_string(), "DENY");
        assert_eq!(Outcome::Indeterminate.to_string(), "INDETERMINATE");
    }

    #[test]
    fn display_decision() {
        let d = Decision::allow(ReasonCode::CapabilityPresent, "has cap");
        let s = d.to_string();
        assert!(s.contains("ALLOW"));
        assert!(s.contains("CapabilityPresent"));
        assert!(s.contains("has cap"));
    }

    #[test]
    fn serde_roundtrip() {
        let d = Decision::deny(ReasonCode::Expired, "expired at 2024-01-01");
        let json = serde_json::to_string(&d).unwrap();
        let parsed: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn serde_with_hash() {
        let hash = [1u8; 32];
        let d = Decision::allow(ReasonCode::AllChecksPassed, "ok").with_policy_hash(hash);
        let json = serde_json::to_string(&d).unwrap();
        let parsed: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
        assert_eq!(parsed.policy_hash, Some(hash));
    }
}
