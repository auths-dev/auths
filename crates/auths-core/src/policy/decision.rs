//! Authorization decision types.
//!
//! # Decision vs TrustDecision
//!
//! This module provides [`Decision`] for **authorization** decisions:
//! "Can this device/identity perform this action?"
//!
//! This is distinct from [`crate::trust::TrustDecision`] which handles
//! **identity verification**: "Is this key who they claim to be?"
//!
//! | Concern | Type | Question |
//! |---------|------|----------|
//! | Identity | `TrustDecision` | Is this key trusted? (TOFU, pins, rotation) |
//! | Authorization | `Decision` | Can this device do this action? (capabilities, expiry) |
//!
//! # Usage
//!
//! ```rust
//! use auths_core::policy::Decision;
//!
//! // Example: device has required capability
//! let decision = Decision::Allow {
//!     reason: "Device has sign_commit capability".into(),
//! };
//!
//! // Example: attestation expired
//! let decision = Decision::Deny {
//!     reason: "Attestation expired at 2024-01-01T00:00:00Z".into(),
//! };
//!
//! // Example: cannot determine (missing data)
//! let decision = Decision::Indeterminate {
//!     reason: "No attestation found for device".into(),
//! };
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

/// Result of an authorization policy evaluation.
///
/// Three-valued logic allows distinguishing between:
/// - Explicit allow (requirements met)
/// - Explicit deny (requirements violated)
/// - Cannot determine (missing information)
///
/// This is important for fail-safe behavior: `Indeterminate` should typically
/// be treated as `Deny` unless the policy explicitly allows pass-through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Authorization granted.
    ///
    /// All requirements were checked and met. The action may proceed.
    Allow {
        /// Human-readable explanation of why authorization was granted.
        reason: String,
    },

    /// Authorization denied.
    ///
    /// A specific requirement was violated. The action must not proceed.
    Deny {
        /// Human-readable explanation of why authorization was denied.
        reason: String,
    },

    /// Cannot determine authorization.
    ///
    /// Required information was missing or invalid. This is NOT the same
    /// as `Deny` - it indicates the policy engine couldn't make a decision.
    ///
    /// Callers should typically treat this as `Deny` for fail-safe behavior.
    Indeterminate {
        /// Human-readable explanation of why a decision couldn't be made.
        reason: String,
    },
}

impl Decision {
    /// Create an Allow decision with the given reason.
    pub fn allow(reason: impl Into<String>) -> Self {
        Self::Allow {
            reason: reason.into(),
        }
    }

    /// Create a Deny decision with the given reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    /// Create an Indeterminate decision with the given reason.
    pub fn indeterminate(reason: impl Into<String>) -> Self {
        Self::Indeterminate {
            reason: reason.into(),
        }
    }

    /// Returns true if this is an Allow decision.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns true if this is a Deny decision.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns true if this is an Indeterminate decision.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }

    /// Returns the reason string for this decision.
    pub fn reason(&self) -> &str {
        match self {
            Self::Allow { reason } => reason,
            Self::Deny { reason } => reason,
            Self::Indeterminate { reason } => reason,
        }
    }

    /// Treat Indeterminate as Deny for fail-safe behavior.
    ///
    /// This is the recommended way to convert a Decision to a boolean
    /// in security-sensitive contexts.
    pub fn is_allowed_fail_safe(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow { reason } => write!(f, "ALLOW: {}", reason),
            Self::Deny { reason } => write!(f, "DENY: {}", reason),
            Self::Indeterminate { reason } => write!(f, "INDETERMINATE: {}", reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_allow_is_allowed() {
        let d = Decision::allow("test reason");
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(!d.is_indeterminate());
        assert_eq!(d.reason(), "test reason");
    }

    #[test]
    fn decision_deny_is_denied() {
        let d = Decision::deny("expired");
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert!(!d.is_indeterminate());
        assert_eq!(d.reason(), "expired");
    }

    #[test]
    fn decision_indeterminate() {
        let d = Decision::indeterminate("missing attestation");
        assert!(!d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.is_indeterminate());
        assert_eq!(d.reason(), "missing attestation");
    }

    #[test]
    fn decision_fail_safe() {
        assert!(Decision::allow("ok").is_allowed_fail_safe());
        assert!(!Decision::deny("no").is_allowed_fail_safe());
        // Indeterminate treated as deny for fail-safe
        assert!(!Decision::indeterminate("unknown").is_allowed_fail_safe());
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::allow("granted").to_string(), "ALLOW: granted");
        assert_eq!(Decision::deny("revoked").to_string(), "DENY: revoked");
        assert_eq!(
            Decision::indeterminate("no data").to_string(),
            "INDETERMINATE: no data"
        );
    }

    #[test]
    fn decision_serialization_roundtrip() {
        let decisions = vec![
            Decision::allow("test allow"),
            Decision::deny("test deny"),
            Decision::indeterminate("test indeterminate"),
        ];

        for original in decisions {
            let json = serde_json::to_string(&original).unwrap();
            let parsed: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(original, parsed);
        }
    }

    #[test]
    fn decision_debug() {
        let d = Decision::allow("test");
        let debug_str = format!("{:?}", d);
        assert!(debug_str.contains("Allow"));
        assert!(debug_str.contains("test"));
    }
}
