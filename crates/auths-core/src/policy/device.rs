//! Device authorization policy.
//!
//! This module implements the device authorization rules that determine
//! whether a device attestation grants permission for a specific action.

use auths_verifier::core::{Attestation, Capability};
use chrono::{DateTime, Utc};

use super::Decision;

/// An action that requires authorization.
///
/// Actions map to capabilities - a device can only perform an action
/// if its attestation includes the corresponding capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Sign a git commit
    SignCommit,
    /// Sign a release
    SignRelease,
    /// Manage organization members
    ManageMembers,
    /// Rotate identity keys
    RotateKeys,
    /// Custom action (must match a custom capability)
    Custom(String),
}

impl Action {
    /// Convert action to the corresponding capability.
    ///
    /// Returns `Err` if a custom action string is invalid (e.g., empty, too long,
    /// contains invalid characters, or uses a reserved namespace).
    pub fn to_capability(&self) -> Result<Capability, String> {
        match self {
            Action::SignCommit => Ok(Capability::sign_commit()),
            Action::SignRelease => Ok(Capability::sign_release()),
            Action::ManageMembers => Ok(Capability::manage_members()),
            Action::RotateKeys => Ok(Capability::rotate_keys()),
            Action::Custom(s) => {
                Capability::parse(s).map_err(|e| format!("invalid custom action '{}': {}", s, e))
            }
        }
    }
}

/// Authorize a device to perform an action.
///
/// # Sans-IO Design
///
/// All inputs are passed explicitly:
/// - No storage access (attestation provided by caller)
/// - No system clock (time injected via `now`)
/// - Pure function: same inputs always produce same output
///
/// # Rules (evaluated in order)
///
/// 1. **Not revoked**: `!att.is_revoked()`
/// 2. **Not expired**: `att.expires_at > now` OR `att.expires_at.is_none()`
/// 3. **Issuer matches**: `att.issuer == expected_issuer`
/// 4. **Capability allows action**: `action.to_capability() in att.capabilities`
///
/// # Arguments
///
/// * `attestation` - The device's attestation
/// * `expected_issuer` - The expected issuer DID (e.g., `did:keri:E...`)
/// * `action` - The action the device wants to perform
/// * `now` - Current time for expiry checks
///
/// # Returns
///
/// `Decision::Allow` if all rules pass, `Decision::Deny` otherwise.
///
/// # Examples
///
/// ```rust
/// use auths_core::policy::{Decision, device::{Action, authorize_device}};
/// use auths_verifier::core::{Attestation, Capability};
/// use auths_verifier::types::DeviceDID;
/// use chrono::Utc;
///
/// let attestation = Attestation {
///     version: 1,
///     rid: "test".into(),
///     issuer: "did:keri:ETest".into(),
///     subject: DeviceDID::new("did:key:z6Mk..."),
///     device_public_key: vec![0; 32],
///     identity_signature: vec![0; 64],
///     device_signature: vec![0; 64],
///     revoked_at: None,
///     expires_at: None,
///     timestamp: None,
///     note: None,
///     payload: None,
///     role: None,
///     capabilities: vec![Capability::sign_commit()],
///     delegated_by: None,
///     signer_type: None,
/// };
///
/// let decision = authorize_device(
///     &attestation,
///     "did:keri:ETest",
///     &Action::SignCommit,
///     Utc::now(),
/// );
///
/// assert!(decision.is_allowed());
/// ```
pub fn authorize_device(
    attestation: &Attestation,
    expected_issuer: &str,
    action: &Action,
    now: DateTime<Utc>,
) -> Decision {
    // Rule 1: Not revoked
    if attestation.is_revoked() {
        return Decision::deny("attestation is revoked");
    }

    // Rule 2: Not expired (expires_at <= now means expired)
    if let Some(expires_at) = attestation.expires_at {
        if expires_at <= now {
            return Decision::deny(format!(
                "attestation expired at {}",
                expires_at.format("%Y-%m-%dT%H:%M:%SZ")
            ));
        }
    }

    // Rule 3: Issuer matches expected
    if attestation.issuer != expected_issuer {
        return Decision::deny(format!(
            "issuer mismatch: expected '{}', got '{}'",
            expected_issuer, attestation.issuer
        ));
    }

    // Rule 4: Capability allows action
    let required_capability = match action.to_capability() {
        Ok(cap) => cap,
        Err(msg) => return Decision::deny(msg),
    };

    // Empty capabilities means no permissions
    if attestation.capabilities.is_empty() {
        return Decision::deny("attestation has no capabilities");
    }

    if !attestation.capabilities.contains(&required_capability) {
        return Decision::deny(format!(
            "capability '{}' not granted",
            capability_name(&required_capability)
        ));
    }

    // All rules passed
    Decision::allow(format!(
        "device authorized for '{}'",
        capability_name(&required_capability)
    ))
}

/// Get a human-readable name for a capability.
fn capability_name(cap: &Capability) -> &str {
    cap.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::core::Ed25519PublicKey;
    use auths_verifier::types::DeviceDID;
    use chrono::Duration;

    fn make_attestation(
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        issuer: &str,
        capabilities: Vec<Capability>,
    ) -> Attestation {
        Attestation {
            version: 1,
            rid: "test-rid".into(),
            issuer: issuer.into(),
            subject: DeviceDID::new("did:key:z6MkTest"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: vec![0; 64],
            device_signature: vec![0; 64],
            revoked_at,
            expires_at,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities,
            delegated_by: None,
            signer_type: None,
        }
    }

    #[test]
    fn valid_attestation_allows() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_allowed());
        assert!(decision.reason().contains("authorized"));
    }

    #[test]
    fn revoked_attestation_denies() {
        let att = make_attestation(
            Some(Utc::now()), // revoked
            None,
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("revoked"));
    }

    #[test]
    fn expired_attestation_denies() {
        let past = Utc::now() - Duration::hours(1);
        let att = make_attestation(
            None,
            Some(past), // expired
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("expired"));
    }

    #[test]
    fn expired_at_boundary_denies() {
        let now = Utc::now();
        let att = make_attestation(
            None,
            Some(now), // exactly at boundary = expired (uses <=)
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("expired"));
    }

    #[test]
    fn not_yet_expired_allows() {
        let future = Utc::now() + Duration::hours(1);
        let att = make_attestation(
            None,
            Some(future), // not yet expired
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_allowed());
    }

    #[test]
    fn issuer_mismatch_denies() {
        let att = make_attestation(
            None,
            None,
            "did:keri:EWrongIssuer", // wrong issuer
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:EExpected", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("issuer mismatch"));
        assert!(decision.reason().contains("EExpected"));
        assert!(decision.reason().contains("EWrongIssuer"));
    }

    #[test]
    fn missing_capability_denies() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![Capability::sign_release()], // has SignRelease, not SignCommit
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("sign_commit"));
        assert!(decision.reason().contains("not granted"));
    }

    #[test]
    fn empty_capabilities_denies() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![], // no capabilities
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("no capabilities"));
    }

    #[test]
    fn multiple_capabilities_allows_matching() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![
                Capability::sign_commit(),
                Capability::sign_release(),
                Capability::manage_members(),
            ],
        );
        let now = Utc::now();

        // Should allow SignRelease since it's in the list
        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignRelease, now);
        assert!(decision.is_allowed());

        // Should allow ManageMembers since it's in the list
        let decision = authorize_device(&att, "did:keri:ETest", &Action::ManageMembers, now);
        assert!(decision.is_allowed());

        // Should deny RotateKeys since it's not in the list
        let decision = authorize_device(&att, "did:keri:ETest", &Action::RotateKeys, now);
        assert!(decision.is_denied());
    }

    #[test]
    fn custom_capability_works() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![Capability::parse("acme:deploy").unwrap()],
        );
        let now = Utc::now();

        // Matching custom capability allows
        let decision = authorize_device(
            &att,
            "did:keri:ETest",
            &Action::Custom("acme:deploy".into()),
            now,
        );
        assert!(decision.is_allowed());

        // Non-matching custom capability denies
        let decision = authorize_device(
            &att,
            "did:keri:ETest",
            &Action::Custom("acme:other".into()),
            now,
        );
        assert!(decision.is_denied());
    }

    #[test]
    fn invalid_custom_action_denies() {
        let att = make_attestation(
            None,
            None,
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        // Invalid characters in custom action should deny
        let decision = authorize_device(
            &att,
            "did:keri:ETest",
            &Action::Custom("invalid action!!!".into()),
            now,
        );
        assert!(decision.is_denied());
        assert!(decision.reason().contains("invalid custom action"));
    }

    #[test]
    fn rule_evaluation_order_revoked_first() {
        // If both revoked and expired, should report revoked (earlier in order)
        let past = Utc::now() - Duration::hours(1);
        let att = make_attestation(
            Some(Utc::now()), // revoked
            Some(past),       // also expired
            "did:keri:ETest",
            vec![Capability::sign_commit()],
        );
        let now = Utc::now();

        let decision = authorize_device(&att, "did:keri:ETest", &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("revoked")); // revoked checked first
    }
}
