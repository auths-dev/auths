//! Organization authorization policy.
//!
//! This module implements org membership authorization rules that determine
//! whether a member can perform actions on behalf of an organization.
//!
//! # Org Membership vs Device Authorization
//!
//! - **Device authorization** ([`super::device`]): Can this device act for an identity?
//! - **Org authorization** (this module): Can this member act for an organization?
//!
//! Both use attestations but with different issuers:
//! - Device attestations: issued by `did:keri:{identity_prefix}`
//! - Org membership attestations: issued by `did:keri:{org_prefix}`
//!
//! # Integration with MemberFilter
//!
//! This policy evaluates individual membership attestations. For bulk queries
//! with filtering (role, capabilities), use the registry's `list_org_members()`
//! with `MemberFilter`, then apply this policy to each result.

use auths_verifier::core::{Attestation, Capability};
use auths_verifier::keri::Prefix;
use chrono::{DateTime, Utc};

use super::Decision;
use super::device::Action;

/// Authorize an org member to perform an action.
///
/// # Sans-IO Design
///
/// All inputs are passed explicitly:
/// - No storage access (membership attestation provided by caller)
/// - No system clock (time injected via `now`)
/// - Pure function: same inputs always produce same output
///
/// # Rules (evaluated in order)
///
/// 1. **Not revoked**: `!att.is_revoked()`
/// 2. **Not expired**: `att.expires_at > now` OR `att.expires_at.is_none()`
/// 3. **Issuer is org**: `att.issuer == expected_org_issuer`
/// 4. **Capability allows action**: `action.to_capability() in att.capabilities`
///
/// # Arguments
///
/// * `member_attestation` - The member's org membership attestation
/// * `expected_org_issuer` - The expected org issuer DID (e.g., `did:keri:EOrg...`)
/// * `action` - The action the member wants to perform
/// * `now` - Current time for expiry checks
///
/// # Returns
///
/// `Decision::Allow` if all rules pass, `Decision::Deny` otherwise.
///
/// # Examples
///
/// ```rust
/// use auths_core::policy::{Decision, device::Action, org::authorize_org_action};
/// use auths_verifier::core::{Attestation, Capability, Ed25519PublicKey, Ed25519Signature, Role};
/// use auths_verifier::types::DeviceDID;
/// use chrono::Utc;
///
/// let membership = Attestation {
///     version: 1,
///     rid: "member".into(),
///     issuer: "did:keri:EOrg123".into(),
///     subject: DeviceDID::new("did:key:z6MkAlice"),
///     device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
///     identity_signature: Ed25519Signature::empty(),
///     device_signature: Ed25519Signature::empty(),
///     revoked_at: None,
///     expires_at: None,
///     timestamp: None,
///     note: None,
///     payload: None,
///     role: Some(Role::Admin),
///     capabilities: vec![Capability::manage_members()],
///     delegated_by: None,
///     signer_type: None,
/// };
///
/// let decision = authorize_org_action(
///     &membership,
///     "did:keri:EOrg123",
///     &Action::ManageMembers,
///     Utc::now(),
/// );
///
/// assert!(decision.is_allowed());
/// ```
pub fn authorize_org_action(
    member_attestation: &Attestation,
    expected_org_issuer: &str,
    action: &Action,
    now: DateTime<Utc>,
) -> Decision {
    // Rule 1: Not revoked
    if member_attestation.is_revoked() {
        return Decision::deny("membership is revoked");
    }

    // Rule 2: Not expired (expires_at <= now means expired)
    if let Some(expires_at) = member_attestation.expires_at
        && expires_at <= now
    {
        return Decision::deny(format!(
            "membership expired at {}",
            expires_at.format("%Y-%m-%dT%H:%M:%SZ")
        ));
    }

    // Rule 3: Issuer is the org
    if member_attestation.issuer != expected_org_issuer {
        return Decision::deny(format!(
            "issuer mismatch: expected org '{}', got '{}'",
            expected_org_issuer, member_attestation.issuer
        ));
    }

    // Rule 4: Capability allows action
    let required_capability = match action.to_capability() {
        Ok(cap) => cap,
        Err(msg) => return Decision::deny(msg),
    };

    // Empty capabilities means no permissions
    if member_attestation.capabilities.is_empty() {
        return Decision::deny("membership has no capabilities");
    }

    if !member_attestation
        .capabilities
        .contains(&required_capability)
    {
        return Decision::deny(format!(
            "capability '{}' not granted by membership",
            capability_name(&required_capability)
        ));
    }

    // All rules passed
    Decision::allow(format!(
        "member authorized for '{}' in org",
        capability_name(&required_capability)
    ))
}

/// Derive the expected issuer DID for an org prefix.
///
/// Org membership attestations must be issued by the org identity itself.
///
/// # Examples
///
/// ```rust
/// use auths_core::policy::org::expected_org_issuer;
/// use auths_verifier::keri::Prefix;
///
/// let prefix = Prefix::new_unchecked("EOrg12345".into());
/// assert_eq!(expected_org_issuer(&prefix), "did:keri:EOrg12345");
/// ```
pub fn expected_org_issuer(org_prefix: &Prefix) -> String {
    format!("did:keri:{}", org_prefix.as_str())
}

/// Get a human-readable name for a capability.
fn capability_name(cap: &Capability) -> &str {
    cap.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::core::{Ed25519PublicKey, Ed25519Signature, ResourceId, Role};
    use auths_verifier::types::DeviceDID;
    use chrono::Duration;

    fn make_membership(
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        issuer: &str,
        capabilities: Vec<Capability>,
        role: Option<Role>,
    ) -> Attestation {
        Attestation {
            version: 1,
            rid: ResourceId::new("membership"),
            issuer: issuer.into(),
            subject: DeviceDID::new("did:key:z6MkMember"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at,
            expires_at,
            timestamp: None,
            note: None,
            payload: None,
            role,
            capabilities,
            delegated_by: None,
            signer_type: None,
        }
    }

    const ORG_ISSUER: &str = "did:keri:EOrg123";

    #[test]
    fn valid_membership_allows() {
        let att = make_membership(
            None,
            None,
            ORG_ISSUER,
            vec![Capability::manage_members()],
            Some(Role::Admin),
        );
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_allowed());
        assert!(decision.reason().contains("authorized"));
    }

    #[test]
    fn no_membership_attestation_handled_by_caller() {
        // This is handled by the caller - if no attestation exists,
        // the caller should return Indeterminate or Deny before calling this.
        // This function requires a valid attestation to be passed in.
        // We test that an empty capabilities list is denied.
        let att = make_membership(None, None, ORG_ISSUER, vec![], Some(Role::Readonly));
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::SignCommit, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("no capabilities"));
    }

    #[test]
    fn revoked_membership_denies() {
        let att = make_membership(
            Some(Utc::now()), // revoked
            None,
            ORG_ISSUER,
            vec![Capability::manage_members()],
            Some(Role::Admin),
        );
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("revoked"));
    }

    #[test]
    fn expired_membership_denies() {
        let past = Utc::now() - Duration::hours(1);
        let att = make_membership(
            None,
            Some(past), // expired
            ORG_ISSUER,
            vec![Capability::manage_members()],
            Some(Role::Admin),
        );
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("expired"));
    }

    #[test]
    fn expired_at_boundary_denies() {
        let now = Utc::now();
        let att = make_membership(
            None,
            Some(now), // exactly at boundary = expired
            ORG_ISSUER,
            vec![Capability::manage_members()],
            Some(Role::Admin),
        );

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("expired"));
    }

    #[test]
    fn issuer_not_org_denies() {
        let att = make_membership(
            None,
            None,
            "did:keri:EDifferentOrg", // wrong org
            vec![Capability::manage_members()],
            Some(Role::Admin),
        );
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("issuer mismatch"));
        assert!(decision.reason().contains("EOrg123"));
        assert!(decision.reason().contains("EDifferentOrg"));
    }

    #[test]
    fn missing_capability_denies() {
        let att = make_membership(
            None,
            None,
            ORG_ISSUER,
            vec![Capability::sign_commit()], // has SignCommit, not ManageMembers
            Some(Role::Member),
        );
        let now = Utc::now();

        let decision = authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now);

        assert!(decision.is_denied());
        assert!(decision.reason().contains("manage_members"));
        assert!(decision.reason().contains("not granted"));
    }

    #[test]
    fn expected_org_issuer_formats_correctly() {
        assert_eq!(
            expected_org_issuer(&Prefix::new_unchecked("EOrg12345".into())),
            "did:keri:EOrg12345"
        );
        assert_eq!(
            expected_org_issuer(&Prefix::new_unchecked("EAcmeInc".into())),
            "did:keri:EAcmeInc"
        );
    }

    #[test]
    fn multiple_capabilities_allows_matching() {
        let att = make_membership(
            None,
            None,
            ORG_ISSUER,
            vec![
                Capability::sign_commit(),
                Capability::sign_release(),
                Capability::manage_members(),
            ],
            Some(Role::Admin),
        );
        let now = Utc::now();

        // All granted capabilities should work
        assert!(authorize_org_action(&att, ORG_ISSUER, &Action::SignCommit, now).is_allowed());
        assert!(authorize_org_action(&att, ORG_ISSUER, &Action::SignRelease, now).is_allowed());
        assert!(authorize_org_action(&att, ORG_ISSUER, &Action::ManageMembers, now).is_allowed());

        // Not granted should deny
        assert!(authorize_org_action(&att, ORG_ISSUER, &Action::RotateKeys, now).is_denied());
    }

    #[test]
    fn role_is_informational_only() {
        // Role doesn't affect authorization - only capabilities matter
        let att_no_role = make_membership(
            None,
            None,
            ORG_ISSUER,
            vec![Capability::sign_commit()],
            None, // no role
        );
        let att_with_role = make_membership(
            None,
            None,
            ORG_ISSUER,
            vec![Capability::sign_commit()],
            Some(Role::Member),
        );
        let now = Utc::now();

        // Both should allow since capability is present
        assert!(
            authorize_org_action(&att_no_role, ORG_ISSUER, &Action::SignCommit, now).is_allowed()
        );
        assert!(
            authorize_org_action(&att_with_role, ORG_ISSUER, &Action::SignCommit, now).is_allowed()
        );
    }
}
