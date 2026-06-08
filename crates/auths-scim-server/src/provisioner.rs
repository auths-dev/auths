//! Identity-provisioning port for the SCIM Joiner/Leaver.
//!
//! The server's HTTP behaviour (idempotency, filtering, error mapping) depends on
//! this port — not on the SDK directly — so it is unit-testable with a double,
//! while production wires [`SdkProvisioner`] to the real `add_member` lifecycle.
//! There is no fake DID and no authoritative database: a provisioned member is a
//! real delegated KERI identity anchored in the org's KEL.

use std::ops::ControlFlow;

use auths_crypto::CurveType;
use auths_scim::mapping::ProvisionAgentRequest;
use auths_sdk::context::AuthsContext;
use auths_sdk::keychain::KeyAlias;
use auths_sdk::ports::RegistryBackend;
use auths_sdk::workflows::org::{Role, add_member, revoke_member};
use auths_verifier::{IdentityDID, Prefix};

/// A member provisioned into an org's KEL — the real delegated identity.
#[derive(Debug, Clone)]
pub struct ProvisionedMember {
    /// The member's KEL prefix (used as the SCIM resource id).
    pub member_prefix: String,
    /// The member's delegated `did:keri:` identity (typed newtype).
    pub identity_did: IdentityDID,
}

/// The result of a hard-revoke (the cryptographic off-boarding from E0).
///
/// Distinguishes a fresh revocation (a `SignedOffboardingRecord` was anchored)
/// from an idempotent repeat on an already-revoked member, so the SCIM layer can
/// report honestly without anchoring a duplicate record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The member was revoked now; durable off-boarding evidence was produced.
    Revoked,
    /// The member was already revoked; a no-op (no duplicate record).
    AlreadyRevoked,
}

/// A typed provisioning failure.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The tenant's org KEL is not provisioned on this host.
    #[error("org not provisioned: {0}")]
    OrgNotProvisioned(String),
    /// The identity-lifecycle backend failed.
    #[error("provisioning backend error: {0}")]
    Backend(String),
}

/// Provisions real delegated members into an org's KEL.
pub trait Provisioner: Send + Sync {
    /// Whether the org KEL for `org_prefix` exists on this host.
    fn org_exists(&self, org_prefix: &str) -> bool;

    /// Provision a new delegated member under `org_prefix`, signed by the org key
    /// stored under `org_key_alias`.
    ///
    /// Args:
    /// * `org_prefix`: The delegating org's KEL prefix.
    /// * `org_key_alias`: Keychain alias of the org's signing key.
    /// * `request`: The provisioning request mapped from the SCIM user.
    ///
    /// Usage:
    /// ```ignore
    /// let member = provisioner.provision("EOrg", "org-acme", &req)?;
    /// ```
    fn provision(
        &self,
        org_prefix: &str,
        org_key_alias: &str,
        request: &ProvisionAgentRequest,
    ) -> Result<ProvisionedMember, ProvisionError>;

    /// Hard-revoke a delegated member — the irreversible cryptographic off-boarding.
    ///
    /// Anchors a revocation in the org KEL and produces a signed off-boarding
    /// record. Idempotent: a member already revoked returns
    /// [`RevokeOutcome::AlreadyRevoked`] without anchoring a duplicate. This is a
    /// distinct, explicit step from a SCIM `active:false` soft-disable —
    /// deprovision is not revocation.
    ///
    /// Args:
    /// * `org_prefix`: The delegating org's KEL prefix.
    /// * `org_key_alias`: Keychain alias of the org's signing key.
    /// * `member_did`: The member's `did:keri:` to revoke.
    ///
    /// Usage:
    /// ```ignore
    /// let outcome = provisioner.revoke("EOrg", "org-acme", "did:keri:EMember")?;
    /// ```
    fn revoke(
        &self,
        org_prefix: &str,
        org_key_alias: &str,
        member_did: &str,
    ) -> Result<RevokeOutcome, ProvisionError>;
}

/// The production [`Provisioner`]: wires SCIM provisioning to `add_member`.
///
/// The host mints the member key (the IdP path — Okta/Entra do not carry KERI
/// keys), the org anchors the delegation in its KEL, and the member's `did:keri:`
/// derives from its `dip` SAID. No fake DID is ever produced.
pub struct SdkProvisioner {
    ctx: AuthsContext,
    member_curve: CurveType,
}

impl SdkProvisioner {
    /// Build a provisioner over an [`AuthsContext`]. Members are minted on
    /// Ed25519 by default (matching `auths org add-member`).
    ///
    /// Args:
    /// * `ctx`: The Auths context (registry + keychain + passphrase) to provision through.
    ///
    /// Usage:
    /// ```ignore
    /// let provisioner = Arc::new(SdkProvisioner::new(ctx));
    /// ```
    pub fn new(ctx: AuthsContext) -> Self {
        Self {
            ctx,
            member_curve: CurveType::Ed25519,
        }
    }

    /// Override the curve newly-minted member keys use.
    pub fn with_member_curve(mut self, curve: CurveType) -> Self {
        self.member_curve = curve;
        self
    }
}

/// Derive a stable, filesystem-safe keychain alias for a provisioned member.
fn member_alias(org_prefix: &str, label: &str) -> String {
    let safe: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("scim-{org_prefix}-{safe}")
}

impl Provisioner for SdkProvisioner {
    fn org_exists(&self, org_prefix: &str) -> bool {
        let prefix = Prefix::new_unchecked(org_prefix.to_string());
        let mut found = false;
        let _ = self.ctx.registry.visit_events(&prefix, 0, &mut |_| {
            found = true;
            ControlFlow::Break(())
        });
        found
    }

    fn provision(
        &self,
        org_prefix: &str,
        org_key_alias: &str,
        request: &ProvisionAgentRequest,
    ) -> Result<ProvisionedMember, ProvisionError> {
        if !self.org_exists(org_prefix) {
            return Err(ProvisionError::OrgNotProvisioned(org_prefix.to_string()));
        }
        let prefix = Prefix::new_unchecked(org_prefix.to_string());
        let org_alias = KeyAlias::new_unchecked(org_key_alias.to_string());
        let label = request.external_id.as_deref().unwrap_or(&request.user_name);
        let alias = KeyAlias::new_unchecked(member_alias(org_prefix, label));
        let result = add_member(
            &self.ctx,
            &prefix,
            &org_alias,
            &alias,
            self.member_curve,
            Role::Member,
            &request.capabilities,
            None,
        )
        .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        let identity_did = IdentityDID::parse(&result.member_did)
            .map_err(|e| ProvisionError::Backend(format!("invalid member DID: {e}")))?;
        Ok(ProvisionedMember {
            member_prefix: result.member_prefix,
            identity_did,
        })
    }

    fn revoke(
        &self,
        org_prefix: &str,
        org_key_alias: &str,
        member_did: &str,
    ) -> Result<RevokeOutcome, ProvisionError> {
        if !self.org_exists(org_prefix) {
            return Err(ProvisionError::OrgNotProvisioned(org_prefix.to_string()));
        }
        let prefix = Prefix::new_unchecked(org_prefix.to_string());
        let org_alias = KeyAlias::new_unchecked(org_key_alias.to_string());
        let record = revoke_member(
            &self.ctx,
            &prefix,
            &org_alias,
            member_did,
            Some("SCIM hard-revoke".to_string()),
        )
        .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        Ok(match record {
            Some(_) => RevokeOutcome::Revoked,
            None => RevokeOutcome::AlreadyRevoked,
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::{
        ProvisionAgentRequest, ProvisionError, ProvisionedMember, Provisioner, RevokeOutcome,
    };
    use auths_verifier::IdentityDID;

    /// A test double that mints deterministic members and counts provision/revoke
    /// calls, so the server's idempotency and the deprovision-vs-revocation
    /// boundary can be asserted without a real keychain/registry.
    pub(crate) struct FakeProvisioner {
        known_orgs: Vec<String>,
        provision_calls: Mutex<usize>,
        revoke_calls: Mutex<usize>,
        revoked: Mutex<HashSet<String>>,
        counter: Mutex<u64>,
    }

    impl FakeProvisioner {
        pub(crate) fn new(known_orgs: &[&str]) -> Self {
            Self {
                known_orgs: known_orgs.iter().map(|s| s.to_string()).collect(),
                provision_calls: Mutex::new(0),
                revoke_calls: Mutex::new(0),
                revoked: Mutex::new(HashSet::new()),
                counter: Mutex::new(0),
            }
        }

        /// How many times a real provisioning (delegation) actually happened.
        pub(crate) fn provision_calls(&self) -> usize {
            *self.provision_calls.lock().expect("lock")
        }

        /// How many times a hard-revoke was invoked (soft-disable must NOT bump this).
        pub(crate) fn revoke_calls(&self) -> usize {
            *self.revoke_calls.lock().expect("lock")
        }
    }

    impl Provisioner for FakeProvisioner {
        fn org_exists(&self, org_prefix: &str) -> bool {
            self.known_orgs.iter().any(|o| o == org_prefix)
        }

        fn provision(
            &self,
            org_prefix: &str,
            _org_key_alias: &str,
            _request: &ProvisionAgentRequest,
        ) -> Result<ProvisionedMember, ProvisionError> {
            if !self.org_exists(org_prefix) {
                return Err(ProvisionError::OrgNotProvisioned(org_prefix.to_string()));
            }
            *self.provision_calls.lock().expect("lock") += 1;
            let mut n = self.counter.lock().expect("lock");
            *n += 1;
            let prefix = format!("EMember{:08}", *n);
            Ok(ProvisionedMember {
                identity_did: IdentityDID::parse(&format!("did:keri:{prefix}")).expect("valid did"),
                member_prefix: prefix,
            })
        }

        fn revoke(
            &self,
            org_prefix: &str,
            _org_key_alias: &str,
            member_did: &str,
        ) -> Result<RevokeOutcome, ProvisionError> {
            if !self.org_exists(org_prefix) {
                return Err(ProvisionError::OrgNotProvisioned(org_prefix.to_string()));
            }
            *self.revoke_calls.lock().expect("lock") += 1;
            let mut revoked = self.revoked.lock().expect("lock");
            if revoked.insert(member_did.to_string()) {
                Ok(RevokeOutcome::Revoked)
            } else {
                Ok(RevokeOutcome::AlreadyRevoked)
            }
        }
    }
}
