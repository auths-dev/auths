//! Test utilities for Attestation construction.

use crate::clock::ClockProvider;
use crate::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
use crate::core::{Capability, OidcBinding, Role, SignerType};
use crate::types::CanonicalDid;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Builder for constructing test `Attestation` instances with sensible defaults.
///
/// All optional fields default to `None`, and required fields have safe test values.
/// Use this in test code to avoid brittle raw struct literals.
///
/// # Usage
/// ```ignore
/// let att = AttestationBuilder::default()
///     .issuer("did:keri:EOrg123")
///     .subject("did:key:zDevice456")
///     .expires_at(Some(Utc::now() + chrono::Duration::hours(1)))
///     .capabilities(vec![Capability::sign_commit()])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AttestationBuilder {
    version: u32,
    rid: ResourceId,
    issuer: CanonicalDid,
    subject: CanonicalDid,
    device_public_key: Ed25519PublicKey,
    identity_signature: Ed25519Signature,
    device_signature: Ed25519Signature,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    timestamp: Option<DateTime<Utc>>,
    note: Option<String>,
    payload: Option<Value>,
    commit_sha: Option<String>,
    commit_message: Option<String>,
    author: Option<String>,
    oidc_binding: Option<OidcBinding>,
    role: Option<Role>,
    capabilities: Vec<Capability>,
    delegated_by: Option<CanonicalDid>,
    supersedes_attestation_rid: Option<ResourceId>,
    signer_type: Option<SignerType>,
    environment_claim: Option<Value>,
}

impl Default for AttestationBuilder {
    fn default() -> Self {
        #[allow(clippy::disallowed_methods)]
        let issuer = CanonicalDid::new_unchecked("did:keri:Etest");
        #[allow(clippy::disallowed_methods)]
        let subject = CanonicalDid::new_unchecked("did:key:ztest");
        Self {
            version: crate::core::ATTESTATION_VERSION,
            rid: ResourceId::new("test-rid"),
            issuer,
            subject,
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            supersedes_attestation_rid: None,
            signer_type: None,
            environment_claim: None,
        }
    }
}

impl AttestationBuilder {
    /// Set the schema version.
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set the resource ID.
    pub fn rid(mut self, rid: impl Into<String>) -> Self {
        self.rid = ResourceId::new(rid);
        self
    }

    /// Set the issuer DID.
    pub fn issuer(mut self, issuer: &str) -> Self {
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test fixture; caller provides DID strings from known sources
        {
            self.issuer = CanonicalDid::new_unchecked(issuer);
        }
        self
    }

    /// Set the subject device DID.
    pub fn subject(mut self, subject: &str) -> Self {
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test fixture; caller provides DID strings from known sources
        {
            self.subject = CanonicalDid::new_unchecked(subject);
        }
        self
    }

    /// Set the device public key (32 bytes).
    pub fn device_public_key(mut self, key: Ed25519PublicKey) -> Self {
        self.device_public_key = key;
        self
    }

    /// Set the identity signature.
    pub fn identity_signature(mut self, sig: Ed25519Signature) -> Self {
        self.identity_signature = sig;
        self
    }

    /// Set the device signature.
    pub fn device_signature(mut self, sig: Ed25519Signature) -> Self {
        self.device_signature = sig;
        self
    }

    /// Set the revocation timestamp.
    pub fn revoked_at(mut self, dt: Option<DateTime<Utc>>) -> Self {
        self.revoked_at = dt;
        self
    }

    /// Set the expiration timestamp.
    pub fn expires_at(mut self, dt: Option<DateTime<Utc>>) -> Self {
        self.expires_at = dt;
        self
    }

    /// Set the creation timestamp.
    pub fn timestamp(mut self, dt: Option<DateTime<Utc>>) -> Self {
        self.timestamp = dt;
        self
    }

    /// Set the human-readable note.
    pub fn note(mut self, note: Option<String>) -> Self {
        self.note = note;
        self
    }

    /// Set the arbitrary JSON payload.
    pub fn payload(mut self, payload: Option<Value>) -> Self {
        self.payload = payload;
        self
    }

    /// Set the Git commit SHA (for commit-signing attestations).
    pub fn commit_sha(mut self, sha: Option<String>) -> Self {
        self.commit_sha = sha;
        self
    }

    /// Set the Git commit message.
    pub fn commit_message(mut self, msg: Option<String>) -> Self {
        self.commit_message = msg;
        self
    }

    /// Set the Git commit author.
    pub fn author(mut self, author: Option<String>) -> Self {
        self.author = author;
        self
    }

    /// Set the OIDC binding information.
    pub fn oidc_binding(mut self, binding: Option<OidcBinding>) -> Self {
        self.oidc_binding = binding;
        self
    }

    /// Set the org membership role.
    pub fn role(mut self, role: Option<Role>) -> Self {
        self.role = role;
        self
    }

    /// Set the capabilities.
    pub fn capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Set the delegating attestation DID.
    pub fn delegated_by(mut self, did: Option<CanonicalDid>) -> Self {
        self.delegated_by = did;
        self
    }

    /// Set the signer type (human/agent/workload).
    pub fn signer_type(mut self, st: Option<SignerType>) -> Self {
        self.signer_type = st;
        self
    }

    /// Set the unsigned environment claim.
    pub fn environment_claim(mut self, claim: Option<Value>) -> Self {
        self.environment_claim = claim;
        self
    }

    /// Consume the builder and construct the `Attestation`.
    pub fn build(self) -> Attestation {
        Attestation {
            version: self.version,
            rid: self.rid,
            issuer: self.issuer,
            subject: self.subject,
            device_public_key: self.device_public_key.into(),
            identity_signature: self.identity_signature,
            device_signature: self.device_signature,
            revoked_at: self.revoked_at,
            expires_at: self.expires_at,
            timestamp: self.timestamp,
            note: self.note,
            payload: self.payload,
            commit_sha: self.commit_sha,
            commit_message: self.commit_message,
            author: self.author,
            oidc_binding: self.oidc_binding,
            role: self.role,
            capabilities: self.capabilities,
            delegated_by: self.delegated_by,
            supersedes_attestation_rid: self.supersedes_attestation_rid,
            signer_type: self.signer_type,
            environment_claim: self.environment_claim,
        }
    }
}

/// Mock clock for testing with injectable time.
///
/// Usage:
/// ```ignore
/// let clock = MockClock(Utc::now());
/// let now = clock.now();
/// ```
pub struct MockClock(pub DateTime<Utc>);

impl ClockProvider for MockClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
