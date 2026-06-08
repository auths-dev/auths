//! Re-exports from [`crate::domains::federation`].
//!
//! All federation-as-attestor logic lives in `domains::federation`. This module
//! exists only to keep `use auths_sdk::workflows::federation::*` imports working
//! across the CLI and other presentation layers, mirroring [`crate::workflows::org`].

pub use crate::domains::federation::anchor::{anchor_attestation, attest_oidc};
pub use crate::domains::federation::error::FederationError;
pub use crate::domains::federation::oidc::{OidcAttestationRequest, verify_oidc_attestation};
pub use crate::domains::federation::saml::{
    SamlAssertion, SamlAssertionVerifier, SamlAttestationRequest, attest_saml,
    verify_saml_attestation,
};
pub use crate::domains::federation::signal::{FederationSignal, evaluate_idp_signals};
pub use crate::domains::federation::types::{
    AttestationContent, GroupId, IdpAttestation, IdpId, LifecycleClaim, Nonce,
};
