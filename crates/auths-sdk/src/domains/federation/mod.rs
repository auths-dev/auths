//! Federation-as-attestor: external IdPs enter the trust fabric as **attestors**,
//! never as the root of trust.
//!
//! A breached Okta/Entra can lie in an [`IdpAttestation`], but it cannot forge the
//! root, rotate keys, or mint authority: the subject is a self-certifying
//! `did:keri:` the IdP does not own, the claim is a closed [`LifecycleClaim`] enum
//! (no free-text smuggling), and the attestation is anchored into the subject's own
//! KEL with the subject's own key. Policy reads it as a [`FederationSignal`] through
//! [`evaluate_idp_signals`] — a negative signal can deny, a positive one can never
//! allow, and there is no function turning any of this into a `Grant`.

pub mod anchor;
pub mod error;
pub mod oidc;
pub mod saml;
pub mod signal;
pub mod types;

pub use anchor::{anchor_attestation, attest_oidc};
pub use error::FederationError;
pub use oidc::{OidcAttestationRequest, verify_oidc_attestation};
pub use saml::{
    SamlAssertion, SamlAssertionVerifier, SamlAttestationRequest, attest_saml,
    verify_saml_attestation,
};
pub use signal::{FederationSignal, evaluate_idp_signals};
pub use types::{AttestationContent, GroupId, IdpAttestation, IdpId, LifecycleClaim, Nonce};
