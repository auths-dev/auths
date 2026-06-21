//! Enterprise IdP verification for Auths.
//!
//! Provides the `IdpVerifier` trait and supporting types for binding
//! Auths identities to corporate identity providers (Okta, Entra ID,
//! Google Workspace, generic SAML 2.0).
//!
//! Usage:
//! ```ignore
//! use auths_idp::{IdpVerifier, IdpProtocol, VerifiedIdpIdentity, OidcJwksClient};
//!
//! let client = OidcJwksClient::with_defaults("https://company.okta.com", "client-id");
//! let key = client.get_key_for_token(&jwt).await?;
//! ```

pub mod binding;
pub mod error;
#[cfg(feature = "oidc")]
pub mod jwks;
pub mod oidc;
pub mod saml;
pub mod types;

pub use binding::{BindingResult, IdpBindingAttestation, bind_identity_to_idp};
pub use error::{IdpError, IdpResult};
#[cfg(feature = "oidc")]
pub use jwks::OidcJwksClient;
pub use oidc::IdpVerifier;
#[cfg(feature = "oidc")]
pub use oidc::entra::EntraIdpVerifier;
#[cfg(feature = "oidc")]
pub use oidc::google::GoogleIdpVerifier;
#[cfg(feature = "oidc")]
pub use oidc::okta::OktaIdpVerifier;
pub use types::{IdpProtocol, VerifiedIdpIdentity};
