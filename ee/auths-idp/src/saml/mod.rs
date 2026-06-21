//! SAML 2.0 Service Provider module for enterprise IdP verification.
//!
//! Gated behind the `saml` feature flag. Requires `libxml2-dev` and
//! `xmlsec1-dev` system packages at build time.

#[cfg(feature = "saml")]
pub mod provider;

#[cfg(feature = "saml")]
pub use provider::SamlIdpVerifier;
