//! Typed federation-as-attestor primitives.
//!
//! An IdP enters the trust fabric as an **attestor**, never a root. The types here
//! make that structural: an [`IdpAttestation`] carries a typed [`IdentityDID`]
//! subject (the self-certifying root the IdP does NOT own), a **closed**
//! [`LifecycleClaim`] enum (there is no free-text claim variant — an untyped string
//! claim cannot be represented), an anti-replay [`Nonce`], a mandatory expiry, and
//! the KEL sequence at which the subject anchored it. There is deliberately no
//! function turning any of these into a `Grant` or `Capability`.

use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use super::error::FederationError;

/// Reject an empty/blank identifier on deserialize (fail-closed, parse-don't-validate).
fn non_empty(raw: String, what: &'static str) -> Result<String, FederationError> {
    if raw.trim().is_empty() {
        return Err(FederationError::InvalidId(format!(
            "{what} must not be empty"
        )));
    }
    Ok(raw)
}

/// The attestor's stable identifier (e.g. `okta.acme.com`) — the IdP that vouches
/// for a fact about a subject it does not own. Validates non-empty on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdpId(String);

/// A group identifier carried by a [`LifecycleClaim::GroupMember`] claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupId(String);

/// An anti-replay nonce binding an attestation to a specific challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Nonce(String);

macro_rules! string_newtype {
    ($ty:ident, $what:literal) => {
        impl $ty {
            /// Construct from a string, rejecting empty/blank input.
            ///
            /// Args:
            /// * `value`: The raw identifier.
            ///
            /// Usage:
            /// ```ignore
            #[doc = concat!("let id = ", stringify!($ty), "::new(\"value\")?;")]
            /// ```
            pub fn new(value: impl Into<String>) -> Result<Self, FederationError> {
                Ok(Self(non_empty(value.into(), $what)?))
            }

            /// Borrow the inner string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                non_empty(raw, $what)
                    .map($ty)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

string_newtype!(IdpId, "idp id");
string_newtype!(GroupId, "group id");
string_newtype!(Nonce, "nonce");

/// The closed set of lifecycle facts an IdP may attest.
///
/// There is no free-text variant by design: an IdP can only assert one of these
/// typed facts, never an arbitrary string claim, so a breached IdP cannot smuggle
/// an unbounded assertion through the attestation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleClaim {
    /// The subject is an active employee/member at the IdP.
    Employed,
    /// The subject belongs to a named group at the IdP.
    GroupMember(GroupId),
    /// The subject is suspended (a deny-capable signal).
    Suspended,
    /// The subject is terminated (a deny-capable signal).
    Terminated,
}

/// The verifiable content of an attestation — exactly the bytes anchored into the
/// subject's KEL. Excludes [`IdpAttestation::anchored_at_seq`], which is the
/// **result** of anchoring, not part of the anchored digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationContent {
    /// The self-certifying root the IdP attests about (it never owns this key).
    pub subject: IdentityDID,
    /// The attestor IdP (the token's verified issuer).
    pub idp: IdpId,
    /// The typed lifecycle fact asserted.
    pub claim: LifecycleClaim,
    /// Anti-replay nonce bound to the challenge.
    pub nonce: Nonce,
    /// Mandatory expiry (injected, never `Utc::now()`).
    pub expires_at: DateTime<Utc>,
}

/// A verified, KEL-anchored IdP attestation.
///
/// Produced by verifying an OIDC `id_token` and anchoring the [`AttestationContent`]
/// into the subject's own KEL. The IdP signs nothing in the KEL — the subject
/// anchors the attestation with its own key, so the IdP remains an attestor, not a
/// root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdpAttestation {
    /// The anchored, verifiable content.
    #[serde(flatten)]
    pub content: AttestationContent,
    /// The subject KEL sequence of the anchoring `ixn`.
    pub anchored_at_seq: u128,
}
