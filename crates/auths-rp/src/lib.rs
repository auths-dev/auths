//! Auths relying-party transport — agent-passport request authentication.
//!
//! A client (an AI agent, a CI job, a service) authenticates an HTTP request by presenting
//! proof-of-control of a delegated KERI credential, instead of a bearer API key. This crate
//! owns the **wire boundary**: it turns an
//! `Authorization: Auths-Presentation <base64url(JSON)>` header into the shipped
//! [`auths_verifier::PresentationEnvelope`], parsed exactly once. Stringly-typed wire fields
//! never reach verification logic — the only exit from "wire world" is
//! [`WirePresentation::parse`].
//!
//! The actual cryptographic check is the shipped, pure `auths_verifier::verify_presentation`;
//! this crate is the transport + (in later tasks) the Axum middleware and challenge store.

use auths_verifier::{PresentationBinding, PresentationEnvelope};
use base64::Engine;
use chrono::{DateTime, Utc};

pub mod challenge;
pub mod principal;

pub use challenge::{
    ChallengeError, ChallengeStore, DEFAULT_CHALLENGE_TTL_SECS, ExpectedNonce,
    InMemoryChallengeStore, IssuedChallenge,
};
pub use principal::{Denied, Grant, VerifiedPrincipal};

/// The `Authorization` scheme name carrying a presentation (RFC 7235 `auth-scheme`).
pub const AUTHS_PRESENTATION_SCHEME: &str = "Auths-Presentation";

/// The fixed nonce width, in bytes.
pub const NONCE_LEN: usize = 32;

/// A non-empty relying-party identifier a presentation is bound to.
///
/// Constructed only via [`Audience::parse`], so an empty audience is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience(String);

impl Audience {
    /// Parse a non-empty audience string.
    ///
    /// Args:
    /// * `s`: The relying-party identifier (e.g. `api.example.com`).
    ///
    /// Usage:
    /// ```
    /// # use auths_rp::Audience;
    /// assert!(Audience::parse("api.example.com").is_ok());
    /// assert!(Audience::parse("").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, WireError> {
        if s.is_empty() {
            return Err(WireError::EmptyAudience);
        }
        Ok(Self(s.to_string()))
    }

    /// The audience as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A fixed-width (32-byte) challenge/TTL nonce.
///
/// The fixed array makes "wrong-length nonce" unrepresentable: [`Nonce::parse_b64url`] is the
/// only fallible constructor and rejects any payload that is not exactly [`NONCE_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wrap an exactly-32-byte array (e.g. freshly drawn from a CSPRNG).
    pub fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Decode a base64url (URL-safe, no padding) nonce of exactly [`NONCE_LEN`] bytes.
    ///
    /// Args:
    /// * `s`: The base64url-encoded nonce.
    ///
    /// Usage:
    /// ```
    /// # use auths_rp::Nonce;
    /// let n = Nonce::from_bytes([7u8; 32]);
    /// assert_eq!(Nonce::parse_b64url(&n.to_b64url()).unwrap(), n);
    /// ```
    pub fn parse_b64url(s: &str) -> Result<Self, WireError> {
        let raw = b64url_decode(s)?;
        let got = raw.len();
        let arr: [u8; NONCE_LEN] = raw.try_into().map_err(|_| WireError::NonceLength { got })?;
        Ok(Self(arr))
    }

    /// The raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode the nonce as base64url (URL-safe, no padding).
    pub fn to_b64url(&self) -> String {
        b64url_encode(&self.0)
    }
}

/// Boundary parse errors — a closed sum the HTTP layer maps to a status exhaustively.
///
/// Distinct variants exist for diagnostics/logging; a relying party should map all of them to
/// a coarse client error (HTTP 400/401) externally so it does not leak which check failed.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The `Authorization` header was absent or carried an empty token.
    #[error("missing or empty Authorization presentation token")]
    MissingHeader,
    /// The `Authorization` scheme was not `Auths-Presentation`.
    #[error("wrong Authorization scheme (expected Auths-Presentation)")]
    WrongScheme,
    /// A base64url field did not decode under the URL-safe alphabet.
    #[error("invalid base64url payload")]
    BadBase64,
    /// The decoded payload was not a well-formed `WirePresentation` JSON.
    #[error("malformed presentation JSON: {0}")]
    BadJson(String),
    /// The audience field was empty.
    #[error("empty audience")]
    EmptyAudience,
    /// The nonce was not exactly [`NONCE_LEN`] bytes.
    #[error("nonce must be 32 bytes, got {got}")]
    NonceLength {
        /// The actual decoded length.
        got: usize,
    },
    /// The TTL `not_after` was not a valid RFC-3339 timestamp.
    #[error("invalid not_after timestamp")]
    BadTimestamp,
}

/// The presentation binding as it appears on the wire (base64url nonce; RFC-3339 `not_after`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireBinding {
    /// Interactive single-use challenge: the verifier-issued nonce the subject signed.
    Challenge {
        /// base64url-encoded 32-byte nonce.
        nonce: String,
    },
    /// Non-interactive TTL: a subject-chosen nonce valid until `not_after`.
    Ttl {
        /// base64url-encoded 32-byte nonce.
        nonce: String,
        /// RFC-3339 expiry instant.
        not_after: String,
    },
}

/// The raw presentation carried in the `Auths-Presentation` header (a base64url JSON token).
///
/// This is the untrusted wire shape. The ONLY way into the domain is [`WirePresentation::parse`],
/// which yields the shipped [`PresentationEnvelope`] plus the bound [`Audience`]; after that, no
/// raw field is trusted by verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WirePresentation {
    /// The SAID (`acdc.d`) of the credential being presented.
    pub credential_said: String,
    /// The relying party this presentation is bound to.
    pub audience: String,
    /// The challenge/TTL binding.
    pub binding: WireBinding,
    /// base64url-encoded subject signature over the canonical presentation message.
    pub signature_b64: String,
}

impl WirePresentation {
    /// Parse the wire shape once into the shipped [`PresentationEnvelope`] + bound [`Audience`].
    ///
    /// Returns typed [`WireError`]s; never panics. After this call the caller works only with
    /// domain types.
    ///
    /// Args: (consumes `self`).
    ///
    /// Usage:
    /// ```
    /// # use auths_rp::{WirePresentation, WireBinding, Nonce};
    /// let wire = WirePresentation {
    ///     credential_said: "ECred".into(),
    ///     audience: "api.example.com".into(),
    ///     binding: WireBinding::Challenge { nonce: Nonce::from_bytes([1u8; 32]).to_b64url() },
    ///     signature_b64: "AAAA".into(),
    /// };
    /// let (envelope, audience) = wire.parse().unwrap();
    /// assert_eq!(audience.as_str(), "api.example.com");
    /// assert_eq!(envelope.credential_said, "ECred");
    /// ```
    pub fn parse(self) -> Result<(PresentationEnvelope, Audience), WireError> {
        let audience = Audience::parse(&self.audience)?;
        let binding = match self.binding {
            WireBinding::Challenge { nonce } => {
                let nonce = Nonce::parse_b64url(&nonce)?;
                PresentationBinding::Challenge {
                    nonce: nonce.as_bytes().to_vec(),
                }
            }
            WireBinding::Ttl { nonce, not_after } => {
                let nonce = Nonce::parse_b64url(&nonce)?;
                let not_after = DateTime::parse_from_rfc3339(&not_after)
                    .map_err(|_| WireError::BadTimestamp)?
                    .with_timezone(&Utc);
                PresentationBinding::Ttl {
                    nonce: nonce.as_bytes().to_vec(),
                    not_after,
                }
            }
        };
        let signature = b64url_decode(&self.signature_b64)?;
        let envelope = PresentationEnvelope {
            credential_said: self.credential_said,
            audience: audience.as_str().to_string(),
            binding,
            signature,
        };
        Ok((envelope, audience))
    }

    /// Decode a `WirePresentation` from a base64url-encoded JSON token.
    ///
    /// Args:
    /// * `token`: The base64url JSON token (the value after the scheme name).
    pub fn from_token(token: &str) -> Result<Self, WireError> {
        let json = b64url_decode(token)?;
        serde_json::from_slice(&json).map_err(|e| WireError::BadJson(e.to_string()))
    }

    /// Encode to the base64url JSON token form (for clients building the header value).
    pub fn to_token(&self) -> Result<String, WireError> {
        let json = serde_json::to_vec(self).map_err(|e| WireError::BadJson(e.to_string()))?;
        Ok(b64url_encode(&json))
    }

    /// Build the wire shape from a signed [`PresentationEnvelope`] (client side).
    ///
    /// Encodes the nonce + signature as base64url and the TTL `not_after` as RFC-3339, the
    /// inverse of [`WirePresentation::parse`].
    pub fn from_envelope(envelope: &PresentationEnvelope) -> Self {
        let binding = match &envelope.binding {
            PresentationBinding::Challenge { nonce } => WireBinding::Challenge {
                nonce: b64url_encode(nonce),
            },
            PresentationBinding::Ttl { nonce, not_after } => WireBinding::Ttl {
                nonce: b64url_encode(nonce),
                not_after: not_after.to_rfc3339(),
            },
        };
        Self {
            credential_said: envelope.credential_said.clone(),
            audience: envelope.audience.clone(),
            binding,
            signature_b64: b64url_encode(&envelope.signature),
        }
    }
}

/// Parse an `Authorization: Auths-Presentation <token>` header value into a [`WirePresentation`].
///
/// The scheme name is matched case-sensitively per the constant; the single space separator and
/// `token68` base64url body follow RFC 7235 §2.1.
///
/// Args:
/// * `authorization`: The raw `Authorization` header value.
///
/// Usage:
/// ```
/// # use auths_rp::{parse_presentation_header, WirePresentation, WireBinding, Nonce};
/// let wire = WirePresentation {
///     credential_said: "ECred".into(),
///     audience: "api.example.com".into(),
///     binding: WireBinding::Challenge { nonce: Nonce::from_bytes([2u8; 32]).to_b64url() },
///     signature_b64: "AAAA".into(),
/// };
/// let header = format!("Auths-Presentation {}", wire.to_token().unwrap());
/// assert!(parse_presentation_header(&header).is_ok());
/// ```
pub fn parse_presentation_header(authorization: &str) -> Result<WirePresentation, WireError> {
    let token = authorization
        .strip_prefix(AUTHS_PRESENTATION_SCHEME)
        .ok_or(WireError::WrongScheme)?
        .trim();
    if token.is_empty() {
        return Err(WireError::MissingHeader);
    }
    WirePresentation::from_token(token)
}

/// Decode base64url (URL-safe). Tolerates trailing `=` padding but rejects the standard alphabet.
fn b64url_decode(s: &str) -> Result<Vec<u8>, WireError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| WireError::BadBase64)
}

/// Encode base64url (URL-safe, no padding).
fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(binding: WireBinding) -> WirePresentation {
        WirePresentation {
            credential_said: "ECredSAID".into(),
            audience: "api.example.com".into(),
            binding,
            signature_b64: b64url_encode(&[9u8; 64]),
        }
    }

    fn challenge_binding() -> WireBinding {
        WireBinding::Challenge {
            nonce: Nonce::from_bytes([7u8; 32]).to_b64url(),
        }
    }

    #[test]
    fn round_trip_token_and_parse() {
        let wire = sample(challenge_binding());
        let token = wire.to_token().unwrap();
        let header = format!("{AUTHS_PRESENTATION_SCHEME} {token}");
        let decoded = parse_presentation_header(&header).unwrap();
        assert_eq!(decoded, wire);
        let (envelope, audience) = decoded.parse().unwrap();
        assert_eq!(audience.as_str(), "api.example.com");
        assert_eq!(envelope.credential_said, "ECredSAID");
        assert_eq!(envelope.signature.len(), 64);
        assert!(matches!(
            envelope.binding,
            PresentationBinding::Challenge { .. }
        ));
    }

    #[test]
    fn ttl_binding_parses_not_after() {
        let wire = sample(WireBinding::Ttl {
            nonce: Nonce::from_bytes([3u8; 32]).to_b64url(),
            not_after: "2030-01-01T00:00:00Z".into(),
        });
        let (envelope, _aud) = wire.parse().unwrap();
        match envelope.binding {
            PresentationBinding::Ttl { not_after, .. } => {
                assert_eq!(not_after.to_rfc3339(), "2030-01-01T00:00:00+00:00");
            }
            PresentationBinding::Challenge { .. } => panic!("expected TTL binding"),
        }
    }

    #[test]
    fn wrong_scheme_rejected() {
        let err = parse_presentation_header("Bearer abc.def").unwrap_err();
        assert!(matches!(err, WireError::WrongScheme));
    }

    #[test]
    fn empty_token_rejected() {
        let err = parse_presentation_header("Auths-Presentation   ").unwrap_err();
        assert!(matches!(err, WireError::MissingHeader));
    }

    #[test]
    fn empty_audience_rejected() {
        let mut wire = sample(challenge_binding());
        wire.audience = String::new();
        assert!(matches!(
            wire.parse().unwrap_err(),
            WireError::EmptyAudience
        ));
    }

    #[test]
    fn wrong_nonce_length_rejected() {
        let wire = sample(WireBinding::Challenge {
            nonce: b64url_encode(&[1u8; 16]), // 16 bytes, not 32
        });
        match wire.parse().unwrap_err() {
            WireError::NonceLength { got } => assert_eq!(got, 16),
            other => panic!("expected NonceLength, got {other:?}"),
        }
    }

    #[test]
    fn standard_alphabet_blob_rejected() {
        // `+` and `/` are valid in standard base64 but NOT in the URL-safe alphabet.
        let err = WirePresentation::from_token("ab+/cd").unwrap_err();
        assert!(matches!(err, WireError::BadBase64));
    }

    #[test]
    fn bad_json_rejected() {
        let token = b64url_encode(b"{ not valid json");
        assert!(matches!(
            WirePresentation::from_token(&token).unwrap_err(),
            WireError::BadJson(_)
        ));
    }

    #[test]
    fn bad_signature_base64_rejected() {
        let mut wire = sample(challenge_binding());
        wire.signature_b64 = "not+valid/b64".into();
        assert!(matches!(wire.parse().unwrap_err(), WireError::BadBase64));
    }
}
