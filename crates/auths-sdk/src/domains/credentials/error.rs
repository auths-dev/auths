use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from credential issuance, revocation, listing, and verification.
///
/// A credential is an ACDC anchored to the issuer's KEL via a backerless TEL
/// (`vcp`/`iss`/`rev`). These errors mirror the SDK delegation surfaces:
/// `thiserror` only, no `anyhow`, with an [`AuthsErrorInfo`] code + suggestion.
///
/// Usage:
/// ```ignore
/// match credentials::issue(&ctx, &issuer, issuee, &caps, role, None) {
///     Err(CredentialError::IssueeNotFound { did }) => { /* issuee has no KEL */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* credential SAID */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The issuee (subject/holder) has no KEL — an issuee must be incepted before a
    /// credential can be issued against it (hard fail, never lazily created).
    #[error("issuee identity not found (no KEL): {did}")]
    IssueeNotFound {
        /// The issuee `did:keri:` that has no resolvable KEL.
        did: String,
    },

    /// The lazy registry (`vcp`) inception or a TEL anchor (`iss`/`rev`) failed.
    #[error("credential registry error: {0}")]
    RegistryError(#[source] auths_id::keri::credential_registry::CredentialRegistryError),

    /// The credential is already revoked — revocation is idempotent, so this is only
    /// surfaced when a caller asks to distinguish "already revoked" from a fresh `rev`.
    #[error("credential already revoked: {said}")]
    AlreadyRevoked {
        /// The credential SAID that was already revoked.
        said: String,
    },

    /// The issuer's KEL is `kt≥2` — single-signature credential anchoring only.
    #[error("issuer is multi-signature (kt≥2); credential anchoring is single-author only")]
    KtThresholdUnsupported,

    /// The pinned capability schema SAID could not be computed (build-time invariant).
    #[error("capability schema unknown or uncomputable")]
    SchemaUnknown,

    /// Verification could not reach a fresh-enough witnessed tip to judge the
    /// credential's status — fail-closed (the resolution layer, F.4, owns this).
    #[error("credential status is stale or unresolvable: {reason}")]
    StaleOrUnresolvable {
        /// Why no fresh witnessed tip was reachable.
        reason: String,
    },

    /// A cryptographic operation failed (issuer-sign, curve resolution).
    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),
}

impl From<auths_id::keri::credential_registry::CredentialRegistryError> for CredentialError {
    fn from(err: auths_id::keri::credential_registry::CredentialRegistryError) -> Self {
        use auths_id::keri::credential_registry::CredentialRegistryError as RegErr;
        match err {
            RegErr::ThresholdUnsupported { .. } => CredentialError::KtThresholdUnsupported,
            other => CredentialError::RegistryError(other),
        }
    }
}

impl From<auths_core::AgentError> for CredentialError {
    fn from(err: auths_core::AgentError) -> Self {
        CredentialError::CryptoError(err)
    }
}

impl AuthsErrorInfo for CredentialError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IssueeNotFound { .. } => "AUTHS-E6101",
            Self::RegistryError(_) => "AUTHS-E6102",
            Self::AlreadyRevoked { .. } => "AUTHS-E6103",
            Self::KtThresholdUnsupported => "AUTHS-E6104",
            Self::SchemaUnknown => "AUTHS-E6105",
            Self::StaleOrUnresolvable { .. } => "AUTHS-E6106",
            Self::CryptoError(e) => e.error_code(),
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IssueeNotFound { .. } => Some(
                "The issuee must have an incepted identity (KEL) before it can be credentialed",
            ),
            Self::RegistryError(_) => {
                Some("Check the issuer identity and registry storage are reachable")
            }
            Self::AlreadyRevoked { .. } => {
                Some("This credential is already revoked; no further action is needed")
            }
            Self::KtThresholdUnsupported => {
                Some("Credential issuance currently requires a single-signature (kt=1) issuer")
            }
            Self::SchemaUnknown => {
                Some("The compiled-in capability schema is unavailable; this is a build defect")
            }
            Self::StaleOrUnresolvable { .. } => Some(
                "No fresh witnessed tip was reachable; sync the issuer KEL/receipts and retry, or relax --require-witnesses",
            ),
            Self::CryptoError(e) => e.suggestion(),
        }
    }
}
