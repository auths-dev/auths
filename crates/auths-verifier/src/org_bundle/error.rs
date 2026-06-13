//! Typed failures verifying an air-gapped org bundle offline.

use auths_crypto::AuthsErrorInfo;

/// A failure verifying an air-gapped org bundle or off-boarding record.
///
/// Every variant is fail-closed: none of these conditions ever yields a
/// "valid" verdict.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrgBundleError {
    /// A bundled KEL failed integrity or authentication: an event's
    /// recomputed SAID did not match its stored `d`, the signature
    /// attachments could not be parsed, or a signature did not verify
    /// against the controlling key-state (RT-002).
    #[error("bundle integrity failure for '{id}': {reason}")]
    Integrity {
        /// The identifier whose KEL failed integrity.
        id: String,
        /// Why integrity failed.
        reason: String,
    },

    /// The org KEL delegates a member whose own KEL is not in the bundle —
    /// the bundle is incomplete and cannot be verified. Fail closed.
    #[error("bundle is missing the KEL for delegated member '{member}'")]
    MissingMemberKel {
        /// The member's `did:keri:`.
        member: String,
    },

    /// A queried member has no delegation seal in the org KEL — the org never
    /// delegated it, so there is no authority to verify. Fail closed.
    #[error("member '{member}' has no delegation seal in the org KEL")]
    MissingDelegatorSeal {
        /// The member's `did:keri:`.
        member: String,
    },

    /// Canonical serialization (`json-canon`) of a bundle or record failed.
    #[error("canonicalization failed: {0}")]
    Canonicalize(String),

    /// A bundle or record could not be parsed from its JSON form.
    #[error("parse failed: {0}")]
    Parse(String),

    /// A signed off-boarding record failed verification: the signature did
    /// not verify, the curve tag mismatched the org key, or the record is not
    /// bound to a matching revocation seal on the org KEL.
    #[error("offboarding record invalid: {0}")]
    RecordInvalid(String),
}

impl AuthsErrorInfo for OrgBundleError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Integrity { .. } => "AUTHS-E2201",
            Self::MissingMemberKel { .. } => "AUTHS-E2202",
            Self::MissingDelegatorSeal { .. } => "AUTHS-E2203",
            Self::Canonicalize(_) => "AUTHS-E2204",
            Self::Parse(_) => "AUTHS-E2205",
            Self::RecordInvalid(_) => "AUTHS-E2206",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Integrity { .. } => Some(
                "The bundle was modified after it was produced; obtain a fresh, untampered bundle",
            ),
            Self::MissingMemberKel { .. } | Self::MissingDelegatorSeal { .. } => {
                Some("The bundle is incomplete; re-produce it with `auths org bundle`")
            }
            Self::Canonicalize(_) | Self::Parse(_) => {
                Some("The file is not a valid air-gapped org bundle; re-export it")
            }
            Self::RecordInvalid(_) => Some(
                "The off-boarding record does not match the org KEL; obtain a fresh bundle from the org",
            ),
        }
    }
}
