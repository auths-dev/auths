//! Export-authorization policy.
//!
//! A plaintext private-key export is the one export that hands out a usable secret in the clear, so it
//! requires an explicit interactive confirmation and is refused non-interactively — a script holding
//! only `AUTHS_PASSPHRASE` (a CI step, a malicious wrapper) must not be able to exfiltrate the signing
//! key silently. Public and (at-rest-encrypted) exports are not gated.

use thiserror::Error;

/// What a key export reveals, for authorization purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportSensitivity {
    /// An unencrypted private key (OpenSSH `pem`) — a usable secret in the clear.
    PlaintextPrivate,
    /// A public key — not a secret.
    Public,
    /// Encrypted key bytes (`enc`) — a secret, but protected at rest.
    Encrypted,
}

/// Refusal reason when an export is not authorized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExportDenied {
    /// A plaintext private-key export was requested without an interactive confirmation.
    #[error(
        "exporting an unencrypted private key requires an interactive confirmation; \
         it is refused non-interactively so AUTHS_PASSPHRASE alone cannot authorize a key dump (AUTHS-E5910)"
    )]
    ConfirmationRequired,
}

/// Authorize a key export.
///
/// A `PlaintextPrivate` export is allowed only when the session is `interactive` **and** the user
/// `confirmed`; every other combination is refused, so a non-interactive caller cannot silently
/// exfiltrate the signing key. Public and encrypted exports are always authorized.
///
/// Args:
/// * `sensitivity`: what the export reveals.
/// * `interactive`: whether a human is present (stdin is a TTY).
/// * `confirmed`: whether the human explicitly confirmed the plaintext dump.
///
/// Usage:
/// ```ignore
/// authorize_key_export(ExportSensitivity::PlaintextPrivate, stdin_is_tty, user_confirmed)?;
/// ```
pub fn authorize_key_export(
    sensitivity: ExportSensitivity,
    interactive: bool,
    confirmed: bool,
) -> Result<(), ExportDenied> {
    match sensitivity {
        ExportSensitivity::PlaintextPrivate if !(interactive && confirmed) => {
            Err(ExportDenied::ConfirmationRequired)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_private_export_refused_when_not_interactively_confirmed() {
        // a script holding only AUTHS_PASSPHRASE (non-interactive) must NOT get the plaintext key
        assert_eq!(
            authorize_key_export(ExportSensitivity::PlaintextPrivate, false, false),
            Err(ExportDenied::ConfirmationRequired),
        );
        // non-interactive but "confirmed" is still refused — a script is never a TTY
        assert_eq!(
            authorize_key_export(ExportSensitivity::PlaintextPrivate, false, true),
            Err(ExportDenied::ConfirmationRequired),
        );
    }

    #[test]
    fn plaintext_private_export_allowed_when_interactively_confirmed() {
        assert!(authorize_key_export(ExportSensitivity::PlaintextPrivate, true, true).is_ok());
    }

    #[test]
    fn public_and_encrypted_exports_are_never_gated() {
        assert!(authorize_key_export(ExportSensitivity::Public, false, false).is_ok());
        assert!(authorize_key_export(ExportSensitivity::Encrypted, false, false).is_ok());
    }
}
