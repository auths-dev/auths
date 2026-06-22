//! Identity-replacement authorization.
//!
//! `auths init --force` replaces the existing root identity (mints a new root and repoints signing), so
//! it requires an explicit confirmation: an interactive confirmation when a human is present, or an
//! explicit token non-interactively. A wrapper or CI invocation re-running `init --force` must not be
//! able to silently rotate the user onto a new (possibly attacker-chosen) root.

use thiserror::Error;

/// Refusal reason when an identity replacement is not authorized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityReplaceDenied {
    /// `--force` was requested without an interactive confirmation (or explicit token).
    #[error(
        "replacing an existing root identity requires an explicit confirmation; \
         it is refused non-interactively so `init --force` cannot silently mint a new root (AUTHS-E5012)"
    )]
    ConfirmationRequired,
}

/// Authorize replacing an existing root identity (`init --force` / `ForceNew`).
///
/// Allowed only when `confirmed` — set by an interactive prompt the user accepted, or by an explicit
/// non-interactive token (`--confirm-replace`). Otherwise refused, so a non-interactive `init --force`
/// cannot silently replace the user's root.
///
/// Args:
/// * `confirmed`: whether the replacement was explicitly confirmed (interactive prompt or token).
///
/// Usage:
/// ```ignore
/// authorize_identity_replacement(user_confirmed)?;
/// ```
pub fn authorize_identity_replacement(confirmed: bool) -> Result<(), IdentityReplaceDenied> {
    if confirmed {
        Ok(())
    } else {
        Err(IdentityReplaceDenied::ConfirmationRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_replace_refused_without_confirmation() {
        // a non-interactive `init --force` with no confirmation must be refused
        assert_eq!(
            authorize_identity_replacement(false),
            Err(IdentityReplaceDenied::ConfirmationRequired),
        );
    }

    #[test]
    fn force_replace_allowed_when_confirmed() {
        assert!(authorize_identity_replacement(true).is_ok());
    }
}
