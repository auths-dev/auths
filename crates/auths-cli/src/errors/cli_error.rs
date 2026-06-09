//! Typed CLI error variants with actionable help text.

/// Structured CLI errors with built-in suggestion and documentation links.
#[derive(thiserror::Error, Debug)]
pub enum CliError {
    #[error("key rotation failed — no pre-rotation commitment found")]
    NoPrerotationCommitment,

    #[error("identity not found — run `auths init` to create one")]
    IdentityNotFound,

    #[error("keychain unavailable — set AUTHS_KEYCHAIN_BACKEND=file for headless environments")]
    KeychainUnavailable,

    #[error("device key '{alias}' not found — import it first with `auths key import`")]
    DeviceKeyNotFound { alias: String },

    #[error("passphrase required — set AUTHS_PASSPHRASE env var for CI environments")]
    PassphraseRequired,

    #[error("attestation expired — issue a new one with `auths device link`")]
    AttestationExpired,

    #[error("capability '{capability}' not granted — check device authorization policies")]
    MissingCapability { capability: String },
}

impl CliError {
    /// Human-readable suggestion for how to recover from this error.
    pub fn suggestion(&self) -> &str {
        match self {
            Self::NoPrerotationCommitment => {
                "Run: auths id rotate --next-key-alias <alias-for-next-key>"
            }
            Self::IdentityNotFound => "Run: auths init",
            Self::KeychainUnavailable => {
                "Set AUTHS_KEYCHAIN_BACKEND=file and AUTHS_PASSPHRASE=<passphrase> in your environment."
            }
            Self::DeviceKeyNotFound { .. } => {
                "Run: auths key import --key-alias <alias> --seed-file <path>"
            }
            Self::PassphraseRequired => {
                "Set AUTHS_PASSPHRASE=<your-passphrase> in the environment, or run interactively."
            }
            Self::AttestationExpired => {
                "Run: auths device link --key <key> --device-key <device-key> --device-did <did>"
            }
            Self::MissingCapability { .. } => {
                "Re-authorize the device with `auths device link` to grant the capability."
            }
        }
    }

    /// Documentation URL for this error, if available.
    ///
    /// Deep links are parked on the docs root until the docs site serves
    /// per-guide routes — every subpath currently 404s.
    pub fn docs_url(&self) -> Option<&str> {
        match self {
            Self::NoPrerotationCommitment | Self::IdentityNotFound | Self::KeychainUnavailable => {
                Some("https://docs.auths.dev")
            }
            _ => None,
        }
    }
}
