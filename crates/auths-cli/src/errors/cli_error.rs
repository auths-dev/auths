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
                "Run: auths key precommit --next-key <path-to-next-pubkey>"
            }
            Self::IdentityNotFound => "Run: auths init",
            Self::KeychainUnavailable => {
                "Set AUTHS_KEYCHAIN_BACKEND=file and AUTHS_PASSPHRASE=<passphrase> in your environment."
            }
            Self::DeviceKeyNotFound { .. } => "Run: auths key import --alias <alias> --file <path>",
            Self::PassphraseRequired => {
                "Set AUTHS_PASSPHRASE=<your-passphrase> in the environment, or run interactively."
            }
            Self::AttestationExpired => "Run: auths device link --device-alias <name>",
            Self::MissingCapability { .. } => {
                "Run: auths device link --capability <cap> to add the capability."
            }
        }
    }

    /// Documentation URL for this error, if available.
    ///
    /// These URLs map to Markdown source files under `docs/guides/` in this repository
    /// (e.g., `docs/guides/key-rotation.md`). Keep the slugs in sync with those filenames
    /// so static site generators (e.g., mdBook, Docusaurus) can serve them correctly.
    pub fn docs_url(&self) -> Option<&str> {
        match self {
            Self::NoPrerotationCommitment => Some("https://docs.auths.dev/guides/key-rotation"),
            Self::IdentityNotFound => Some("https://docs.auths.dev/guides/getting-started"),
            Self::KeychainUnavailable => Some("https://docs.auths.dev/guides/headless-setup"),
            _ => None,
        }
    }
}
