//! Namespace verification port traits and types for proof-of-ownership verification.

use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use auths_verifier::CanonicalDid;

/// Package ecosystem identifier for namespace claims.
///
/// Args:
/// (no arguments — this is an enum definition)
///
/// Usage:
/// ```ignore
/// let eco = Ecosystem::parse("crates.io")?;
/// assert_eq!(eco, Ecosystem::Cargo);
/// assert_eq!(eco.as_str(), "cargo");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// Node Package Manager (npmjs.com).
    Npm,
    /// Python Package Index (pypi.org).
    Pypi,
    /// Rust crate registry (crates.io).
    Cargo,
    /// Docker Hub container registry.
    Docker,
    /// Go module proxy (pkg.go.dev).
    Go,
    /// Maven Central (Java/JVM).
    Maven,
    /// NuGet (.NET).
    Nuget,
}

impl Ecosystem {
    /// Returns the canonical lowercase string identifier for this ecosystem.
    ///
    /// Usage:
    /// ```ignore
    /// assert_eq!(Ecosystem::Cargo.as_str(), "cargo");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Docker => "docker",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::Nuget => "nuget",
        }
    }

    /// Parse an ecosystem string, accepting canonical names and common aliases.
    ///
    /// Args:
    /// * `s`: The ecosystem string to parse (case-insensitive).
    ///
    /// Usage:
    /// ```ignore
    /// assert_eq!(Ecosystem::parse("crates.io")?, Ecosystem::Cargo);
    /// assert_eq!(Ecosystem::parse("NPM")?, Ecosystem::Npm);
    /// ```
    pub fn parse(s: &str) -> Result<Self, NamespaceVerifyError> {
        match s.to_ascii_lowercase().as_str() {
            "npm" | "npmjs" | "npmjs.com" => Ok(Self::Npm),
            "pypi" | "pypi.org" => Ok(Self::Pypi),
            "cargo" | "crates.io" | "crates" => Ok(Self::Cargo),
            "docker" | "dockerhub" | "docker.io" => Ok(Self::Docker),
            "go" | "golang" | "go.dev" | "pkg.go.dev" => Ok(Self::Go),
            "maven" | "maven-central" | "mvn" => Ok(Self::Maven),
            "nuget" | "nuget.org" => Ok(Self::Nuget),
            _ => Err(NamespaceVerifyError::UnsupportedEcosystem {
                ecosystem: s.to_string(),
            }),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated package name within an ecosystem.
///
/// Rejects empty strings, control characters, and path traversal patterns.
///
/// Usage:
/// ```ignore
/// let name = PackageName::parse("my-package")?;
/// assert_eq!(name.as_str(), "my-package");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PackageName(String);

impl PackageName {
    /// Parse and validate a package name string.
    ///
    /// Args:
    /// * `s`: The package name to validate.
    ///
    /// Usage:
    /// ```ignore
    /// let name = PackageName::parse("left-pad")?;
    /// ```
    pub fn parse(s: &str) -> Result<Self, NamespaceVerifyError> {
        if s.is_empty() {
            return Err(NamespaceVerifyError::InvalidPackageName {
                name: s.to_string(),
                reason: "package name cannot be empty".to_string(),
            });
        }

        if s.chars().any(|c| c.is_control()) {
            return Err(NamespaceVerifyError::InvalidPackageName {
                name: s.to_string(),
                reason: "package name contains control characters".to_string(),
            });
        }

        if s.contains("..") || s.starts_with('/') || s.starts_with('\\') {
            return Err(NamespaceVerifyError::InvalidPackageName {
                name: s.to_string(),
                reason: "package name contains path traversal".to_string(),
            });
        }

        Ok(Self(s.to_string()))
    }

    /// Returns the package name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Verification token for namespace ownership challenges.
///
/// Tokens must have the `auths-verify-` prefix followed by a hex-encoded suffix.
/// Token generation is an infrastructure concern — this type only validates and holds.
///
/// Usage:
/// ```ignore
/// let token = VerificationToken::parse("auths-verify-abc123def456")?;
/// assert_eq!(token.as_str(), "auths-verify-abc123def456");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerificationToken(String);

const TOKEN_PREFIX: &str = "auths-verify-";

impl VerificationToken {
    /// Parse and validate a verification token string.
    ///
    /// Args:
    /// * `s`: The token string to validate. Must have `auths-verify-` prefix and hex suffix.
    ///
    /// Usage:
    /// ```ignore
    /// let token = VerificationToken::parse("auths-verify-deadbeef")?;
    /// ```
    pub fn parse(s: &str) -> Result<Self, NamespaceVerifyError> {
        let suffix =
            s.strip_prefix(TOKEN_PREFIX)
                .ok_or_else(|| NamespaceVerifyError::InvalidToken {
                    reason: format!("token must start with '{TOKEN_PREFIX}'"),
                })?;

        if suffix.is_empty() {
            return Err(NamespaceVerifyError::InvalidToken {
                reason: "token suffix cannot be empty".to_string(),
            });
        }

        if !suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(NamespaceVerifyError::InvalidToken {
                reason: "token suffix must be hex-encoded".to_string(),
            });
        }

        Ok(Self(s.to_string()))
    }

    /// Returns the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerificationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Method used to verify namespace ownership.
///
/// Usage:
/// ```ignore
/// let method = VerificationMethod::ApiOwnership;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Verify by publishing a token in a release (e.g., PyPI project_urls).
    PublishToken,
    /// Verify via registry API ownership/collaborator endpoint.
    ApiOwnership,
    /// Verify via DNS TXT record (e.g., Go modules).
    DnsTxt,
}

/// Proof of namespace ownership returned after successful verification.
///
/// Usage:
/// ```ignore
/// let proof = NamespaceOwnershipProof {
///     ecosystem: Ecosystem::Npm,
///     package_name: PackageName::parse("my-package")?,
///     proof_url: "https://registry.npmjs.org/my-package".parse()?,
///     method: VerificationMethod::ApiOwnership,
///     verified_at: now,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceOwnershipProof {
    /// The ecosystem where ownership was verified.
    pub ecosystem: Ecosystem,
    /// The package name that was verified.
    pub package_name: PackageName,
    /// URL where the proof can be independently verified.
    pub proof_url: Url,
    /// The method used to verify ownership.
    pub method: VerificationMethod,
    /// When the verification was performed.
    pub verified_at: DateTime<Utc>,
}

/// Challenge issued to a user to prove namespace ownership.
///
/// Usage:
/// ```ignore
/// let challenge = VerificationChallenge {
///     ecosystem: Ecosystem::Cargo,
///     package_name: PackageName::parse("my-crate")?,
///     did: CanonicalDid::parse("did:keri:abc123")?,
///     token: VerificationToken::parse("auths-verify-deadbeef")?,
///     instructions: "Add this token to your crate owners".to_string(),
///     expires_at: now + Duration::hours(1),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationChallenge {
    /// The ecosystem for this challenge.
    pub ecosystem: Ecosystem,
    /// The package being verified.
    pub package_name: PackageName,
    /// The DID claiming ownership.
    pub did: CanonicalDid,
    /// The verification token to place in the registry.
    pub token: VerificationToken,
    /// Human-readable instructions for completing the challenge.
    pub instructions: String,
    /// When this challenge expires.
    pub expires_at: DateTime<Utc>,
}

/// Verified platform identity context for cross-referencing during namespace verification.
///
/// SECURITY: This struct must ONLY be populated from server-verified platform claims
/// (i.e., claims with `verified_at IS NOT NULL` in the registry). Never accept
/// self-asserted usernames from CLI arguments — the CLI must fetch verified claims
/// from the registry before building this context.
///
/// The verification chain is:
/// 1. User runs `auths id claim github` → OAuth proves they control the GitHub account
/// 2. Registry stores the verified claim with `verified_at`
/// 3. User runs `auths namespace claim` → CLI fetches verified claims from registry
/// 4. This context is built from those verified claims only
/// 5. The namespace verifier cross-references against the ecosystem API (e.g., crates.io)
///
/// Usage:
/// ```ignore
/// // CORRECT: populated from registry-verified claims
/// let ctx = fetch_verified_platform_context(&registry_url, &did).await?;
///
/// // WRONG: self-asserted from CLI args (vulnerable to spoofing)
/// // let ctx = PlatformContext { github_username: Some(cli_arg), .. };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformContext {
    /// GitHub username from a verified platform claim.
    pub github_username: Option<String>,
    /// npm username from a verified platform claim.
    pub npm_username: Option<String>,
    /// PyPI username from a verified platform claim.
    pub pypi_username: Option<String>,
}

/// Errors from namespace verification operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(NamespaceVerifyError::UnsupportedEcosystem { .. }) => { /* unknown ecosystem */ }
///     Err(NamespaceVerifyError::OwnershipNotConfirmed { .. }) => { /* user is not owner */ }
///     Err(e) => return Err(e.into()),
///     Ok(proof) => { /* proceed with proof */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NamespaceVerifyError {
    /// The requested ecosystem is not supported.
    #[error("unsupported ecosystem: {ecosystem}")]
    UnsupportedEcosystem {
        /// The ecosystem string that was not recognized.
        ecosystem: String,
    },

    /// The package was not found in the upstream registry.
    #[error("package '{package_name}' not found in {ecosystem}")]
    PackageNotFound {
        /// The ecosystem where the lookup failed.
        ecosystem: Ecosystem,
        /// The package name that was not found.
        package_name: String,
    },

    /// Ownership could not be confirmed via the upstream registry.
    #[error("ownership of '{package_name}' on {ecosystem} not confirmed for the given identity")]
    OwnershipNotConfirmed {
        /// The ecosystem checked.
        ecosystem: Ecosystem,
        /// The package name checked.
        package_name: String,
    },

    /// The verification challenge has expired.
    #[error("verification challenge expired")]
    ChallengeExpired,

    /// The verification token is invalid.
    #[error("invalid verification token: {reason}")]
    InvalidToken {
        /// Why the token is invalid.
        reason: String,
    },

    /// The package name is invalid.
    #[error("invalid package name '{name}': {reason}")]
    InvalidPackageName {
        /// The rejected package name.
        name: String,
        /// Why the name is invalid.
        reason: String,
    },

    /// A network error occurred during verification.
    #[error("verification network error: {message}")]
    NetworkError {
        /// Human-readable error detail.
        message: String,
    },

    /// The upstream registry returned a rate limit response.
    #[error("rate limited by {ecosystem} registry")]
    RateLimited {
        /// The ecosystem that rate-limited us.
        ecosystem: Ecosystem,
    },
}

impl auths_crypto::AuthsErrorInfo for NamespaceVerifyError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedEcosystem { .. } => "AUTHS-E3961",
            Self::PackageNotFound { .. } => "AUTHS-E3962",
            Self::OwnershipNotConfirmed { .. } => "AUTHS-E3963",
            Self::ChallengeExpired => "AUTHS-E3964",
            Self::InvalidToken { .. } => "AUTHS-E3965",
            Self::InvalidPackageName { .. } => "AUTHS-E3966",
            Self::NetworkError { .. } => "AUTHS-E3967",
            Self::RateLimited { .. } => "AUTHS-E3968",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedEcosystem { .. } => {
                Some("Supported ecosystems: npm, pypi, cargo, docker, go, maven, nuget")
            }
            Self::PackageNotFound { .. } => {
                Some("Check the package name and ensure it exists on the registry")
            }
            Self::OwnershipNotConfirmed { .. } => {
                Some("Ensure you are listed as an owner/collaborator on the upstream registry")
            }
            Self::ChallengeExpired => Some("Start a new verification challenge"),
            Self::InvalidToken { .. } => {
                Some("Tokens must start with 'auths-verify-' followed by a hex string")
            }
            Self::InvalidPackageName { .. } => Some(
                "Package names cannot be empty, contain control characters, or use path traversal",
            ),
            Self::NetworkError { .. } => Some("Check your internet connection and try again"),
            Self::RateLimited { .. } => Some("Wait a moment and retry the verification"),
        }
    }
}

/// Verifies ownership of a namespace (package) on an upstream registry.
///
/// Each ecosystem adapter implements this trait. The SDK stores adapters
/// as `Arc<dyn NamespaceVerifier>` in a registry map keyed by [`Ecosystem`].
///
/// Usage:
/// ```ignore
/// let verifier: Arc<dyn NamespaceVerifier> = registry.get(&Ecosystem::Npm)?;
/// let challenge = verifier.initiate(&package_name, &did, &platform_ctx).await?;
/// // ... user completes challenge ...
/// let proof = verifier.verify(&package_name, &did, &platform_ctx, &challenge).await?;
/// ```
#[async_trait]
pub trait NamespaceVerifier: Send + Sync {
    /// Returns the ecosystem this verifier handles.
    fn ecosystem(&self) -> Ecosystem;

    /// Initiate a verification challenge for the given package.
    ///
    /// Args:
    /// * `now`: Current time (injected, never call `Utc::now()` directly).
    /// * `package_name`: The package to verify ownership of.
    /// * `did`: The caller's canonical DID.
    /// * `platform`: Verified platform identity context for cross-referencing.
    async fn initiate(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        platform: &PlatformContext,
    ) -> Result<VerificationChallenge, NamespaceVerifyError>;

    /// Verify the challenge was completed and return ownership proof.
    ///
    /// Args:
    /// * `now`: Current time (injected, never call `Utc::now()` directly).
    /// * `package_name`: The package to verify ownership of.
    /// * `did`: The caller's canonical DID.
    /// * `platform`: Verified platform identity context for cross-referencing.
    /// * `challenge`: The challenge previously returned by [`initiate`](Self::initiate).
    async fn verify(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        platform: &PlatformContext,
        challenge: &VerificationChallenge,
    ) -> Result<NamespaceOwnershipProof, NamespaceVerifyError>;
}
