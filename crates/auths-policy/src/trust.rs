//! Trust registry types and matching logic for OIDC provider boundaries.
//!
//! Defines `TrustRegistry`, `TrustRegistryEntry`, and `ValidatedIssuerUrl` —
//! types that constrain which OIDC providers can authorize which capabilities
//! for which repositories.

use serde::{Deserialize, Serialize};

use crate::glob::glob_match;
use crate::types::{CanonicalCapability, ValidatedGlob};

/// Maximum length for issuer URL strings.
const MAX_ISSUER_URL_LEN: usize = 512;

/// A validated OIDC issuer URL (HTTPS, no wildcards, no path traversal).
///
/// Args:
/// * `url`: An HTTPS URL string for an OIDC provider issuer.
///
/// Usage:
/// ```ignore
/// let url = ValidatedIssuerUrl::parse("https://token.actions.githubusercontent.com")?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedIssuerUrl(String);

/// Error returned when parsing an issuer URL fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerUrlParseError(pub String);

impl std::fmt::Display for IssuerUrlParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IssuerUrlParseError {}

impl ValidatedIssuerUrl {
    /// Parse and validate an OIDC issuer URL.
    ///
    /// Args:
    /// * `raw`: The URL string to validate.
    ///
    /// Usage:
    /// ```ignore
    /// let url = ValidatedIssuerUrl::parse("https://accounts.google.com")?;
    /// ```
    pub fn parse(raw: &str) -> Result<Self, IssuerUrlParseError> {
        let trimmed = raw.trim();

        if trimmed.is_empty() || trimmed.len() > MAX_ISSUER_URL_LEN {
            return Err(IssuerUrlParseError(format!(
                "issuer URL must be 1-{MAX_ISSUER_URL_LEN} chars, got {}",
                trimmed.len()
            )));
        }

        if !trimmed.starts_with("https://") {
            return Err(IssuerUrlParseError(
                "issuer URL must start with https://".into(),
            ));
        }

        if trimmed.contains("..") {
            return Err(IssuerUrlParseError(
                "issuer URL must not contain path traversal (..)".into(),
            ));
        }

        if trimmed.contains('*') {
            return Err(IssuerUrlParseError(
                "issuer URL must not contain wildcards".into(),
            ));
        }

        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerUrlParseError(
                "issuer URL must not contain control characters".into(),
            ));
        }

        // Must have a host after https://
        let after_scheme = &trimmed["https://".len()..];
        let host = after_scheme.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err(IssuerUrlParseError("issuer URL must have a host".into()));
        }

        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ValidatedIssuerUrl {
    type Error = IssuerUrlParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<ValidatedIssuerUrl> for String {
    fn from(v: ValidatedIssuerUrl) -> Self {
        v.0
    }
}

/// A trust boundary mapping an OIDC provider to allowed repos and capabilities.
///
/// Args:
/// * `provider_issuer`: The OIDC issuer URL (e.g., "https://token.actions.githubusercontent.com").
/// * `allowed_repos`: Glob patterns for allowed repositories (org must be literal).
/// * `allowed_capabilities`: Capabilities this provider may authorize.
/// * `max_token_ttl_seconds`: Maximum token TTL the bridge will issue for this provider.
/// * `require_witness_quorum`: Optional minimum witness quorum for this provider.
///
/// Usage:
/// ```ignore
/// let entry = TrustRegistryEntry {
///     provider_issuer: ValidatedIssuerUrl::parse("https://token.actions.githubusercontent.com")?,
///     allowed_repos: vec![ValidatedGlob::parse("myorg/*")?],
///     allowed_capabilities: vec![CanonicalCapability::parse("deploy:staging")?],
///     max_token_ttl_seconds: 3600,
///     require_witness_quorum: None,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRegistryEntry {
    pub provider_issuer: ValidatedIssuerUrl,
    pub allowed_repos: Vec<ValidatedGlob>,
    pub allowed_capabilities: Vec<CanonicalCapability>,
    pub max_token_ttl_seconds: u64,
    pub require_witness_quorum: Option<usize>,
}

impl TrustRegistryEntry {
    /// Check if a repo is allowed by this entry's repo patterns.
    ///
    /// Args:
    /// * `repo`: Repository identifier (e.g., "myorg/myrepo").
    ///
    /// Usage:
    /// ```ignore
    /// if entry.repo_allowed("myorg/myrepo") { /* ... */ }
    /// ```
    pub fn repo_allowed(&self, repo: &str) -> bool {
        if self.allowed_repos.is_empty() {
            return true;
        }
        self.allowed_repos.iter().any(|pat| glob_match(pat, repo))
    }

    /// Intersect requested capabilities with this entry's allowed capabilities.
    ///
    /// Args:
    /// * `requested`: The capabilities requested in the exchange.
    ///
    /// Usage:
    /// ```ignore
    /// let effective = entry.intersect_capabilities(&requested_caps);
    /// ```
    pub fn intersect_capabilities(
        &self,
        requested: &[CanonicalCapability],
    ) -> Vec<CanonicalCapability> {
        requested
            .iter()
            .filter(|r| self.allowed_capabilities.contains(r))
            .cloned()
            .collect()
    }
}

/// A collection of trust registry entries defining provider boundaries.
///
/// Usage:
/// ```ignore
/// let registry = TrustRegistry::new(vec![entry1, entry2]);
/// if let Some(entry) = registry.lookup("https://token.actions.githubusercontent.com") {
///     // check entry constraints
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRegistry {
    entries: Vec<TrustRegistryEntry>,
}

impl TrustRegistry {
    pub fn new(entries: Vec<TrustRegistryEntry>) -> Self {
        Self { entries }
    }

    /// Look up the first trust entry matching a provider issuer URL.
    ///
    /// Args:
    /// * `provider_issuer`: The OIDC issuer URL to look up.
    ///
    /// Usage:
    /// ```ignore
    /// let entry = registry.lookup("https://token.actions.githubusercontent.com");
    /// ```
    pub fn lookup(&self, provider_issuer: &str) -> Option<&TrustRegistryEntry> {
        self.entries
            .iter()
            .find(|e| e.provider_issuer.as_str() == provider_issuer)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[TrustRegistryEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_https_issuer_url() {
        let url = ValidatedIssuerUrl::parse("https://token.actions.githubusercontent.com");
        assert!(url.is_ok());
        assert_eq!(
            url.unwrap().as_str(),
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn reject_http_issuer_url() {
        let url = ValidatedIssuerUrl::parse("http://insecure.example.com");
        assert!(url.is_err());
        assert!(url.unwrap_err().0.contains("https://"));
    }

    #[test]
    fn reject_wildcard_issuer_url() {
        let url = ValidatedIssuerUrl::parse("https://*.example.com");
        assert!(url.is_err());
        assert!(url.unwrap_err().0.contains("wildcard"));
    }

    #[test]
    fn reject_empty_issuer_url() {
        assert!(ValidatedIssuerUrl::parse("").is_err());
    }

    #[test]
    fn reject_path_traversal() {
        assert!(ValidatedIssuerUrl::parse("https://example.com/../admin").is_err());
    }

    #[test]
    fn reject_no_host() {
        assert!(ValidatedIssuerUrl::parse("https://").is_err());
    }

    fn github_entry() -> TrustRegistryEntry {
        TrustRegistryEntry {
            provider_issuer: ValidatedIssuerUrl::parse(
                "https://token.actions.githubusercontent.com",
            )
            .unwrap(),
            allowed_repos: vec![ValidatedGlob::parse("myorg/*").unwrap()],
            allowed_capabilities: vec![
                CanonicalCapability::parse("deploy:staging").unwrap(),
                CanonicalCapability::parse("sign:commit").unwrap(),
            ],
            max_token_ttl_seconds: 3600,
            require_witness_quorum: None,
        }
    }

    #[test]
    fn lookup_found() {
        let registry = TrustRegistry::new(vec![github_entry()]);
        let entry = registry.lookup("https://token.actions.githubusercontent.com");
        assert!(entry.is_some());
    }

    #[test]
    fn lookup_not_found() {
        let registry = TrustRegistry::new(vec![github_entry()]);
        let entry = registry.lookup("https://accounts.google.com");
        assert!(entry.is_none());
    }

    #[test]
    fn repo_allowed_glob_match() {
        let entry = github_entry();
        assert!(entry.repo_allowed("myorg/myrepo"));
        assert!(entry.repo_allowed("myorg/other-repo"));
    }

    #[test]
    fn repo_denied_wrong_org() {
        let entry = github_entry();
        assert!(!entry.repo_allowed("otherorg/myrepo"));
    }

    #[test]
    fn repo_allowed_empty_patterns_allows_all() {
        let mut entry = github_entry();
        entry.allowed_repos = vec![];
        assert!(entry.repo_allowed("anyorg/anyrepo"));
    }

    #[test]
    fn capability_intersection_full_overlap() {
        let entry = github_entry();
        let requested = vec![
            CanonicalCapability::parse("deploy:staging").unwrap(),
            CanonicalCapability::parse("sign:commit").unwrap(),
        ];
        let effective = entry.intersect_capabilities(&requested);
        assert_eq!(effective.len(), 2);
    }

    #[test]
    fn capability_intersection_partial_overlap() {
        let entry = github_entry();
        let requested = vec![
            CanonicalCapability::parse("deploy:staging").unwrap(),
            CanonicalCapability::parse("deploy:production").unwrap(),
        ];
        let effective = entry.intersect_capabilities(&requested);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].as_str(), "deploy:staging");
    }

    #[test]
    fn capability_intersection_no_overlap() {
        let entry = github_entry();
        let requested = vec![CanonicalCapability::parse("deploy:production").unwrap()];
        let effective = entry.intersect_capabilities(&requested);
        assert!(effective.is_empty());
    }

    #[test]
    fn serde_round_trip() {
        let registry = TrustRegistry::new(vec![github_entry()]);
        let json = serde_json::to_string(&registry).unwrap();
        let parsed: TrustRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(registry, parsed);
    }

    #[test]
    fn serde_entry_round_trip() {
        let entry = github_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TrustRegistryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn serde_rejects_invalid_issuer_url() {
        let json = r#"{
            "provider_issuer": "http://insecure.example.com",
            "allowed_repos": [],
            "allowed_capabilities": [],
            "max_token_ttl_seconds": 3600,
            "require_witness_quorum": null
        }"#;
        let result: Result<TrustRegistryEntry, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
