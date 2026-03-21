//! npm registry namespace verification adapter.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use url::Url;

use auths_core::ports::namespace::{
    Ecosystem, NamespaceOwnershipProof, NamespaceVerifier, NamespaceVerifyError, PackageName,
    PlatformContext, VerificationChallenge, VerificationMethod,
};
use auths_verifier::CanonicalDid;

use super::generate_verification_token;

/// npm registry namespace ownership verifier.
///
/// Verifies package ownership by checking the `maintainers` field in the
/// public package metadata endpoint. Falls back to matching the `repository.url`
/// against the user's verified GitHub claim.
///
/// Usage:
/// ```ignore
/// let verifier = NpmVerifier::new();
/// let challenge = verifier.initiate(&package, &did, &platform).await?;
/// let proof = verifier.verify(&package, &did, &platform, &challenge).await?;
/// ```
pub struct NpmVerifier {
    client: reqwest::Client,
    base_url: Url,
}

impl NpmVerifier {
    /// Create a new verifier targeting the production npm registry.
    pub fn new() -> Self {
        Self {
            client: crate::default_http_client(),
            // INVARIANT: hardcoded valid URL
            #[allow(clippy::expect_used)]
            base_url: Url::parse("https://registry.npmjs.org").expect("valid URL"),
        }
    }

    /// Create a verifier with a custom base URL (for testing).
    ///
    /// Args:
    /// * `base_url`: The base URL to use instead of `https://registry.npmjs.org`.
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            client: crate::default_http_client(),
            base_url,
        }
    }

    fn package_url(&self, package_name: &str) -> String {
        let encoded = urlencoding::encode(package_name);
        format!("{}/{}", self.base_url, encoded)
    }

    async fn fetch_metadata(
        &self,
        package_name: &str,
    ) -> Result<NpmPackageMetadata, NamespaceVerifyError> {
        let url = self.package_url(package_name);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| NamespaceVerifyError::NetworkError {
                message: e.to_string(),
            })?;

        match resp.status().as_u16() {
            200 => {}
            404 => {
                return Err(NamespaceVerifyError::PackageNotFound {
                    ecosystem: Ecosystem::Npm,
                    package_name: package_name.to_string(),
                });
            }
            429 => {
                return Err(NamespaceVerifyError::RateLimited {
                    ecosystem: Ecosystem::Npm,
                });
            }
            status => {
                return Err(NamespaceVerifyError::NetworkError {
                    message: format!("npm registry returned HTTP {status}"),
                });
            }
        }

        resp.json()
            .await
            .map_err(|e| NamespaceVerifyError::NetworkError {
                message: format!("failed to parse npm metadata: {e}"),
            })
    }
}

impl Default for NpmVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NamespaceVerifier for NpmVerifier {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    async fn initiate(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        platform: &PlatformContext,
    ) -> Result<VerificationChallenge, NamespaceVerifyError> {
        self.fetch_metadata(package_name.as_str()).await?;

        if platform.npm_username.is_none() && platform.github_username.is_none() {
            return Err(NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Npm,
                package_name: package_name.as_str().to_string(),
            });
        }

        let token = generate_verification_token();
        let expires_at = now + Duration::hours(1);

        let identity_desc = platform
            .npm_username
            .as_deref()
            .map(|u| format!("npm user '{u}'"))
            .or_else(|| {
                platform
                    .github_username
                    .as_deref()
                    .map(|u| format!("GitHub user '{u}'"))
            })
            .unwrap_or_default();

        Ok(VerificationChallenge {
            ecosystem: Ecosystem::Npm,
            package_name: package_name.clone(),
            did: did.clone(),
            token,
            instructions: format!(
                "Verify your identity ({identity_desc}) is listed as a maintainer \
                 of npm package '{}'",
                package_name.as_str()
            ),
            expires_at,
        })
    }

    async fn verify(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        _did: &CanonicalDid,
        platform: &PlatformContext,
        _challenge: &VerificationChallenge,
    ) -> Result<NamespaceOwnershipProof, NamespaceVerifyError> {
        let metadata = self.fetch_metadata(package_name.as_str()).await?;

        if let Some(npm_username) = platform.npm_username.as_deref() {
            let is_maintainer = metadata
                .maintainers
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(npm_username));

            if is_maintainer {
                let package_url = self.package_url(package_name.as_str());
                // INVARIANT: package_url is built from a valid base_url
                #[allow(clippy::expect_used)]
                let proof_url = Url::parse(&package_url).expect("package URL is valid");

                return Ok(NamespaceOwnershipProof {
                    ecosystem: Ecosystem::Npm,
                    package_name: package_name.clone(),
                    proof_url,
                    method: VerificationMethod::ApiOwnership,
                    verified_at: now,
                });
            }
        }

        if let Some(github_username) = platform.github_username.as_deref() {
            let github_owner = metadata
                .repository
                .as_ref()
                .and_then(|r| extract_github_owner(&r.url));

            if let Some(owner) = github_owner
                && owner.eq_ignore_ascii_case(github_username)
            {
                let package_url = self.package_url(package_name.as_str());
                // INVARIANT: package_url is built from a valid base_url
                #[allow(clippy::expect_used)]
                let proof_url = Url::parse(&package_url).expect("package URL is valid");

                return Ok(NamespaceOwnershipProof {
                    ecosystem: Ecosystem::Npm,
                    package_name: package_name.clone(),
                    proof_url,
                    method: VerificationMethod::ApiOwnership,
                    verified_at: now,
                });
            }
        }

        Err(NamespaceVerifyError::OwnershipNotConfirmed {
            ecosystem: Ecosystem::Npm,
            package_name: package_name.as_str().to_string(),
        })
    }
}

/// Extract the GitHub owner from a repository URL.
fn extract_github_owner(url: &str) -> Option<String> {
    let url = url.strip_prefix("git+").unwrap_or(url);
    let url = url.strip_suffix(".git").unwrap_or(url);
    let parsed = Url::parse(url).ok()?;
    if parsed.host_str() != Some("github.com") {
        return None;
    }
    let segments: Vec<_> = parsed.path_segments()?.collect();
    if segments.is_empty() || segments[0].is_empty() {
        return None;
    }
    Some(segments[0].to_string())
}

#[derive(Debug, Deserialize)]
struct NpmPackageMetadata {
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    repository: Option<NpmRepository>,
}

#[derive(Debug, Deserialize)]
struct NpmMaintainer {
    name: String,
}

#[derive(Debug, Deserialize)]
struct NpmRepository {
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_github_owner_standard_url() {
        assert_eq!(
            extract_github_owner("https://github.com/expressjs/express"),
            Some("expressjs".to_string())
        );
    }

    #[test]
    fn extract_github_owner_git_plus_url() {
        assert_eq!(
            extract_github_owner("git+https://github.com/expressjs/express.git"),
            Some("expressjs".to_string())
        );
    }

    #[test]
    fn extract_github_owner_non_github() {
        assert_eq!(extract_github_owner("https://gitlab.com/user/repo"), None);
    }

    #[test]
    fn extract_github_owner_empty_path() {
        assert_eq!(extract_github_owner("https://github.com/"), None);
    }

    #[test]
    fn parse_npm_metadata_response() {
        let json = r#"{
            "name": "express",
            "maintainers": [
                { "name": "dougwilson", "email": "doug@somethingdoug.com" },
                { "name": "wesleytodd", "email": "wes@wesleytodd.com" }
            ],
            "repository": {
                "type": "git",
                "url": "git+https://github.com/expressjs/express.git"
            }
        }"#;
        let meta: NpmPackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.maintainers.len(), 2);
        assert_eq!(meta.maintainers[0].name, "dougwilson");
        assert!(meta.repository.is_some());
    }

    #[test]
    fn parse_npm_metadata_empty_maintainers() {
        let json = r#"{"name": "empty-pkg", "maintainers": []}"#;
        let meta: NpmPackageMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.maintainers.is_empty());
        assert!(meta.repository.is_none());
    }

    #[test]
    fn parse_npm_metadata_no_maintainers_field() {
        let json = r#"{"name": "bare-pkg"}"#;
        let meta: NpmPackageMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.maintainers.is_empty());
    }

    #[test]
    fn scoped_package_url_encoding() {
        let verifier = NpmVerifier::new();
        let url = verifier.package_url("@scope/package");
        assert!(url.contains("%40scope%2Fpackage"));
    }
}
