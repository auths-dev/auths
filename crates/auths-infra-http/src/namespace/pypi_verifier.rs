//! PyPI namespace verification adapter.

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

/// PyPI namespace ownership verifier.
///
/// Primary method: cross-references the GitHub repository URL in package metadata
/// with the user's verified GitHub claim. Fallback: checks `ownership.roles` if
/// the user has a verified PyPI username.
///
/// Usage:
/// ```ignore
/// let verifier = PypiVerifier::new();
/// let challenge = verifier.initiate(&package, &did, &platform).await?;
/// let proof = verifier.verify(&package, &did, &platform, &challenge).await?;
/// ```
pub struct PypiVerifier {
    client: reqwest::Client,
    base_url: Url,
}

impl PypiVerifier {
    /// Create a new verifier targeting the production PyPI API.
    pub fn new() -> Self {
        Self {
            client: crate::default_http_client(),
            // INVARIANT: hardcoded valid URL
            #[allow(clippy::expect_used)]
            base_url: Url::parse("https://pypi.org").expect("valid URL"),
        }
    }

    /// Create a verifier with a custom base URL (for testing).
    ///
    /// Args:
    /// * `base_url`: The base URL to use instead of `https://pypi.org`.
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            client: crate::default_http_client(),
            base_url,
        }
    }

    fn package_url(&self, package_name: &str) -> String {
        let normalized = normalize_pypi_name(package_name);
        format!("{}/pypi/{}/json", self.base_url, normalized)
    }

    async fn fetch_metadata(
        &self,
        package_name: &str,
    ) -> Result<PypiResponse, NamespaceVerifyError> {
        let url = self.package_url(package_name);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| NamespaceVerifyError::NetworkError {
                    message: e.to_string(),
                })?;

        match resp.status().as_u16() {
            200 => {}
            404 => {
                return Err(NamespaceVerifyError::PackageNotFound {
                    ecosystem: Ecosystem::Pypi,
                    package_name: package_name.to_string(),
                });
            }
            429 => {
                return Err(NamespaceVerifyError::RateLimited {
                    ecosystem: Ecosystem::Pypi,
                });
            }
            status => {
                return Err(NamespaceVerifyError::NetworkError {
                    message: format!("PyPI returned HTTP {status}"),
                });
            }
        }

        resp.json()
            .await
            .map_err(|e| NamespaceVerifyError::NetworkError {
                message: format!("failed to parse PyPI response: {e}"),
            })
    }
}

impl Default for PypiVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NamespaceVerifier for PypiVerifier {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    async fn initiate(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        platform: &PlatformContext,
    ) -> Result<VerificationChallenge, NamespaceVerifyError> {
        self.fetch_metadata(package_name.as_str()).await?;

        if platform.github_username.is_none() && platform.pypi_username.is_none() {
            return Err(NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Pypi,
                package_name: package_name.as_str().to_string(),
            });
        }

        let token = generate_verification_token();
        let expires_at = now + Duration::hours(1);

        let identity_desc = platform
            .github_username
            .as_deref()
            .map(|u| format!("GitHub account ({u})"))
            .unwrap_or_else(|| "your verified identity".to_string());

        Ok(VerificationChallenge {
            ecosystem: Ecosystem::Pypi,
            package_name: package_name.clone(),
            did: did.clone(),
            token,
            instructions: format!(
                "Your {identity_desc} will be verified against the package's \
                 repository link for '{}'",
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
        let response = self.fetch_metadata(package_name.as_str()).await?;

        if let Some(github_username) = platform.github_username.as_deref() {
            let github_owner = extract_github_owner_from_pypi(&response.info);
            if let Some(owner) = github_owner
                && owner.eq_ignore_ascii_case(github_username)
            {
                let package_url = self.package_url(package_name.as_str());
                // INVARIANT: package_url is built from a valid base_url
                #[allow(clippy::expect_used)]
                let proof_url = Url::parse(&package_url).expect("package URL is valid");

                return Ok(NamespaceOwnershipProof {
                    ecosystem: Ecosystem::Pypi,
                    package_name: package_name.clone(),
                    proof_url,
                    method: VerificationMethod::ApiOwnership,
                    verified_at: now,
                });
            }
        }

        if let Some(pypi_username) = platform.pypi_username.as_deref()
            && let Some(ownership) = &response.ownership
        {
            let is_owner = ownership.roles.iter().any(|r| {
                (r.role == "Owner" || r.role == "Maintainer")
                    && r.user.eq_ignore_ascii_case(pypi_username)
            });

            if is_owner {
                let package_url = self.package_url(package_name.as_str());
                #[allow(clippy::expect_used)]
                let proof_url = Url::parse(&package_url).expect("package URL is valid");

                return Ok(NamespaceOwnershipProof {
                    ecosystem: Ecosystem::Pypi,
                    package_name: package_name.clone(),
                    proof_url,
                    method: VerificationMethod::ApiOwnership,
                    verified_at: now,
                });
            }
        }

        Err(NamespaceVerifyError::OwnershipNotConfirmed {
            ecosystem: Ecosystem::Pypi,
            package_name: package_name.as_str().to_string(),
        })
    }
}

/// Normalize a PyPI package name: lowercase, replace underscores and dots with hyphens.
fn normalize_pypi_name(name: &str) -> String {
    name.to_lowercase().replace(['_', '.'], "-")
}

/// Extract GitHub owner from PyPI package info's project_urls or home_page.
fn extract_github_owner_from_pypi(info: &PypiInfo) -> Option<String> {
    let github_keys = [
        "Source",
        "Repository",
        "Source Code",
        "GitHub",
        "Homepage",
        "Code",
    ];

    if let Some(project_urls) = &info.project_urls {
        for key in &github_keys {
            if let Some(url) = project_urls.get(*key)
                && let Some(owner) = extract_github_owner(url)
            {
                return Some(owner);
            }
        }
    }

    if let Some(home_page) = &info.home_page
        && let Some(owner) = extract_github_owner(home_page)
    {
        return Some(owner);
    }

    None
}

/// Extract the GitHub owner from a URL.
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
struct PypiResponse {
    info: PypiInfo,
    ownership: Option<PypiOwnership>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    project_urls: Option<std::collections::HashMap<String, String>>,
    home_page: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiOwnership {
    #[serde(default)]
    roles: Vec<PypiRole>,
}

#[derive(Debug, Deserialize)]
struct PypiRole {
    role: String,
    user: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pypi_name_hyphens_underscores_dots() {
        assert_eq!(normalize_pypi_name("My_Package"), "my-package");
        assert_eq!(normalize_pypi_name("some.thing"), "some-thing");
        assert_eq!(normalize_pypi_name("REQUESTS"), "requests");
        assert_eq!(normalize_pypi_name("my-package"), "my-package");
        assert_eq!(normalize_pypi_name("Mixed_Case.Dots"), "mixed-case-dots");
    }

    #[test]
    fn extract_github_owner_from_standard_url() {
        assert_eq!(
            extract_github_owner("https://github.com/psf/requests"),
            Some("psf".to_string())
        );
    }

    #[test]
    fn extract_github_owner_from_git_plus_url() {
        assert_eq!(
            extract_github_owner("git+https://github.com/psf/requests.git"),
            Some("psf".to_string())
        );
    }

    #[test]
    fn extract_github_owner_non_github() {
        assert_eq!(
            extract_github_owner("https://bitbucket.org/user/repo"),
            None
        );
    }

    #[test]
    fn extract_owner_from_pypi_project_urls() {
        let info = PypiInfo {
            project_urls: Some(
                [(
                    "Source".to_string(),
                    "https://github.com/psf/requests".to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            home_page: None,
        };
        assert_eq!(
            extract_github_owner_from_pypi(&info),
            Some("psf".to_string())
        );
    }

    #[test]
    fn extract_owner_from_pypi_home_page_fallback() {
        let info = PypiInfo {
            project_urls: Some(
                [(
                    "Documentation".to_string(),
                    "https://docs.example.com".to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            home_page: Some("https://github.com/owner/repo".to_string()),
        };
        assert_eq!(
            extract_github_owner_from_pypi(&info),
            Some("owner".to_string())
        );
    }

    #[test]
    fn extract_owner_from_pypi_no_github_url() {
        let info = PypiInfo {
            project_urls: Some(
                [(
                    "Documentation".to_string(),
                    "https://docs.example.com".to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            home_page: Some("https://example.com".to_string()),
        };
        assert_eq!(extract_github_owner_from_pypi(&info), None);
    }

    #[test]
    fn parse_pypi_response_with_ownership() {
        let json = r#"{
            "info": {
                "name": "requests",
                "home_page": "https://requests.readthedocs.io",
                "project_urls": {
                    "Source": "https://github.com/psf/requests"
                }
            },
            "ownership": {
                "roles": [
                    { "role": "Owner", "user": "Lukasa" },
                    { "role": "Maintainer", "user": "nateprewitt" }
                ]
            }
        }"#;
        let resp: PypiResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ownership.is_some());
        assert_eq!(resp.ownership.as_ref().unwrap().roles.len(), 2);
    }

    #[test]
    fn parse_pypi_response_without_ownership() {
        let json = r#"{
            "info": {
                "name": "some-pkg",
                "project_urls": null,
                "home_page": null
            }
        }"#;
        let resp: PypiResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ownership.is_none());
    }
}
