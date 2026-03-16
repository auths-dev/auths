//! crates.io namespace verification adapter.

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

/// crates.io namespace ownership verifier.
///
/// Verifies crate ownership by cross-referencing the crates.io owners API
/// with the user's verified GitHub platform claim.
///
/// Usage:
/// ```ignore
/// let verifier = CargoVerifier::new();
/// let challenge = verifier.initiate(&package, &did, &platform).await?;
/// let proof = verifier.verify(&package, &did, &platform, &challenge).await?;
/// ```
pub struct CargoVerifier {
    client: reqwest::Client,
    base_url: Url,
}

impl CargoVerifier {
    /// Create a new verifier targeting the production crates.io API.
    pub fn new() -> Self {
        Self {
            client: crate::default_http_client(),
            // INVARIANT: hardcoded valid URL
            #[allow(clippy::expect_used)]
            base_url: Url::parse("https://crates.io").expect("valid URL"),
        }
    }

    /// Create a verifier with a custom base URL (for testing).
    ///
    /// Args:
    /// * `base_url`: The base URL to use instead of `https://crates.io`.
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            client: crate::default_http_client(),
            base_url,
        }
    }

    fn owners_url(&self, crate_name: &str) -> String {
        format!("{}/api/v1/crates/{}/owners", self.base_url, crate_name)
    }

    fn crate_url(&self, crate_name: &str) -> String {
        format!("{}/api/v1/crates/{}", self.base_url, crate_name)
    }

    async fn fetch_crate_exists(&self, crate_name: &str) -> Result<(), NamespaceVerifyError> {
        let url = self.crate_url(crate_name);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| NamespaceVerifyError::NetworkError {
                    message: e.to_string(),
                })?;

        match resp.status().as_u16() {
            200 => Ok(()),
            404 => Err(NamespaceVerifyError::PackageNotFound {
                ecosystem: Ecosystem::Cargo,
                package_name: crate_name.to_string(),
            }),
            429 => Err(NamespaceVerifyError::RateLimited {
                ecosystem: Ecosystem::Cargo,
            }),
            status => Err(NamespaceVerifyError::NetworkError {
                message: format!("crates.io returned HTTP {status}"),
            }),
        }
    }

    async fn fetch_owners(
        &self,
        crate_name: &str,
    ) -> Result<Vec<CratesIoOwner>, NamespaceVerifyError> {
        let url = self.owners_url(crate_name);
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
                    ecosystem: Ecosystem::Cargo,
                    package_name: crate_name.to_string(),
                });
            }
            429 => {
                return Err(NamespaceVerifyError::RateLimited {
                    ecosystem: Ecosystem::Cargo,
                });
            }
            status => {
                return Err(NamespaceVerifyError::NetworkError {
                    message: format!("crates.io owners API returned HTTP {status}"),
                });
            }
        }

        let body: CratesIoOwnersResponse =
            resp.json()
                .await
                .map_err(|e| NamespaceVerifyError::NetworkError {
                    message: format!("failed to parse crates.io owners response: {e}"),
                })?;

        Ok(body.users)
    }
}

impl Default for CargoVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NamespaceVerifier for CargoVerifier {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    async fn initiate(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        platform: &PlatformContext,
    ) -> Result<VerificationChallenge, NamespaceVerifyError> {
        self.fetch_crate_exists(package_name.as_str()).await?;

        let github_username = platform.github_username.as_deref().ok_or_else(|| {
            NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Cargo,
                package_name: package_name.as_str().to_string(),
            }
        })?;

        let token = generate_verification_token();
        let expires_at = now + Duration::hours(1);

        Ok(VerificationChallenge {
            ecosystem: Ecosystem::Cargo,
            package_name: package_name.clone(),
            did: did.clone(),
            token,
            instructions: format!(
                "Verify your GitHub account ({github_username}) is listed as an owner \
                 of crate '{}' on crates.io",
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
        let github_username = platform.github_username.as_deref().ok_or_else(|| {
            NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Cargo,
                package_name: package_name.as_str().to_string(),
            }
        })?;

        let owners = self.fetch_owners(package_name.as_str()).await?;

        let is_owner = owners.iter().any(|owner| {
            if owner.kind == "user" {
                owner.login.eq_ignore_ascii_case(github_username)
            } else if owner.kind == "team" {
                extract_team_org(&owner.login)
                    .is_some_and(|org| github_username.eq_ignore_ascii_case(org))
            } else {
                false
            }
        });

        if !is_owner {
            return Err(NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Cargo,
                package_name: package_name.as_str().to_string(),
            });
        }

        let owners_url = self.owners_url(package_name.as_str());
        // INVARIANT: owners_url is built from a valid base_url
        #[allow(clippy::expect_used)]
        let proof_url = Url::parse(&owners_url).expect("owners URL is valid");

        Ok(NamespaceOwnershipProof {
            ecosystem: Ecosystem::Cargo,
            package_name: package_name.clone(),
            proof_url,
            method: VerificationMethod::ApiOwnership,
            verified_at: now,
        })
    }
}

/// Extract org name from team login format `github:org:team`.
fn extract_team_org(login: &str) -> Option<&str> {
    let parts: Vec<&str> = login.split(':').collect();
    if parts.len() >= 2 && parts[0] == "github" {
        Some(parts[1])
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
struct CratesIoOwnersResponse {
    users: Vec<CratesIoOwner>,
}

#[derive(Debug, Deserialize)]
struct CratesIoOwner {
    login: String,
    kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_team_org_from_team_login() {
        assert_eq!(
            extract_team_org("github:serde-rs:publish"),
            Some("serde-rs")
        );
        assert_eq!(extract_team_org("github:myorg:team"), Some("myorg"));
    }

    #[test]
    fn extract_team_org_returns_none_for_user_login() {
        assert_eq!(extract_team_org("dtolnay"), None);
        assert_eq!(extract_team_org(""), None);
    }

    #[test]
    fn owner_matching_case_insensitive() {
        let owners = [
            CratesIoOwner {
                login: "DTolnay".to_string(),
                kind: "user".to_string(),
            },
            CratesIoOwner {
                login: "github:serde-rs:publish".to_string(),
                kind: "team".to_string(),
            },
        ];

        let found_user = owners
            .iter()
            .any(|o| o.kind == "user" && o.login.eq_ignore_ascii_case("dtolnay"));
        assert!(found_user);

        let found_team = owners.iter().any(|o| {
            o.kind == "team"
                && extract_team_org(&o.login)
                    .is_some_and(|org| "serde-rs".eq_ignore_ascii_case(org))
        });
        assert!(found_team);
    }

    #[test]
    fn owner_not_found_in_list() {
        let owners = [CratesIoOwner {
            login: "someone-else".to_string(),
            kind: "user".to_string(),
        }];

        let found = owners
            .iter()
            .any(|o| o.kind == "user" && o.login.eq_ignore_ascii_case("myuser"));
        assert!(!found);
    }

    #[test]
    fn parse_owners_response() {
        let json = r#"{"users":[{"id":3618,"login":"dtolnay","kind":"user","url":"https://github.com/dtolnay","name":"David Tolnay"},{"id":8138,"login":"github:serde-rs:publish","kind":"team","url":"https://github.com/serde-rs"}]}"#;
        let resp: CratesIoOwnersResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.users.len(), 2);
        assert_eq!(resp.users[0].login, "dtolnay");
        assert_eq!(resp.users[0].kind, "user");
        assert_eq!(resp.users[1].login, "github:serde-rs:publish");
        assert_eq!(resp.users[1].kind, "team");
    }
}
