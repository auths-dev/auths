//! GitHub OIDC cross-reference: verifies a GitHub token and validates
//! the actor matches the expected KERI identity linkage.

use crate::error::BridgeError;
use crate::github_oidc::{JwksClient, verify_github_token};

/// Result of a successful GitHub OIDC cross-reference.
///
/// Args:
/// * `actor`: The verified GitHub username from the token.
/// * `repository`: The repository from the GitHub token.
///
/// Usage:
/// ```ignore
/// let result = verify_github_cross_reference(&token, "octocat", &client).await?;
/// assert_eq!(result.actor, "octocat");
/// ```
#[derive(Debug, Clone)]
pub struct CrossReferenceResult {
    pub actor: String,
    pub repository: String,
}

/// Verifies a GitHub OIDC token and cross-references the actor against the expected identity.
///
/// Args:
/// * `token`: The raw GitHub Actions OIDC JWT.
/// * `expected_actor`: The GitHub username expected to match the KERI identity.
/// * `jwks_client`: The JWKS client for token verification.
///
/// Usage:
/// ```ignore
/// let result = verify_github_cross_reference(&gh_token, "octocat", &jwks_client).await?;
/// ```
pub async fn verify_github_cross_reference(
    token: &str,
    expected_actor: &str,
    jwks_client: &JwksClient,
) -> Result<CrossReferenceResult, BridgeError> {
    let claims = verify_github_token(token, jwks_client).await?;

    if claims.actor != expected_actor {
        tracing::warn!(
            expected_actor = expected_actor,
            actual_actor = claims.actor,
            repository = claims.repository,
            "GitHub actor mismatch"
        );
        return Err(BridgeError::ActorMismatch {
            expected: expected_actor.to_string(),
            actual: claims.actor,
        });
    }

    tracing::info!(
        actor = claims.actor,
        repository = claims.repository,
        "GitHub OIDC cross-reference verified"
    );

    Ok(CrossReferenceResult {
        actor: claims.actor,
        repository: claims.repository,
    })
}
