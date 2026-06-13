//! The sign-time half of the keyless CI exchange: validate the runner's
//! OIDC token and turn it into a signature-covered [`OidcBinding`].
//!
//! The runner never holds an org key. It presents the token its CI platform
//! minted for the job; we validate it — signature against the issuer's JWKS,
//! issuer, audience, expiry — and embed the verified, platform-normalized
//! claims in the attestation's signed envelope. The org's side of the
//! exchange happens at verify time: `artifact verify --oidc-policy` joins
//! these claims against the OIDC-subject policy the org pinned.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use auths_infra_http::{HttpJwksClient, HttpJwtValidator, PinnedJwksClient};
use auths_sdk::domains::signing::ci_env::CiPlatform;
use auths_sdk::workflows::ci::machine_identity::{
    OidcMachineIdentityConfig, create_machine_identity_from_oidc_token,
};
use auths_verifier::core::OidcBinding;

/// The default OIDC issuer when none is given: GitHub Actions, the platform
/// the zero-secret CI story ships on first.
pub const DEFAULT_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Map the detected CI platform onto the OIDC claim-normalization platform.
///
/// Fail-closed: a platform without a known OIDC claim shape cannot produce a
/// binding the policy join can trust, so it is an error — never a guess.
fn oidc_platform(platform: &CiPlatform) -> Result<&'static str> {
    match platform {
        CiPlatform::GithubActions => Ok("github"),
        CiPlatform::GitlabCi => Ok("gitlab"),
        CiPlatform::CircleCi => Ok("circleci"),
        CiPlatform::Generic | CiPlatform::Local => bail!(
            "--oidc-token needs a CI platform with a known OIDC claim shape \
             (GitHub Actions, GitLab CI, or CircleCI) — detected {:?}",
            platform
        ),
    }
}

/// Validate an OIDC token and return the verified binding to embed.
///
/// Args:
/// * `token_path`: File holding the raw JWT (tokens are bearer secrets —
///   they travel by file, never argv).
/// * `issuer`: Expected token issuer (exact match).
/// * `audience`: Expected token audience (exact match).
/// * `jwks_path`: Optional pinned JWKS file. When absent, the issuer's
///   published JWKS is fetched over HTTPS.
/// * `platform`: The CI platform whose claim shape normalizes the token.
/// * `now`: Current time for expiry validation.
pub fn resolve_oidc_binding(
    token_path: &Path,
    issuer: &str,
    audience: &str,
    jwks_path: Option<&Path>,
    platform: &CiPlatform,
    now: DateTime<Utc>,
) -> Result<OidcBinding> {
    let oidc_platform = oidc_platform(platform)?;

    let token = std::fs::read_to_string(token_path)
        .with_context(|| format!("Failed to read OIDC token from {token_path:?}"))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("OIDC token file {token_path:?} is empty");
    }

    let validator = match jwks_path {
        Some(path) => {
            let jwks_raw = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read pinned JWKS from {path:?}"))?;
            let jwks: serde_json::Value = serde_json::from_str(&jwks_raw)
                .with_context(|| format!("Pinned JWKS {path:?} is not valid JSON"))?;
            HttpJwtValidator::new(Arc::new(PinnedJwksClient::new(jwks)))
        }
        None => HttpJwtValidator::new(Arc::new(HttpJwksClient::with_default_ttl())),
    };

    let config = OidcMachineIdentityConfig {
        issuer: issuer.to_string(),
        audience: audience.to_string(),
        platform: oidc_platform.to_string(),
    };

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let identity = rt
        .block_on(create_machine_identity_from_oidc_token(
            token,
            config,
            Arc::new(validator),
            now,
        ))
        .map_err(|e| anyhow::anyhow!("OIDC token validation failed: {e}"))?;

    Ok(OidcBinding::from(&identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_platform_cannot_present_a_token() {
        let err = oidc_platform(&CiPlatform::Local).expect_err("local must be rejected");
        assert!(err.to_string().contains("known OIDC claim shape"));
    }

    #[test]
    fn github_maps_to_github_claim_shape() {
        assert_eq!(oidc_platform(&CiPlatform::GithubActions).unwrap(), "github");
    }
}
