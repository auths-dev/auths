//! CI environment detection and typed metadata for ephemeral signing.

use serde::{Deserialize, Serialize};

/// CI platform identifier.
///
/// Usage:
/// ```ignore
/// let platform = CiPlatform::GithubActions;
/// assert_eq!(serde_json::to_string(&platform)?, "\"github_actions\"");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiPlatform {
    /// GitHub Actions.
    GithubActions,
    /// GitLab CI/CD.
    GitlabCi,
    /// CircleCI.
    CircleCi,
    /// Generic CI platform (detected via `CI` env var).
    Generic,
    /// Local development (explicit opt-in via `--ci-platform local`).
    Local,
}

/// Structured CI environment metadata embedded in ephemeral attestations.
///
/// Serialized into the attestation `payload` (covered by signature). The
/// shape mirrors SLSA provenance's `invocation`/`builder` triple: *which
/// source* (`repository` + `sha`), *which workflow* (`workflow_ref`), and
/// *which run* (`run_id`). Capturing all three under signature is what lets
/// a verifier bind an artifact to a specific commit of a specific repo built
/// by a specific workflow — rather than trusting the runner's word for it.
///
/// Args:
/// * `platform` - CI platform identifier.
/// * `repository` - Source repository, `owner/name` (SLSA source identity).
/// * `workflow_ref` - Fully-qualified workflow reference (SLSA builder id).
/// * `sha` - Commit SHA the workflow ran against (SLSA source digest).
/// * `run_id` - CI run identifier.
/// * `actor` - User or bot that triggered the run.
/// * `runner_os` - OS of the CI runner.
///
/// Usage:
/// ```ignore
/// let env = detect_ci_environment().unwrap();
/// assert_eq!(env.platform, CiPlatform::GithubActions);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiEnvironment {
    /// CI platform.
    pub platform: CiPlatform,
    /// Source repository in `owner/name` form (SLSA source identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Fully-qualified workflow reference — the SLSA builder identity, e.g.
    /// `owner/repo/.github/workflows/release.yml@refs/tags/v1` on GitHub.
    /// Falls back to the bare workflow name only when the canonical ref is
    /// unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,
    /// Commit SHA the workflow ran against (SLSA source digest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// CI run identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// User or bot that triggered the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// OS of the CI runner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_os: Option<String>,
}

/// Detect CI environment from standard environment variables.
///
/// Returns `None` if no CI environment is detected.
///
/// Usage:
/// ```ignore
/// if let Some(env) = detect_ci_environment() {
///     println!("Running in {:?}", env.platform);
/// }
/// ```
#[allow(clippy::disallowed_methods)] // CLI boundary: reading CI env vars
pub fn detect_ci_environment() -> Option<CiEnvironment> {
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
        return Some(CiEnvironment {
            platform: CiPlatform::GithubActions,
            repository: std::env::var("GITHUB_REPOSITORY").ok(),
            // Prefer the SLSA-canonical fully-qualified ref; the bare
            // workflow name is only a fallback for runners that don't set it.
            workflow_ref: std::env::var("GITHUB_WORKFLOW_REF")
                .ok()
                .or_else(|| std::env::var("GITHUB_WORKFLOW").ok()),
            sha: std::env::var("GITHUB_SHA").ok(),
            run_id: std::env::var("GITHUB_RUN_ID").ok(),
            actor: std::env::var("GITHUB_ACTOR").ok(),
            runner_os: std::env::var("RUNNER_OS").ok(),
        });
    }

    if std::env::var("GITLAB_CI").is_ok() {
        return Some(CiEnvironment {
            platform: CiPlatform::GitlabCi,
            repository: std::env::var("CI_PROJECT_PATH").ok(),
            workflow_ref: std::env::var("CI_CONFIG_PATH").ok(),
            sha: std::env::var("CI_COMMIT_SHA").ok(),
            run_id: std::env::var("CI_PIPELINE_ID").ok(),
            actor: std::env::var("GITLAB_USER_LOGIN").ok(),
            runner_os: None,
        });
    }

    if std::env::var("CIRCLECI").is_ok() {
        return Some(CiEnvironment {
            platform: CiPlatform::CircleCi,
            repository: std::env::var("CIRCLE_PROJECT_REPONAME").ok(),
            workflow_ref: std::env::var("CIRCLE_WORKFLOW_ID").ok(),
            sha: std::env::var("CIRCLE_SHA1").ok(),
            run_id: std::env::var("CIRCLE_BUILD_NUM").ok(),
            actor: std::env::var("CIRCLE_USERNAME").ok(),
            runner_os: None,
        });
    }

    if std::env::var("CI").is_ok() {
        return Some(CiEnvironment {
            platform: CiPlatform::Generic,
            repository: None,
            workflow_ref: None,
            sha: None,
            run_id: None,
            actor: None,
            runner_os: None,
        });
    }

    None
}
