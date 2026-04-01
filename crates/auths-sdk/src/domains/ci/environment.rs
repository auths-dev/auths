//! CI environment detection.
//!
//! Detects the CI platform from environment variables. This is domain logic
//! that agents and servers need — not just the CLI.

use super::types::CiEnvironment;

/// Detect the CI platform from well-known environment variables.
///
/// Args:
/// * `detected_name`: Optional CI platform name string (e.g. from prior detection).
///   If `None`, returns `CiEnvironment::Unknown`.
///
/// Usage:
/// ```ignore
/// let env = map_ci_environment(&Some("GitHub Actions".into()));
/// ```
pub fn map_ci_environment(detected_name: &Option<String>) -> CiEnvironment {
    match detected_name.as_deref() {
        Some("GitHub Actions") => CiEnvironment::GitHubActions,
        Some("GitLab CI") => CiEnvironment::GitLabCi,
        Some(name) => CiEnvironment::Custom {
            name: name.to_string(),
        },
        None => CiEnvironment::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_github_actions() {
        let env = map_ci_environment(&Some("GitHub Actions".into()));
        assert!(matches!(env, CiEnvironment::GitHubActions));
    }

    #[test]
    fn detects_gitlab_ci() {
        let env = map_ci_environment(&Some("GitLab CI".into()));
        assert!(matches!(env, CiEnvironment::GitLabCi));
    }

    #[test]
    fn detects_custom_ci() {
        let env = map_ci_environment(&Some("Buildkite".into()));
        assert!(matches!(env, CiEnvironment::Custom { name } if name == "Buildkite"));
    }

    #[test]
    fn returns_unknown_for_none() {
        let env = map_ci_environment(&None);
        assert!(matches!(env, CiEnvironment::Unknown));
    }
}
