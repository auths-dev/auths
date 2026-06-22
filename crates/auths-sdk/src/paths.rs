//! Re-exports of path utilities from `auths-core`.

use std::path::PathBuf;

use auths_core::paths::AuthsHomeError;

pub use auths_core::paths::{auths_home, auths_home_with_config};

/// Resolve the registry (local storage) directory for a command, honoring an explicit `--repo` override.
///
/// When `override_path` is `Some` (the user passed `--repo <dir>`), that directory is used verbatim, so
/// the command's identity store and existing-identity check are scoped to it rather than silently
/// falling back to the default `~/.auths`. When `None`, the default home is used.
///
/// Args:
/// * `override_path`: the `--repo` override, if the user supplied one.
///
/// Usage:
/// ```ignore
/// let registry_path = resolve_registry_path(ctx.repo_path.clone())?;
/// ```
pub fn resolve_registry_path(override_path: Option<PathBuf>) -> Result<PathBuf, AuthsHomeError> {
    match override_path {
        Some(p) => Ok(p),
        None => auths_home(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_registry_path_honors_override() {
        // --repo <dir> must scope storage to <dir>, not silently fall back to the default home
        let custom = PathBuf::from("/tmp/auths-custom-repo-xyz");
        assert_eq!(resolve_registry_path(Some(custom.clone())).unwrap(), custom);
    }
}
