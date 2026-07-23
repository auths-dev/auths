//! Re-exports of path utilities from `auths-core`.

use std::path::PathBuf;

pub use auths_core::paths::{auths_home, auths_home_with_config, AuthsHomeError, AuthsPaths};

/// Resolve the registry (local storage) directory for a command, honoring an explicit `--repo` override.
///
/// Delegates to `AuthsPaths::resolve(override_path.as_deref())`.
pub fn resolve_registry_path(override_path: Option<PathBuf>) -> Result<PathBuf, AuthsHomeError> {
    AuthsPaths::resolve(override_path.as_deref()).map(|p| p.registry_dir)
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
