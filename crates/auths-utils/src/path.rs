use std::path::{Path, PathBuf};

/// Expand a leading `~/` or bare `~` to the user's home directory.
///
/// Args:
/// * `path`: A filesystem path that may start with `~`.
///
/// Usage:
/// ```
/// # use std::path::Path;
/// # use auths_utils::path::expand_tilde;
/// let expanded = expand_tilde(Path::new("/tmp/foo")).unwrap();
/// assert_eq!(expanded, Path::new("/tmp/foo"));
/// ```
#[allow(clippy::disallowed_methods)] // INVARIANT: tilde expansion requires OS home-dir lookup
pub fn expand_tilde(path: &Path) -> Result<PathBuf, ExpandTildeError> {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        let home = dirs::home_dir().ok_or(ExpandTildeError::HomeDirNotFound)?;
        if s == "~" {
            Ok(home)
        } else {
            Ok(home.join(&s[2..]))
        }
    } else {
        Ok(path.to_path_buf())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExpandTildeError {
    #[error("could not determine home directory")]
    HomeDirNotFound,
}
