use anyhow::Result;
use std::path::Path;

/// Write data to a file with restrictive permissions (0o600 on Unix).
///
/// Uses atomic temp-file-then-rename to avoid TOCTOU races where the file
/// exists with default permissions before being restricted.
///
/// Args:
/// * `path` - Destination file path.
/// * `data` - Bytes to write.
pub fn write_sensitive_file(path: &Path, data: impl AsRef<[u8]>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("No parent directory for {:?}", path))?;

        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        // NamedTempFile creates with 0o600 by default on most systems,
        // but we set it explicitly via the persisted file permissions.
        tmp.write_all(data.as_ref())?;
        tmp.flush()?;

        let tmp_path = tmp.into_temp_path();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        tmp_path.persist(path)?;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        log::warn!("Restrictive file permissions not enforced on this platform");
        std::fs::write(path, data)?;
        Ok(())
    }
}

/// Create a directory with restrictive permissions (0o700 on Unix).
///
/// Args:
/// * `path` - Directory path to create (including parents).
pub fn create_restricted_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // Create parents with default permissions first
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    // Tighten permissions on existing directory
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
                    Ok(())
                } else {
                    Err(e.into())
                }
            })
    }

    #[cfg(not(unix))]
    {
        log::warn!("Restrictive directory permissions not enforced on this platform");
        std::fs::create_dir_all(path)?;
        Ok(())
    }
}
