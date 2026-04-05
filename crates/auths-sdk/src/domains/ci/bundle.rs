//! Identity repo bundler — packages `~/.auths` into a portable base64 tar.gz.

use super::error::CiError;
use base64::Engine as _;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use std::path::Path;
use tar::Builder;
use walkdir::WalkDir;

/// Build a base64-encoded tar.gz of the identity repo directory.
///
/// Creates a flat archive (contents at root, no directory prefix) excluding
/// `*.sock` and `*.lock` files. Sets `mtime(0)` for reproducible archives.
///
/// Args:
/// * `auths_dir`: Path to the `~/.auths` directory to bundle.
///
/// Usage:
/// ```ignore
/// let b64 = build_identity_bundle(Path::new("/home/user/.auths"))?;
/// ```
pub fn build_identity_bundle(auths_dir: &Path) -> Result<String, CiError> {
    let mut buf = Vec::new();
    {
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut archive = Builder::new(gz);
        add_dir_to_tar(&mut archive, auths_dir, Path::new("."))?;
        let gz = archive.into_inner().map_err(|e| CiError::BundleFailed {
            reason: format!("tar finalize: {e}"),
        })?;
        gz.finish().map_err(|e| CiError::BundleFailed {
            reason: format!("gzip finalize: {e}"),
        })?;
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&buf))
}

/// Recursively add a directory to a tar archive, excluding `*.sock` and `*.lock` files.
fn add_dir_to_tar<W: Write>(
    archive: &mut Builder<W>,
    src_dir: &Path,
    prefix: &Path,
) -> Result<(), CiError> {
    for entry in WalkDir::new(src_dir).follow_links(false) {
        let entry = entry.map_err(|e| CiError::BundleFailed {
            reason: format!("walk: {e}"),
        })?;
        let path = entry.path();

        // Exclude socket and lock files
        if let Some(ext) = path.extension()
            && (ext == "sock" || ext == "lock")
        {
            continue;
        }

        let rel = path
            .strip_prefix(src_dir)
            .map_err(|e| CiError::BundleFailed {
                reason: format!("strip prefix: {e}"),
            })?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let archive_path = prefix.join(rel);

        let metadata = entry.metadata().map_err(|e| CiError::BundleFailed {
            reason: format!("metadata for {}: {e}", path.display()),
        })?;

        if metadata.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, &archive_path, &[] as &[u8])
                .map_err(|e| CiError::BundleFailed {
                    reason: format!("append dir {}: {e}", archive_path.display()),
                })?;
        } else if metadata.is_file() {
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: bundle must read identity repo files from disk
            let data = std::fs::read(path).map_err(|e| CiError::BundleFailed {
                reason: format!("read {}: {e}", path.display()),
            })?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, &archive_path, data.as_slice())
                .map_err(|e| CiError::BundleFailed {
                    reason: format!("append file {}: {e}", archive_path.display()),
                })?;
        }
        // Skip symlinks, sockets, etc.
    }
    Ok(())
}

/// Generate a cryptographically secure passphrase for CI device keys.
///
/// Returns a 64-character hex string (32 random bytes), which is shell-safe
/// across all platforms (no special characters that need escaping).
///
/// Usage:
/// ```ignore
/// let passphrase = generate_ci_passphrase();
/// assert_eq!(passphrase.len(), 64);
/// ```
pub fn generate_ci_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
