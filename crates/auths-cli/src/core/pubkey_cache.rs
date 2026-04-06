//! Public key cache for passphrase-free signing.
//!
//! This module caches public keys in `~/.auths/pubkeys/<alias>.pub` to enable
//! truly passphrase-free signing after first use. The agent can use these
//! cached public keys to verify which key to use for signing without needing
//! to decrypt the private key.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::PathBuf;

use super::fs::{create_restricted_dir, write_sensitive_file};

/// Get the pubkey cache directory path (~/.auths/pubkeys), respecting AUTHS_HOME.
fn get_pubkey_cache_dir() -> Result<PathBuf> {
    Ok(auths_sdk::paths::auths_home()
        .map_err(|e| anyhow!(e))?
        .join("pubkeys"))
}

/// Get the cache file path for a specific alias.
fn get_cache_path(alias: &str) -> Result<PathBuf> {
    let dir = get_pubkey_cache_dir()?;
    // Sanitize alias to prevent path traversal
    let safe_alias = alias.replace(['/', '\\', '\0'], "_");
    Ok(dir.join(format!("{}.pub", safe_alias)))
}

/// Cache a public key for the given alias.
///
/// The public key is stored as hex-encoded bytes in `~/.auths/pubkeys/<alias>.pub`.
///
/// # Arguments
/// * `alias` - The key alias (e.g., "default").
/// * `pubkey` - The 32-byte Ed25519 public key bytes.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err` if the cache directory cannot be created or the file cannot be written.
pub fn cache_pubkey(alias: &str, pubkey: &[u8]) -> Result<()> {
    if pubkey.len() != 32 {
        return Err(anyhow!(
            "Invalid public key length: expected 32 bytes, got {}",
            pubkey.len()
        ));
    }

    let cache_dir = get_pubkey_cache_dir()?;
    create_restricted_dir(&cache_dir)
        .with_context(|| format!("Failed to create pubkey cache directory: {:?}", cache_dir))?;

    let cache_path = get_cache_path(alias)?;
    let hex_pubkey = hex::encode(pubkey);

    write_sensitive_file(&cache_path, &hex_pubkey)
        .with_context(|| format!("Failed to write pubkey cache file: {:?}", cache_path))?;

    Ok(())
}

/// Get a cached public key for the given alias.
///
/// # Arguments
/// * `alias` - The key alias (e.g., "default").
///
/// # Returns
/// * `Ok(Some(Vec<u8>))` - The 32-byte public key if cached.
/// * `Ok(None)` - If no cache exists for this alias.
/// * `Err` - If there's an error reading or parsing the cache.
pub fn get_cached_pubkey(alias: &str) -> Result<Option<Vec<u8>>> {
    let cache_path = get_cache_path(alias)?;

    if !cache_path.exists() {
        return Ok(None);
    }

    let hex_pubkey = fs::read_to_string(&cache_path)
        .with_context(|| format!("Failed to read pubkey cache file: {:?}", cache_path))?;

    let pubkey = hex::decode(hex_pubkey.trim())
        .with_context(|| format!("Invalid hex in pubkey cache file: {:?}", cache_path))?;

    if pubkey.len() != 32 {
        return Err(anyhow!(
            "Invalid cached public key length in {:?}: expected 32 bytes, got {}",
            cache_path,
            pubkey.len()
        ));
    }

    Ok(Some(pubkey))
}

/// Clear the cached public key for the given alias.
///
/// This should be called when a key is deleted or rotated.
///
/// # Arguments
/// * `alias` - The key alias (e.g., "default").
///
/// # Returns
/// * `Ok(true)` - If the cache was cleared.
/// * `Ok(false)` - If no cache existed for this alias.
/// * `Err` - If there's an error deleting the cache file.
pub fn clear_cached_pubkey(alias: &str) -> Result<bool> {
    let cache_path = get_cache_path(alias)?;

    if !cache_path.exists() {
        return Ok(false);
    }

    fs::remove_file(&cache_path)
        .with_context(|| format!("Failed to remove pubkey cache file: {:?}", cache_path))?;

    Ok(true)
}

/// Clear all cached public keys.
///
/// This is useful for a complete cache reset.
///
/// # Returns
/// * `Ok(usize)` - The number of cache files removed.
/// * `Err` - If there's an error accessing the cache directory.
pub fn clear_all_cached_pubkeys() -> Result<usize> {
    let cache_dir = get_pubkey_cache_dir()?;

    if !cache_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in fs::read_dir(&cache_dir)
        .with_context(|| format!("Failed to read pubkey cache directory: {:?}", cache_dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "pub") {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove cache file: {:?}", path))?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests use a temporary directory override for isolation.
    // In production, the actual ~/.auths/pubkeys directory is used.

    #[test]
    fn test_get_cache_path_sanitizes_alias() {
        let path = get_cache_path("test/alias").unwrap();
        assert!(path.to_string_lossy().contains("test_alias.pub"));
    }

    #[test]
    fn test_cache_pubkey_validates_length() {
        let result = cache_pubkey("test", &[0u8; 16]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 32 bytes")
        );
    }
}
