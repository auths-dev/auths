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
/// The public key is stored in `~/.auths/pubkeys/<alias>.pub` as `<curve>:<hex>`,
/// e.g. `ed25519:abcdef...` or `p256:02abcdef...`.
///
/// Args:
/// * `alias` - The key alias (e.g., "default").
/// * `pubkey` - Raw public key bytes.
/// * `curve` - The curve type of the key.
pub fn cache_pubkey(alias: &str, pubkey: &[u8], curve: auths_crypto::CurveType) -> Result<()> {
    let cache_dir = get_pubkey_cache_dir()?;
    create_restricted_dir(&cache_dir)
        .with_context(|| format!("Failed to create pubkey cache directory: {:?}", cache_dir))?;

    let cache_path = get_cache_path(alias)?;
    let content = format!("{}:{}", curve, hex::encode(pubkey));

    write_sensitive_file(&cache_path, &content)
        .with_context(|| format!("Failed to write pubkey cache file: {:?}", cache_path))?;

    Ok(())
}

/// Get a cached public key for the given alias.
///
/// Returns the raw key bytes and curve type. Handles legacy cache files
/// (plain hex without curve prefix) by assuming Ed25519.
///
/// Args:
/// * `alias` - The key alias (e.g., "default").
pub fn get_cached_pubkey(alias: &str) -> Result<Option<(Vec<u8>, auths_crypto::CurveType)>> {
    let cache_path = get_cache_path(alias)?;

    if !cache_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&cache_path)
        .with_context(|| format!("Failed to read pubkey cache file: {:?}", cache_path))?;

    let trimmed = content.trim();

    let (curve, hex_str) = if let Some((curve_tag, hex_part)) = trimmed.split_once(':') {
        let curve = match curve_tag {
            "ed25519" => auths_crypto::CurveType::Ed25519,
            "p256" => auths_crypto::CurveType::P256,
            other => {
                return Err(anyhow!(
                    "Unknown curve in cache file {:?}: {other}",
                    cache_path
                ));
            }
        };
        (curve, hex_part)
    } else {
        // Legacy format: plain hex, assume Ed25519
        (auths_crypto::CurveType::Ed25519, trimmed)
    };

    let pubkey = hex::decode(hex_str)
        .with_context(|| format!("Invalid hex in pubkey cache file: {:?}", cache_path))?;

    Ok(Some((pubkey, curve)))
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
    fn test_get_cache_path_returns_pub_extension() {
        let path = get_cache_path("mykey").unwrap();
        assert!(path.to_string_lossy().ends_with("mykey.pub"));
    }
}
