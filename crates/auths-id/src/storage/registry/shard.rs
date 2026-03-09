//! Sharding utilities for registry paths.
//!
//! Sharding distributes identities and devices across 2-level directory
//! structures to avoid large directories that slow down Git operations.
//!
//! ## Sharding Strategy
//!
//! Both KERI prefixes and device DIDs use their first 4 characters split
//! into two 2-character segments:
//!
//! - KERI prefix `EXq5YqaL...` → `EX/q5/EXq5YqaL.../`
//! - Device DID `did_key_z6Mk...` → `z6/Mk/did_key_z6Mk.../`
//!
//! ## Performance Guardrails
//!
//! ### Shard Depth
//!
//! All paths use **2-level sharding** (depth >= 2), producing paths like:
//!
//! ```text
//! v1/identities/{shard1}/{shard2}/{prefix}/...
//! v1/devices/{shard1}/{shard2}/{did}/...
//! ```
//!
//! This bounds directory fanout to ~4096 entries per level (64 * 64 for base64).
//!
//! ### Early Exit in Visitor Methods
//!
//! All `visit_*` methods in [`crate::storage::registry::RegistryBackend`] accept
//! a visitor callback that can return `ControlFlow::Break(())` to stop early:
//!
//! ```rust,ignore
//! backend.visit_identities(&mut |prefix| {
//!     if found_what_i_need {
//!         return ControlFlow::Break(()); // Stop iteration
//!     }
//!     ControlFlow::Continue(())
//! })?;
//! ```
//!
//! This prevents unbounded iteration when only a subset of results is needed.

use super::backend::RegistryError;
use crate::keri::Prefix;

/// Storage schema version prefix for Git tree paths.
/// This is independent of the HTTP API version.
pub const STORAGE_SCHEMA_VERSION: &str = "v1";

/// Shard a KERI prefix into 2-level directory structure.
///
/// Uses chars [0..2] and [2..4] case-preserved.
///
/// # Errors
///
/// Returns `RegistryError::InvalidPrefix` if prefix is not ASCII or shorter than 4 bytes.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::shard_prefix;
/// use auths_id::keri::Prefix;
///
/// let prefix = Prefix::new_unchecked("EXq5YqaL".to_string());
/// let (s1, s2) = shard_prefix(&prefix).unwrap();
/// assert_eq!(s1, "EX");
/// assert_eq!(s2, "q5");
/// ```
pub fn shard_prefix(prefix: &Prefix) -> Result<(String, String), RegistryError> {
    let prefix_str = prefix.as_str();
    if !prefix_str.is_ascii() {
        return Err(RegistryError::InvalidPrefix {
            prefix: prefix_str.into(),
            reason: "must be ASCII".into(),
        });
    }
    if prefix_str.len() < 4 {
        return Err(RegistryError::InvalidPrefix {
            prefix: prefix_str.into(),
            reason: "must be at least 4 characters".into(),
        });
    }

    // Safe to slice: ASCII chars are always 1 byte, so byte boundaries = char boundaries
    let s1 = prefix_str[0..2].to_string();
    let s2 = prefix_str[2..4].to_string();
    Ok((s1, s2))
}

/// Shard a sanitized device DID into 2-level directory structure.
///
/// Strips "did_key_" prefix (if present), then uses bytes[0..2] and bytes[2..4].
///
/// # Errors
///
/// Returns `RegistryError::InvalidDeviceDid` if key part is not ASCII or too short.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::shard_device_did;
///
/// let (s1, s2) = shard_device_did("did_key_z6MkTest").unwrap();
/// assert_eq!(s1, "z6");
/// assert_eq!(s2, "Mk");
/// ```
pub fn shard_device_did(sanitized_did: &str) -> Result<(String, String), RegistryError> {
    let key_part = sanitized_did
        .strip_prefix("did_key_")
        .unwrap_or(sanitized_did);

    if !key_part.is_ascii() {
        return Err(RegistryError::InvalidDeviceDid {
            did: sanitized_did.into(),
            reason: "key part must be ASCII".into(),
        });
    }
    if key_part.len() < 4 {
        return Err(RegistryError::InvalidDeviceDid {
            did: sanitized_did.into(),
            reason: "key part must be at least 4 characters".into(),
        });
    }

    // Safe to slice: ASCII chars are always 1 byte, so byte boundaries = char boundaries
    let s1 = key_part[0..2].to_string();
    let s2 = key_part[2..4].to_string();
    Ok((s1, s2))
}

/// Split a path string into parts.
///
/// Filters out empty segments from leading/trailing/double slashes.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::path_parts;
///
/// let parts = path_parts("v1/identities/EX/q5/prefix");
/// assert_eq!(parts, vec!["v1", "identities", "EX", "q5", "prefix"]);
/// ```
pub fn path_parts(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Build a path for an identity in the registry tree.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::identity_path;
/// use auths_id::keri::Prefix;
///
/// let prefix = Prefix::new_unchecked("EXq5YqaL123".to_string());
/// let path = identity_path(&prefix).unwrap();
/// assert_eq!(path, "v1/identities/EX/q5/EXq5YqaL123");
/// ```
pub fn identity_path(prefix: &Prefix) -> Result<String, RegistryError> {
    let (s1, s2) = shard_prefix(prefix)?;
    Ok(format!(
        "{}/identities/{}/{}/{}",
        STORAGE_SCHEMA_VERSION,
        s1,
        s2,
        prefix.as_str()
    ))
}

/// Build a path for a device in the registry tree.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::device_path;
///
/// let path = device_path("did_key_z6MkTest123").unwrap();
/// assert_eq!(path, "v1/devices/z6/Mk/did_key_z6MkTest123");
/// ```
pub fn device_path(sanitized_did: &str) -> Result<String, RegistryError> {
    let (s1, s2) = shard_device_did(sanitized_did)?;
    Ok(format!(
        "{}/devices/{}/{}/{}",
        STORAGE_SCHEMA_VERSION, s1, s2, sanitized_did
    ))
}

/// Build a path for an org in the registry tree.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::org_path;
/// use auths_id::keri::Prefix;
///
/// let prefix = Prefix::new_unchecked("EOrg1234567890".to_string());
/// let path = org_path(&prefix).unwrap();
/// assert_eq!(path, "v1/orgs/EO/rg/EOrg1234567890");
/// ```
pub fn org_path(org_did_prefix: &Prefix) -> Result<String, RegistryError> {
    let (s1, s2) = shard_prefix(org_did_prefix)?;
    Ok(format!(
        "{}/orgs/{}/{}/{}",
        STORAGE_SCHEMA_VERSION,
        s1,
        s2,
        org_did_prefix.as_str()
    ))
}

/// Sanitize a DID for use as a filesystem path component.
///
/// Replaces ':' with '_' to avoid issues on Windows and in Git trees.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::sanitize_did;
///
/// assert_eq!(sanitize_did("did:key:z6MkTest"), "did_key_z6MkTest");
/// ```
pub fn sanitize_did(did: &str) -> String {
    did.replace(':', "_")
}

/// Unsanitize a DID path component back to proper DID format.
///
/// Restores exactly the first two underscores to colons, matching the
/// `did:<method>:<method-specific-id>` structure. Any remaining underscores
/// (e.g., Base64url characters in KERI prefixes) are preserved as-is.
///
/// # Example
///
/// ```
/// use auths_id::storage::registry::shard::unsanitize_did;
///
/// assert_eq!(unsanitize_did("did_key_z6MkTest"), "did:key:z6MkTest");
/// assert_eq!(unsanitize_did("did_keri_ERNbk_r7dPglPwh"), "did:keri:ERNbk_r7dPglPwh");
/// ```
pub fn unsanitize_did(sanitized: &str) -> String {
    let mut result = sanitized.to_string();
    if let Some(pos) = result.find('_') {
        result.replace_range(pos..pos + 1, ":");
        if let Some(pos2) = result[pos + 1..].find('_') {
            result.replace_range(pos + 1 + pos2..pos + 1 + pos2 + 1, ":");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- shard_prefix tests ---

    #[test]
    fn shard_prefix_valid() {
        let p = Prefix::new_unchecked("EXq5YqaL".to_string());
        let (s1, s2) = shard_prefix(&p).unwrap();
        assert_eq!(s1, "EX");
        assert_eq!(s2, "q5");
    }

    #[test]
    fn shard_prefix_exactly_4_chars() {
        let p = Prefix::new_unchecked("ABCD".to_string());
        let (s1, s2) = shard_prefix(&p).unwrap();
        assert_eq!(s1, "AB");
        assert_eq!(s2, "CD");
    }

    #[test]
    fn shard_prefix_too_short() {
        let p = Prefix::new_unchecked("ABC".to_string());
        let err = shard_prefix(&p).unwrap_err();
        match err {
            RegistryError::InvalidPrefix { prefix, reason } => {
                assert_eq!(prefix, "ABC");
                assert!(reason.contains("at least 4"));
            }
            _ => panic!("Expected InvalidPrefix error"),
        }
    }

    #[test]
    fn shard_prefix_non_ascii() {
        let p = Prefix::new_unchecked("EXñ5Test".to_string());
        let err = shard_prefix(&p).unwrap_err();
        match err {
            RegistryError::InvalidPrefix { prefix, reason } => {
                assert_eq!(prefix, "EXñ5Test");
                assert!(reason.contains("ASCII"));
            }
            _ => panic!("Expected InvalidPrefix error"),
        }
    }

    // --- shard_device_did tests ---

    #[test]
    fn shard_device_did_with_prefix() {
        let (s1, s2) = shard_device_did("did_key_z6MkTest").unwrap();
        assert_eq!(s1, "z6");
        assert_eq!(s2, "Mk");
    }

    #[test]
    fn shard_device_did_without_prefix() {
        let (s1, s2) = shard_device_did("z6MkTest").unwrap();
        assert_eq!(s1, "z6");
        assert_eq!(s2, "Mk");
    }

    #[test]
    fn shard_device_did_too_short() {
        let err = shard_device_did("did_key_z6M").unwrap_err();
        match err {
            RegistryError::InvalidDeviceDid { did, reason } => {
                assert_eq!(did, "did_key_z6M");
                assert!(reason.contains("at least 4"));
            }
            _ => panic!("Expected InvalidDeviceDid error"),
        }
    }

    #[test]
    fn shard_device_did_non_ascii() {
        let err = shard_device_did("did_key_z6ñk").unwrap_err();
        match err {
            RegistryError::InvalidDeviceDid { did: _, reason } => {
                assert!(reason.contains("ASCII"));
            }
            _ => panic!("Expected InvalidDeviceDid error"),
        }
    }

    // --- path_parts tests ---

    #[test]
    fn path_parts_normal() {
        let parts = path_parts("v1/identities/EX/q5/prefix");
        assert_eq!(parts, vec!["v1", "identities", "EX", "q5", "prefix"]);
    }

    #[test]
    fn path_parts_leading_slash() {
        let parts = path_parts("/v1/identities");
        assert_eq!(parts, vec!["v1", "identities"]);
    }

    #[test]
    fn path_parts_trailing_slash() {
        let parts = path_parts("v1/identities/");
        assert_eq!(parts, vec!["v1", "identities"]);
    }

    #[test]
    fn path_parts_double_slash() {
        let parts = path_parts("v1//identities");
        assert_eq!(parts, vec!["v1", "identities"]);
    }

    #[test]
    fn path_parts_empty() {
        let parts = path_parts("");
        assert!(parts.is_empty());
    }

    // --- identity_path tests ---

    #[test]
    fn identity_path_valid() {
        let p = Prefix::new_unchecked("EXq5YqaL123".to_string());
        let path = identity_path(&p).unwrap();
        assert_eq!(path, "v1/identities/EX/q5/EXq5YqaL123");
    }

    // --- device_path tests ---

    #[test]
    fn device_path_valid() {
        let path = device_path("did_key_z6MkTest123").unwrap();
        assert_eq!(path, "v1/devices/z6/Mk/did_key_z6MkTest123");
    }

    // --- org_path tests ---

    #[test]
    fn org_path_valid() {
        let p = Prefix::new_unchecked("EOrg1234567890".to_string());
        let path = org_path(&p).unwrap();
        assert_eq!(path, "v1/orgs/EO/rg/EOrg1234567890");
    }

    // --- sanitize/unsanitize tests ---

    #[test]
    fn sanitize_did_replaces_colons() {
        assert_eq!(sanitize_did("did:key:z6MkTest"), "did_key_z6MkTest");
        assert_eq!(sanitize_did("did:keri:EPrefix"), "did_keri_EPrefix");
    }

    #[test]
    fn unsanitize_did_replaces_underscores() {
        assert_eq!(unsanitize_did("did_key_z6MkTest"), "did:key:z6MkTest");
        assert_eq!(unsanitize_did("did_keri_EPrefix"), "did:keri:EPrefix");
    }

    #[test]
    fn unsanitize_did_preserves_underscores_in_keri_prefix() {
        // KERI prefixes use Base64url which includes underscores
        assert_eq!(
            unsanitize_did("did_keri_ERNbk_r7dPglPwh"),
            "did:keri:ERNbk_r7dPglPwh"
        );
        assert_eq!(
            unsanitize_did("did_keri_ExR_E7Y0W1A02St"),
            "did:keri:ExR_E7Y0W1A02St"
        );
    }

    #[test]
    fn sanitize_unsanitize_roundtrip() {
        let original = "did:key:z6MkSomeDevice123";
        let sanitized = sanitize_did(original);
        let unsanitized = unsanitize_did(&sanitized);
        assert_eq!(unsanitized, original);
    }

    #[test]
    fn sanitize_unsanitize_roundtrip_keri_with_underscores() {
        let original = "did:keri:ERNbk_r7dPglPwh_ybgW7y1Ld2qXFx7DtTOjRPsJa5eMA";
        let sanitized = sanitize_did(original);
        let unsanitized = unsanitize_did(&sanitized);
        assert_eq!(unsanitized, original);
    }

    // =========================================================================
    // Performance Guardrail Tests
    // =========================================================================

    /// Verify identity paths have shard depth >= 2.
    ///
    /// Path format: v1 / identities / shard1 / shard2 / prefix
    /// This ensures directories are bounded to ~64*64 = 4096 entries max per shard level.
    #[test]
    fn identity_path_shard_depth_at_least_2() {
        let p = Prefix::new_unchecked("EXq5YqaL123".to_string());
        let path = identity_path(&p).unwrap();
        let parts = path_parts(&path);

        // Must be: v1 / identities / EX / q5 / EXq5YqaL123 = 5 parts
        assert!(
            parts.len() >= 5,
            "identity path shard depth must be >= 2: got {} parts in '{}'",
            parts.len(),
            path
        );

        // Verify structure
        assert_eq!(parts[0], "v1", "first part must be schema version");
        assert_eq!(parts[1], "identities", "second part must be 'identities'");
        assert_eq!(parts[2].len(), 2, "first shard must be 2 chars");
        assert_eq!(parts[3].len(), 2, "second shard must be 2 chars");
    }

    /// Verify device paths have shard depth >= 2.
    ///
    /// Path format: v1 / devices / shard1 / shard2 / sanitized_did
    #[test]
    fn device_path_shard_depth_at_least_2() {
        let path = device_path("did_key_z6MkTest123").unwrap();
        let parts = path_parts(&path);

        // Must be: v1 / devices / z6 / Mk / did_key_z6MkTest123 = 5 parts
        assert!(
            parts.len() >= 5,
            "device path shard depth must be >= 2: got {} parts in '{}'",
            parts.len(),
            path
        );

        // Verify structure
        assert_eq!(parts[0], "v1", "first part must be schema version");
        assert_eq!(parts[1], "devices", "second part must be 'devices'");
        assert_eq!(parts[2].len(), 2, "first shard must be 2 chars");
        assert_eq!(parts[3].len(), 2, "second shard must be 2 chars");
    }

    /// Verify org paths have shard depth >= 2.
    #[test]
    fn org_path_shard_depth_at_least_2() {
        let p = Prefix::new_unchecked("EOrg1234567890".to_string());
        let path = org_path(&p).unwrap();
        let parts = path_parts(&path);

        // Must be: v1 / orgs / EO / rg / EOrg1234567890 = 5 parts
        assert!(
            parts.len() >= 5,
            "org path shard depth must be >= 2: got {} parts in '{}'",
            parts.len(),
            path
        );

        // Verify structure
        assert_eq!(parts[0], "v1", "first part must be schema version");
        assert_eq!(parts[1], "orgs", "second part must be 'orgs'");
        assert_eq!(parts[2].len(), 2, "first shard must be 2 chars");
        assert_eq!(parts[3].len(), 2, "second shard must be 2 chars");
    }

    /// Verify shard fanout is bounded.
    ///
    /// With 2-character shards from base64-like alphabet:
    /// - KERI prefixes start with D, E, etc. (limited first char)
    /// - Device DIDs start with z6 (ed25519 multicodec)
    ///
    /// Theoretical max per shard level is 64*64 = 4096 but realistic is much lower.
    #[test]
    fn shard_fanout_bounded_by_design() {
        // First char of KERI prefix is derivation code (D, E, 0, 1, etc.)
        // This limits first shard to ~10-20 possible values
        // Second shard can be any 2 base64 chars = max 64*64 = 4096

        // For devices, first shard is typically "z6" (ed25519)
        // This naturally bounds fanout to 1 directory at first level

        // This test documents the design assumption
        let p = Prefix::new_unchecked("EXq5YqaL".to_string());
        let (s1, _s2) = shard_prefix(&p).unwrap();
        assert!(
            s1.chars().next().unwrap().is_ascii_alphanumeric(),
            "first shard char should be alphanumeric"
        );

        let (s1, _s2) = shard_device_did("did_key_z6MkTest").unwrap();
        assert_eq!(s1, "z6", "device shard typically starts with z6");
    }
}
