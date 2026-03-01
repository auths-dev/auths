//! Centralized path construction for the Git registry tree.
//!
//! All schema-versioned path strings and entity file paths are built here.
//! `adapter.rs` must not perform inline string concatenation for entity paths —
//! call these functions instead.

use auths_id::storage::registry::shard::STORAGE_SCHEMA_VERSION;

// ── Schema versioning ────────────────────────────────────────────────────────

/// Prefix `path` with the current storage schema version.
///
/// Args:
/// * `path`: Relative path within the versioned tree (e.g. `"metadata.json"`).
///
/// Usage:
/// ```ignore
/// let p = versioned("metadata.json"); // "v1/metadata.json"
/// ```
pub fn versioned(path: &str) -> String {
    format!("{}/{}", STORAGE_SCHEMA_VERSION, path)
}

// ── Simple concatenation ─────────────────────────────────────────────────────

/// Append `name` to `parent` with a `/` separator.
///
/// Args:
/// * `parent`: Parent path segment.
/// * `name`: Child path segment to append.
///
/// Usage:
/// ```ignore
/// let p = child("v1/identities/EX/q5", "EXq5..."); // "v1/identities/EX/q5/EXq5..."
/// ```
pub fn child(parent: &str, name: &str) -> String {
    format!("{}/{}", parent, name)
}

// ── Identity paths ───────────────────────────────────────────────────────────

/// Path to the events directory for an identity.
///
/// Args:
/// * `identity_base`: Base path returned by `identity_path(prefix)`.
///
/// Usage:
/// ```ignore
/// let dir = events_dir(&base); // "v1/identities/.../events"
/// ```
pub fn events_dir(identity_base: &str) -> String {
    format!("{}/events", identity_base)
}

/// Path to a specific event file.
///
/// Args:
/// * `identity_base`: Base path for the identity.
/// * `seq`: Zero-based sequence number.
///
/// Usage:
/// ```ignore
/// let path = event_file(&base, 3); // "v1/identities/.../events/00000003.json"
/// ```
pub fn event_file(identity_base: &str, seq: u64) -> String {
    format!("{}/events/{:08}.json", identity_base, seq)
}

/// Path to the tip metadata file.
///
/// Args:
/// * `identity_base`: Base path for the identity.
///
/// Usage:
/// ```ignore
/// let path = tip_file(&base); // "v1/identities/.../tip.json"
/// ```
pub fn tip_file(identity_base: &str) -> String {
    format!("{}/tip.json", identity_base)
}

/// Path to the cached key-state file.
///
/// Args:
/// * `identity_base`: Base path for the identity.
///
/// Usage:
/// ```ignore
/// let path = state_file(&base); // "v1/identities/.../state.json"
/// ```
pub fn state_file(identity_base: &str) -> String {
    format!("{}/state.json", identity_base)
}

// ── Device / attestation paths ───────────────────────────────────────────────

/// Path to the current (latest) attestation file for a device.
///
/// Args:
/// * `device_base`: Base path returned by `device_path(sanitized_did)`.
///
/// Usage:
/// ```ignore
/// let path = attestation_file(&base); // "v1/devices/.../attestation.json"
/// ```
pub fn attestation_file(device_base: &str) -> String {
    format!("{}/attestation.json", device_base)
}

/// Path to the history directory for a device.
///
/// Args:
/// * `device_base`: Base path for the device.
///
/// Usage:
/// ```ignore
/// let dir = history_dir(&base); // "v1/devices/.../history"
/// ```
pub fn history_dir(device_base: &str) -> String {
    format!("{}/history", device_base)
}

/// Path to a single history entry file.
///
/// Args:
/// * `device_base`: Base path for the device.
/// * `entry_id`: Sortable entry identifier (e.g. `"20240101T000000.000_<rid-suffix>"`).
///
/// Usage:
/// ```ignore
/// let path = history_entry_file(&base, &entry_id); // "v1/devices/.../history/<id>.json"
/// ```
pub fn history_entry_file(device_base: &str, entry_id: &str) -> String {
    format!("{}/history/{}.json", device_base, entry_id)
}

// ── Org member paths ─────────────────────────────────────────────────────────

/// Path to the members directory for an org.
///
/// Args:
/// * `org_base`: Base path returned by `org_path(prefix)`.
///
/// Usage:
/// ```ignore
/// let dir = members_dir(&base); // "v1/orgs/.../members"
/// ```
pub fn members_dir(org_base: &str) -> String {
    format!("{}/members", org_base)
}

/// Path to a specific org member file.
///
/// Args:
/// * `org_base`: Base path for the org.
/// * `sanitized_member_did`: Sanitized DID string (`:` replaced with `_`).
///
/// Usage:
/// ```ignore
/// let path = member_file(&base, &sanitized_did); // "v1/orgs/.../members/<did>.json"
/// ```
pub fn member_file(org_base: &str, sanitized_member_did: &str) -> String {
    format!("{}/members/{}.json", org_base, sanitized_member_did)
}
