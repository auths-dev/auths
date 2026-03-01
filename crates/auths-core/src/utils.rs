//! Utility helpers.

/// Trim and lowercase an alias string to produce a canonical form.
pub fn sanitize_alias(alias: &str) -> String {
    alias.trim().to_lowercase()
}
