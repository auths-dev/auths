//! Global constants for the Auths CLI.

/// GitHub OAuth scopes required for SSH signing key operations.
///
/// Includes:
/// - `read:user`: Get user profile information
/// - `gist`: Create and manage Gists for proof publishing
/// - `write:ssh_signing_key`: Upload SSH signing keys to GitHub account
pub const GITHUB_SSH_UPLOAD_SCOPES: &str = "read:user gist write:ssh_signing_key";
