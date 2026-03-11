//! Shared error trait for structured error codes across all Auths crates.

/// Trait for error metadata providing structured error codes and actionable suggestions.
///
/// All user-facing Auths error types implement this trait to provide:
/// - A unique error code for programmatic handling (e.g., `AUTHS-E3001`)
/// - An optional human-readable suggestion for how to resolve the error
///
/// Args:
/// (no arguments — this is a trait definition)
///
/// Usage:
/// ```ignore
/// use auths_crypto::AuthsErrorInfo;
///
/// impl AuthsErrorInfo for MyError {
///     fn error_code(&self) -> &'static str { "AUTHS-E0001" }
///     fn suggestion(&self) -> Option<&'static str> { None }
/// }
/// ```
pub trait AuthsErrorInfo {
    /// Returns a unique error code string for this error variant.
    fn error_code(&self) -> &'static str;

    /// Returns an optional actionable suggestion for resolving the error.
    fn suggestion(&self) -> Option<&'static str>;
}
