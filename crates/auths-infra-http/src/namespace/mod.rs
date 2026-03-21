//! Namespace verification adapters for package ecosystem ownership proofs.

mod cargo_verifier;
mod npm_verifier;
mod pypi_verifier;

pub use cargo_verifier::CargoVerifier;
pub use npm_verifier::NpmVerifier;
pub use pypi_verifier::PypiVerifier;

use auths_core::ports::namespace::VerificationToken;

/// Generate a cryptographically random verification token.
///
/// Lives in `auths-infra-http` (not `auths-core`) because token generation
/// depends on `rand` and `hex`, which are infrastructure concerns.
///
/// Usage:
/// ```ignore
/// let token = generate_verification_token();
/// assert!(token.as_str().starts_with("auths-verify-"));
/// ```
pub fn generate_verification_token() -> VerificationToken {
    use rand::Rng;
    let bytes: [u8; 8] = rand::rngs::OsRng.r#gen();
    let raw = format!("auths-verify-{}", hex::encode(bytes));
    // INVARIANT: prefix is correct and hex::encode always produces valid hex
    #[allow(clippy::expect_used)]
    VerificationToken::parse(&raw).expect("generated token is always valid")
}
