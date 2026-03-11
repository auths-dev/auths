/// Contract test suite for [`GitDiagnosticProvider`] implementations.
///
/// Args:
/// * `$name` — identifier for the generated module.
/// * `$setup` — expression that returns `(impl GitDiagnosticProvider, _guard)`.
///
/// Usage:
/// ```ignore
/// git_diagnostic_provider_contract_tests!(
///     fake,
///     { (FakeGitDiagnosticProvider::new(true, vec![]), ()) },
/// );
/// ```
#[macro_export]
macro_rules! git_diagnostic_provider_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use $crate::ports::diagnostics::GitDiagnosticProvider as _;

            use super::*;

            #[test]
            fn contract_check_git_version_returns_result() {
                let (provider, _guard) = $setup;
                let result = provider.check_git_version();
                assert!(result.is_ok(), "check_git_version should return Ok");
                let check = result.unwrap();
                assert!(!check.name.is_empty(), "check name should not be empty");
            }

            #[test]
            fn contract_get_git_config_returns_result() {
                let (provider, _guard) = $setup;
                let result = provider.get_git_config("gpg.format");
                assert!(
                    result.is_ok(),
                    "get_git_config should return Ok even for missing keys"
                );
            }
        }
    };
}

/// Contract test suite for [`CryptoDiagnosticProvider`] implementations.
///
/// Args:
/// * `$name` — identifier for the generated module.
/// * `$setup` — expression that returns `(impl CryptoDiagnosticProvider, _guard)`.
///
/// Usage:
/// ```ignore
/// crypto_diagnostic_provider_contract_tests!(
///     fake,
///     { (FakeCryptoDiagnosticProvider::new(true), ()) },
/// );
/// ```
#[macro_export]
macro_rules! crypto_diagnostic_provider_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use $crate::ports::diagnostics::CryptoDiagnosticProvider as _;

            use super::*;

            #[test]
            fn contract_check_ssh_keygen_returns_result() {
                let (provider, _guard) = $setup;
                let result = provider.check_ssh_keygen_available();
                assert!(
                    result.is_ok(),
                    "check_ssh_keygen_available should return Ok"
                );
                let check = result.unwrap();
                assert!(!check.name.is_empty(), "check name should not be empty");
            }
        }
    };
}
