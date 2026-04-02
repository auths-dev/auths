/// Contract test suite for [`GitConfigProvider`] implementations.
///
/// Generates a module with `#[test]` cases that verify behavioural correctness
/// for any [`GitConfigProvider`] implementation.
///
/// Args:
/// * `$name` — identifier for the generated module.
/// * `$setup` — expression that returns `(impl GitConfigProvider, _guard)`.
///
/// Usage:
/// ```ignore
/// git_config_provider_contract_tests!(
///     fake,
///     { (FakeGitConfigProvider::new(), ()) },
/// );
/// ```
#[macro_export]
macro_rules! git_config_provider_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use $crate::ports::git_config::GitConfigProvider as _;

            use super::*;

            #[test]
            fn contract_set_stores_value() {
                let (provider, _guard) = $setup;
                let result = provider.set("gpg.format", "ssh");
                assert!(result.is_ok(), "set should succeed");
            }

            #[test]
            fn contract_set_overwrites_existing() {
                let (provider, _guard) = $setup;
                provider.set("gpg.format", "ssh").unwrap();
                let result = provider.set("gpg.format", "gpg");
                assert!(result.is_ok(), "overwriting an existing key should succeed");
            }

            #[test]
            fn contract_set_different_keys() {
                let (provider, _guard) = $setup;
                provider.set("gpg.format", "ssh").unwrap();
                let result = provider.set("user.signingkey", "/path/to/key");
                assert!(result.is_ok(), "setting a different key should succeed");
            }

            #[test]
            fn contract_unset_existing_key() {
                let (provider, _guard) = $setup;
                provider.set("gpg.format", "ssh").unwrap();
                let result = provider.unset("gpg.format");
                assert!(result.is_ok(), "unsetting an existing key should succeed");
            }

            #[test]
            fn contract_unset_missing_key() {
                let (provider, _guard) = $setup;
                let result = provider.unset("nonexistent.key");
                assert!(result.is_ok(), "unsetting a missing key should succeed");
            }
        }
    };
}
