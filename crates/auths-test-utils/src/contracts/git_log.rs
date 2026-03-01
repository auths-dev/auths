/// Contract test suite for [`GitLogProvider`] implementations.
///
/// Generates a module with `#[test]` cases that verify behavioural correctness
/// for any [`GitLogProvider`] implementation.
///
/// Args:
/// * `$name` — identifier for the generated module (e.g. `fake`).
/// * `$setup` — expression evaluated fresh inside each test; must return
///   `(impl GitLogProvider, _guard)` with at least `$min_commits` commits
///   already seeded.
/// * `$min_commits` — the minimum number of commits seeded by `$setup`
///   (must be >= 2 for the limit test to be meaningful).
///
/// Usage:
/// ```ignore
/// git_log_provider_contract_tests!(
///     fake,
///     {
///         let commits = vec![make_commit("a"), make_commit("b"), make_commit("c")];
///         (FakeGitLogProvider::with_commits(commits), ())
///     },
///     3,
/// );
/// ```
#[macro_export]
macro_rules! git_log_provider_contract_tests {
    ($name:ident, $setup:expr, $min_commits:expr $(,)?) => {
        mod $name {
            use auths_sdk::ports::git::GitLogProvider as _;

            use super::*;

            #[test]
            fn contract_walk_all_returns_expected_count() {
                let (provider, _guard) = $setup;
                let commits = provider.walk_commits(None, None).unwrap();
                assert!(
                    commits.len() >= $min_commits,
                    "expected >= {} commits, got {}",
                    $min_commits,
                    commits.len()
                );
            }

            #[test]
            fn contract_walk_limit_one_returns_one() {
                let (provider, _guard) = $setup;
                let commits = provider.walk_commits(None, Some(1)).unwrap();
                assert_eq!(commits.len(), 1, "limit=1 should return exactly 1 commit");
            }

            #[test]
            fn contract_walk_limit_zero_returns_none() {
                let (provider, _guard) = $setup;
                let commits = provider.walk_commits(None, Some(0)).unwrap();
                assert!(commits.is_empty(), "limit=0 should return no commits");
            }
        }
    };
}
