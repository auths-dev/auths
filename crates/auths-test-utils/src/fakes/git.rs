use auths_sdk::ports::git::{CommitRecord, GitLogProvider, GitProviderError};

/// A configurable in-memory implementation of [`GitLogProvider`] for testing.
///
/// Use [`FakeGitLogProvider::with_commits`] to simulate a successful walk and
/// [`FakeGitLogProvider::poisoned`] to simulate a lock-poisoned error.
///
/// Respects the `limit` parameter — returns at most `limit` commits when set.
/// The `range` parameter has no meaningful in-memory analogue and is ignored.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::fakes::git::FakeGitLogProvider;
///
/// let provider = FakeGitLogProvider::with_commits(vec![commit_a, commit_b]);
/// let result = provider.walk_commits(None, Some(1)).unwrap();
/// assert_eq!(result.len(), 1);
/// ```
pub struct FakeGitLogProvider {
    commits: Vec<CommitRecord>,
    fail: bool,
}

impl FakeGitLogProvider {
    /// Create a provider that returns the given commits.
    ///
    /// Args:
    /// * `commits`: The commits to return from `walk_commits`.
    pub fn with_commits(commits: Vec<CommitRecord>) -> Self {
        Self {
            commits,
            fail: false,
        }
    }

    /// Create a provider that always returns `GitProviderError::LockPoisoned`.
    pub fn poisoned() -> Self {
        Self {
            commits: vec![],
            fail: true,
        }
    }
}

impl GitLogProvider for FakeGitLogProvider {
    fn walk_commits(
        &self,
        _range: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<CommitRecord>, GitProviderError> {
        if self.fail {
            return Err(GitProviderError::LockPoisoned);
        }
        let commits = match limit {
            Some(n) => self.commits.iter().take(n).cloned().collect(),
            None => self.commits.clone(),
        };
        Ok(commits)
    }
}
