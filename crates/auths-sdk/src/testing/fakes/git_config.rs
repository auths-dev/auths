use std::collections::HashMap;
use std::sync::Mutex;

use crate::ports::git_config::{GitConfigError, GitConfigProvider};

/// Recorded call from [`FakeGitConfigProvider`].
#[derive(Debug, Clone)]
pub struct GitConfigSetCall {
    /// The git config key that was set.
    pub key: String,
    /// The value it was set to.
    pub value: String,
}

/// Configurable fake for [`GitConfigProvider`].
///
/// Stores config values in memory and records all calls for assertion.
///
/// Usage:
/// ```ignore
/// let fake = FakeGitConfigProvider::new();
/// let fake = FakeGitConfigProvider::new().with_config("gpg.format", "ssh");
/// let fake = FakeGitConfigProvider::new().set_fails_with("permission denied");
/// assert_eq!(fake.set_calls().len(), 1);
/// ```
pub struct FakeGitConfigProvider {
    configs: Mutex<HashMap<String, String>>,
    set_calls: Mutex<Vec<GitConfigSetCall>>,
    fail_on_set: Mutex<Option<String>>,
}

impl Default for FakeGitConfigProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeGitConfigProvider {
    /// Create a fake with empty config state.
    pub fn new() -> Self {
        Self {
            configs: Mutex::new(HashMap::new()),
            set_calls: Mutex::new(Vec::new()),
            fail_on_set: Mutex::new(None),
        }
    }

    /// Pre-populate a config key-value pair.
    pub fn with_config(self, key: &str, value: &str) -> Self {
        self.configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.into(), value.into());
        self
    }

    /// Configure all `set` calls to fail with the given message.
    pub fn set_fails_with(self, msg: &str) -> Self {
        *self.fail_on_set.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.into());
        self
    }

    /// Return all recorded `set` calls.
    pub fn set_calls(&self) -> Vec<GitConfigSetCall> {
        self.set_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Read a config value by key (for test assertions).
    pub fn get(&self, key: &str) -> Option<String> {
        self.configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }
}

impl GitConfigProvider for FakeGitConfigProvider {
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError> {
        if let Some(msg) = self
            .fail_on_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Err(GitConfigError::CommandFailed(msg.clone()));
        }
        self.set_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(GitConfigSetCall {
                key: key.into(),
                value: value.into(),
            });
        self.configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.into(), value.into());
        Ok(())
    }

    fn unset(&self, key: &str) -> Result<(), GitConfigError> {
        self.configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::fakes::git_config::FakeGitConfigProvider;

    crate::git_config_provider_contract_tests!(fake, { (FakeGitConfigProvider::new(), ()) },);
}
