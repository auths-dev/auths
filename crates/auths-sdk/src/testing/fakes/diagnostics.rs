use crate::ports::diagnostics::{
    CheckCategory, CheckResult, CryptoDiagnosticProvider, DiagnosticError, GitDiagnosticProvider,
};

/// Configurable fake for [`GitDiagnosticProvider`].
pub struct FakeGitDiagnosticProvider {
    version_passes: bool,
    version_string: String,
    configs: Vec<(String, Option<String>)>,
}

impl FakeGitDiagnosticProvider {
    /// Create a new fake with configurable git version check and config lookup results.
    ///
    /// Args:
    /// * `version_passes`: Whether `check_git_version` should report success.
    /// * `configs`: Key-value pairs returned by `get_git_config`.
    pub fn new(version_passes: bool, configs: Vec<(&str, Option<&str>)>) -> Self {
        Self {
            version_passes,
            version_string: "git version 2.40.0".to_string(),
            configs: configs
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
                .collect(),
        }
    }

    /// Override the version string returned by `check_git_version`.
    ///
    /// Args:
    /// * `version`: Raw version string, e.g. `"git version 2.30.0"`.
    pub fn with_version_string(mut self, version: &str) -> Self {
        self.version_string = version.to_string();
        self
    }
}

impl GitDiagnosticProvider for FakeGitDiagnosticProvider {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        Ok(CheckResult {
            name: "Git installed".to_string(),
            passed: self.version_passes,
            message: if self.version_passes {
                Some(self.version_string.clone())
            } else {
                Some("git not found".to_string())
            },
            config_issues: vec![],
            category: CheckCategory::Advisory,
        })
    }

    fn get_git_config(&self, key: &str) -> Result<Option<String>, DiagnosticError> {
        Ok(self
            .configs
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.clone()))
    }
}

/// Configurable fake for [`CryptoDiagnosticProvider`].
pub struct FakeCryptoDiagnosticProvider {
    ssh_keygen_passes: bool,
}

impl FakeCryptoDiagnosticProvider {
    /// Create a new fake with configurable ssh-keygen availability.
    ///
    /// Args:
    /// * `ssh_keygen_passes`: Whether `check_ssh_keygen_available` should report success.
    pub fn new(ssh_keygen_passes: bool) -> Self {
        Self { ssh_keygen_passes }
    }
}

impl CryptoDiagnosticProvider for FakeCryptoDiagnosticProvider {
    fn check_ssh_keygen_available(&self) -> Result<CheckResult, DiagnosticError> {
        Ok(CheckResult {
            name: "ssh-keygen installed".to_string(),
            passed: self.ssh_keygen_passes,
            message: None,
            config_issues: vec![],
            category: CheckCategory::Advisory,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::fakes::diagnostics::{
        FakeCryptoDiagnosticProvider, FakeGitDiagnosticProvider,
    };

    crate::git_diagnostic_provider_contract_tests!(fake_git, {
        (FakeGitDiagnosticProvider::new(true, vec![]), ())
    },);

    crate::crypto_diagnostic_provider_contract_tests!(fake_crypto, {
        (FakeCryptoDiagnosticProvider::new(true), ())
    },);
}
