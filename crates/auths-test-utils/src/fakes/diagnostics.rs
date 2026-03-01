use auths_sdk::ports::diagnostics::{
    CheckResult, CryptoDiagnosticProvider, DiagnosticError, GitDiagnosticProvider,
};

/// Configurable fake for [`GitDiagnosticProvider`].
pub struct FakeGitDiagnosticProvider {
    version_passes: bool,
    configs: Vec<(String, Option<String>)>,
}

impl FakeGitDiagnosticProvider {
    pub fn new(version_passes: bool, configs: Vec<(&str, Option<&str>)>) -> Self {
        Self {
            version_passes,
            configs: configs
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
                .collect(),
        }
    }
}

impl GitDiagnosticProvider for FakeGitDiagnosticProvider {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        Ok(CheckResult {
            name: "Git installed".to_string(),
            passed: self.version_passes,
            message: if self.version_passes {
                Some("git version 2.40.0".to_string())
            } else {
                Some("git not found".to_string())
            },
            config_issues: vec![],
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
        })
    }
}
