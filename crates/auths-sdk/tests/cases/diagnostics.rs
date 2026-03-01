use auths_sdk::workflows::diagnostics::DiagnosticsWorkflow;
use auths_test_utils::fakes::diagnostics::{
    FakeCryptoDiagnosticProvider, FakeGitDiagnosticProvider,
};

#[test]
fn test_diagnostics_all_pass() {
    let git = FakeGitDiagnosticProvider::new(
        true,
        vec![
            ("gpg.format", Some("ssh")),
            ("commit.gpgsign", Some("true")),
            ("tag.gpgsign", Some("true")),
            ("user.signingkey", Some("auths:main")),
            ("gpg.ssh.program", Some("auths-sign")),
        ],
    );
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    assert!(
        report.checks.iter().all(|c| c.passed),
        "all checks should pass: {:?}",
        report.checks
    );
}

#[test]
fn test_diagnostics_partial_failure() {
    let git = FakeGitDiagnosticProvider::new(true, vec![]);
    let crypto = FakeCryptoDiagnosticProvider::new(false);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let ssh_check = report
        .checks
        .iter()
        .find(|c| c.name == "ssh-keygen installed")
        .unwrap();
    assert!(!ssh_check.passed);

    let signing_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git signing config")
        .unwrap();
    assert!(!signing_check.passed);
}

#[test]
fn test_diagnostics_git_only_mock() {
    let git = FakeGitDiagnosticProvider::new(false, vec![]);
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let git_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git installed")
        .unwrap();
    assert!(!git_check.passed);
}

#[test]
fn test_diagnostics_git_config_missing() {
    let git = FakeGitDiagnosticProvider::new(
        true,
        vec![
            ("gpg.format", Some("ssh")),
            ("commit.gpgsign", Some("true")),
            ("tag.gpgsign", Some("true")),
            // user.signingkey and gpg.ssh.program missing
        ],
    );
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let signing_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git signing config")
        .unwrap();
    assert!(!signing_check.passed);
    assert!(
        signing_check
            .config_issues
            .iter()
            .any(|i| matches!(i, auths_sdk::ports::diagnostics::ConfigIssue::Absent(_))),
        "expected Absent config issues, got: {:?}",
        signing_check.config_issues
    );
}
