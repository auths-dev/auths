use auths_sdk::testing::fakes::{FakeCryptoDiagnosticProvider, FakeGitDiagnosticProvider};
use auths_sdk::workflows::diagnostics::{DiagnosticsWorkflow, parse_git_version};

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
            ("user.name", Some("Test User")),
            ("user.email", Some("test@example.com")),
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

#[test]
fn test_diagnostics_git_version_too_low() {
    let git =
        FakeGitDiagnosticProvider::new(true, vec![]).with_version_string("git version 2.30.0");
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let version_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git version")
        .expect("Git version check must exist");
    assert!(
        !version_check.passed,
        "version 2.30.0 should fail minimum check"
    );
    assert!(
        version_check
            .message
            .as_deref()
            .unwrap_or("")
            .contains("2.30.0"),
        "message should contain the detected version"
    );
}

#[test]
fn test_diagnostics_git_version_sufficient() {
    let git =
        FakeGitDiagnosticProvider::new(true, vec![]).with_version_string("git version 2.40.0");
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let version_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git version")
        .expect("Git version check must exist");
    assert!(
        version_check.passed,
        "version 2.40.0 should pass minimum check"
    );
}

#[test]
fn test_diagnostics_git_user_config_missing() {
    let git = FakeGitDiagnosticProvider::new(true, vec![]);
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let user_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git user identity")
        .expect("Git user identity check must exist");
    assert!(!user_check.passed, "missing user.name/email should fail");
    assert!(
        user_check
            .config_issues
            .iter()
            .any(|i| matches!(i, auths_sdk::ports::diagnostics::ConfigIssue::Absent(k) if k == "user.name")),
        "expected Absent(user.name), got: {:?}",
        user_check.config_issues
    );
}

#[test]
fn test_diagnostics_git_user_config_present() {
    let git = FakeGitDiagnosticProvider::new(
        true,
        vec![
            ("user.name", Some("Test User")),
            ("user.email", Some("test@example.com")),
        ],
    );
    let crypto = FakeCryptoDiagnosticProvider::new(true);

    let workflow = DiagnosticsWorkflow::new(&git, &crypto);
    let report = workflow.run().unwrap();

    let user_check = report
        .checks
        .iter()
        .find(|c| c.name == "Git user identity")
        .expect("Git user identity check must exist");
    assert!(user_check.passed, "present user.name/email should pass");
    assert!(
        user_check
            .message
            .as_deref()
            .unwrap_or("")
            .contains("Test User"),
        "message should contain the user name"
    );
}

#[test]
fn test_parse_git_version_various_formats() {
    assert_eq!(parse_git_version("git version 2.39.0"), Some((2, 39, 0)));
    assert_eq!(parse_git_version("git version 2.34.1"), Some((2, 34, 1)));
    assert_eq!(
        parse_git_version("git version 2.39.0.windows.1"),
        Some((2, 39, 0))
    );
    assert_eq!(parse_git_version("git version 2.30"), Some((2, 30, 0)));
    assert_eq!(parse_git_version("no version here"), None);
}
