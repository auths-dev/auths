use auths_sdk::ports::git::{CommitRecord, SignatureStatus};
use auths_sdk::testing::fakes::FakeGitLogProvider;
use auths_sdk::workflows::audit::AuditWorkflow;

fn make_commit(hash: &str, status: SignatureStatus) -> CommitRecord {
    CommitRecord {
        hash: hash.to_string(),
        author_name: "Test Author".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: "2024-01-15T10:00:00+00:00".to_string(),
        message: "test commit".to_string(),
        signature_status: status,
    }
}

#[test]
fn test_audit_empty_repo() {
    let provider = FakeGitLogProvider::with_commits(vec![]);
    let workflow = AuditWorkflow::new(&provider);
    let report = workflow.generate_report(None, None).unwrap();

    assert_eq!(report.summary.total_commits, 0);
    assert_eq!(report.summary.signed_commits, 0);
    assert_eq!(report.summary.unsigned_commits, 0);
    assert!(report.commits.is_empty());
}

#[test]
fn test_audit_all_signed() {
    let provider = FakeGitLogProvider::with_commits(vec![
        make_commit(
            "abc1234",
            SignatureStatus::AuthsSigned {
                signer_did: "did:keri:abc".to_string(),
            },
        ),
        make_commit("def5678", SignatureStatus::GpgSigned { verified: true }),
        make_commit("ghi9012", SignatureStatus::SshSigned),
    ]);
    let workflow = AuditWorkflow::new(&provider);
    let report = workflow.generate_report(None, None).unwrap();

    assert_eq!(report.summary.total_commits, 3);
    assert_eq!(report.summary.signed_commits, 3);
    assert_eq!(report.summary.unsigned_commits, 0);
    assert_eq!(report.summary.auths_signed, 1);
    assert_eq!(report.summary.gpg_signed, 1);
    assert_eq!(report.summary.ssh_signed, 1);
    assert_eq!(report.summary.verification_passed, 2);
}

#[test]
fn test_audit_mixed_signatures() {
    let provider = FakeGitLogProvider::with_commits(vec![
        make_commit(
            "abc1234",
            SignatureStatus::AuthsSigned {
                signer_did: "did:keri:abc".to_string(),
            },
        ),
        make_commit("def5678", SignatureStatus::Unsigned),
        make_commit("ghi9012", SignatureStatus::GpgSigned { verified: false }),
        make_commit(
            "jkl3456",
            SignatureStatus::InvalidSignature {
                reason: "corrupt".to_string(),
            },
        ),
    ]);
    let workflow = AuditWorkflow::new(&provider);
    let report = workflow.generate_report(None, None).unwrap();

    assert_eq!(report.summary.total_commits, 4);
    assert_eq!(report.summary.signed_commits, 3);
    assert_eq!(report.summary.unsigned_commits, 1);
    assert_eq!(report.summary.verification_failed, 2);
    assert_eq!(report.summary.auths_signed, 1);
    assert_eq!(report.summary.gpg_signed, 1);
    assert_eq!(report.summary.verification_passed, 1);
}

#[test]
fn test_audit_lock_poisoned() {
    let provider = FakeGitLogProvider::poisoned();
    let workflow = AuditWorkflow::new(&provider);
    let result = workflow.generate_report(None, None);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("lock poisoned"),
        "expected LockPoisoned error, got: {}",
        err
    );
}

#[test]
fn test_audit_respects_limit() {
    let provider = FakeGitLogProvider::with_commits(vec![
        make_commit("abc1234", SignatureStatus::Unsigned),
        make_commit("def5678", SignatureStatus::Unsigned),
        make_commit("ghi9012", SignatureStatus::Unsigned),
    ]);
    let workflow = AuditWorkflow::new(&provider);
    let report = workflow.generate_report(None, Some(2)).unwrap();

    assert_eq!(report.commits.len(), 2);
    assert_eq!(report.summary.total_commits, 2);
}
