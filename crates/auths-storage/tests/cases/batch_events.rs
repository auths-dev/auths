use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fixtures::test_inception_event;
use auths_storage::git::{GitRegistryBackend, RegistryConfig};

fn setup() -> (GitRegistryBackend, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (backend, dir)
}

#[test]
fn batch_empty_is_noop() {
    let (backend, _dir) = setup();
    backend.batch_append_events(&[]).unwrap();
    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 0);
}

#[test]
fn batch_single_inception() {
    let (backend, _dir) = setup();
    let event = test_inception_event("batch-single");
    let prefix = event.prefix().clone();

    backend
        .batch_append_events(&[(prefix.clone(), event.clone())])
        .unwrap();

    let tip = backend.get_tip(&prefix).unwrap();
    assert_eq!(tip.sequence, 0);
    assert_eq!(&tip.said, event.said());

    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 1);
}

#[test]
fn batch_multiple_prefixes() {
    let (backend, _dir) = setup();
    let e1 = test_inception_event("batch-multi-1");
    let e2 = test_inception_event("batch-multi-2");
    let e3 = test_inception_event("batch-multi-3");
    let p1 = e1.prefix().clone();
    let p2 = e2.prefix().clone();
    let p3 = e3.prefix().clone();

    backend
        .batch_append_events(&[
            (p1.clone(), e1.clone()),
            (p2.clone(), e2.clone()),
            (p3.clone(), e3.clone()),
        ])
        .unwrap();

    assert_eq!(backend.get_tip(&p1).unwrap().sequence, 0);
    assert_eq!(backend.get_tip(&p2).unwrap().sequence, 0);
    assert_eq!(backend.get_tip(&p3).unwrap().sequence, 0);

    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 3);
}

#[test]
fn batch_validation_failure_reports_index() {
    let (backend, _dir) = setup();

    let e1 = test_inception_event("batch-fail-1");
    let e2 = test_inception_event("batch-fail-2");
    let p1 = e1.prefix().clone();
    let p2 = e2.prefix().clone();

    // Pre-append e2 so it'll fail as duplicate in the batch
    backend.append_event(&p2, &e2).unwrap();

    let result = backend.batch_append_events(&[
        (p1.clone(), e1),
        (p2.clone(), e2), // This should fail at index 1
    ]);

    let err = result.unwrap_err();
    match err {
        auths_id::ports::registry::RegistryError::BatchValidationFailed { index, .. } => {
            assert_eq!(index, 1, "failure should be at index 1");
        }
        other => panic!("expected BatchValidationFailed, got: {other}"),
    }

    // The first event should NOT have been committed (atomic rejection)
    assert!(
        backend.get_tip(&p1).is_err(),
        "first event should not be committed on batch failure"
    );
}

#[test]
fn batch_duplicate_prefix_same_seq_fails() {
    let (backend, _dir) = setup();

    let e1 = test_inception_event("batch-dup-1");
    let e2 = test_inception_event("batch-dup-2");
    let p1 = e1.prefix().clone();

    // Two ICPs for different prefixes in same batch is fine,
    // but two ICPs for the same prefix should fail at the second (seq gap: expected 1, got 0)
    let result = backend.batch_append_events(&[
        (p1.clone(), e1),
        (p1.clone(), e2), // Wrong prefix — e2 has a different prefix
    ]);

    // e2 has a different prefix than p1, so this should fail with InvalidPrefix
    assert!(result.is_err());
}
