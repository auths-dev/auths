use auths_core::ports::storage::{EventLogReader, EventLogWriter, StorageError};
use auths_infra_git::{GitEventLog, GitRepo};
use auths_verifier::keri::Prefix;

fn setup() -> (tempfile::TempDir, GitRepo) {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let git_repo = GitRepo::open(dir.path()).unwrap();
    (dir, git_repo)
}

#[test]
fn append_and_read_event() {
    let (_dir, repo) = setup();
    let log = GitEventLog::new(&repo);

    let prefix = Prefix::new_unchecked("ETestPrefix".to_string());
    log.append_event(&prefix, b"{\"type\":\"icp\"}").unwrap();
    let data = log.read_event_log(&prefix).unwrap();
    assert_eq!(data, b"{\"type\":\"icp\"}");
}

#[test]
fn read_event_at_specific_sequence() {
    let (_dir, repo) = setup();
    let log = GitEventLog::new(&repo);

    let prefix = Prefix::new_unchecked("ESeqTest".to_string());
    log.append_event(&prefix, b"event-0").unwrap();
    log.append_event(&prefix, b"event-1").unwrap();
    log.append_event(&prefix, b"event-2").unwrap();

    let evt0 = log.read_event_at(&prefix, 0).unwrap();
    assert_eq!(evt0, b"event-0");

    let evt2 = log.read_event_at(&prefix, 2).unwrap();
    assert_eq!(evt2, b"event-2");
}

#[test]
fn read_event_at_out_of_range() {
    let (_dir, repo) = setup();
    let log = GitEventLog::new(&repo);

    let prefix = Prefix::new_unchecked("EBounds".to_string());
    log.append_event(&prefix, b"only-one").unwrap();

    let result = log.read_event_at(&prefix, 5);
    assert!(matches!(result, Err(StorageError::NotFound { .. })));
}

#[test]
fn read_empty_log_returns_empty() {
    let (_dir, repo) = setup();
    let log = GitEventLog::new(&repo);

    let prefix = Prefix::new_unchecked("ENonexistent".to_string());
    let data = log.read_event_log(&prefix).unwrap();
    assert!(data.is_empty());
}

#[test]
fn multiple_events_concatenated_in_order() {
    let (_dir, repo) = setup();
    let log = GitEventLog::new(&repo);

    let prefix = Prefix::new_unchecked("EConcat".to_string());
    log.append_event(&prefix, b"AAA").unwrap();
    log.append_event(&prefix, b"BBB").unwrap();

    let data = log.read_event_log(&prefix).unwrap();
    assert_eq!(data, b"AAABBB");
}
