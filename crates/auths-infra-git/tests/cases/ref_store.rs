use auths_core::ports::storage::{RefReader, RefWriter, StorageError};
use auths_infra_git::{GitRefStore, GitRepo};

fn setup() -> (tempfile::TempDir, GitRepo) {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let git_repo = GitRepo::open(dir.path()).unwrap();
    (dir, git_repo)
}

#[test]
fn update_and_resolve_ref() {
    let (_dir, repo) = setup();
    let store = GitRefStore::new(&repo);

    store
        .update_ref("refs/test/myref", b"payload", "test update")
        .unwrap();
    let oid_bytes = store.resolve_ref("refs/test/myref").unwrap();
    assert_eq!(oid_bytes.len(), 20);
}

#[test]
fn resolve_missing_ref_returns_not_found() {
    let (_dir, repo) = setup();
    let store = GitRefStore::new(&repo);

    let result = store.resolve_ref("refs/test/missing");
    assert!(matches!(result, Err(StorageError::NotFound { .. })));
}

#[test]
fn list_refs_matches_glob() {
    let (_dir, repo) = setup();
    let store = GitRefStore::new(&repo);

    store.update_ref("refs/test/a", b"1", "create a").unwrap();
    store.update_ref("refs/test/b", b"2", "create b").unwrap();
    store.update_ref("refs/other/c", b"3", "create c").unwrap();

    let mut refs = store.list_refs("refs/test/*").unwrap();
    refs.sort();
    assert_eq!(refs, vec!["refs/test/a", "refs/test/b"]);
}

#[test]
fn delete_ref_removes_it() {
    let (_dir, repo) = setup();
    let store = GitRefStore::new(&repo);

    store
        .update_ref("refs/test/del", b"data", "create")
        .unwrap();
    store.delete_ref("refs/test/del").unwrap();

    let result = store.resolve_ref("refs/test/del");
    assert!(matches!(result, Err(StorageError::NotFound { .. })));
}

#[test]
fn delete_missing_ref_is_idempotent() {
    let (_dir, repo) = setup();
    let store = GitRefStore::new(&repo);

    store.delete_ref("refs/test/never").unwrap();
}
