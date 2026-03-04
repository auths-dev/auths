use auths_core::ports::storage::{BlobReader, BlobWriter, StorageError};
use auths_infra_git::{GitBlobStore, GitRepo};

fn setup() -> (tempfile::TempDir, GitRepo) {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let git_repo = GitRepo::open(dir.path()).unwrap();
    (dir, git_repo)
}

#[test]
fn put_and_get_blob() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.put_blob("test/data", b"hello world").unwrap();
    let data = store.get_blob("test/data").unwrap();
    assert_eq!(data, b"hello world");
}

#[test]
fn get_missing_blob_returns_not_found() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    let result = store.get_blob("nonexistent/path");
    assert!(matches!(result, Err(StorageError::NotFound { .. })));
}

#[test]
fn blob_exists_returns_false_for_missing() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    assert!(!store.blob_exists("nonexistent").unwrap());
}

#[test]
fn blob_exists_returns_true_after_put() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.put_blob("exists/test", b"data").unwrap();
    assert!(store.blob_exists("exists/test").unwrap());
}

#[test]
fn list_blobs_finds_stored() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.put_blob("ns/a", b"1").unwrap();
    store.put_blob("ns/b", b"2").unwrap();
    store.put_blob("other/c", b"3").unwrap();

    let mut paths = store.list_blobs("ns/").unwrap();
    paths.sort();
    assert_eq!(paths, vec!["ns/a", "ns/b"]);
}

#[test]
fn delete_blob_removes_ref() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.put_blob("del/test", b"data").unwrap();
    assert!(store.blob_exists("del/test").unwrap());

    store.delete_blob("del/test").unwrap();
    assert!(!store.blob_exists("del/test").unwrap());
}

#[test]
fn delete_missing_blob_is_idempotent() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.delete_blob("never/existed").unwrap();
}

#[test]
fn put_blob_overwrites() {
    let (_dir, repo) = setup();
    let store = GitBlobStore::new(&repo);

    store.put_blob("overwrite/test", b"first").unwrap();
    store.put_blob("overwrite/test", b"second").unwrap();
    let data = store.get_blob("overwrite/test").unwrap();
    assert_eq!(data, b"second");
}
