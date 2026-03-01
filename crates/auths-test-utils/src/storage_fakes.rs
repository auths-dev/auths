use auths_core::ports::storage::{
    BlobReader, BlobWriter, EventLogReader, EventLogWriter, RefReader, RefWriter, StorageError,
};
use auths_verifier::keri::Prefix;
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory fake implementing all 6 storage port traits.
///
/// Useful for testing domain logic without a Git repository. All data
/// is stored in `HashMap`s behind a `Mutex` for `Send + Sync` compliance.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::storage_fakes::InMemoryStorage;
/// use auths_core::ports::storage::BlobWriter;
///
/// let store = InMemoryStorage::new();
/// store.put_blob("test/path", b"data").unwrap();
/// ```
pub struct InMemoryStorage {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    refs: Mutex<HashMap<String, Vec<u8>>>,
    event_logs: Mutex<HashMap<String, Vec<Vec<u8>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
            refs: Mutex::new(HashMap::new()),
            event_logs: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobReader for InMemoryStorage {
    fn get_blob(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let store = self.blobs.lock().unwrap();
        store
            .get(path)
            .cloned()
            .ok_or_else(|| StorageError::not_found(path))
    }

    fn list_blobs(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let store = self.blobs.lock().unwrap();
        Ok(store
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn blob_exists(&self, path: &str) -> Result<bool, StorageError> {
        let store = self.blobs.lock().unwrap();
        Ok(store.contains_key(path))
    }
}

impl BlobWriter for InMemoryStorage {
    fn put_blob(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut store = self.blobs.lock().unwrap();
        store.insert(path.to_string(), data.to_vec());
        Ok(())
    }

    fn delete_blob(&self, path: &str) -> Result<(), StorageError> {
        let mut store = self.blobs.lock().unwrap();
        store.remove(path);
        Ok(())
    }
}

impl RefReader for InMemoryStorage {
    fn resolve_ref(&self, refname: &str) -> Result<Vec<u8>, StorageError> {
        let store = self.refs.lock().unwrap();
        store
            .get(refname)
            .cloned()
            .ok_or_else(|| StorageError::not_found(refname))
    }

    fn list_refs(&self, glob: &str) -> Result<Vec<String>, StorageError> {
        let store = self.refs.lock().unwrap();
        let pattern = glob.trim_end_matches('*');
        Ok(store
            .keys()
            .filter(|k| k.starts_with(pattern))
            .cloned()
            .collect())
    }
}

impl RefWriter for InMemoryStorage {
    fn update_ref(&self, refname: &str, target: &[u8], _message: &str) -> Result<(), StorageError> {
        let mut store = self.refs.lock().unwrap();
        store.insert(refname.to_string(), target.to_vec());
        Ok(())
    }

    fn delete_ref(&self, refname: &str) -> Result<(), StorageError> {
        let mut store = self.refs.lock().unwrap();
        store.remove(refname);
        Ok(())
    }
}

impl EventLogReader for InMemoryStorage {
    fn read_event_log(&self, prefix: &Prefix) -> Result<Vec<u8>, StorageError> {
        let store = self.event_logs.lock().unwrap();
        match store.get(prefix.as_str()) {
            Some(events) => Ok(events.iter().flatten().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    fn read_event_at(&self, prefix: &Prefix, seq: u64) -> Result<Vec<u8>, StorageError> {
        let store = self.event_logs.lock().unwrap();
        let key = prefix.as_str();
        let events = store.get(key).ok_or_else(|| StorageError::not_found(key))?;
        events
            .get(seq as usize)
            .cloned()
            .ok_or_else(|| StorageError::not_found(format!("{}/seq/{}", key, seq)))
    }
}

impl EventLogWriter for InMemoryStorage {
    fn append_event(&self, prefix: &Prefix, event: &[u8]) -> Result<(), StorageError> {
        let mut store = self.event_logs.lock().unwrap();
        store
            .entry(prefix.as_str().to_string())
            .or_default()
            .push(event.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip() {
        let store = InMemoryStorage::new();
        store.put_blob("a/b", b"hello").unwrap();
        assert_eq!(store.get_blob("a/b").unwrap(), b"hello");
        assert!(store.blob_exists("a/b").unwrap());
    }

    #[test]
    fn blob_not_found() {
        let store = InMemoryStorage::new();
        assert!(matches!(
            store.get_blob("missing"),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn blob_delete() {
        let store = InMemoryStorage::new();
        store.put_blob("x", b"data").unwrap();
        store.delete_blob("x").unwrap();
        assert!(!store.blob_exists("x").unwrap());
    }

    #[test]
    fn ref_roundtrip() {
        let store = InMemoryStorage::new();
        store.update_ref("refs/test", b"oid", "msg").unwrap();
        assert_eq!(store.resolve_ref("refs/test").unwrap(), b"oid");
    }

    #[test]
    fn event_log_append_and_read() {
        let store = InMemoryStorage::new();
        let pfx = Prefix::new_unchecked("prefix".to_string());
        store.append_event(&pfx, b"evt0").unwrap();
        store.append_event(&pfx, b"evt1").unwrap();

        assert_eq!(store.read_event_at(&pfx, 0).unwrap(), b"evt0");
        assert_eq!(store.read_event_at(&pfx, 1).unwrap(), b"evt1");

        let full = store.read_event_log(&pfx).unwrap();
        assert_eq!(full, b"evt0evt1");
    }

    #[test]
    fn event_log_empty_returns_empty() {
        let store = InMemoryStorage::new();
        let pfx = Prefix::new_unchecked("none".to_string());
        assert!(store.read_event_log(&pfx).unwrap().is_empty());
    }

    #[test]
    fn list_blobs_with_prefix() {
        let store = InMemoryStorage::new();
        store.put_blob("ns/a", b"1").unwrap();
        store.put_blob("ns/b", b"2").unwrap();
        store.put_blob("other/c", b"3").unwrap();

        let mut paths = store.list_blobs("ns/").unwrap();
        paths.sort();
        assert_eq!(paths, vec!["ns/a", "ns/b"]);
    }

    #[test]
    fn list_refs_with_glob() {
        let store = InMemoryStorage::new();
        store.update_ref("refs/a/1", b"x", "").unwrap();
        store.update_ref("refs/a/2", b"y", "").unwrap();
        store.update_ref("refs/b/1", b"z", "").unwrap();

        let mut refs = store.list_refs("refs/a/*").unwrap();
        refs.sort();
        assert_eq!(refs, vec!["refs/a/1", "refs/a/2"]);
    }
}
