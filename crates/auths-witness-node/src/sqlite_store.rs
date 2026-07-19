//! The durable [`AnchorStore`] adapter.
//!
//! A witness's entire value is non-amnesiac memory: a store that forgets its
//! per-seed state lets a restarted witness co-sign a conflicting head at an
//! index it already co-signed — the exact equivocation the network exists to
//! prevent. This adapter keeps that state in SQLite (the workspace's single
//! `links = sqlite3` owner — never a second, eventually-consistent store), with
//! the compare-and-set expressed as one guarded write inside a transaction so
//! the database, not the request handler, is the serialization point.

use std::path::Path;
use std::sync::Arc;

use auths_anchor::{Anchor, AnchorStore, CasOutcome, SeedId, StoreError};
use parking_lot::Mutex;

/// A file-backed, single-writer latest-anchor store with atomic CAS.
pub struct SqliteAnchorStore {
    conn: Arc<Mutex<sqlite::Connection>>,
}

fn backend(e: sqlite::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl SqliteAnchorStore {
    /// Open (or create) the store at `path`, in WAL mode for durable
    /// single-writer semantics.
    ///
    /// Args:
    /// * `path`: the database file.
    ///
    /// Usage:
    /// ```ignore
    /// let store = SqliteAnchorStore::open(&data_dir.join("anchors.db"))?;
    /// ```
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = sqlite::Connection::open(path).map_err(backend)?;
        conn.execute("PRAGMA journal_mode = WAL").map_err(backend)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS anchors (
                seed_id TEXT PRIMARY KEY,
                idx INTEGER NOT NULL,
                anchor TEXT NOT NULL
            )",
        )
        .map_err(backend)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn read_latest(
        conn: &sqlite::Connection,
        seed_hex: &str,
    ) -> Result<Option<Anchor>, StoreError> {
        let mut stmt = conn
            .prepare("SELECT anchor FROM anchors WHERE seed_id = ?")
            .map_err(backend)?;
        stmt.bind((1, seed_hex)).map_err(backend)?;
        if let Ok(sqlite::State::Row) = stmt.next() {
            let raw: String = stmt.read(0).map_err(backend)?;
            let anchor: Anchor =
                serde_json::from_str(&raw).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            return Ok(Some(anchor));
        }
        Ok(None)
    }
}

impl AnchorStore for SqliteAnchorStore {
    fn compare_and_set(
        &self,
        seed: &SeedId,
        expected_index: Option<u64>,
        next: &Anchor,
    ) -> Result<CasOutcome, StoreError> {
        let conn = self.conn.lock();
        let seed_hex = seed.to_hex();
        let serialized =
            serde_json::to_string(next).map_err(|e| StoreError::Backend(e.to_string()))?;

        conn.execute("BEGIN IMMEDIATE").map_err(backend)?;
        let outcome = (|| -> Result<CasOutcome, StoreError> {
            let current = Self::read_latest(&conn, &seed_hex)?;
            match (current, expected_index) {
                (None, None) => {
                    let mut stmt = conn
                        .prepare("INSERT INTO anchors (seed_id, idx, anchor) VALUES (?, ?, ?)")
                        .map_err(backend)?;
                    stmt.bind((1, seed_hex.as_str())).map_err(backend)?;
                    stmt.bind((2, next.index as i64)).map_err(backend)?;
                    stmt.bind((3, serialized.as_str())).map_err(backend)?;
                    while stmt.next().map_err(backend)? != sqlite::State::Done {}
                    Ok(CasOutcome::Won)
                }
                (Some(current), Some(expected)) if current.index == expected => {
                    let mut stmt = conn
                        .prepare("UPDATE anchors SET idx = ?, anchor = ? WHERE seed_id = ?")
                        .map_err(backend)?;
                    stmt.bind((1, next.index as i64)).map_err(backend)?;
                    stmt.bind((2, serialized.as_str())).map_err(backend)?;
                    stmt.bind((3, seed_hex.as_str())).map_err(backend)?;
                    while stmt.next().map_err(backend)? != sqlite::State::Done {}
                    Ok(CasOutcome::Won)
                }
                (Some(current), _) => Ok(CasOutcome::Lost(Box::new(current))),
                (None, Some(_)) => Err(StoreError::Backend(
                    "caller expected a prior anchor but the store has none".into(),
                )),
            }
        })();

        match &outcome {
            Ok(_) => conn.execute("COMMIT").map_err(backend)?,
            Err(_) => {
                let _ = conn.execute("ROLLBACK");
            }
        }
        outcome
    }

    fn latest(&self, seed: &SeedId) -> Result<Option<Anchor>, StoreError> {
        let conn = self.conn.lock();
        Self::read_latest(&conn, &seed.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anchors.db");
        let anchor = crate::anchor_role::tests_support::signed_anchor(1, [1u8; 32]);
        {
            let store = SqliteAnchorStore::open(&path).unwrap();
            assert!(matches!(
                store
                    .compare_and_set(&anchor.seed_id, None, &anchor)
                    .unwrap(),
                CasOutcome::Won
            ));
        }
        let store = SqliteAnchorStore::open(&path).unwrap();
        let latest = store.latest(&anchor.seed_id).unwrap().unwrap();
        assert_eq!(latest, anchor);
    }

    #[test]
    fn cas_lost_returns_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteAnchorStore::open(&dir.path().join("a.db")).unwrap();
        let first = crate::anchor_role::tests_support::signed_anchor(1, [1u8; 32]);
        store.compare_and_set(&first.seed_id, None, &first).unwrap();
        let second = crate::anchor_role::tests_support::signed_anchor(2, [2u8; 32]);
        match store
            .compare_and_set(&second.seed_id, None, &second)
            .unwrap()
        {
            CasOutcome::Lost(winner) => assert_eq!(*winner, first),
            CasOutcome::Won => panic!("stale expectation must lose"),
        }
    }
}
