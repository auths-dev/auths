//! SQLite-based witness storage for persistence.
//!
//! This module provides persistent storage for witness state, enabling
//! the witness to recover its first-seen records and receipts after restart.
//!
//! # Schema
//!
//! Two tables are used:
//! - `first_seen`: Records (prefix, seq) → SAID mappings
//! - `receipts`: Stores issued receipts by (prefix, event_said)
//!
//! # Feature Gate
//!
//! This module requires the `witness-server` feature.

use std::path::Path;

use auths_verifier::keri::{Prefix, Said};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use super::error::WitnessError;
use super::receipt::Receipt;

/// SQLite-based storage for witness state.
///
/// Stores first-seen records and issued receipts with WAL mode for
/// durability and concurrent reads.
pub struct WitnessStorage {
    conn: Connection,
}

impl WitnessStorage {
    /// Open or create a witness storage database.
    ///
    /// Creates the necessary tables if they don't exist.
    pub fn open(path: &Path) -> Result<Self, WitnessError> {
        let conn = Connection::open(path)
            .map_err(|e| WitnessError::Storage(format!("failed to open database: {}", e)))?;

        // Enable WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| WitnessError::Storage(format!("failed to enable WAL: {}", e)))?;

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory storage (for testing).
    pub fn in_memory() -> Result<Self, WitnessError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WitnessError::Storage(format!("failed to open in-memory db: {}", e)))?;

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> Result<(), WitnessError> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS first_seen (
                    prefix TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    said TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (prefix, seq)
                );

                CREATE TABLE IF NOT EXISTS receipts (
                    prefix TEXT NOT NULL,
                    event_said TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (prefix, event_said)
                );

                CREATE INDEX IF NOT EXISTS idx_receipts_prefix ON receipts(prefix);
                "#,
            )
            .map_err(|e| WitnessError::Storage(format!("failed to create schema: {}", e)))?;

        Ok(())
    }

    /// Record a first-seen event.
    ///
    /// If the (prefix, seq) already exists, this is a no-op (idempotent).
    pub fn record_first_seen(
        &self,
        now: DateTime<Utc>,
        prefix: &Prefix,
        seq: u64,
        said: &Said,
    ) -> Result<(), WitnessError> {
        let now = now.to_rfc3339();

        self.conn
            .execute(
                "INSERT OR IGNORE INTO first_seen (prefix, seq, said, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![prefix.as_str(), seq as i64, said.as_str(), now],
            )
            .map_err(|e| WitnessError::Storage(format!("failed to record first_seen: {}", e)))?;

        Ok(())
    }

    /// Get the first-seen SAID for a (prefix, seq).
    pub fn get_first_seen(&self, prefix: &Prefix, seq: u64) -> Result<Option<Said>, WitnessError> {
        let result: Result<String, _> = self.conn.query_row(
            "SELECT said FROM first_seen WHERE prefix = ?1 AND seq = ?2",
            params![prefix.as_str(), seq as i64],
            |row| row.get(0),
        );

        match result {
            Ok(said) => Ok(Some(Said::new_unchecked(said))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WitnessError::Storage(format!(
                "failed to get first_seen: {}",
                e
            ))),
        }
    }

    /// Check for duplicity: same (prefix, seq) with different SAID.
    ///
    /// Returns:
    /// - `Ok(None)` if no previous record or same SAID
    /// - `Ok(Some(existing_said))` if different SAID (duplicity!)
    pub fn check_duplicity(
        &self,
        now: DateTime<Utc>,
        prefix: &Prefix,
        seq: u64,
        said: &Said,
    ) -> Result<Option<Said>, WitnessError> {
        match self.get_first_seen(prefix, seq)? {
            None => {
                // First time seeing this (prefix, seq)
                self.record_first_seen(now, prefix, seq, said)?;
                Ok(None)
            }
            Some(existing) if existing == *said => {
                // Same SAID, no duplicity
                Ok(None)
            }
            Some(existing) => {
                // Different SAID - duplicity!
                Ok(Some(existing))
            }
        }
    }

    /// Store an issued receipt.
    pub fn store_receipt(
        &self,
        now: DateTime<Utc>,
        prefix: &Prefix,
        receipt: &Receipt,
    ) -> Result<(), WitnessError> {
        let now = now.to_rfc3339();
        let json = serde_json::to_string(receipt)
            .map_err(|e| WitnessError::Serialization(e.to_string()))?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO receipts (prefix, event_said, receipt_json, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![prefix.as_str(), receipt.a.as_str(), json, now],
            )
            .map_err(|e| WitnessError::Storage(format!("failed to store receipt: {}", e)))?;

        Ok(())
    }

    /// Retrieve a receipt by prefix and event SAID.
    pub fn get_receipt(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<Receipt>, WitnessError> {
        let result = self.conn.query_row(
            "SELECT receipt_json FROM receipts WHERE prefix = ?1 AND event_said = ?2",
            params![prefix.as_str(), event_said.as_str()],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(json) => {
                let receipt = serde_json::from_str(&json)
                    .map_err(|e| WitnessError::Serialization(e.to_string()))?;
                Ok(Some(receipt))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WitnessError::Storage(format!(
                "failed to get receipt: {}",
                e
            ))),
        }
    }

    /// Get the latest sequence number seen for a prefix.
    pub fn get_latest_seq(&self, prefix: &Prefix) -> Result<Option<u64>, WitnessError> {
        let result = self.conn.query_row(
            "SELECT MAX(seq) FROM first_seen WHERE prefix = ?1",
            params![prefix.as_str()],
            |row| row.get::<_, Option<i64>>(0),
        );

        match result {
            Ok(Some(seq)) => Ok(Some(seq as u64)),
            Ok(None) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WitnessError::Storage(format!(
                "failed to get latest seq: {}",
                e
            ))),
        }
    }

    /// Count total first-seen records.
    pub fn count_first_seen(&self) -> Result<usize, WitnessError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM first_seen", [], |row| row.get(0))
            .map_err(|e| WitnessError::Storage(format!("failed to count: {}", e)))?;

        Ok(count as usize)
    }

    /// Count total receipts.
    pub fn count_receipts(&self) -> Result<usize, WitnessError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .map_err(|e| WitnessError::Storage(format!("failed to count: {}", e)))?;

        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Prefix {
        Prefix::new_unchecked(s.into())
    }

    fn said(s: &str) -> Said {
        Said::new_unchecked(s.into())
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn sample_receipt(event_said: &str) -> Receipt {
        Receipt {
            v: "KERI10JSON".into(),
            t: "rct".into(),
            d: Said::new_unchecked("EReceipt".into()),
            i: "did:key:witness".into(),
            s: 5,
            a: Said::new_unchecked(event_said.into()),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn storage_in_memory() {
        let storage = WitnessStorage::in_memory().unwrap();
        assert_eq!(storage.count_first_seen().unwrap(), 0);
    }

    #[test]
    fn record_and_get_first_seen() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        storage
            .record_first_seen(now(), &p, 0, &said("ESAID_A"))
            .unwrap();

        let result = storage.get_first_seen(&p, 0).unwrap();
        assert_eq!(result, Some(said("ESAID_A")));

        // Non-existent
        let result = storage.get_first_seen(&p, 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn first_seen_idempotent() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        storage
            .record_first_seen(now(), &p, 0, &said("ESAID_A"))
            .unwrap();
        storage
            .record_first_seen(now(), &p, 0, &said("ESAID_A"))
            .unwrap();

        assert_eq!(storage.count_first_seen().unwrap(), 1);
    }

    #[test]
    fn check_duplicity_first_time() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        let result = storage
            .check_duplicity(now(), &p, 0, &said("ESAID_A"))
            .unwrap();
        assert!(result.is_none());

        // Verify it was recorded
        assert_eq!(
            storage.get_first_seen(&p, 0).unwrap(),
            Some(said("ESAID_A"))
        );
    }

    #[test]
    fn check_duplicity_same_said() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        storage
            .record_first_seen(now(), &p, 0, &said("ESAID_A"))
            .unwrap();

        let result = storage
            .check_duplicity(now(), &p, 0, &said("ESAID_A"))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn check_duplicity_different_said() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        storage
            .record_first_seen(now(), &p, 0, &said("ESAID_A"))
            .unwrap();

        let result = storage
            .check_duplicity(now(), &p, 0, &said("ESAID_B"))
            .unwrap();
        assert_eq!(result, Some(said("ESAID_A")));
    }

    #[test]
    fn store_and_get_receipt() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        let receipt = sample_receipt("EEVENT_SAID");
        storage.store_receipt(now(), &p, &receipt).unwrap();

        let result = storage.get_receipt(&p, &said("EEVENT_SAID")).unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.a, "EEVENT_SAID");
    }

    #[test]
    fn get_receipt_not_found() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        let result = storage.get_receipt(&p, &said("ENONEXISTENT")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_latest_seq() {
        let storage = WitnessStorage::in_memory().unwrap();
        let p = prefix("EPrefix");

        // No records
        assert!(storage.get_latest_seq(&p).unwrap().is_none());

        storage
            .record_first_seen(now(), &p, 0, &said("ES0"))
            .unwrap();
        storage
            .record_first_seen(now(), &p, 5, &said("ES5"))
            .unwrap();
        storage
            .record_first_seen(now(), &p, 3, &said("ES3"))
            .unwrap();

        assert_eq!(storage.get_latest_seq(&p).unwrap(), Some(5));
    }
}
