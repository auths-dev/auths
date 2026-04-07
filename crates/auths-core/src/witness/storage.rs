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

use auths_keri::{Prefix, Said};
use chrono::{DateTime, Utc};
use sqlite::Connection;

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
        conn.execute("PRAGMA journal_mode=WAL")
            .map_err(|e| WitnessError::Storage(format!("failed to enable WAL: {}", e)))?;

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory storage (for testing).
    pub fn in_memory() -> Result<Self, WitnessError> {
        let conn = Connection::open(":memory:")
            .map_err(|e| WitnessError::Storage(format!("failed to open in-memory db: {}", e)))?;

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> Result<(), WitnessError> {
        self.conn
            .execute(
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

        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO first_seen (prefix, seq, said, created_at) VALUES (?, ?, ?, ?)"
        ).map_err(|e| WitnessError::Storage(format!("failed to prepare record_first_seen: {}", e)))?;

        stmt.bind((1, prefix.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind prefix: {}", e)))?;
        stmt.bind((2, seq as i64))
            .map_err(|e| WitnessError::Storage(format!("failed to bind seq: {}", e)))?;
        stmt.bind((3, said.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind said: {}", e)))?;
        stmt.bind((4, now.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind now: {}", e)))?;

        stmt.next().map_err(|e| {
            WitnessError::Storage(format!("failed to execute record_first_seen: {}", e))
        })?;

        Ok(())
    }

    /// Get the first-seen SAID for a (prefix, seq).
    pub fn get_first_seen(&self, prefix: &Prefix, seq: u64) -> Result<Option<Said>, WitnessError> {
        let mut stmt = self
            .conn
            .prepare("SELECT said FROM first_seen WHERE prefix = ? AND seq = ?")
            .map_err(|e| {
                WitnessError::Storage(format!("failed to prepare get_first_seen: {}", e))
            })?;

        stmt.bind((1, prefix.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind prefix: {}", e)))?;
        stmt.bind((2, seq as i64))
            .map_err(|e| WitnessError::Storage(format!("failed to bind seq: {}", e)))?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let said: String = stmt
                .read(0)
                .map_err(|e| WitnessError::Storage(format!("failed to read said: {}", e)))?;
            Ok(Some(Said::new_unchecked(said)))
        } else {
            Ok(None)
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

        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO receipts (prefix, event_said, receipt_json, created_at) VALUES (?, ?, ?, ?)"
        ).map_err(|e| WitnessError::Storage(format!("failed to prepare store_receipt: {}", e)))?;

        stmt.bind((1, prefix.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind prefix: {}", e)))?;
        stmt.bind((2, receipt.a.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind event_said: {}", e)))?;
        stmt.bind((3, json.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind json: {}", e)))?;
        stmt.bind((4, now.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind now: {}", e)))?;

        stmt.next().map_err(|e| {
            WitnessError::Storage(format!("failed to execute store_receipt: {}", e))
        })?;

        Ok(())
    }

    /// Retrieve a receipt by prefix and event SAID.
    pub fn get_receipt(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<Receipt>, WitnessError> {
        let mut stmt = self
            .conn
            .prepare("SELECT receipt_json FROM receipts WHERE prefix = ? AND event_said = ?")
            .map_err(|e| WitnessError::Storage(format!("failed to prepare get_receipt: {}", e)))?;

        stmt.bind((1, prefix.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind prefix: {}", e)))?;
        stmt.bind((2, event_said.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind event_said: {}", e)))?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let json: String = stmt.read(0).map_err(|e| {
                WitnessError::Storage(format!("failed to read receipt_json: {}", e))
            })?;
            let receipt = serde_json::from_str(&json)
                .map_err(|e| WitnessError::Serialization(e.to_string()))?;
            Ok(Some(receipt))
        } else {
            Ok(None)
        }
    }

    /// Get the latest sequence number seen for a prefix.
    pub fn get_latest_seq(&self, prefix: &Prefix) -> Result<Option<u64>, WitnessError> {
        let mut stmt = self
            .conn
            .prepare("SELECT MAX(seq) FROM first_seen WHERE prefix = ?")
            .map_err(|e| {
                WitnessError::Storage(format!("failed to prepare get_latest_seq: {}", e))
            })?;

        stmt.bind((1, prefix.as_str()))
            .map_err(|e| WitnessError::Storage(format!("failed to bind prefix: {}", e)))?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let seq: Option<i64> = stmt
                .read(0)
                .map_err(|e| WitnessError::Storage(format!("failed to read max seq: {}", e)))?;
            Ok(seq.map(|s| s as u64))
        } else {
            Ok(None)
        }
    }

    /// Count total first-seen records.
    pub fn count_first_seen(&self) -> Result<usize, WitnessError> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM first_seen")
            .map_err(|e| {
                WitnessError::Storage(format!("failed to prepare count_first_seen: {}", e))
            })?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let count: i64 = stmt
                .read(0)
                .map_err(|e| WitnessError::Storage(format!("failed to read count: {}", e)))?;
            Ok(count as usize)
        } else {
            Ok(0)
        }
    }

    /// Count total receipts.
    pub fn count_receipts(&self) -> Result<usize, WitnessError> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM receipts")
            .map_err(|e| {
                WitnessError::Storage(format!("failed to prepare count_receipts: {}", e))
            })?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let count: i64 = stmt
                .read(0)
                .map_err(|e| WitnessError::Storage(format!("failed to read count: {}", e)))?;
            Ok(count as usize)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
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
