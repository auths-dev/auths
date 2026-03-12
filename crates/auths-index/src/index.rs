use crate::error::Result;
use crate::schema;
use auths_verifier::core::{CommitOid, ResourceId};
use auths_verifier::keri::{Prefix, Said};
use auths_verifier::types::{DeviceDID, IdentityDID};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlite::Connection;
use std::path::Path;

/// Indexed metadata for an attestation stored in the SQLite index.
/// This contains only metadata - full attestation data is loaded from Git when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedAttestation {
    /// Primary key - the attestation RID
    pub rid: ResourceId,
    /// DID of the issuer (controller)
    pub issuer_did: IdentityDID,
    /// DID of the device this attestation is for
    pub device_did: DeviceDID,
    /// Git ref path (e.g., refs/auths/devices/nodes/...)
    pub git_ref: String,
    /// Git commit OID for loading full attestation (None when OID is not yet known)
    pub commit_oid: Option<CommitOid>,
    /// When this attestation was revoked, if applicable
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optional expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,
    /// When this index entry was last updated
    pub updated_at: DateTime<Utc>,
}

/// Index entry for a KERI identity (prefix → current key state summary).
///
/// Stores only the fields needed for O(1) membership and key lookups.
/// Full `KeyState` is loaded from `GitRegistryBackend` when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedIdentity {
    pub prefix: Prefix,
    pub current_keys: Vec<String>,
    pub sequence: u64,
    pub tip_said: Said,
    pub updated_at: DateTime<Utc>,
}

/// Index entry for an org membership attestation.
///
/// Enables O(1) org member listing without Git tree traversal.
/// Full `Attestation` is loaded from Git when policy evaluation needs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedOrgMember {
    pub org_prefix: Prefix,
    pub member_did: DeviceDID,
    pub issuer_did: IdentityDID,
    pub rid: ResourceId,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// SQLite-backed index for O(1) attestation, identity, and org member lookups.
pub struct AttestationIndex {
    conn: Connection,
}

impl AttestationIndex {
    /// Opens an existing index or creates a new one at the given path.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        schema::init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Creates an in-memory index (for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open(":memory:")?;
        schema::init_schema(&conn)?;
        Ok(Self { conn })
    }

    // =========================================================================
    // Attestation methods
    // =========================================================================

    /// Inserts or updates an attestation in the index.
    pub fn upsert_attestation(&self, att: &IndexedAttestation) -> Result<()> {
        let revoked_at_str = att.revoked_at.map(|dt| dt.to_rfc3339());
        let expires_at_str = att.expires_at.map(|dt| dt.to_rfc3339());
        let updated_at_str = att.updated_at.to_rfc3339();

        let mut stmt = self.conn.prepare(
            r#"
            INSERT INTO attestations (rid, issuer_did, device_did, git_ref, commit_oid, revoked_at, expires_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rid) DO UPDATE SET
                issuer_did = excluded.issuer_did,
                device_did = excluded.device_did,
                git_ref = excluded.git_ref,
                commit_oid = excluded.commit_oid,
                revoked_at = excluded.revoked_at,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            "#,
        )?;

        stmt.bind((1, att.rid.as_str()))?;
        stmt.bind((2, att.issuer_did.as_str()))?;
        stmt.bind((3, att.device_did.as_str()))?;
        stmt.bind((4, att.git_ref.as_str()))?;
        stmt.bind((5, att.commit_oid.as_ref().map(|c| c.as_str())))?;
        stmt.bind((6, revoked_at_str.as_deref()))?;
        stmt.bind((7, expires_at_str.as_deref()))?;
        stmt.bind((8, updated_at_str.as_str()))?;

        stmt.next()?;
        Ok(())
    }

    /// Queries attestations by device DID.
    pub fn query_by_device(&self, device_did: &str) -> Result<Vec<IndexedAttestation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rid, issuer_did, device_did, git_ref, commit_oid, revoked_at, expires_at, updated_at FROM attestations WHERE device_did = ?")?;

        stmt.bind((1, device_did))?;

        let mut results = Vec::new();
        while let Ok(sqlite::State::Row) = stmt.next() {
            results.push(self.row_to_attestation(&stmt)?);
        }
        Ok(results)
    }

    /// Queries attestations by issuer DID.
    pub fn query_by_issuer(&self, issuer_did: &str) -> Result<Vec<IndexedAttestation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rid, issuer_did, device_did, git_ref, commit_oid, revoked_at, expires_at, updated_at FROM attestations WHERE issuer_did = ?")?;

        stmt.bind((1, issuer_did))?;

        let mut results = Vec::new();
        while let Ok(sqlite::State::Row) = stmt.next() {
            results.push(self.row_to_attestation(&stmt)?);
        }
        Ok(results)
    }

    /// Queries attestations expiring before the given deadline.
    pub fn query_expiring_before(
        &self,
        deadline: DateTime<Utc>,
    ) -> Result<Vec<IndexedAttestation>> {
        let deadline_str = deadline.to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT rid, issuer_did, device_did, git_ref, commit_oid, revoked_at, expires_at, updated_at FROM attestations WHERE expires_at IS NOT NULL AND expires_at < ? AND revoked_at IS NULL",
        )?;

        stmt.bind((1, deadline_str.as_str()))?;

        let mut results = Vec::new();
        while let Ok(sqlite::State::Row) = stmt.next() {
            results.push(self.row_to_attestation(&stmt)?);
        }
        Ok(results)
    }

    /// Queries all active (non-revoked) attestations.
    pub fn query_active(&self) -> Result<Vec<IndexedAttestation>> {
        let mut stmt = self.conn.prepare(
            "SELECT rid, issuer_did, device_did, git_ref, commit_oid, revoked_at, expires_at, updated_at FROM attestations WHERE revoked_at IS NULL",
        )?;

        let mut results = Vec::new();
        while let Ok(sqlite::State::Row) = stmt.next() {
            results.push(self.row_to_attestation(&stmt)?);
        }
        Ok(results)
    }

    /// Clears all attestations from the index.
    pub fn clear(&self) -> Result<()> {
        self.conn.execute("DELETE FROM attestations")?;
        Ok(())
    }

    /// Returns the count of attestations in the index.
    pub fn count(&self) -> Result<usize> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM attestations")?;
        if let Ok(sqlite::State::Row) = stmt.next() {
            let count: i64 = stmt.read(0)?;
            return Ok(count as usize);
        }
        Ok(0)
    }

    /// Returns statistics about the index.
    pub fn stats(&self) -> Result<IndexStats> {
        let total = self.count()?;

        let mut stmt_active = self
            .conn
            .prepare("SELECT COUNT(*) FROM attestations WHERE revoked_at IS NULL")?;
        let active = if let Ok(sqlite::State::Row) = stmt_active.next() {
            stmt_active.read::<i64, _>(0)?
        } else {
            0
        };

        let mut stmt_revoked = self
            .conn
            .prepare("SELECT COUNT(*) FROM attestations WHERE revoked_at IS NOT NULL")?;
        let revoked = if let Ok(sqlite::State::Row) = stmt_revoked.next() {
            stmt_revoked.read::<i64, _>(0)?
        } else {
            0
        };

        let mut stmt_expiry = self
            .conn
            .prepare("SELECT COUNT(*) FROM attestations WHERE expires_at IS NOT NULL")?;
        let with_expiry = if let Ok(sqlite::State::Row) = stmt_expiry.next() {
            stmt_expiry.read::<i64, _>(0)?
        } else {
            0
        };

        let mut stmt_devices = self
            .conn
            .prepare("SELECT COUNT(DISTINCT device_did) FROM attestations")?;
        let unique_devices = if let Ok(sqlite::State::Row) = stmt_devices.next() {
            stmt_devices.read::<i64, _>(0)?
        } else {
            0
        };

        let mut stmt_issuers = self
            .conn
            .prepare("SELECT COUNT(DISTINCT issuer_did) FROM attestations")?;
        let unique_issuers = if let Ok(sqlite::State::Row) = stmt_issuers.next() {
            stmt_issuers.read::<i64, _>(0)?
        } else {
            0
        };

        Ok(IndexStats {
            total_attestations: total,
            active_attestations: active as usize,
            revoked_attestations: revoked as usize,
            with_expiry: with_expiry as usize,
            unique_devices: unique_devices as usize,
            unique_issuers: unique_issuers as usize,
        })
    }

    /// Helper to convert a database row to an IndexedAttestation.
    fn row_to_attestation(&self, stmt: &sqlite::Statement) -> Result<IndexedAttestation> {
        let rid: String = stmt.read(0)?;
        let issuer_did: String = stmt.read(1)?;
        let device_did: String = stmt.read(2)?;
        let git_ref: String = stmt.read(3)?;
        let commit_oid: Option<String> = stmt.read(4)?;
        let revoked_at_str: Option<String> = stmt.read(5)?;
        let expires_at_str: Option<String> = stmt.read(6)?;
        let updated_at_str: String = stmt.read(7)?;

        let revoked_at = revoked_at_str
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let expires_at = expires_at_str
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(IndexedAttestation {
            rid: ResourceId::new(rid),
            issuer_did: IdentityDID::new_unchecked(issuer_did),
            device_did: DeviceDID::new_unchecked(device_did),
            git_ref,
            commit_oid: commit_oid
                .filter(|s| !s.is_empty())
                .and_then(|s| CommitOid::parse(&s).ok()),
            revoked_at,
            expires_at,
            updated_at,
        })
    }

    // =========================================================================
    // Identity methods
    // =========================================================================

    /// Inserts or updates an identity in the index.
    pub fn upsert_identity(&self, identity: &IndexedIdentity) -> Result<()> {
        let keys_json = serde_json::to_string(&identity.current_keys)?;
        let mut stmt = self.conn.prepare(
            r#"
            INSERT INTO identities (prefix, current_keys, sequence, tip_said, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(prefix) DO UPDATE SET
                current_keys = excluded.current_keys,
                sequence     = excluded.sequence,
                tip_said     = excluded.tip_said,
                updated_at   = excluded.updated_at
            "#,
        )?;

        stmt.bind((1, identity.prefix.as_str()))?;
        stmt.bind((2, keys_json.as_str()))?;
        stmt.bind((3, identity.sequence as i64))?;
        stmt.bind((4, identity.tip_said.as_str()))?;
        stmt.bind((5, identity.updated_at.to_rfc3339().as_str()))?;

        stmt.next()?;
        Ok(())
    }

    /// Queries an identity by prefix.
    pub fn query_identity(&self, prefix: &str) -> Result<Option<IndexedIdentity>> {
        let mut stmt = self.conn.prepare(
            "SELECT prefix, current_keys, sequence, tip_said, updated_at
             FROM identities WHERE prefix = ?",
        )?;

        stmt.bind((1, prefix))?;

        if let Ok(sqlite::State::Row) = stmt.next() {
            let prefix: String = stmt.read(0)?;
            let keys_json: String = stmt.read(1)?;
            let sequence: i64 = stmt.read(2)?;
            let tip_said: String = stmt.read(3)?;
            let updated_at_str: String = stmt.read(4)?;

            let current_keys: Vec<String> = serde_json::from_str(&keys_json)?;
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(Some(IndexedIdentity {
                prefix: Prefix::new_unchecked(prefix),
                current_keys,
                sequence: sequence as u64,
                tip_said: Said::new_unchecked(tip_said),
                updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Org member methods
    // =========================================================================

    /// Inserts or updates an org member in the index.
    pub fn upsert_org_member(&self, member: &IndexedOrgMember) -> Result<()> {
        let mut stmt = self.conn.prepare(
            r#"
            INSERT INTO org_members
                (org_prefix, member_did, issuer_did, rid, revoked_at, expires_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_prefix, member_did) DO UPDATE SET
                issuer_did = excluded.issuer_did,
                rid        = excluded.rid,
                revoked_at = excluded.revoked_at,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            "#,
        )?;

        stmt.bind((1, member.org_prefix.as_str()))?;
        stmt.bind((2, member.member_did.as_str()))?;
        stmt.bind((3, member.issuer_did.as_str()))?;
        stmt.bind((4, member.rid.as_str()))?;
        stmt.bind((5, member.revoked_at.map(|dt| dt.to_rfc3339()).as_deref()))?;
        stmt.bind((6, member.expires_at.map(|dt| dt.to_rfc3339()).as_deref()))?;
        stmt.bind((7, member.updated_at.to_rfc3339().as_str()))?;

        stmt.next()?;
        Ok(())
    }

    /// Lists all members of an org from the index.
    pub fn list_org_members_indexed(&self, org_prefix: &str) -> Result<Vec<IndexedOrgMember>> {
        let mut stmt = self.conn.prepare(
            "SELECT org_prefix, member_did, issuer_did, rid, revoked_at, expires_at, updated_at
             FROM org_members WHERE org_prefix = ?
             ORDER BY member_did ASC",
        )?;

        stmt.bind((1, org_prefix))?;

        let parse_dt = |s: Option<String>| {
            s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc))
        };

        let mut members = Vec::new();
        while let Ok(sqlite::State::Row) = stmt.next() {
            let org_prefix: String = stmt.read(0)?;
            let member_did: String = stmt.read(1)?;
            let issuer_did: String = stmt.read(2)?;
            let rid: String = stmt.read(3)?;
            let revoked_str: Option<String> = stmt.read(4)?;
            let expires_str: Option<String> = stmt.read(5)?;
            let updated_str: String = stmt.read(6)?;

            members.push(IndexedOrgMember {
                org_prefix: Prefix::new_unchecked(org_prefix),
                member_did: DeviceDID::new_unchecked(member_did),
                issuer_did: IdentityDID::new_unchecked(issuer_did),
                rid: ResourceId::new(rid),
                revoked_at: parse_dt(revoked_str),
                expires_at: parse_dt(expires_str),
                updated_at: DateTime::parse_from_rfc3339(&updated_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }

        Ok(members)
    }

    /// Returns the count of org members for a given org in the index.
    pub fn count_org_members(&self, org_prefix: &str) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM org_members WHERE org_prefix = ?")?;
        stmt.bind((1, org_prefix))?;
        if let Ok(sqlite::State::Row) = stmt.next() {
            let count: i64 = stmt.read(0)?;
            return Ok(count as usize);
        }
        Ok(0)
    }
}

/// Statistics about the attestation index.
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub total_attestations: usize,
    pub active_attestations: usize,
    pub revoked_attestations: usize,
    pub with_expiry: usize,
    pub unique_devices: usize,
    pub unique_issuers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_attestation(
        rid: &str,
        device: &str,
        revoked_at: Option<DateTime<Utc>>,
    ) -> IndexedAttestation {
        IndexedAttestation {
            rid: ResourceId::new(rid),
            issuer_did: IdentityDID::new_unchecked("did:key:issuer123"),
            device_did: DeviceDID::new_unchecked(device),
            git_ref: format!("refs/auths/devices/nodes/{}/signatures", device),
            commit_oid: None,
            revoked_at,
            expires_at: Some(Utc::now() + Duration::days(30)),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_in_memory_index() {
        let index = AttestationIndex::in_memory().unwrap();
        assert_eq!(index.count().unwrap(), 0);
    }

    #[test]
    fn test_upsert_and_query() {
        let index = AttestationIndex::in_memory().unwrap();
        let att = create_test_attestation("rid1", "did:key:device1", None);

        index.upsert_attestation(&att).unwrap();
        assert_eq!(index.count().unwrap(), 1);

        let results = index.query_by_device("did:key:device1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rid, "rid1");
    }

    #[test]
    fn test_upsert_updates_existing() {
        let index = AttestationIndex::in_memory().unwrap();
        let mut att = create_test_attestation("rid1", "did:key:device1", None);

        index.upsert_attestation(&att).unwrap();
        assert_eq!(index.count().unwrap(), 1);

        // Update the attestation
        att.revoked_at = Some(Utc::now());
        index.upsert_attestation(&att).unwrap();
        assert_eq!(index.count().unwrap(), 1);

        let results = index.query_by_device("did:key:device1").unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].revoked_at.is_some());
    }

    #[test]
    fn test_query_by_issuer() {
        let index = AttestationIndex::in_memory().unwrap();
        let att1 = create_test_attestation("rid1", "did:key:device1", None);
        let att2 = create_test_attestation("rid2", "did:key:device2", None);

        index.upsert_attestation(&att1).unwrap();
        index.upsert_attestation(&att2).unwrap();

        let results = index.query_by_issuer("did:key:issuer123").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_active() {
        let index = AttestationIndex::in_memory().unwrap();
        let att1 = create_test_attestation("rid1", "did:key:device1", None);
        let att2 = create_test_attestation("rid2", "did:key:device2", Some(Utc::now()));

        index.upsert_attestation(&att1).unwrap();
        index.upsert_attestation(&att2).unwrap();

        let active = index.query_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].rid, "rid1");
    }

    #[test]
    fn test_query_expiring_before() {
        let index = AttestationIndex::in_memory().unwrap();

        let mut att1 = create_test_attestation("rid1", "did:key:device1", None);
        att1.expires_at = Some(Utc::now() + Duration::days(5));

        let mut att2 = create_test_attestation("rid2", "did:key:device2", None);
        att2.expires_at = Some(Utc::now() + Duration::days(60));

        index.upsert_attestation(&att1).unwrap();
        index.upsert_attestation(&att2).unwrap();

        let deadline = Utc::now() + Duration::days(10);
        let expiring = index.query_expiring_before(deadline).unwrap();
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].rid, "rid1");
    }

    #[test]
    fn test_clear() {
        let index = AttestationIndex::in_memory().unwrap();
        let att = create_test_attestation("rid1", "did:key:device1", None);

        index.upsert_attestation(&att).unwrap();
        assert_eq!(index.count().unwrap(), 1);

        index.clear().unwrap();
        assert_eq!(index.count().unwrap(), 0);
    }

    #[test]
    fn test_stats() {
        let index = AttestationIndex::in_memory().unwrap();
        let att1 = create_test_attestation("rid1", "did:key:device1", None);
        let att2 = create_test_attestation("rid2", "did:key:device2", Some(Utc::now()));

        index.upsert_attestation(&att1).unwrap();
        index.upsert_attestation(&att2).unwrap();

        let stats = index.stats().unwrap();
        assert_eq!(stats.total_attestations, 2);
        assert_eq!(stats.active_attestations, 1);
        assert_eq!(stats.revoked_attestations, 1);
        assert_eq!(stats.unique_devices, 2);
        assert_eq!(stats.unique_issuers, 1);
    }

    #[test]
    fn test_upsert_and_query_identity() {
        let index = AttestationIndex::in_memory().unwrap();
        let identity = IndexedIdentity {
            prefix: Prefix::new_unchecked("ETestPrefix123".to_string()),
            current_keys: vec!["DKey1".to_string(), "DKey2".to_string()],
            sequence: 3,
            tip_said: Said::new_unchecked("ETipSaid123".to_string()),
            updated_at: Utc::now(),
        };

        index.upsert_identity(&identity).unwrap();

        let result = index.query_identity("ETestPrefix123").unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.prefix, "ETestPrefix123");
        assert_eq!(result.sequence, 3);
        assert_eq!(result.current_keys.len(), 2);
        assert_eq!(result.tip_said, "ETipSaid123");
    }

    #[test]
    fn test_upsert_identity_updates_existing() {
        let index = AttestationIndex::in_memory().unwrap();
        let identity = IndexedIdentity {
            prefix: Prefix::new_unchecked("ETestPrefix".to_string()),
            current_keys: vec!["DKey1".to_string()],
            sequence: 0,
            tip_said: Said::new_unchecked("ESaid0".to_string()),
            updated_at: Utc::now(),
        };
        index.upsert_identity(&identity).unwrap();

        let updated = IndexedIdentity {
            prefix: Prefix::new_unchecked("ETestPrefix".to_string()),
            current_keys: vec!["DKey2".to_string()],
            sequence: 1,
            tip_said: Said::new_unchecked("ESaid1".to_string()),
            updated_at: Utc::now(),
        };
        index.upsert_identity(&updated).unwrap();

        let result = index.query_identity("ETestPrefix").unwrap().unwrap();
        assert_eq!(result.sequence, 1);
        assert_eq!(result.tip_said, "ESaid1");
        assert_eq!(result.current_keys, vec!["DKey2"]);
    }

    #[test]
    fn test_query_identity_not_found() {
        let index = AttestationIndex::in_memory().unwrap();
        let result = index.query_identity("ENotExist").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_upsert_and_list_org_members() {
        let index = AttestationIndex::in_memory().unwrap();
        let member = IndexedOrgMember {
            org_prefix: Prefix::new_unchecked("did:keri:EOrg".to_string()),
            member_did: DeviceDID::new_unchecked("did:key:z6MkMember1"),
            issuer_did: IdentityDID::new_unchecked("did:keri:EOrg"),
            rid: ResourceId::new("rid-member-1"),
            revoked_at: None,
            expires_at: None,
            updated_at: Utc::now(),
        };

        index.upsert_org_member(&member).unwrap();

        let members = index.list_org_members_indexed("did:keri:EOrg").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].member_did.as_str(), "did:key:z6MkMember1");
        assert_eq!(members[0].rid, "rid-member-1");
    }

    #[test]
    fn test_upsert_org_member_updates_existing() {
        let index = AttestationIndex::in_memory().unwrap();
        let member = IndexedOrgMember {
            org_prefix: Prefix::new_unchecked("did:keri:EOrg".to_string()),
            member_did: DeviceDID::new_unchecked("did:key:z6MkMember1"),
            issuer_did: IdentityDID::new_unchecked("did:keri:EOrg"),
            rid: ResourceId::new("rid-v1"),
            revoked_at: None,
            expires_at: None,
            updated_at: Utc::now(),
        };
        index.upsert_org_member(&member).unwrap();

        let updated = IndexedOrgMember {
            org_prefix: Prefix::new_unchecked("did:keri:EOrg".to_string()),
            member_did: DeviceDID::new_unchecked("did:key:z6MkMember1"),
            issuer_did: IdentityDID::new_unchecked("did:keri:EOrg"),
            rid: ResourceId::new("rid-v2"),
            revoked_at: Some(Utc::now()),
            expires_at: None,
            updated_at: Utc::now(),
        };
        index.upsert_org_member(&updated).unwrap();

        let members = index.list_org_members_indexed("did:keri:EOrg").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].rid, "rid-v2");
        assert!(members[0].revoked_at.is_some());
    }

    #[test]
    fn test_count_org_members() {
        let index = AttestationIndex::in_memory().unwrap();
        assert_eq!(index.count_org_members("did:keri:EOrg").unwrap(), 0);

        for i in 0..3 {
            index
                .upsert_org_member(&IndexedOrgMember {
                    org_prefix: Prefix::new_unchecked("did:keri:EOrg".to_string()),
                    member_did: DeviceDID::new_unchecked(format!("did:key:z6MkMember{}", i)),
                    issuer_did: IdentityDID::new_unchecked("did:keri:EOrg"),
                    rid: ResourceId::new(format!("rid-{}", i)),
                    revoked_at: None,
                    expires_at: None,
                    updated_at: Utc::now(),
                })
                .unwrap();
        }

        assert_eq!(index.count_org_members("did:keri:EOrg").unwrap(), 3);
        assert_eq!(index.count_org_members("did:keri:EOther").unwrap(), 0);
    }
}
