use auths_verifier::{
    CanonicalDid, Capability, DeviceDID, Ed25519PublicKey, Ed25519Signature, IdentityDID, Role,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The type of mutation recorded in a transparency log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum EntryType {
    Register,
    Rotate,
    Abandon,
    OrgCreate,
    OrgAddMember,
    OrgRevokeMember,
    DeviceBind,
    DeviceRevoke,
    Attest,
    NamespaceClaim,
    NamespaceDelegate,
    NamespaceTransfer,
    AccessGrant,
    AccessRevoke,
}

/// Access tier controlling rate limits and feature gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum AccessTier {
    Anonymous,
    Free,
    Team,
    Enterprise,
}

impl AccessTier {
    /// Returns the tier as a lowercase string matching the serde serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Free => "free",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }
}

/// The body of a log entry, specific to each [`EntryType`].
///
/// Designed so adding new entry types in future epics is a mechanical
/// addition of a new variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum EntryBody {
    Register {
        inception_event: Value,
    },
    Rotate {
        rotation_event: Value,
    },
    Abandon {
        reason: Option<String>,
    },
    OrgCreate {
        display_name: String,
    },
    OrgAddMember {
        member_did: IdentityDID,
        role: Role,
        capabilities: Vec<Capability>,
        delegated_by: IdentityDID,
    },
    OrgRevokeMember {
        member_did: IdentityDID,
    },
    DeviceBind {
        device_did: DeviceDID,
        public_key: Ed25519PublicKey,
    },
    DeviceRevoke {
        device_did: DeviceDID,
    },
    Attest(Value),
    NamespaceClaim {
        ecosystem: String,
        package_name: String,
    },
    NamespaceDelegate {
        ecosystem: String,
        package_name: String,
        delegate_did: IdentityDID,
    },
    NamespaceTransfer {
        ecosystem: String,
        package_name: String,
        new_owner_did: IdentityDID,
    },
    AccessGrant {
        subject_did: IdentityDID,
        tier: AccessTier,
        daily_limit: u32,
        expires_at: DateTime<Utc>,
    },
    AccessRevoke {
        subject_did: IdentityDID,
        reason: Option<String>,
    },
}

/// The subset of an [`Entry`] that the actor signs.
///
/// The sequencer assigns `sequence` and `timestamp` after — those fields
/// are authenticated by the Merkle tree, not the actor's signature.
///
/// Usage:
/// ```ignore
/// let content = EntryContent {
///     entry_type: EntryType::Register,
///     body: EntryBody::Register { inception_event: serde_json::json!({}) },
///     actor_did: CanonicalDid::parse("did:keri:E...")?,
/// };
/// let canonical = content.canonicalize()?;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct EntryContent {
    pub entry_type: EntryType,
    pub body: EntryBody,
    pub actor_did: CanonicalDid,
}

impl EntryContent {
    /// Canonical JSON bytes for signing (via `json-canon`).
    pub fn canonicalize(&self) -> Result<Vec<u8>, crate::error::TransparencyError> {
        let value = serde_json::to_value(self)
            .map_err(|e| crate::error::TransparencyError::EntryError(e.to_string()))?;
        json_canon::to_vec(&value)
            .map_err(|e| crate::error::TransparencyError::EntryError(e.to_string()))
    }
}

/// A complete log entry with sequencer-assigned fields.
///
/// Args:
/// * `sequence` — Monotonically increasing index assigned by the sequencer.
/// * `timestamp` — Wall-clock time assigned by the sequencer.
/// * `content` — The actor-signed payload.
/// * `actor_sig` — Ed25519 signature over the canonical `EntryContent`.
///
/// Usage:
/// ```ignore
/// let entry = Entry {
///     sequence: 0,
///     timestamp: Utc::now(),
///     content: entry_content,
///     actor_sig: sig,
/// };
/// let leaf_data = entry.leaf_data()?;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct Entry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub content: EntryContent,
    pub actor_sig: Ed25519Signature,
}

impl Entry {
    /// Canonical JSON bytes of the full entry for Merkle leaf hashing.
    pub fn leaf_data(&self) -> Result<Vec<u8>, crate::error::TransparencyError> {
        let value = serde_json::to_value(self)
            .map_err(|e| crate::error::TransparencyError::EntryError(e.to_string()))?;
        json_canon::to_vec(&value)
            .map_err(|e| crate::error::TransparencyError::EntryError(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_verifier::Ed25519Signature;

    #[test]
    fn entry_type_serializes_snake_case() {
        let json = serde_json::to_string(&EntryType::Register).unwrap();
        assert_eq!(json, r#""register""#);
    }

    #[test]
    fn entry_content_canonicalize_deterministic() {
        let content = EntryContent {
            entry_type: EntryType::DeviceBind,
            body: EntryBody::DeviceBind {
                device_did: DeviceDID::new_unchecked(
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                ),
                public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            },
            actor_did: CanonicalDid::new_unchecked("did:keri:Eabc"),
        };
        let a = content.canonicalize().unwrap();
        let b = content.canonicalize().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn entry_json_roundtrip() {
        let entry = Entry {
            sequence: 42,
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            content: EntryContent {
                entry_type: EntryType::OrgAddMember,
                body: EntryBody::OrgAddMember {
                    member_did: IdentityDID::new_unchecked("did:keri:Emember"),
                    role: Role::Admin,
                    capabilities: vec![Capability::sign_commit()],
                    delegated_by: IdentityDID::new_unchecked("did:keri:Eadmin"),
                },
                actor_did: CanonicalDid::new_unchecked("did:keri:Eadmin"),
            },
            actor_sig: Ed25519Signature::empty(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.sequence, back.sequence);
    }
}
