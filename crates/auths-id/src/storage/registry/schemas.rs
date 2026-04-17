//! JSON schema types for the packed registry storage.
//!
//! # Cache/Index Semantics
//!
//! These types represent **cached/indexed views**, not sources of truth:
//!
//! - [`TipInfo`]: O(1) lookup of latest event (derived from events directory)
//! - [`CachedStateJson`]: Pre-computed key state (derived from KEL replay)
//! - [`RegistryMetadata`]: Aggregate counts (derived from tree traversal)
//!
//! All of these can be rebuilt from the canonical KEL events. They exist
//! purely for performance optimization and cold-start efficiency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keri::Said;
use crate::keri::state::KeyState;

/// Schema version for all registry types.
pub const SCHEMA_VERSION: u32 = 1;

/// Tip info for an identity's KEL.
///
/// Stored at `v1/identities/<shard>/<prefix>/tip.json`.
///
/// # Purpose
///
/// Provides O(1) lookup of the latest event without traversing the events directory.
/// This is a **derived cache** that can be rebuilt by scanning `events/*.json`.
///
/// # Rebuild Semantics
///
/// To rebuild: scan event files, find highest sequence number, read that event's SAID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TipInfo {
    /// Schema version (always 1 for now)
    pub version: u32,
    /// Sequence number of the latest event
    pub sequence: u128,
    /// SAID (Self-Addressing Identifier) of the latest event
    pub said: Said,
}

impl TipInfo {
    /// Create a new TipInfo for the given sequence and SAID.
    pub fn new(sequence: u128, said: Said) -> Self {
        Self {
            version: SCHEMA_VERSION,
            sequence,
            said,
        }
    }
}

/// Cached KeyState stored in the registry tree.
///
/// Stored at `v1/identities/<shard>/<prefix>/state.json`.
///
/// # Verification Requirement
///
/// **CRITICAL**: This cache MUST be verified before use:
///
/// 1. Check `validated_against_said` matches current `tip.json` SAID
/// 2. If mismatch, replay KEL from events to recompute state
/// 3. Never trust cached state without verification
///
/// # Rebuild Semantics
///
/// To rebuild: replay all events in sequence order, apply state transitions.
///
/// # Limitations
///
/// - Good for cold starts (avoids full KEL replay)
/// - Does NOT fix split-view attacks (requires witnesses/backers)
/// - Written on each event append to keep cache fresh
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedStateJson {
    /// Schema version
    pub version: u32,
    /// The cached key state
    pub state: KeyState,
    /// SAID of tip event when this state was computed.
    /// Used to verify cache freshness.
    pub validated_against_said: Said,
}

impl CachedStateJson {
    /// Create a new CachedStateJson for the given state and tip SAID.
    pub fn new(state: KeyState, validated_against_said: Said) -> Self {
        Self {
            version: SCHEMA_VERSION,
            state,
            validated_against_said,
        }
    }

    /// Check if this cached state is valid for the given tip SAID.
    pub fn is_valid_for(&self, tip_said: &Said) -> bool {
        self.validated_against_said == *tip_said
    }
}

/// Registry-wide metadata.
///
/// Stored at `v1/metadata.json`.
/// Provides statistics and version info for the registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryMetadata {
    /// Schema version
    pub version: u32,
    /// Number of identities in the registry
    pub identity_count: u64,
    /// Number of devices in the registry
    pub device_count: u64,
    /// Number of org members in the registry
    #[serde(default)]
    pub member_count: u64,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl RegistryMetadata {
    /// Create a new RegistryMetadata with the given counts.
    pub fn new(
        now: DateTime<Utc>,
        identity_count: u64,
        device_count: u64,
        member_count: u64,
    ) -> Self {
        Self {
            version: SCHEMA_VERSION,
            identity_count,
            device_count,
            member_count,
            updated_at: now,
        }
    }

    /// Create an empty metadata record with a zero epoch timestamp.
    pub fn empty() -> Self {
        Self {
            version: SCHEMA_VERSION,
            identity_count: 0,
            device_count: 0,
            member_count: 0,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }
}

impl Default for RegistryMetadata {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{CesrKey, Prefix, Said, Threshold};

    #[test]
    fn tip_info_new_sets_version() {
        let tip = TipInfo::new(5, Said::new_unchecked("ESaidTest123".to_string()));
        assert_eq!(tip.version, SCHEMA_VERSION);
        assert_eq!(tip.sequence, 5);
        assert_eq!(tip.said, "ESaidTest123");
    }

    #[test]
    fn tip_info_roundtrips() {
        let tip = TipInfo::new(42, Said::new_unchecked("ETestSaid".to_string()));
        let json = serde_json::to_string(&tip).unwrap();
        let parsed: TipInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(tip, parsed);
    }

    #[test]
    fn cached_state_is_valid_for_matching_said() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![CesrKey::new_unchecked("DKey".to_string())],
            vec![Said::new_unchecked("ENext".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ESaid".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        );
        let tip_said = Said::new_unchecked("ETipSaid".to_string());
        let cached = CachedStateJson::new(state, tip_said.clone());

        assert!(cached.is_valid_for(&tip_said));
        let different_said = Said::new_unchecked("EDifferentSaid".to_string());
        assert!(!cached.is_valid_for(&different_said));
    }

    #[test]
    fn cached_state_roundtrips() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![CesrKey::new_unchecked("DKey".to_string())],
            vec![Said::new_unchecked("ENext".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ESaid".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        );
        let cached =
            CachedStateJson::new(state.clone(), Said::new_unchecked("ETipSaid".to_string()));

        let json = serde_json::to_string(&cached).unwrap();
        let parsed: CachedStateJson = serde_json::from_str(&json).unwrap();

        assert_eq!(cached.version, parsed.version);
        assert_eq!(cached.state, parsed.state);
        assert_eq!(cached.validated_against_said, parsed.validated_against_said);
    }

    #[test]
    fn registry_metadata_new_sets_given_time() {
        let now = Utc::now();
        let meta = RegistryMetadata::new(now, 10, 20, 5);

        assert_eq!(meta.version, SCHEMA_VERSION);
        assert_eq!(meta.identity_count, 10);
        assert_eq!(meta.device_count, 20);
        assert_eq!(meta.member_count, 5);
        assert_eq!(meta.updated_at, now);
    }

    #[test]
    fn registry_metadata_empty_has_zero_counts() {
        let meta = RegistryMetadata::empty();
        assert_eq!(meta.identity_count, 0);
        assert_eq!(meta.device_count, 0);
        assert_eq!(meta.member_count, 0);
    }

    #[test]
    fn registry_metadata_roundtrips() {
        let meta = RegistryMetadata::new(Utc::now(), 100, 500, 25);
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: RegistryMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, parsed);
    }
}
