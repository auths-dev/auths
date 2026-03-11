//! Incremental KEL validation engine.
//!
//! This module provides O(k) incremental validation where k is the number of
//! new events since the last cached validation, instead of O(n) full replay.
//!
//! ## Algorithm
//!
//! 1. Load cached state (includes last_commit_oid)
//! 2. Verify cache integrity (SAID matches event in cached commit)
//! 3. Walk from tip backwards to find the cached commit
//! 4. If k > MAX_INCREMENTAL_EVENTS, skip to full replay
//! 5. Verify linear history (exactly 1 parent per commit)
//! 6. Reverse the delta to get oldest-to-newest order
//! 7. Validate and apply each new event to the cached state
//! 8. Write updated cache with new tip position
//!
//! If any step fails, fall back to full replay.
//!
//! ## Invariants
//!
//! - KEL must be strictly linear (no merge commits)
//! - Cache is only trusted if SAID in cache matches SAID in cached commit
//! - Incremental path is bounded to prevent pathological walks

use chrono::{DateTime, Utc};

use super::cache;
use super::event::Event;
use super::kel::{GitKel, KelError};
use super::state::KeyState;
use super::types::Said;
use crate::domain::EventHash;

/// Maximum number of events to validate incrementally.
/// If k exceeds this, fall back to full replay to avoid pathological walks.
pub const MAX_INCREMENTAL_EVENTS: usize = 10_000;

/// Result of incremental validation attempt.
#[derive(Debug)]
pub enum IncrementalResult {
    /// Cache hit - state matches current tip exactly
    CacheHit(KeyState),
    /// Incremental success - validated k new events
    IncrementalSuccess {
        state: KeyState,
        events_validated: usize,
    },
    /// Cache miss - needs full replay (cache missing, corrupt, or not in ancestry)
    NeedsFullReplay(ReplayReason),
}

/// Reason why full replay is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReason {
    /// No cache file exists
    NoCacheFile,
    /// Cache file exists but couldn't be parsed or version mismatch
    CacheCorrupt,
    /// Cached commit OID doesn't exist in repository
    CachedCommitMissing,
    /// Cached commit is not in the ancestry of tip
    CachedCommitNotInAncestry,
    /// Cache SAID doesn't match SAID in cached commit (cache lies)
    CacheSaidMismatch,
    /// Too many events since cache (k > MAX_INCREMENTAL_EVENTS)
    TooManyEvents,
}

/// Errors specific to incremental validation.
/// These are hard errors that indicate KEL corruption, not cache problems.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IncrementalError {
    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Chain continuity error: expected previous SAID {expected}, got {actual}")]
    ChainContinuity { expected: Said, actual: Said },

    #[error("Sequence error: expected {expected}, got {actual}")]
    SequenceError { expected: u64, actual: u64 },

    #[error("Malformed sequence number: {raw:?}")]
    MalformedSequence { raw: String },

    #[error("Invalid event type in KEL: {0}")]
    InvalidEventType(String),

    #[error("KEL history is non-linear: commit {commit} has {parent_count} parents (expected 1)")]
    NonLinearHistory { commit: String, parent_count: usize },

    #[error("KEL history is corrupted: commit {commit} has no parent but is not inception")]
    MissingParent { commit: String },
}

impl auths_core::error::AuthsErrorInfo for IncrementalError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Kel(_) => "AUTHS-E4951",
            Self::ChainContinuity { .. } => "AUTHS-E4952",
            Self::SequenceError { .. } => "AUTHS-E4953",
            Self::MalformedSequence { .. } => "AUTHS-E4954",
            Self::InvalidEventType(_) => "AUTHS-E4955",
            Self::NonLinearHistory { .. } => "AUTHS-E4956",
            Self::MissingParent { .. } => "AUTHS-E4957",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Kel(_) => None,
            Self::ChainContinuity { .. } => Some("The KEL chain is broken; clear the cache and retry"),
            Self::SequenceError { .. } => Some("The KEL has sequence gaps; re-sync from a trusted source"),
            Self::MalformedSequence { .. } => None,
            Self::InvalidEventType(_) => None,
            Self::NonLinearHistory { .. } => Some("The KEL has merge commits, indicating tampering"),
            Self::MissingParent { .. } => Some("The KEL commit history is corrupted"),
        }
    }
}

/// Attempt incremental validation from cached state to current tip.
///
/// Returns `IncrementalResult::NeedsFullReplay` if:
/// - No cache exists
/// - Cache version mismatch or corrupt
/// - Cached commit doesn't exist in repo
/// - Cached commit is not in the ancestry of tip
/// - Cache SAID doesn't match SAID in cached commit
/// - Too many events since cache (k > MAX_INCREMENTAL_EVENTS)
///
/// Returns `IncrementalResult::CacheHit` if cache matches tip exactly.
///
/// Returns `IncrementalResult::IncrementalSuccess` if we successfully validated
/// from cached position to tip.
///
/// Returns `Err(IncrementalError)` for hard errors (KEL corruption like merge
/// commits, broken chain). These should NOT fall back - they indicate real problems.
pub fn try_incremental_validation<'a>(
    kel: &GitKel<'a>,
    did: &str,
    now: DateTime<Utc>,
) -> Result<IncrementalResult, IncrementalError> {
    // Get current tip
    let tip_hash = kel.tip_commit_hash()?;
    let tip_event = kel.read_event_from_commit_hash(tip_hash)?;
    let tip_said = tip_event.said();

    // Try to load cached state
    let cached = match cache::try_load_cached_state_full(kel.workdir(), did) {
        Some(c) => c,
        None => {
            log::debug!("KEL cache miss for {}: no cache file", did);
            return Ok(IncrementalResult::NeedsFullReplay(
                ReplayReason::NoCacheFile,
            ));
        }
    };

    // Check if cache matches tip exactly (cache hit)
    if cached.validated_against_tip_said == *tip_said {
        log::debug!("KEL cache hit for {}", did);
        return Ok(IncrementalResult::CacheHit(cached.state));
    }

    // Parse cached commit hash
    let cached_hash = match GitKel::parse_hash(cached.last_commit_oid.as_str()) {
        Ok(h) => h,
        Err(_) => {
            log::debug!("KEL cache corrupt for {}: invalid commit hash", did);
            return Ok(IncrementalResult::NeedsFullReplay(
                ReplayReason::CacheCorrupt,
            ));
        }
    };

    // Verify cached commit exists
    if !kel.commit_exists(cached_hash) {
        log::debug!(
            "KEL cache miss for {}: cached commit {} doesn't exist",
            did,
            cached_hash
        );
        return Ok(IncrementalResult::NeedsFullReplay(
            ReplayReason::CachedCommitMissing,
        ));
    }

    // CACHE TRUST RULE: Verify cache SAID matches SAID in cached commit
    let cached_event = kel.read_event_from_commit_hash(cached_hash)?;
    if *cached_event.said() != cached.validated_against_tip_said {
        log::warn!(
            "KEL cache SAID mismatch for {}: cache says {} but commit has {}",
            did,
            cached.validated_against_tip_said,
            cached_event.said()
        );
        return Ok(IncrementalResult::NeedsFullReplay(
            ReplayReason::CacheSaidMismatch,
        ));
    }

    // Build the delta: walk from tip backwards to cached commit
    // This also enforces linear history (exactly 1 parent per commit)
    let delta = match build_delta_with_linearity_check(kel, tip_hash, cached_hash)? {
        Some(d) => d,
        None => {
            log::debug!("KEL cache miss for {}: cached commit not in ancestry", did);
            return Ok(IncrementalResult::NeedsFullReplay(
                ReplayReason::CachedCommitNotInAncestry,
            ));
        }
    };

    // Check if k exceeds threshold
    if delta.len() > MAX_INCREMENTAL_EVENTS {
        log::info!(
            "KEL incremental skip for {}: {} events exceeds threshold {}",
            did,
            delta.len(),
            MAX_INCREMENTAL_EVENTS
        );
        return Ok(IncrementalResult::NeedsFullReplay(
            ReplayReason::TooManyEvents,
        ));
    }

    log::debug!(
        "KEL incremental validation for {}: {} new events",
        did,
        delta.len()
    );

    // Apply events incrementally
    let mut state = cached.state;
    let events_validated = delta.len();

    for hash in delta {
        let event = kel.read_event_from_commit_hash(hash)?;
        apply_event_to_state(&mut state, &event)?;
    }

    // Verify final state matches tip
    if state.last_event_said != *tip_said {
        return Err(IncrementalError::ChainContinuity {
            expected: tip_said.clone(),
            actual: state.last_event_said.clone(),
        });
    }

    // Write updated cache
    let _ = cache::write_kel_cache(
        kel.workdir(),
        did,
        &state,
        tip_said.as_str(),
        &tip_hash.to_hex(),
        now,
    );

    Ok(IncrementalResult::IncrementalSuccess {
        state,
        events_validated,
    })
}

/// Build the list of commits from cached position (exclusive) to tip (inclusive).
///
/// Also enforces that the KEL is strictly linear (exactly 1 parent per commit,
/// except inception which has 0).
///
/// Returns `None` if cached_hash is not in the ancestry of tip_hash.
/// Returns `Some(vec![])` if cached_hash == tip_hash (nothing to do).
/// Returns `Some(vec![...])` with commits in oldest-to-newest order.
///
/// Returns `Err(IncrementalError::NonLinearHistory)` if any commit has >1 parent.
fn build_delta_with_linearity_check(
    kel: &GitKel<'_>,
    tip_hash: EventHash,
    cached_hash: EventHash,
) -> Result<Option<Vec<EventHash>>, IncrementalError> {
    if tip_hash == cached_hash {
        return Ok(Some(Vec::new()));
    }

    let mut delta = Vec::new();
    let mut current = tip_hash;

    loop {
        delta.push(current);

        // Get parent count and enforce linearity
        let parent_count = kel.parent_count(current)?;

        if parent_count > 1 {
            // Merge commit detected - this is a hard error
            return Err(IncrementalError::NonLinearHistory {
                commit: current.to_hex(),
                parent_count,
            });
        }

        if parent_count == 0 {
            // Reached inception without finding cached commit
            // This means cache is invalid (not in ancestry)
            return Ok(None);
        }

        // INVARIANT: parent_count==1 verified above
        #[allow(clippy::expect_used)]
        let parent = kel.parent_hash(current)?.expect("parent_count was 1");

        if parent == cached_hash {
            // Found the cached commit - we're done
            break;
        }
        current = parent;
    }

    // Reverse to get oldest-to-newest order
    delta.reverse();
    Ok(Some(delta))
}

/// Apply a single event to the key state.
///
/// This is a pure function that validates chain continuity and sequence,
/// then updates the state accordingly.
fn apply_event_to_state(state: &mut KeyState, event: &Event) -> Result<(), IncrementalError> {
    let expected_sequence = state.sequence + 1;
    let actual_sequence = event.sequence().value();

    // Verify sequence increments by 1
    if actual_sequence != expected_sequence {
        return Err(IncrementalError::SequenceError {
            expected: expected_sequence,
            actual: actual_sequence,
        });
    }

    // Verify chain continuity (previous SAID matches our current tip)
    if let Some(prev_said) = event.previous() {
        if *prev_said != state.last_event_said {
            return Err(IncrementalError::ChainContinuity {
                expected: state.last_event_said.clone(),
                actual: prev_said.clone(),
            });
        }
    } else {
        // Only inception events have no previous, and we shouldn't see those
        // in incremental validation (cache always starts after inception)
        return Err(IncrementalError::InvalidEventType(
            "Unexpected inception event in incremental validation".to_string(),
        ));
    }

    // Apply the event
    match event {
        Event::Rot(rot) => {
            let threshold =
                rot.kt
                    .parse::<u64>()
                    .map_err(|_| IncrementalError::MalformedSequence {
                        raw: rot.kt.clone(),
                    })?;
            let next_threshold =
                rot.nt
                    .parse::<u64>()
                    .map_err(|_| IncrementalError::MalformedSequence {
                        raw: rot.nt.clone(),
                    })?;

            state.apply_rotation(
                rot.k.clone(),
                rot.n.clone(),
                threshold,
                next_threshold,
                actual_sequence,
                rot.d.clone(),
            );
        }
        Event::Ixn(ixn) => {
            state.apply_interaction(actual_sequence, ixn.d.clone());
        }
        Event::Icp(_) => {
            return Err(IncrementalError::InvalidEventType(
                "Inception event after KEL start".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::Prefix;

    // Integration tests for incremental validation are in kel.rs
    // since they need access to a full GitKel setup

    #[test]
    fn test_incremental_result_variants() {
        // Just verify the enum compiles and has expected variants
        let state = KeyState::from_inception(
            Prefix::new_unchecked("ETest".to_string()),
            vec!["DKey".to_string()],
            vec!["ENext".to_string()],
            1,
            1,
            Said::new_unchecked("ESaid".to_string()),
        );

        let _hit = IncrementalResult::CacheHit(state.clone());
        let _success = IncrementalResult::IncrementalSuccess {
            state,
            events_validated: 5,
        };
        let _miss = IncrementalResult::NeedsFullReplay(ReplayReason::NoCacheFile);
    }

    #[test]
    fn test_replay_reasons() {
        // Verify all replay reasons
        assert_ne!(ReplayReason::NoCacheFile, ReplayReason::CacheCorrupt);
        assert_ne!(
            ReplayReason::CachedCommitMissing,
            ReplayReason::CacheSaidMismatch
        );
        assert_ne!(
            ReplayReason::TooManyEvents,
            ReplayReason::CachedCommitNotInAncestry
        );
    }
}
