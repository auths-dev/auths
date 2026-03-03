//! Identity freeze management.
//!
//! A freeze temporarily disables all signing operations for an identity.
//! The freeze state is stored as a `freeze.json` file in the identity
//! repository (e.g., `~/.auths/freeze.json`).
//!
//! # Freeze Lifecycle
//!
//! 1. User runs `auths emergency freeze --duration 24h`
//! 2. `freeze.json` is written with `frozen_until` timestamp
//! 3. `auths-sign` checks for active freeze before every signature
//! 4. Freeze expires automatically, or user runs unfreeze

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::FreezeError;

/// Filename for the freeze state file.
const FREEZE_FILE: &str = "freeze.json";

/// Freeze state persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeState {
    /// When the freeze was created.
    pub frozen_at: DateTime<Utc>,
    /// When the freeze expires.
    pub frozen_until: DateTime<Utc>,
    /// Optional reason for the freeze.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FreezeState {
    /// Check if this freeze is currently active.
    ///
    /// Args:
    /// * `now`: The reference time to check against.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        now < self.frozen_until
    }

    /// Human-readable description of when the freeze expires.
    ///
    /// Args:
    /// * `now`: The reference time used to compute remaining duration.
    pub fn expires_description(&self, now: DateTime<Utc>) -> String {
        let remaining = self.frozen_until - now;
        if remaining.num_hours() > 24 {
            format!("{} days", remaining.num_days())
        } else if remaining.num_hours() > 0 {
            format!("{} hours", remaining.num_hours())
        } else if remaining.num_minutes() > 0 {
            format!("{} minutes", remaining.num_minutes())
        } else {
            "less than a minute".to_string()
        }
    }
}

/// Path to the freeze file for a given repo.
pub fn freeze_file_path(repo_path: &Path) -> PathBuf {
    repo_path.join(FREEZE_FILE)
}

/// Load the current freeze state, if any.
///
/// Returns `None` if no freeze file exists or the freeze has expired.
///
/// Args:
/// * `repo_path`: Path to the identity repository.
/// * `now`: The reference time used to check if the freeze is still active.
pub fn load_active_freeze(
    repo_path: &Path,
    now: DateTime<Utc>,
) -> Result<Option<FreezeState>, FreezeError> {
    let path = freeze_file_path(repo_path);
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)?;
    let state: FreezeState = serde_json::from_str(&contents)?;

    if state.is_active(now) {
        Ok(Some(state))
    } else {
        let _ = std::fs::remove_file(&path);
        Ok(None)
    }
}

/// Write a freeze state to disk.
pub fn store_freeze(repo_path: &Path, state: &FreezeState) -> Result<(), FreezeError> {
    let path = freeze_file_path(repo_path);
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Remove the freeze file (unfreeze).
pub fn remove_freeze(repo_path: &Path) -> Result<bool, FreezeError> {
    let path = freeze_file_path(repo_path);
    if path.exists() {
        std::fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Parse a human-readable duration string into a `chrono::Duration`.
///
/// Supported formats: `30m`, `1h`, `24h`, `7d`, `1w`.
pub fn parse_duration(s: &str) -> Result<chrono::Duration, FreezeError> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = if let Some(n) = s.strip_suffix('w') {
        (n, 'w')
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 'd')
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 'h')
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 'm')
    } else {
        return Err(FreezeError::InvalidDuration(format!(
            "Invalid duration '{}'. Use formats like: 30m, 1h, 24h, 7d, 1w",
            s
        )));
    };

    let num: u64 = num_str.parse().map_err(|_| {
        FreezeError::InvalidDuration(format!(
            "Invalid number in duration '{}'. Use formats like: 30m, 1h, 24h, 7d, 1w",
            s
        ))
    })?;

    if num == 0 {
        return Err(FreezeError::ZeroDuration);
    }

    let duration = match unit {
        'm' => chrono::Duration::minutes(num as i64),
        'h' => chrono::Duration::hours(num as i64),
        'd' => chrono::Duration::days(num as i64),
        'w' => chrono::Duration::weeks(num as i64),
        _ => unreachable!(),
    };

    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("24h").unwrap();
        assert_eq!(d.num_hours(), 24);
    }

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration("7d").unwrap();
        assert_eq!(d.num_days(), 7);
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("30m").unwrap();
        assert_eq!(d.num_minutes(), 30);
    }

    #[test]
    fn test_parse_duration_weeks() {
        let d = parse_duration("1w").unwrap();
        assert_eq!(d.num_days(), 7);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("24x").is_err());
    }

    #[test]
    fn test_store_and_load_freeze() {
        let dir = TempDir::new().unwrap();
        let state = FreezeState {
            frozen_at: Utc::now(),
            frozen_until: Utc::now() + chrono::Duration::hours(24),
            reason: Some("test freeze".to_string()),
        };

        store_freeze(dir.path(), &state).unwrap();

        let loaded = load_active_freeze(dir.path(), Utc::now()).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert!(loaded.is_active(Utc::now()));
        assert_eq!(loaded.reason.as_deref(), Some("test freeze"));
    }

    #[test]
    fn test_expired_freeze_returns_none() {
        let dir = TempDir::new().unwrap();
        let state = FreezeState {
            frozen_at: Utc::now() - chrono::Duration::hours(48),
            frozen_until: Utc::now() - chrono::Duration::hours(24),
            reason: None,
        };

        store_freeze(dir.path(), &state).unwrap();

        let loaded = load_active_freeze(dir.path(), Utc::now()).unwrap();
        assert!(loaded.is_none());

        // Stale file should be cleaned up
        assert!(!freeze_file_path(dir.path()).exists());
    }

    #[test]
    fn test_no_freeze_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let loaded = load_active_freeze(dir.path(), Utc::now()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_remove_freeze() {
        let dir = TempDir::new().unwrap();
        let state = FreezeState {
            frozen_at: Utc::now(),
            frozen_until: Utc::now() + chrono::Duration::hours(1),
            reason: None,
        };

        store_freeze(dir.path(), &state).unwrap();
        assert!(freeze_file_path(dir.path()).exists());

        let removed = remove_freeze(dir.path()).unwrap();
        assert!(removed);
        assert!(!freeze_file_path(dir.path()).exists());

        // Removing when no file exists returns false
        let removed = remove_freeze(dir.path()).unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_freeze_state_extends_duration() {
        let dir = TempDir::new().unwrap();

        // First freeze: 1 hour
        let state1 = FreezeState {
            frozen_at: Utc::now(),
            frozen_until: Utc::now() + chrono::Duration::hours(1),
            reason: None,
        };
        store_freeze(dir.path(), &state1).unwrap();

        // Second freeze: 24 hours — should overwrite
        let state2 = FreezeState {
            frozen_at: Utc::now(),
            frozen_until: Utc::now() + chrono::Duration::hours(24),
            reason: Some("extended".to_string()),
        };
        store_freeze(dir.path(), &state2).unwrap();

        let loaded = load_active_freeze(dir.path(), Utc::now()).unwrap().unwrap();
        assert_eq!(loaded.reason.as_deref(), Some("extended"));
        // Should be closer to 24h than 1h
        assert!(loaded.frozen_until > Utc::now() + chrono::Duration::hours(23));
    }
}
