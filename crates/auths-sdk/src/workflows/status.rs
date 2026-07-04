//! Status workflow — aggregates identity, device, and agent state for user-friendly reporting.

use crate::result::{DeviceReadiness, NextStep};
use chrono::{DateTime, Duration, Utc};

/// Status rules for reporting Auths state.
///
/// The consumed surface is [`StatusWorkflow::compute_readiness`] (per-device
/// readiness from expiry/revocation) and [`StatusWorkflow::next_steps_from_readiness`]
/// (the next-step rules). The CLI (`auths status`) loads identity/devices/agent
/// itself and calls these — they are the single source of truth for the rules.
pub struct StatusWorkflow;

impl StatusWorkflow {
    /// The next-step rules, keyed on the minimal facts they need — identity presence, each device's
    /// readiness, and whether the signing agent is live. The single source of truth for these rules,
    /// including the recovery single-point-of-failure signpost, so any presentation layer (the CLI)
    /// shares them rather than re-deriving its own.
    ///
    /// Args:
    /// * `identity_present`: whether an identity is initialized.
    /// * `readinesses`: the readiness of each device in the roster.
    /// * `agent_running`: whether the signing agent is live.
    pub fn next_steps_from_readiness(
        identity_present: bool,
        readinesses: &[DeviceReadiness],
        agent_running: bool,
    ) -> Vec<NextStep> {
        let mut steps = Vec::new();

        // No identity initialized
        if !identity_present {
            steps.push(NextStep {
                summary: "Initialize your identity".to_string(),
                command: "auths init --profile developer".to_string(),
            });
            return steps;
        }

        // No devices linked
        if readinesses.is_empty() {
            steps.push(NextStep {
                summary: "Link this device to your identity".to_string(),
                command: "auths pair".to_string(),
            });
        }

        // Devices expiring soon
        let expiring_soon = readinesses
            .iter()
            .filter(|r| **r == DeviceReadiness::ExpiringSoon)
            .count();
        if expiring_soon > 0 {
            steps.push(NextStep {
                summary: format!("{} device(s) expiring soon", expiring_soon),
                command: "auths device extend".to_string(),
            });
        }

        // A single usable device is a recovery single point of failure: if it is lost or
        // compromised there is no second device to recover the identity from.
        if Self::needs_recovery_device(readinesses) {
            steps.push(NextStep {
                summary: "Add a recovery device — with only one device, losing or compromising it \
                          leaves no way to recover your identity"
                    .to_string(),
                command: "auths pair".to_string(),
            });
        }

        // Agent not running
        if !agent_running {
            steps.push(NextStep {
                summary: "Start the authentication agent for signing".to_string(),
                command: "auths agent start".to_string(),
            });
        }

        // Always suggest viewing help for deeper features
        if steps.is_empty() {
            steps.push(NextStep {
                summary: "Explore advanced features".to_string(),
                command: "auths --help-all".to_string(),
            });
        }

        steps
    }

    /// Determine device readiness given expiration timestamps.
    pub fn compute_readiness(
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> DeviceReadiness {
        if revoked_at.is_some() {
            return DeviceReadiness::Revoked;
        }

        match expires_at {
            Some(exp) if exp < now => DeviceReadiness::Expired,
            Some(exp) if exp - now < Duration::days(7) => DeviceReadiness::ExpiringSoon,
            Some(_) => DeviceReadiness::Ok,
            None => DeviceReadiness::Ok, // No expiry set
        }
    }

    /// Whether the identity is a recovery single point of failure: exactly one usable
    /// (non-revoked, non-expired) device, so a lost or compromised device leaves no second
    /// device to recover from. Zero devices is a different state (link a device first).
    ///
    /// Args:
    /// * `readinesses`: the readiness of each device in the roster.
    fn needs_recovery_device(readinesses: &[DeviceReadiness]) -> bool {
        readinesses
            .iter()
            .filter(|r| !matches!(r, DeviceReadiness::Revoked | DeviceReadiness::Expired))
            .count()
            == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_revoked() {
        let now = Utc::now();
        let readiness =
            StatusWorkflow::compute_readiness(None, Some(now - Duration::hours(1)), now);
        assert_eq!(readiness, DeviceReadiness::Revoked);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_expired() {
        let now = Utc::now();
        let exp = now - Duration::days(1);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::Expired);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_expiring_soon() {
        let now = Utc::now();
        let exp = now + Duration::days(3);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::ExpiringSoon);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_ok() {
        let now = Utc::now();
        let exp = now + Duration::days(30);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::Ok);
    }

    #[test]
    fn test_next_steps_no_identity() {
        let steps = StatusWorkflow::next_steps_from_readiness(false, &[], false);
        assert!(!steps.is_empty());
        assert!(steps[0].command.contains("init"));
    }

    #[test]
    fn single_usable_device_is_a_recovery_single_point_of_failure() {
        // One usable device → no second device to recover from → flagged.
        assert!(StatusWorkflow::needs_recovery_device(&[
            DeviceReadiness::Ok
        ]));
        // Two usable devices → a recovery path exists → not flagged.
        assert!(!StatusWorkflow::needs_recovery_device(&[
            DeviceReadiness::Ok,
            DeviceReadiness::Ok
        ]));
        // A revoked device is not a recovery option: one usable + one revoked is still a
        // single point of failure.
        assert!(StatusWorkflow::needs_recovery_device(&[
            DeviceReadiness::Ok,
            DeviceReadiness::Revoked
        ]));
        // Zero devices is a different state (link a device first), not a recovery nag.
        assert!(!StatusWorkflow::needs_recovery_device(&[]));
    }

    #[test]
    fn single_device_identity_is_told_to_add_a_recovery_device() {
        let steps = StatusWorkflow::next_steps_from_readiness(true, &[DeviceReadiness::Ok], true);
        assert!(
            steps.iter().any(|s| s.summary.contains("recovery device")),
            "a single-device identity must be told to add a recovery device, got {steps:?}"
        );
    }
}
