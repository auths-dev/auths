//! Status workflow — aggregates identity, device, and agent state for user-friendly reporting.

use crate::result::{
    AgentStatus, DeviceReadiness, DeviceStatus, IdentityStatus, NextStep, StatusReport,
};
use chrono::{DateTime, Duration, Utc};
use std::path::Path;

/// Status workflow for reporting Auths state.
///
/// This workflow aggregates information from identity storage, device attestations,
/// and agent status to produce a unified StatusReport suitable for CLI display.
///
/// Usage:
/// ```ignore
/// let report = StatusWorkflow::query(&ctx, Utc::now())?;
/// println!("Identity: {}", report.identity.controller_did);
/// ```
pub struct StatusWorkflow;

impl StatusWorkflow {
    /// Query the current status of the Auths system.
    ///
    /// Args:
    /// * `repo_path` - Path to the Auths repository.
    /// * `now` - Current time for expiry calculations.
    ///
    /// Returns a StatusReport with identity, device, and agent state.
    ///
    /// This is a placeholder implementation; the real version will integrate
    /// with IdentityStorage, AttestationSource, and agent discovery ports.
    pub fn query(repo_path: &Path, _now: DateTime<Utc>) -> Result<StatusReport, String> {
        let _ = repo_path; // Placeholder to avoid unused warning
        // TODO: In full implementation, load identity from IdentityStorage
        let identity = None; // Placeholder

        // TODO: In full implementation, load attestations from AttestationSource
        // and aggregate by device with expiry checking
        let devices = Vec::new(); // Placeholder

        // TODO: In full implementation, check agent socket and PID
        let agent = AgentStatus {
            running: false,
            pid: None,
            socket_path: None,
        };

        // Compute next steps based on current state
        let next_steps = Self::compute_next_steps(&identity, &devices, &agent);

        Ok(StatusReport {
            identity,
            devices,
            agent,
            next_steps,
        })
    }

    /// Compute suggested next steps based on current state.
    fn compute_next_steps(
        identity: &Option<IdentityStatus>,
        devices: &[DeviceStatus],
        agent: &AgentStatus,
    ) -> Vec<NextStep> {
        let mut steps = Vec::new();

        // No identity initialized
        if identity.is_none() {
            steps.push(NextStep {
                summary: "Initialize your identity".to_string(),
                command: "auths init --profile developer".to_string(),
            });
            return steps;
        }

        // No devices linked
        if devices.is_empty() {
            steps.push(NextStep {
                summary: "Link this device to your identity".to_string(),
                command: "auths pair".to_string(),
            });
        }

        // Device expiring soon
        let expiring_soon = devices
            .iter()
            .filter(|d| d.readiness == DeviceReadiness::ExpiringSoon)
            .count();
        if expiring_soon > 0 {
            steps.push(NextStep {
                summary: format!("{} device(s) expiring soon", expiring_soon),
                command: "auths device extend".to_string(),
            });
        }

        // Agent not running
        if !agent.running {
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
        let steps = StatusWorkflow::compute_next_steps(
            &None,
            &[],
            &AgentStatus {
                running: false,
                pid: None,
                socket_path: None,
            },
        );
        assert!(!steps.is_empty());
        assert!(steps[0].command.contains("init"));
    }
}
