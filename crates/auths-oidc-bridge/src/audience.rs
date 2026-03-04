//! Audience format detection and validation for cloud providers.

use crate::error::BridgeError;

/// Detected cloud provider based on audience format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceKind {
    /// AWS STS (e.g. `sts.amazonaws.com`).
    Aws,
    /// GCP Workload Identity Federation.
    Gcp,
    /// Azure AD / Entra ID.
    Azure,
    /// Unknown or custom audience.
    Custom,
}

impl AudienceKind {
    /// Returns the provider name as a string, or `None` for `Custom`.
    pub fn provider_name(self) -> Option<&'static str> {
        match self {
            Self::Aws => Some("aws"),
            Self::Gcp => Some("gcp"),
            Self::Azure => Some("azure"),
            Self::Custom => None,
        }
    }
}

/// Controls how audience format mismatches are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AudienceValidation {
    /// Log warnings on format mismatch but allow the request (default).
    #[default]
    Warn,
    /// Reject requests with audience format mismatches.
    Strict,
    /// Skip audience format validation entirely.
    None,
}

impl AudienceValidation {
    /// Parse from a string value (for env var parsing).
    pub fn from_str_value(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "warn" => Some(Self::Warn),
            "strict" => Some(Self::Strict),
            "none" => Some(Self::None),
            _ => Option::None,
        }
    }
}

/// Detect the cloud provider from the audience string and validate the format.
///
/// Returns the detected `AudienceKind`. In `Strict` mode, returns an error
/// for format mismatches. In `Warn` mode, logs warnings. In `None` mode,
/// skips all validation.
pub fn validate_audience_format(
    audience: &str,
    mode: &AudienceValidation,
) -> Result<AudienceKind, BridgeError> {
    let kind = detect_audience_kind(audience);

    if *mode == AudienceValidation::None {
        return Ok(kind);
    }

    // Check for GCP format mismatches
    if kind == AudienceKind::Gcp && !is_valid_gcp_audience(audience) {
        let msg = format!(
            "GCP audience format mismatch: expected \
             https://iam.googleapis.com/projects/{{NUMBER}}/locations/global/\
             workloadIdentityPools/{{POOL}}/providers/{{PROVIDER}}, got: {audience}"
        );
        match mode {
            AudienceValidation::Strict => {
                return Err(BridgeError::InvalidRequest(msg));
            }
            AudienceValidation::Warn => {
                tracing::warn!("{msg}");
            }
            AudienceValidation::None => unreachable!(),
        }
    }

    tracing::info!(audience = audience, kind = ?kind, "audience format detected");
    Ok(kind)
}

/// Detect the audience kind from the audience string.
pub fn detect_audience_kind(audience: &str) -> AudienceKind {
    if audience.contains("amazonaws.com") {
        AudienceKind::Aws
    } else if audience.starts_with("https://iam.googleapis.com/") {
        AudienceKind::Gcp
    } else if audience.starts_with("api://") || looks_like_guid(audience) {
        AudienceKind::Azure
    } else {
        AudienceKind::Custom
    }
}

/// Check if a GCP audience matches the expected Workload Identity Federation format.
///
/// Expected: `https://iam.googleapis.com/projects/{NUMBER}/locations/global/workloadIdentityPools/{POOL}/providers/{PROVIDER}`
fn is_valid_gcp_audience(audience: &str) -> bool {
    let Some(rest) = audience.strip_prefix("https://iam.googleapis.com/projects/") else {
        return false;
    };

    // Expected: {NUMBER}/locations/global/workloadIdentityPools/{POOL}/providers/{PROVIDER}
    let parts: Vec<&str> = rest
        .splitn(2, "/locations/global/workloadIdentityPools/")
        .collect();
    if parts.len() != 2 {
        return false;
    }

    let project_number = parts[0];
    if project_number.is_empty() || !project_number.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Expected: {POOL}/providers/{PROVIDER}
    let provider_parts: Vec<&str> = parts[1].splitn(2, "/providers/").collect();
    if provider_parts.len() != 2 {
        return false;
    }

    let pool_id = provider_parts[0];
    let provider_id = provider_parts[1];

    !pool_id.is_empty() && !provider_id.is_empty()
}

/// Check if a string looks like a GUID (8-4-4-4-12 hex digits).
fn looks_like_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}
