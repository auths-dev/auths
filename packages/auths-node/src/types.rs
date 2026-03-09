use napi_derive::napi;

use auths_verifier::types::{
    ChainLink as RustChainLink, VerificationReport as RustVerificationReport,
    VerificationStatus as RustVerificationStatus,
};

#[napi(object)]
#[derive(Clone)]
pub struct NapiVerificationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub error_code: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiVerificationStatus {
    pub status_type: String,
    pub at: Option<String>,
    pub step: Option<u32>,
    pub missing_link: Option<String>,
    pub required: Option<u32>,
    pub verified: Option<u32>,
}

impl NapiVerificationStatus {
    pub fn is_valid(&self) -> bool {
        self.status_type == "Valid"
    }
}

impl From<RustVerificationStatus> for NapiVerificationStatus {
    fn from(status: RustVerificationStatus) -> Self {
        match status {
            RustVerificationStatus::Valid => NapiVerificationStatus {
                status_type: "Valid".to_string(),
                at: None,
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Expired { at } => NapiVerificationStatus {
                status_type: "Expired".to_string(),
                at: Some(at.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Revoked { at } => NapiVerificationStatus {
                status_type: "Revoked".to_string(),
                at: at.map(|t| t.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::InvalidSignature { step } => NapiVerificationStatus {
                status_type: "InvalidSignature".to_string(),
                at: None,
                step: Some(step as u32),
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::BrokenChain { missing_link } => NapiVerificationStatus {
                status_type: "BrokenChain".to_string(),
                at: None,
                step: None,
                missing_link: Some(missing_link),
                required: None,
                verified: None,
            },
            RustVerificationStatus::InsufficientWitnesses { required, verified } => {
                NapiVerificationStatus {
                    status_type: "InsufficientWitnesses".to_string(),
                    at: None,
                    step: None,
                    missing_link: None,
                    required: Some(required as u32),
                    verified: Some(verified as u32),
                }
            }
        }
    }
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiChainLink {
    pub issuer: String,
    pub subject: String,
    pub valid: bool,
    pub error: Option<String>,
}

impl From<RustChainLink> for NapiChainLink {
    fn from(link: RustChainLink) -> Self {
        NapiChainLink {
            issuer: link.issuer,
            subject: link.subject,
            valid: link.valid,
            error: link.error,
        }
    }
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiVerificationReport {
    pub status: NapiVerificationStatus,
    pub chain: Vec<NapiChainLink>,
    pub warnings: Vec<String>,
}

impl NapiVerificationReport {
    pub fn is_valid(&self) -> bool {
        self.status.is_valid()
    }
}

impl From<RustVerificationReport> for NapiVerificationReport {
    fn from(report: RustVerificationReport) -> Self {
        NapiVerificationReport {
            status: report.status.into(),
            chain: report.chain.into_iter().map(|l| l.into()).collect(),
            warnings: report.warnings,
        }
    }
}

// Identity types

#[napi(object)]
#[derive(Clone)]
pub struct NapiIdentityResult {
    pub did: String,
    pub key_alias: String,
    pub public_key_hex: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiAgentIdentityBundle {
    pub agent_did: String,
    pub key_alias: String,
    pub attestation_json: String,
    pub public_key_hex: String,
    pub repo_path: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiDelegatedAgentBundle {
    pub agent_did: String,
    pub key_alias: String,
    pub attestation_json: String,
    pub public_key_hex: String,
    pub repo_path: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiRotationResult {
    pub controller_did: String,
    pub new_key_fingerprint: String,
    pub previous_key_fingerprint: String,
    pub sequence: u64,
}

// Device types

#[napi(object)]
#[derive(Clone)]
pub struct NapiLinkResult {
    pub device_did: String,
    pub attestation_id: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiExtensionResult {
    pub device_did: String,
    pub new_expires_at: String,
    pub previous_expires_at: Option<String>,
}

// Signing types

#[napi(object)]
#[derive(Clone)]
pub struct NapiCommitSignResult {
    pub signature: String,
    pub signer_did: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiActionEnvelope {
    pub envelope_json: String,
    pub signature_hex: String,
    pub signer_did: String,
}
