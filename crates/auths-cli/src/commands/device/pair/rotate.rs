//! Device-key rotation post-response handler (LAN mode).
//!
//! Runs on the Mac side after the phone's `/response` lands on a session
//! created with `SessionMode::Rotate`. The phone signed the binding
//! message with its OLD Secure Enclave key and included a
//! `rotation_proof` in the body (FFI-side support pending); this module
//! verifies that proof against the device's stored attestation, resolves
//! the prior attestation RID, and produces a superseding attestation
//! via `auths_sdk::attestation::create_superseding_attestation`.
//!
//! The actual rotation_proof verification path is gated behind a TODO:
//! the FFI does not yet populate the proof field (see task #8 in the
//! rotation rollout). Until that lands, this handler returns a clear
//! error describing what's missing so the CLI caller and the phone
//! surface the same diagnostic.

use std::path::Path;

use anyhow::Result;
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::pairing::{PairingSession, SubmitResponseRequest};
use chrono::{DateTime, Utc};
use console::style;

use super::common::print_rotation_completion;

/// Complete a rotation session. Currently stubbed — full implementation
/// requires the phone-side FFI to populate a `rotation_proof` field in
/// `SubmitResponseRequest` (task #8 in the rotation rollout) plus the
/// storage-side RID lookup by old device DID.
pub(crate) fn handle_rotation_response(
    _now: DateTime<Utc>,
    _session: &PairingSession,
    response: SubmitResponseRequest,
    _auths_dir: &Path,
    _env_config: &EnvironmentConfig,
) -> Result<()> {
    println!();
    println!(
        "  {} {}",
        style("Rotation:").yellow().bold(),
        style("device-key rotation is not yet end-to-end functional.").yellow()
    );
    println!(
        "  {} The phone-side FFI does not yet emit the rotation proof; the Mac \
         daemon cannot create a superseding attestation without it.",
        style("Note:").dim()
    );
    println!();

    // Surface whatever the phone did send so operators can see the
    // response landed, even if we can't yet complete the ceremony.
    if let Some(name) = response.device_name.as_deref() {
        print_rotation_completion(Some(name), &response.device_did);
    } else {
        print_rotation_completion(None, &response.device_did);
    }

    anyhow::bail!("rotation protocol plumbing incomplete — FFI rotation-proof support pending")
}
