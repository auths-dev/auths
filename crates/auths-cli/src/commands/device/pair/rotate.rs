//! Device-key rotation post-response handler (LAN mode).
//!
//! Runs on the Mac side after the phone's `/response` lands on a session
//! that was created with [`SessionMode::Rotate`]. The phone signed the
//! rotation binding message with its OLD Secure Enclave key and included
//! both its current `device_signing_pubkey` (OLD) and
//! `new_device_signing_pubkey` (NEW) in the body. The daemon already
//! verified the `Auths-Sig` header against the OLD pubkey; this
//! handler:
//!
//! 1. Decodes the rotation fields from the response.
//! 2. Rebuilds the rotation binding bytes and verifies the body-level
//!    signature against the OLD pubkey (defense-in-depth — the header
//!    check alone doesn't prove the OLD key approved *this* transition).
//! 3. Derives the NEW device DID from the NEW pubkey.
//! 4. Loads the existing attestation the controller previously issued
//!    for the OLD device DID.
//! 5. Creates a superseding attestation whose
//!    `supersedes_attestation_rid` points to the OLD attestation and
//!    whose `device_public_key`/`subject` identify the NEW key.
//! 6. Persists via the attestation sink and prints the one-line
//!    completion footer.
//!
//! Each step returns a specific error so a failure mid-rotation surfaces
//! a precise diagnosis, not a generic "rotation failed."
//!
//! [`SessionMode::Rotate`]: auths_sdk::pairing::SessionMode::Rotate

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use console::style;

use auths_crypto::RingCryptoProvider;
use auths_sdk::attestation::{AttestationSink, create_superseding_attestation};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::{KeyStorage, get_platform_keychain_with_config};
use auths_sdk::pairing::{PairingSession, SubmitResponseRequest};
use auths_sdk::ports::{AttestationMetadata, AttestationSource, IdentityStorage, ManagedIdentity};
use auths_sdk::signing::{PassphraseProvider, StorageSigner};
use auths_sdk::storage::{RegistryAttestationStorage, RegistryIdentityStorage};
use auths_verifier::core::Attestation;
use auths_verifier::types::{CanonicalDid, DeviceDID};

use super::common::{CHECK, GEAR, LINK, PHONE, create_wait_spinner, print_rotation_completion};

/// Complete a rotation session: verify the OLD-key binding signature over
/// the rotation message, emit a superseding attestation for the NEW key.
pub(crate) fn handle_rotation_response(
    now: DateTime<Utc>,
    session: &PairingSession,
    response: SubmitResponseRequest,
    auths_dir: &Path,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    println!();
    println!(
        "{}",
        style(format!("━━━ {LINK}Rotation Response Received ━━━"))
            .bold()
            .cyan()
    );
    println!();

    let decoded = decode_rotation_response(&response)
        .context("Rotation response body was missing or malformed")?;

    if let Some(name) = &decoded.device_name {
        println!(
            "  {} {}",
            style(format!("{PHONE}Device:")).dim(),
            style(name).bold()
        );
    }

    let verify_spinner = create_wait_spinner(&format!(
        "{GEAR}Verifying rotation signature with old key..."
    ));
    verify_rotation_binding(session, &decoded)
        .context("Old-key signature over rotation binding did not verify")?;
    verify_spinner.finish_with_message(format!("{CHECK}Old-key signature verified"));

    let new_device_did =
        DeviceDID::from_public_key(&decoded.new_device_pubkey_compressed, decoded.curve);
    println!(
        "  {} {} {} {}",
        style("DID:").dim(),
        style(&decoded.old_device_did).dim(),
        style("→").dim(),
        style(new_device_did.as_str()).cyan()
    );

    if !auths_dir.exists() {
        anyhow::bail!(
            "No local identity found at {}. Run `auths init` first.",
            auths_dir.display()
        );
    }

    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(auths_dir.to_path_buf()));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(auths_dir));
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        Arc::clone(&attestation_storage) as Arc<dyn AttestationSource + Send + Sync>;
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_storage) as Arc<dyn AttestationSink + Send + Sync>;

    let managed: ManagedIdentity = identity_storage
        .load_identity()
        .context("Failed to load controller identity from ~/.auths")?;

    println!(
        "  {} {}",
        style("Controller:").dim(),
        style(managed.controller_did.as_str()).cyan(),
    );

    let old_attestation =
        find_old_attestation(attestation_source.as_ref(), &decoded.old_device_did)
            .context("Failed to locate the attestation being superseded")?;

    let keychain = get_platform_keychain_with_config(env_config)?;
    let aliases = keychain
        .list_aliases_for_identity(&managed.controller_did)
        .context("Failed to list controller key aliases")?;
    let identity_key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            anyhow!(
                "No signing key found for identity {}",
                managed.controller_did
            )
        })?;

    // `passphrase_provider` is the CLI-level provider already wrapped
    // with `KeychainPassphraseProvider` by `factories::load_cli_config`
    // — using Touch ID (or the user's configured policy) to retrieve
    // the cached passphrase without re-typing. See
    // `auths-cli::factories::mod::load_cli_config`.
    let key_storage: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
    let signer = StorageSigner::new(Arc::clone(&key_storage));

    let attest_spinner = create_wait_spinner(&format!("{GEAR}Creating superseding attestation..."));

    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: None,
        note: Some("Rotated via QR".to_string()),
    };

    let new_attestation = create_superseding_attestation(
        now,
        &managed.storage_id,
        &managed.controller_did,
        &new_device_did,
        &decoded.new_device_pubkey_compressed,
        decoded.curve,
        None,
        &meta,
        &signer,
        passphrase_provider.as_ref(),
        Some(&identity_key_alias),
        None,
        old_attestation.capabilities.clone(),
        old_attestation.role,
        None,
        None,
        None,
        old_attestation.subject.as_str(),
    )
    .map_err(anyhow::Error::from)
    .context("Failed to sign superseding attestation")?;

    attestation_sink
        .export(
            &auths_verifier::VerifiedAttestation::dangerous_from_unchecked(new_attestation.clone()),
        )
        .context("Failed to persist superseding attestation")?;
    attestation_sink.sync_index(&new_attestation);

    attest_spinner.finish_with_message(format!("{CHECK}Superseding attestation created"));
    print_rotation_completion(decoded.device_name.as_deref(), new_device_did.as_str());

    Ok(())
}

/// Decoded, length- and format-validated fields of a rotation `/response`.
struct DecodedRotationResponse {
    old_device_did: DeviceDID,
    /// OLD pubkey, 33-byte compressed P-256 SEC1.
    old_device_pubkey_compressed: Vec<u8>,
    /// NEW pubkey, 33-byte compressed P-256 SEC1.
    new_device_pubkey_compressed: Vec<u8>,
    /// Device ECDH ephemeral pubkey, 33-byte compressed P-256 SEC1.
    device_ephemeral: Vec<u8>,
    /// Raw r||s ECDSA signature over the rotation binding message by
    /// the OLD key (64 bytes).
    signature_raw: Vec<u8>,
    curve: auths_crypto::CurveType,
    device_name: Option<String>,
}

fn decode_rotation_response(response: &SubmitResponseRequest) -> Result<DecodedRotationResponse> {
    let old_pubkey = response
        .device_signing_pubkey
        .decode()
        .context("invalid base64 in device_signing_pubkey (old key)")?;
    if old_pubkey.len() != 33 {
        anyhow::bail!(
            "old device_signing_pubkey must be 33-byte compressed P-256 (got {} bytes)",
            old_pubkey.len()
        );
    }

    let new_pubkey_b64 = response.new_device_signing_pubkey.as_ref().ok_or_else(|| {
        anyhow!(
            "rotation response missing `new_device_signing_pubkey` — \
             phone-side FFI did not populate the rotation field"
        )
    })?;
    let new_pubkey = new_pubkey_b64
        .decode()
        .context("invalid base64 in new_device_signing_pubkey")?;
    if new_pubkey.len() != 33 {
        anyhow::bail!(
            "new_device_signing_pubkey must be 33-byte compressed P-256 (got {} bytes)",
            new_pubkey.len()
        );
    }
    if new_pubkey == old_pubkey {
        anyhow::bail!("rotation response carries identical old and new pubkeys");
    }

    let device_ephemeral = response
        .device_ephemeral_pubkey
        .decode()
        .context("invalid base64 in device_ephemeral_pubkey")?;
    if device_ephemeral.len() != 33 {
        anyhow::bail!(
            "device_ephemeral_pubkey must be 33-byte compressed P-256 (got {} bytes)",
            device_ephemeral.len()
        );
    }

    let signature_raw = response
        .signature
        .decode()
        .context("invalid base64 in signature")?;
    if signature_raw.len() != 64 {
        anyhow::bail!(
            "signature must be 64-byte raw r||s (got {} bytes)",
            signature_raw.len()
        );
    }

    let old_device_did =
        DeviceDID::parse(&response.device_did).map_err(|e| anyhow!("invalid device_did: {e}"))?;

    Ok(DecodedRotationResponse {
        old_device_did,
        old_device_pubkey_compressed: old_pubkey,
        new_device_pubkey_compressed: new_pubkey,
        device_ephemeral,
        signature_raw,
        curve: response.curve.into(),
        device_name: response.device_name.clone(),
    })
}

/// Verify the signature in the response body covers the exact
/// rotation binding bytes the phone-side FFI emitted:
///
/// ```text
/// binding = session_id || short_code || initiator_eph || device_eph || new_pubkey
/// ```
///
/// Matches `auths-mobile-ffi::build_rotation_binding_message` byte-for-byte.
fn verify_rotation_binding(
    session: &PairingSession,
    decoded: &DecodedRotationResponse,
) -> Result<()> {
    let initiator_eph = session
        .ephemeral_pubkey_bytes()
        .map_err(|e| anyhow!("failed to get initiator ephemeral pubkey: {e}"))?;

    let session_id = session.token.session_id.as_bytes();
    let short_code = session.token.short_code.as_bytes();

    let mut binding = Vec::with_capacity(session_id.len() + short_code.len() + 33 + 33 + 33);
    binding.extend_from_slice(session_id);
    binding.extend_from_slice(short_code);
    binding.extend_from_slice(&initiator_eph);
    binding.extend_from_slice(&decoded.device_ephemeral);
    binding.extend_from_slice(&decoded.new_device_pubkey_compressed);

    // Curve-agnostic verification path — stays inside the sanctioned
    // crypto backend rather than linking `p256` directly.
    RingCryptoProvider::p256_verify(
        &decoded.old_device_pubkey_compressed,
        &binding,
        &decoded.signature_raw,
    )
    .map_err(|e| anyhow!("ECDSA verification failed: {e}"))?;

    Ok(())
}

/// Locate the attestation the controller previously issued for
/// `old_device_did`. Returns the freshest non-revoked record; errors if
/// none is found or if every record has already been revoked.
fn find_old_attestation(
    source: &dyn AttestationSource,
    old_device_did: &DeviceDID,
) -> Result<Attestation> {
    let attestations = source
        .load_attestations_for_device(old_device_did)
        .map_err(|e| anyhow!("failed to read attestations: {e}"))?;

    if attestations.is_empty() {
        anyhow::bail!(
            "no existing attestation found for device {} — has this device been paired?",
            old_device_did
        );
    }

    // Prefer the most recent non-revoked record. Multiple revoked
    // records can coexist (recovery history); rotation should chain
    // from whatever the live one is.
    let chosen = attestations
        .iter()
        .filter(|a| !a.is_revoked())
        .max_by_key(|a| a.timestamp.unwrap_or_else(Utc::now))
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "all attestations for device {} are revoked; cannot rotate a revoked device",
                old_device_did
            )
        })?;

    // Sanity: make sure the controller issued this attestation. A
    // foreign-issued attestation here would be a cross-identity mix-up.
    let _ = CanonicalDid::try_from(chosen.issuer.as_str()).map_err(|e| {
        anyhow!(
            "existing attestation issuer '{}' is not a valid controller DID: {e}",
            chosen.issuer
        )
    })?;

    Ok(chosen)
}
