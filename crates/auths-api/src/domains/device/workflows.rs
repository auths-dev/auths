//! Device domain workflows - link, revoke, and extend operations.

use auths_core::ports::clock::ClockProvider;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::attestation::revoke::create_signed_revocation;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_verifier::core::ResourceId;
use auths_verifier::types::DeviceDID;
use chrono::Duration;

pub use auths_sdk::{
    DeviceError, DeviceExtensionConfig, DeviceExtensionResult, DeviceLinkConfig, DeviceLinkResult,
};

use auths_sdk::context::AuthsContext;
use auths_sdk::error::SdkStorageError;
use auths_verifier::core::VerifiedAttestation;

/// Helper to create a signer from the context.
fn build_signer(
    ctx: &AuthsContext,
) -> StorageSigner<std::sync::Arc<dyn auths_core::storage::KeyStorage + Send + Sync>> {
    StorageSigner::new(ctx.key_storage.clone())
}

/// Link a new device to the identity.
///
/// Creates a device attestation, persists it, and returns the device DID and metadata.
///
/// Args:
/// * `config`: Configuration for the link operation (identity key, device key, etc).
/// * `ctx`: Auths context with storage, attestation, and signing ports.
/// * `clock`: Clock for timestamping the operation.
///
/// Usage:
/// ```ignore
/// let result = link_device(&config, &ctx, &SystemClock)?;
/// println!("Device linked: {}", result.device_did);
/// ```
pub fn link_device(
    config: DeviceLinkConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceLinkResult, DeviceError> {
    // Determine which key to use for device public key
    let device_key_alias = config
        .device_key_alias
        .clone()
        .unwrap_or_else(|| config.identity_key_alias.clone());

    // Extract device public key from keychain
    let pk_bytes = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &device_key_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(DeviceError::CryptoError)?;

    // Derive device DID from public key
    let device_did = DeviceDID::from_ed25519(pk_bytes.as_slice().try_into().map_err(|_| {
        DeviceError::StorageError(SdkStorageError::Identity(
            auths_id::error::StorageError::InvalidData("Invalid public key length".to_string()),
        ))
    })?);

    // Load identity to get controller DID
    let identity = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    // Build signer and create attestation
    let signer = build_signer(ctx);
    let now = clock.now();
    let rid = format!("rid:device:{}", ctx.uuid_provider.new_id());
    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: config.expires_in.map(|s| now + Duration::seconds(s as i64)),
        note: config.note.clone(),
    };

    let attestation = create_signed_attestation(
        now,
        &rid,
        &identity.controller_did,
        &device_did,
        pk_bytes.as_slice(),
        None,
        &meta,
        &signer,
        ctx.passphrase_provider.as_ref(),
        Some(&config.identity_key_alias),
        Some(&device_key_alias),
        vec![],
        None,
        None,
    )
    .map_err(DeviceError::AttestationError)?;

    // We are the signer, so mark as verified and store
    let verified = VerifiedAttestation::dangerous_from_unchecked(attestation.clone());
    ctx.attestation_sink
        .export(&verified)
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    Ok(DeviceLinkResult {
        device_did,
        attestation_id: ResourceId::new(attestation.rid.to_string()),
    })
}

/// Revoke an existing device from the identity.
///
/// Marks a device as revoked in the attestation store, preventing further use.
///
/// Args:
/// * `device_did`: The device DID to revoke.
/// * `identity_key_alias`: The identity key for signing the revocation.
/// * `ctx`: Auths context with storage and signing ports.
/// * `note`: Optional human-readable revocation reason.
/// * `clock`: Clock for timestamping.
///
/// Usage:
/// ```ignore
/// revoke_device(&device_did, &key_alias, &ctx, None, &SystemClock)?;
/// println!("Device revoked");
/// ```
pub fn revoke_device(
    device_did: &DeviceDID,
    identity_key_alias: &KeyAlias,
    ctx: &AuthsContext,
    note: Option<String>,
    clock: &dyn ClockProvider,
) -> Result<(), DeviceError> {
    // Load the device's current attestation
    let attestations = ctx
        .attestation_source
        .load_attestations_for_device(device_did)
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    let current = attestations
        .into_iter()
        .find(|att| !att.is_revoked())
        .ok_or_else(|| DeviceError::DeviceNotFound {
            did: device_did.to_string(),
        })?;

    // Load identity
    let identity = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    // Build signer
    let signer = build_signer(ctx);
    let now = clock.now();

    // Create revocation
    let revocation = create_signed_revocation(
        &current.rid.to_string(),
        &identity.controller_did,
        device_did,
        current.device_public_key.as_bytes(),
        note,
        None,
        now,
        &signer,
        ctx.passphrase_provider.as_ref(),
        identity_key_alias,
    )
    .map_err(DeviceError::AttestationError)?;

    // We are the signer, so mark as verified and store
    let verified = VerifiedAttestation::dangerous_from_unchecked(revocation);
    ctx.attestation_sink
        .export(&verified)
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    Ok(())
}

/// Extend the expiration time of a device authorization.
///
/// Extends the device's authorized period by creating a new attestation with
/// an updated expiration timestamp.
///
/// Args:
/// * `config`: Configuration with device DID, identity key, etc.
/// * `ctx`: Auths context with storage and signing ports.
/// * `clock`: Clock for timestamping.
///
/// Returns:
/// * `DeviceExtensionResult` with the device DID and new expiration time.
///
/// Usage:
/// ```ignore
/// let result = extend_device(&config, &ctx, &SystemClock)?;
/// println!("Expires at: {}", result.new_expires_at);
/// ```
pub fn extend_device(
    config: DeviceExtensionConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceExtensionResult, DeviceError> {
    let now = clock.now();
    let new_expires_at = now + Duration::seconds(config.expires_in as i64);

    // Load the device's current attestation
    let attestations = ctx
        .attestation_source
        .load_attestations_for_device(&config.device_did)
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    let current = attestations
        .into_iter()
        .find(|att| !att.is_revoked())
        .ok_or_else(|| DeviceError::DeviceNotFound {
            did: config.device_did.to_string(),
        })?;

    let previous_expires_at = current.expires_at;

    // Load identity
    let identity = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    // Build signer
    let signer = build_signer(ctx);

    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: Some(new_expires_at),
        note: None,
    };

    // Create new attestation with updated expiry
    let new_attestation = create_signed_attestation(
        now,
        &current.rid.to_string(),
        &identity.controller_did,
        &config.device_did,
        current.device_public_key.as_bytes(),
        current.payload.clone(),
        &meta,
        &signer,
        ctx.passphrase_provider.as_ref(),
        Some(&config.identity_key_alias),
        config.device_key_alias.as_ref(),
        vec![],
        None,
        None,
    )
    .map_err(DeviceError::AttestationError)?;

    // We are the signer, so mark as verified and store
    let verified = VerifiedAttestation::dangerous_from_unchecked(new_attestation);
    ctx.attestation_sink
        .export(&verified)
        .map_err(|e| DeviceError::StorageError(SdkStorageError::Identity(e)))?;

    Ok(DeviceExtensionResult {
        device_did: config.device_did.clone(),
        new_expires_at,
        previous_expires_at,
    })
}
