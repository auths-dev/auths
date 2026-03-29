use std::convert::TryInto;
use std::sync::Arc;

use auths_core::ports::clock::ClockProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::attestation::export::AttestationSink;
use auths_id::attestation::group::AttestationGroup;
use auths_id::attestation::revoke::create_signed_revocation;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::identity::IdentityStorage;
use auths_verifier::core::{Capability, Ed25519PublicKey, ResourceId};
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::domains::device::error::{DeviceError, DeviceExtensionError};
use crate::domains::device::types::{
    DeviceExtensionConfig, DeviceExtensionResult, DeviceLinkConfig, DeviceLinkResult,
};

struct AttestationParams {
    identity_did: IdentityDID,
    device_did: DeviceDID,
    device_public_key: Vec<u8>,
    payload: Option<serde_json::Value>,
    meta: AttestationMetadata,
    capabilities: Vec<Capability>,
    identity_alias: KeyAlias,
    device_alias: Option<KeyAlias>,
}

fn build_attestation_params(
    config: &DeviceLinkConfig,
    identity_did: IdentityDID,
    device_did: DeviceDID,
    device_public_key: Vec<u8>,
    now: DateTime<Utc>,
) -> AttestationParams {
    AttestationParams {
        identity_did,
        device_did,
        device_public_key,
        payload: config.payload.clone(),
        meta: AttestationMetadata {
            timestamp: Some(now),
            expires_at: config
                .expires_in
                .map(|s| now + chrono::Duration::seconds(s as i64)),
            note: config.note.clone(),
        },
        capabilities: config.capabilities.clone(),
        identity_alias: config.identity_key_alias.clone(),
        device_alias: config.device_key_alias.clone(),
    }
}

/// Links a new device to an existing identity by creating a signed attestation.
///
/// Args:
/// * `config`: Device link parameters (identity alias, capabilities, etc.).
/// * `ctx`: Runtime context providing storage adapters, key material, and passphrase provider.
/// * `clock`: Clock provider for timestamp generation.
///
/// Usage:
/// ```ignore
/// let result = link_device(config, &ctx, &SystemClock)?;
/// ```
pub fn link_device(
    config: DeviceLinkConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceLinkResult, DeviceError> {
    let now = clock.now();
    let identity = load_identity(ctx.identity_storage.as_ref())?;
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let (device_did, pk_bytes) = extract_device_key(
        &config,
        ctx.key_storage.as_ref(),
        ctx.passphrase_provider.as_ref(),
    )?;
    let params = build_attestation_params(
        &config,
        identity.controller_did,
        device_did.clone(),
        pk_bytes,
        now,
    );
    let attestation_rid = sign_and_persist_attestation(
        now,
        &params,
        &identity.storage_id,
        &signer,
        ctx.passphrase_provider.as_ref(),
        ctx.attestation_sink.as_ref(),
    )?;

    Ok(DeviceLinkResult {
        device_did,
        attestation_id: ResourceId::new(attestation_rid),
    })
}

/// Revokes a device's attestation by creating a signed revocation record.
///
/// Args:
/// * `device_did`: The DID of the device to revoke.
/// * `identity_key_alias`: Keychain alias for the identity key that will sign the revocation.
/// * `ctx`: Runtime context providing storage adapters, key material, and passphrase provider.
/// * `note`: Optional reason for revocation.
/// * `clock`: Clock provider for timestamp generation.
///
/// Usage:
/// ```ignore
/// revoke_device("did:key:z6Mk...", "my-identity", &ctx, Some("Lost laptop"), &clock)?;
/// ```
pub fn revoke_device(
    device_did: &str,
    identity_key_alias: &KeyAlias,
    ctx: &AuthsContext,
    note: Option<String>,
    clock: &dyn ClockProvider,
) -> Result<(), DeviceError> {
    let now = clock.now();
    let identity = load_identity(ctx.identity_storage.as_ref())?;
    let device_pk = find_device_public_key(ctx.attestation_source.as_ref(), device_did)?;
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));

    let target_did = DeviceDID::from_ed25519(device_pk.as_bytes());

    let revocation = create_signed_revocation(
        &identity.storage_id,
        &identity.controller_did,
        &target_did,
        device_pk.as_bytes(),
        note,
        None,
        now,
        &signer,
        ctx.passphrase_provider.as_ref(),
        identity_key_alias,
    )
    .map_err(DeviceError::AttestationError)?;

    ctx.attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(revocation))
        .map_err(|e| DeviceError::StorageError(e.into()))?;

    Ok(())
}

/// Extends the expiration of an existing device authorization by creating a new attestation.
///
/// Loads the latest attestation for the given device DID, verifies it is not revoked,
/// then creates a new signed attestation with the extended expiry and persists it.
/// Capabilities are preserved as empty (`vec![]`) — the extension renews the grant
/// duration only, it does not change what the device is permitted to do.
///
/// Args:
/// * `config`: Extension parameters (device DID, seconds until expiration, key aliases, registry path).
/// * `ctx`: Runtime context providing storage adapters, key material, and passphrase provider.
/// * `clock`: Clock provider for timestamp generation.
///
/// Usage:
/// ```ignore
/// let result = extend_device(config, &ctx, &SystemClock)?;
/// ```
pub fn extend_device(
    config: DeviceExtensionConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceExtensionResult, DeviceExtensionError> {
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));

    let identity = load_identity(ctx.identity_storage.as_ref())
        .map_err(|_| DeviceExtensionError::IdentityNotFound)?;

    let group = AttestationGroup::from_list(
        ctx.attestation_source
            .load_all_attestations()
            .map_err(|e| DeviceExtensionError::StorageError(e.into()))?,
    );

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: config.device_did is a did:key string supplied by the CLI from an existing attestation
    let device_did_obj = DeviceDID::new_unchecked(config.device_did.clone());
    let latest =
        group
            .latest(&device_did_obj)
            .ok_or_else(|| DeviceExtensionError::NoAttestationFound {
                device_did: config.device_did.clone(),
            })?;

    if latest.is_revoked() {
        return Err(DeviceExtensionError::AlreadyRevoked {
            device_did: config.device_did.clone(),
        });
    }

    let previous_expires_at = latest.expires_at;
    let now = clock.now();
    let new_expires_at = now + chrono::Duration::seconds(config.expires_in as i64);

    let meta = AttestationMetadata {
        note: latest.note.clone(),
        timestamp: Some(now),
        expires_at: Some(new_expires_at),
    };

    let extended = create_signed_attestation(
        now,
        &identity.storage_id,
        &identity.controller_did,
        &device_did_obj,
        latest.device_public_key.as_bytes(),
        latest.payload.clone(),
        &meta,
        &signer,
        ctx.passphrase_provider.as_ref(),
        Some(&config.identity_key_alias),
        config.device_key_alias.as_ref(),
        vec![],
        None,
        None,
    )
    .map_err(DeviceExtensionError::AttestationFailed)?;

    ctx.attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(extended.clone()))
        .map_err(|e| DeviceExtensionError::StorageError(e.into()))?;

    ctx.attestation_sink.sync_index(&extended);

    Ok(DeviceExtensionResult {
        #[allow(clippy::disallowed_methods)] // INVARIANT: config.device_did was already validated above when constructing device_did_obj
        device_did: DeviceDID::new_unchecked(config.device_did),
        new_expires_at,
        previous_expires_at,
    })
}

struct LoadedIdentity {
    controller_did: IdentityDID,
    storage_id: String,
}

fn load_identity(identity_storage: &dyn IdentityStorage) -> Result<LoadedIdentity, DeviceError> {
    let managed = identity_storage
        .load_identity()
        .map_err(|e| DeviceError::IdentityNotFound {
            did: format!("identity load failed: {e}"),
        })?;
    Ok(LoadedIdentity {
        controller_did: managed.controller_did,
        storage_id: managed.storage_id,
    })
}

fn extract_device_key(
    config: &DeviceLinkConfig,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<(DeviceDID, Vec<u8>), DeviceError> {
    let alias = config
        .device_key_alias
        .as_ref()
        .unwrap_or(&config.identity_key_alias);

    let pk_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        alias,
        passphrase_provider,
    )
    .map_err(DeviceError::CryptoError)?;

    let device_did = DeviceDID::from_ed25519(pk_bytes.as_slice().try_into().map_err(|_| {
        DeviceError::CryptoError(auths_core::AgentError::InvalidInput(
            "public key is not 32 bytes".into(),
        ))
    })?);

    if let Some(ref expected) = config.device_did
        && expected != &device_did.to_string()
    {
        return Err(DeviceError::DeviceDidMismatch {
            expected: expected.clone(),
            actual: device_did.to_string(),
        });
    }

    Ok((device_did, pk_bytes))
}

fn sign_and_persist_attestation(
    now: DateTime<Utc>,
    params: &AttestationParams,
    rid: &str,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    attestation_sink: &dyn AttestationSink,
) -> Result<String, DeviceError> {
    let attestation = create_signed_attestation(
        now,
        rid,
        &params.identity_did,
        &params.device_did,
        &params.device_public_key,
        params.payload.clone(),
        &params.meta,
        signer,
        passphrase_provider,
        Some(&params.identity_alias),
        params.device_alias.as_ref(),
        params.capabilities.clone(),
        None,
        None,
    )
    .map_err(DeviceError::AttestationError)?;

    let attestation_rid = attestation.rid.to_string();

    attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
        .map_err(|e| DeviceError::StorageError(e.into()))?;

    Ok(attestation_rid)
}

fn find_device_public_key(
    attestation_source: &dyn AttestationSource,
    device_did: &str,
) -> Result<Ed25519PublicKey, DeviceError> {
    let attestations = attestation_source
        .load_all_attestations()
        .map_err(|e| DeviceError::StorageError(e.into()))?;

    for att in &attestations {
        if att.subject.as_str() == device_did {
            return Ok(att.device_public_key);
        }
    }

    Err(DeviceError::DeviceNotFound {
        did: device_did.to_string(),
    })
}
