//! Device pairing orchestration.
//!
//! Business logic for validating pairing codes, verifying sessions,
//! and creating device attestations. All presentation concerns
//! (spinners, passphrase prompts, console output) remain in the CLI.

#[cfg(feature = "lan-pairing")]
pub mod lan;

// Re-exports of pairing types from auths-core for CLI consumption
pub use auths_core::pairing::types::{
    Base64UrlEncoded, CreateSessionRequest, SubmitResponseRequest,
};
pub use auths_core::pairing::{
    PairingResponse, PairingSession, PairingToken, QrOptions, normalize_short_code, render_qr,
};

use auths_core::pairing::SessionStatus;
use auths_core::ports::clock::ClockProvider;
use auths_core::ports::pairing::PairingRelayClient;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::identity::IdentityStorage;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;

use crate::context::AuthsContext;

/// Errors from pairing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    /// The short code format is invalid.
    #[error("invalid short code format: {0}")]
    InvalidShortCode(String),
    /// The session is not in the expected state for pairing.
    #[error("session not available for pairing: {0}")]
    SessionNotAvailable(String),
    /// The pairing session has expired.
    #[error("session expired")]
    SessionExpired,
    /// The ephemeral ECDH key exchange failed.
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),
    /// Creating the device attestation failed.
    #[error("attestation creation failed: {0}")]
    AttestationFailed(String),
    /// The identity could not be loaded from storage.
    #[error("identity not found: {0}")]
    IdentityNotFound(String),
    /// The DID derived from the device public key does not match the claimed DID.
    #[error("device DID mismatch: response says '{response}' but key derives '{derived}'")]
    DidMismatch {
        /// The DID claimed by the responding device.
        response: String,
        /// The DID derived from the device's public key.
        derived: String,
    },
    /// A storage operation failed during pairing.
    #[error("storage error: {0}")]
    StorageError(String),
    /// The selected key is hardware-backed (e.g. Secure Enclave) and cannot
    /// export the raw seed material pairing requires.
    #[error(
        "pairing requires a software-backed key; alias '{alias}' is hardware-backed and cannot export raw material"
    )]
    HardwareKeyNotExportable {
        /// The key alias whose backend refused to export.
        alias: String,
    },
    /// The LAN pairing daemon could not be constructed.
    #[cfg(feature = "lan-pairing")]
    #[error("pairing daemon error: {0}")]
    DaemonError(String),
}

/// Parameters for initiating a new pairing session.
///
/// Args:
/// * `controller_did`: DID of the identity initiating the pairing.
/// * `registry`: Registry endpoint URL.
/// * `capabilities`: Capability strings to grant to the paired device.
/// * `expiry_secs`: Session lifetime in seconds.
///
/// Usage:
/// ```ignore
/// let params = PairingSessionParams {
///     controller_did: "did:keri:abc123".into(),
///     registry: "https://registry.auths.dev".into(),
///     capabilities: vec!["sign_commit".into()],
///     expiry_secs: 300,
/// };
/// ```
pub struct PairingSessionParams {
    /// DID of the identity initiating the pairing.
    pub controller_did: String,
    /// Registry endpoint URL.
    pub registry: String,
    /// Capability strings to grant to the paired device.
    pub capabilities: Vec<String>,
    /// Session lifetime in seconds.
    pub expiry_secs: u64,
}

/// The result of building a pairing session request.
///
/// Contains the live session (for ECDH later) and the registration payload
/// to POST to the registry.
///
/// Usage:
/// ```ignore
/// let req = build_pairing_session_request(params)?;
/// client.post(url).json(&req.create_request).send().await?;
/// let shared_secret = req.session.complete_exchange(&device_pubkey)?;
/// ```
pub struct PairingSessionRequest {
    /// The live pairing session with the ephemeral ECDH keypair.
    pub session: auths_core::pairing::PairingSession,
    /// The registration payload to POST to the registry.
    pub create_request: auths_core::pairing::types::CreateSessionRequest,
}

/// Decrypted pairing response payload from the responding device.
///
/// Built by the CLI after completing ECDH and resolving the identity key.
/// Passed to [`complete_pairing_from_response`] for attestation creation.
///
/// Args:
/// * `auths_dir`: Path to the `~/.auths` identity repository.
/// * `device_pubkey`: Ed25519 signing public key bytes (32 bytes).
/// * `device_did`: DID string of the responding device.
/// * `device_name`: Optional human-readable device name.
/// * `capabilities`: Capability strings to grant.
/// * `identity_key_alias`: Resolved keychain alias for the identity key.
///
/// Usage:
/// ```ignore
/// let response = DecryptedPairingResponse {
///     auths_dir: auths_dir.to_path_buf(),
///     device_pubkey: pubkey_bytes,
///     device_did: DeviceDID::new_unchecked("did:key:z6Mk..."),
///     device_name: Some("iPhone 15".into()),
///     capabilities: vec!["sign_commit".into()],
///     identity_key_alias: "main".into(),
/// };
/// ```
pub struct DecryptedPairingResponse {
    /// Path to the `~/.auths` identity repository.
    pub auths_dir: PathBuf,
    /// Signing public key bytes (32 bytes Ed25519, 33 bytes P-256 compressed).
    pub device_pubkey: Vec<u8>,
    /// Curve of `device_pubkey`. Carried in-band so downstream code never
    /// re-derives curve from byte length.
    pub curve: auths_crypto::CurveType,
    /// DID of the responding device.
    pub device_did: DeviceDID,
    /// Optional human-readable device name.
    pub device_name: Option<String>,
    /// Capability strings to grant.
    pub capabilities: Vec<String>,
    /// Resolved keychain alias for the identity key.
    pub identity_key_alias: KeyAlias,
}

/// Outcome of a completed pairing operation.
///
/// Usage:
/// ```ignore
/// match result {
///     PairingCompletionResult::Success { device_did, .. } => println!("Paired {}", device_did),
///     PairingCompletionResult::Fallback { error, .. } => {
///         eprintln!("Attestation failed: {}", error);
///         save_device_info(auths_dir, &raw_response)?;
///     }
/// }
/// ```
pub enum PairingCompletionResult {
    /// Pairing completed successfully with a signed attestation.
    Success {
        /// The DID of the paired device.
        device_did: DeviceDID,
        /// Optional human-readable name of the paired device.
        device_name: Option<String>,
    },
    /// Attestation creation failed; caller should fall back to raw device info storage.
    Fallback {
        /// The DID of the device that could not be fully attested.
        device_did: DeviceDID,
        /// Optional human-readable name of the device.
        device_name: Option<String>,
        /// The error message from the failed attestation attempt.
        error: String,
    },
}

/// Parameters for creating a pairing attestation.
///
/// Args:
/// * `identity_storage`: Pre-initialized identity storage adapter.
/// * `key_storage`: Pre-initialized key storage for signing key access.
/// * `device_pubkey`: The device's Ed25519 public key (32 bytes).
/// * `device_did_str`: The device's DID string.
/// * `capabilities`: List of capability strings to grant.
/// * `identity_key_alias`: The key alias to use for signing.
/// * `passphrase_provider`: Provider for the signing passphrase.
///
/// Usage:
/// ```ignore
/// let attestation = create_pairing_attestation(&params, now)?;
/// ```
pub struct PairingAttestationParams<'a> {
    /// Pre-initialized identity storage adapter.
    pub identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    /// Pre-initialized key storage for signing key access.
    pub key_storage: Arc<dyn KeyStorage + Send + Sync>,
    /// The device's signing public key (32 bytes Ed25519, 33 bytes P-256 compressed).
    pub device_pubkey: &'a [u8],
    /// The signing curve of `device_pubkey`. Carried in-band so the attestation
    /// boundary never infers curve from byte length.
    pub curve: auths_crypto::CurveType,
    /// The device's DID string.
    pub device_did_str: &'a str,
    /// List of capability strings to grant.
    pub capabilities: &'a [String],
    /// The key alias to use for signing.
    pub identity_key_alias: &'a KeyAlias,
    /// Provider for the signing passphrase.
    pub passphrase_provider:
        std::sync::Arc<dyn auths_core::signing::PassphraseProvider + Send + Sync>,
}

/// Validate and normalize a pairing short code.
///
/// Args:
/// * `code`: The raw short code input from the user.
///
/// Usage:
/// ```ignore
/// let normalized = validate_short_code("ABC-123")?;
/// assert_eq!(normalized, "ABC123");
/// ```
pub fn validate_short_code(code: &str) -> Result<String, PairingError> {
    let normalized = normalize_short_code(code);

    if normalized.len() != 6 {
        return Err(PairingError::InvalidShortCode(format!(
            "must be exactly 6 characters (got {})",
            normalized.len()
        )));
    }

    if !normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(PairingError::InvalidShortCode(
            "must contain only alphanumeric characters".to_string(),
        ));
    }

    Ok(normalized)
}

/// Verify that a pairing session is in the correct state for pairing.
///
/// Args:
/// * `status`: The session status from the registry.
///
/// Usage:
/// ```ignore
/// verify_session_status(&session_status)?;
/// ```
pub fn verify_session_status(
    status: &auths_core::pairing::types::SessionStatus,
) -> Result<(), PairingError> {
    use auths_core::pairing::types::SessionStatus;

    match status {
        SessionStatus::Pending => Ok(()),
        SessionStatus::Expired => Err(PairingError::SessionExpired),
        other => Err(PairingError::SessionNotAvailable(format!("{:?}", other))),
    }
}

/// Verify that a derived device DID matches the claimed DID.
///
/// Args:
/// * `device_pubkey`: The device's Ed25519 public key (32 bytes).
/// * `claimed_did`: The DID string claimed by the device.
///
/// Usage:
/// ```ignore
/// verify_device_did(&pubkey_bytes, "did:key:z...")?;
/// ```
pub fn verify_device_did(
    device_pubkey: &[u8],
    curve: auths_crypto::CurveType,
    claimed_did: &str,
) -> Result<(), PairingError> {
    use auths_verifier::types::DeviceDID;

    let derived = DeviceDID::from_public_key(device_pubkey, curve);
    let claimed = DeviceDID::parse(claimed_did).map_err(|_| PairingError::DidMismatch {
        response: claimed_did.to_string(),
        derived: derived.to_string(),
    })?;

    if derived != claimed {
        return Err(PairingError::DidMismatch {
            response: claimed.to_string(),
            derived: derived.to_string(),
        });
    }

    Ok(())
}

/// Create a signed device attestation for a paired device.
///
/// Args:
/// * `params`: Attestation creation parameters.
///
/// Usage:
/// ```ignore
/// let attestation = create_pairing_attestation(&PairingAttestationParams {
///     auths_dir: Path::new("~/.auths"),
///     device_pubkey: &pubkey_bytes,
///     device_did_str: "did:key:z...",
///     capabilities: &["sign_commit".to_string()],
///     identity_key_alias: "main",
///     passphrase_provider: provider,
/// })?;
/// ```
pub fn create_pairing_attestation(
    params: &PairingAttestationParams,
    now: DateTime<Utc>,
) -> Result<auths_verifier::core::Attestation, PairingError> {
    use auths_core::signing::StorageSigner;
    use auths_id::attestation::create::create_signed_attestation;
    use auths_id::identity::helpers::ManagedIdentity;
    use auths_id::storage::git_refs::AttestationMetadata;
    use auths_verifier::Capability;
    use auths_verifier::types::DeviceDID;

    let managed_identity: ManagedIdentity = params
        .identity_storage
        .load_identity()
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;

    let controller_did = managed_identity.controller_did;
    let rid = managed_identity.storage_id;

    let curve = params.curve;
    if params.device_pubkey.len() != curve.public_key_len() {
        return Err(PairingError::AttestationFailed(format!(
            "device pubkey length {} does not match declared curve {} (expected {} bytes)",
            params.device_pubkey.len(),
            curve,
            curve.public_key_len(),
        )));
    }

    verify_device_did(params.device_pubkey, curve, params.device_did_str)?;

    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: None,
        note: Some("Paired via QR".to_string()),
    };

    let device_capabilities: Vec<Capability> = params
        .capabilities
        .iter()
        .map(|s| {
            s.parse::<Capability>()
                .map_err(|e| PairingError::AttestationFailed(format!("invalid capability: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let target_did = DeviceDID::parse(params.device_did_str)
        .map_err(|e| PairingError::AttestationFailed(format!("invalid device DID: {e}")))?;
    let secure_signer = StorageSigner::new(Arc::clone(&params.key_storage));

    let attestation = create_signed_attestation(
        now,
        &rid,
        &controller_did,
        &target_did,
        params.device_pubkey,
        curve,
        None,
        &meta,
        &secure_signer,
        params.passphrase_provider.as_ref(),
        Some(params.identity_key_alias),
        None,
        device_capabilities,
        None,
        None,
        None, // commit_sha
        None,
    )
    .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;

    Ok(attestation)
}

/// Build a pairing session and its registry registration payload.
///
/// Generates a new `PairingSession` with an ephemeral X25519 keypair and
/// constructs the `CreateSessionRequest` ready to POST to the registry.
///
/// Args:
/// * `params`: Session parameters (controller DID, registry, capabilities, expiry).
///
/// Usage:
/// ```ignore
/// let req = build_pairing_session_request(PairingSessionParams {
///     controller_did: "did:keri:abc123".into(),
///     registry: "https://registry.auths.dev".into(),
///     capabilities: vec!["sign_commit".into()],
///     expiry_secs: 300,
/// })?;
/// client.post(&url).json(&req.create_request).send().await?;
/// ```
pub fn build_pairing_session_request(
    now: DateTime<Utc>,
    params: PairingSessionParams,
) -> Result<PairingSessionRequest, PairingError> {
    use auths_core::pairing::PairingToken;
    use auths_core::pairing::types::CreateSessionRequest;

    let expiry = chrono::Duration::seconds(params.expiry_secs as i64);
    let session = PairingToken::generate_with_expiry(
        now,
        params.controller_did,
        params.registry,
        params.capabilities,
        expiry,
    )
    .map_err(|e| PairingError::KeyExchangeFailed(e.to_string()))?;

    let session_id = session.token.session_id.clone();
    let create_request = CreateSessionRequest {
        session_id: session_id.clone(),
        controller_did: session.token.controller_did.clone(),
        ephemeral_pubkey: auths_core::pairing::types::Base64UrlEncoded::from_raw(
            session.token.ephemeral_pubkey.clone(),
        ),
        short_code: session.token.short_code.clone(),
        capabilities: session.token.capabilities.clone(),
        expires_at: session.token.expires_at.timestamp(),
    };

    Ok(PairingSessionRequest {
        session,
        create_request,
    })
}

/// Complete a pairing operation from a decrypted device response.
///
/// Creates and exports a signed device attestation. Returns
/// [`PairingCompletionResult::Success`] on success, or
/// [`PairingCompletionResult::Fallback`] when attestation creation fails
/// so the caller can perform alternative device info storage.
///
/// This function performs no I/O beyond attestation persistence and holds
/// no mutable session state — it is fully testable without a live connection.
///
/// Args:
/// * `response`: Decrypted response payload built by the CLI after ECDH.
/// * `passphrase_provider`: Provider for the identity key passphrase.
///
/// Usage:
/// ```ignore
/// let result = complete_pairing_from_response(decrypted, provider)?;
/// match result {
///     PairingCompletionResult::Success { device_did, .. } => println!("Paired"),
///     PairingCompletionResult::Fallback { error, .. } => {
///         eprintln!("Attestation failed: {}", error);
///     }
/// }
/// ```
pub fn complete_pairing_from_response(
    response: DecryptedPairingResponse,
    identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    attestation_sink: Arc<dyn AttestationSink + Send + Sync>,
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    clock: &dyn ClockProvider,
) -> Result<PairingCompletionResult, PairingError> {
    let now = clock.now();

    let DecryptedPairingResponse {
        device_pubkey,
        curve,
        device_did,
        device_name,
        capabilities,
        identity_key_alias,
        ..
    } = response;

    let attestation_result = {
        let params = PairingAttestationParams {
            identity_storage,
            key_storage,
            device_pubkey: &device_pubkey,
            curve,
            device_did_str: device_did.as_str(),
            capabilities: &capabilities,
            identity_key_alias: &identity_key_alias,
            passphrase_provider,
        };
        create_pairing_attestation(&params, now)
    };

    let attestation = match attestation_result {
        Ok(a) => a,
        Err(e) => {
            return Ok(PairingCompletionResult::Fallback {
                device_did,
                device_name,
                error: e.to_string(),
            });
        }
    };

    attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation.clone()))
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    attestation_sink.sync_index(&attestation);

    Ok(PairingCompletionResult::Success {
        device_did,
        device_name,
    })
}

/// Load device signing material from the local keychain via the context's injected providers.
///
/// Loads the managed identity to find the controller DID, resolves the signing key alias,
/// decrypts the key using the context's passphrase provider, and derives the device DID.
///
/// The passphrase prompt is delegated to `ctx.passphrase_provider` — the CLI sets this
/// to `CliPassphraseProvider` which handles stdin; tests may use a prefilled provider.
///
/// Args:
/// * `ctx`: Runtime context supplying `identity_storage`, `key_storage`, and `passphrase_provider`.
///
/// Usage:
/// ```ignore
/// let material = load_device_signing_material(&ctx)?;
/// join_pairing_session(code, registry, &relay, now, &material, hostname).await?;
/// ```
pub fn load_device_signing_material(
    ctx: &AuthsContext,
) -> Result<DeviceSigningMaterial, PairingError> {
    use auths_core::crypto::signer::decrypt_keypair;
    use auths_id::identity::helpers::ManagedIdentity;

    let managed: ManagedIdentity = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: managed.controller_did is an IdentityDID loaded from IdentityStorage::load_identity(), already validated
    let controller_identity_did = IdentityDID::new_unchecked(managed.controller_did.to_string());
    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&controller_identity_did)
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;

    let key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            PairingError::IdentityNotFound(format!(
                "no signing key found for identity {}",
                managed.controller_did
            ))
        })?;

    if ctx.key_storage.is_hardware_backend() {
        return Err(PairingError::HardwareKeyNotExportable {
            alias: key_alias.to_string(),
        });
    }

    let (_did, _role, encrypted_key) = ctx
        .key_storage
        .load_key(&key_alias)
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    let prompt = format!("Enter passphrase for key '{}': ", key_alias);
    let passphrase = ctx
        .passphrase_provider
        .get_passphrase(&prompt)
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    let pkcs8_bytes = decrypt_keypair(&encrypted_key, passphrase.as_str())
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    let parsed = auths_crypto::parse_key_material(&pkcs8_bytes)
        .map_err(|e| PairingError::KeyExchangeFailed(format!("failed to parse key: {e}")))?;

    let curve = parsed.seed.curve();
    let device_did = DeviceDID::from_public_key(&parsed.public_key, curve);

    Ok(DeviceSigningMaterial {
        seed: parsed.seed,
        public_key: parsed.public_key,
        device_did,
        controller_did: managed.controller_did.to_string(),
    })
}

/// Load the controller DID from a pre-initialized identity storage adapter.
///
/// Args:
/// * `identity_storage`: Pre-initialized identity storage adapter.
///
/// Usage:
/// ```ignore
/// let did = load_controller_did(identity_storage.as_ref())?;
/// ```
pub fn load_controller_did(identity_storage: &dyn IdentityStorage) -> Result<String, PairingError> {
    use auths_id::identity::helpers::ManagedIdentity;

    let managed: ManagedIdentity = identity_storage
        .load_identity()
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;

    Ok(managed.controller_did.into_inner())
}

/// Key material loaded from the local device keychain for use in pairing operations.
///
/// Usage:
/// ```ignore
/// let material = load_device_signing_material(&ctx)?;
/// join_pairing_session(code, registry, &relay, now, &material, hostname).await?;
/// ```
pub struct DeviceSigningMaterial {
    /// Typed signing seed — curve travels with the seed so pairing flows
    /// never need to infer curve from pubkey byte length.
    pub seed: auths_crypto::TypedSeed,
    /// Public key bytes (32 for Ed25519, 33 for P-256 compressed).
    pub public_key: Vec<u8>,
    /// DID of the local device.
    pub device_did: DeviceDID,
    /// DID of the controller identity this device belongs to.
    pub controller_did: String,
}

/// Progress events fired by [`initiate_online_pairing`] so the CLI can update spinners.
///
/// The SDK fires these during the async operation — the callback must not block.
pub enum PairingStatus {
    /// The session was registered; contains the token for QR display and TTL info.
    SessionCreated {
        /// Pairing token (used to render the QR code).
        token: PairingToken,
        /// Session time-to-live in seconds.
        ttl_seconds: u64,
    },
    /// The SDK is now waiting for a device to respond.
    WaitingForApproval,
    /// A device response was received.
    Approved,
}

/// Orchestrate an online pairing session: register, wait for approval, complete attestation.
///
/// Fires `on_status` callbacks as the session progresses so the CLI can update
/// spinners and display QR code output without any knowledge of the HTTP transport.
///
/// Args:
/// * `params`: Session parameters (controller DID, registry, capabilities, expiry).
/// * `relay`: Pairing relay client (HTTP implementation injected by CLI).
/// * `ctx`: Runtime context carrying identity/attestation storage and key material.
/// * `now`: Current time (injected by caller — no `Utc::now()` in SDK).
/// * `on_status`: Optional progress callback; fires `SessionCreated`, `WaitingForApproval`, `Approved`.
///
/// Usage:
/// ```ignore
/// let result = initiate_online_pairing(params, &relay, &ctx, Utc::now(), Some(&on_status)).await?;
/// ```
// INVARIANT: online-pairing is a sequence of relay round-trips that share local
// state (session keys, status events, context references). Splitting at the
// round-trip boundary would force threading 6+ values through sub-helpers with
// no test or correctness benefit. One-line overrun is acceptable.
#[allow(clippy::too_many_lines)]
pub async fn initiate_online_pairing<R: PairingRelayClient>(
    params: PairingSessionParams,
    relay: &R,
    ctx: &AuthsContext,
    now: DateTime<Utc>,
    on_status: Option<&(dyn Fn(PairingStatus) + Send + Sync)>,
) -> Result<PairingCompletionResult, PairingError> {
    let registry = params.registry.clone();
    let expiry = std::time::Duration::from_secs(params.expiry_secs);

    let session_req = build_pairing_session_request(now, params)?;
    let mut session = session_req.session;
    let create_request = session_req.create_request;
    let session_id = create_request.session_id.clone();

    let created = relay
        .create_session(&registry, &create_request)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    if let Some(cb) = on_status {
        cb(PairingStatus::SessionCreated {
            token: session.token.clone(),
            ttl_seconds: created.ttl_seconds,
        });
    }

    if let Some(cb) = on_status {
        cb(PairingStatus::WaitingForApproval);
    }

    let session_state = relay
        .wait_for_update(&registry, &session_id, expiry)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    let state = match session_state {
        None => return Err(PairingError::SessionExpired),
        Some(s) => s,
    };

    match state.status {
        SessionStatus::Responded => {}
        SessionStatus::Cancelled => {
            return Err(PairingError::SessionNotAvailable("cancelled".into()));
        }
        SessionStatus::Expired => return Err(PairingError::SessionExpired),
        other => return Err(PairingError::SessionNotAvailable(format!("{other:?}"))),
    }

    let response = state.response.ok_or_else(|| {
        PairingError::StorageError(
            "server returned Responded status but no response payload".into(),
        )
    })?;

    if let Some(cb) = on_status {
        cb(PairingStatus::Approved);
    }

    let device_ecdh_bytes: Vec<u8> = response
        .device_ephemeral_pubkey
        .decode()
        .map_err(|e| PairingError::KeyExchangeFailed(format!("invalid ephemeral pubkey: {e}")))?;

    let device_signing_bytes = response
        .device_signing_pubkey
        .decode()
        .map_err(|e| PairingError::KeyExchangeFailed(format!("invalid signing pubkey: {e}")))?;

    let signature_bytes = response
        .signature
        .decode()
        .map_err(|e| PairingError::KeyExchangeFailed(format!("invalid signature: {e}")))?;

    let curve: auths_crypto::CurveType = response.curve.into();
    session
        .verify_response(
            &device_signing_bytes,
            &device_ecdh_bytes,
            &signature_bytes,
            curve,
        )
        .map_err(|e| PairingError::KeyExchangeFailed(e.to_string()))?;

    let _shared_secret = session
        .complete_exchange(&device_ecdh_bytes)
        .map_err(|e| PairingError::KeyExchangeFailed(e.to_string()))?;

    let controller_did = load_controller_did(ctx.identity_storage.as_ref())?;
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: controller_did comes from load_controller_did() which returns into_inner() of a validated IdentityDID from storage
    let controller_identity_did = IdentityDID::new_unchecked(controller_did.clone());
    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&controller_identity_did)
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;
    let identity_key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            PairingError::IdentityNotFound(format!("no signing key found for {controller_did}"))
        })?;

    let decrypted = DecryptedPairingResponse {
        auths_dir: PathBuf::new(),
        device_pubkey: device_signing_bytes,
        curve,
        #[allow(clippy::disallowed_methods)] // INVARIANT: response.device_did was verified by session.verify_response() which validated the signature against the device's signing key
        device_did: DeviceDID::new_unchecked(response.device_did.to_string()),
        device_name: response.device_name.clone(),
        capabilities: session.token.capabilities.clone(),
        identity_key_alias,
    };

    complete_pairing_from_response(
        decrypted,
        Arc::clone(&ctx.identity_storage),
        Arc::clone(&ctx.attestation_sink),
        Arc::clone(&ctx.key_storage),
        Arc::clone(&ctx.passphrase_provider),
        ctx.clock.as_ref(),
    )
}

/// Orchestrate joining a pairing session: lookup by code, create ECDH response, submit.
///
/// The CLI retains passphrase prompting and key loading (see `DeviceSigningMaterial`).
/// This function contains only the protocol logic: code validation, session lookup,
/// ECDH response creation, and submission.
///
/// Args:
/// * `code`: Short code entered by the user (normalized internally).
/// * `registry_url`: Pairing relay server URL.
/// * `relay`: Pairing relay client.
/// * `now`: Current time (injected by caller).
/// * `material`: Decrypted device signing material loaded by the CLI.
/// * `device_name`: Optional friendly name to include in the response.
///
/// Usage:
/// ```ignore
/// let result = join_pairing_session(code, registry, &relay, now, &material, hostname).await?;
/// ```
pub async fn join_pairing_session<R: PairingRelayClient>(
    code: &str,
    registry_url: &str,
    relay: &R,
    now: DateTime<Utc>,
    material: &DeviceSigningMaterial,
    device_name: Option<String>,
) -> Result<PairingCompletionResult, PairingError> {
    let normalized = validate_short_code(code)?;

    let session_data = relay
        .lookup_by_code(registry_url, &normalized)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    verify_session_status(&session_data.status)?;

    let token_data = session_data
        .token
        .ok_or_else(|| PairingError::StorageError("session has no token data".into()))?;

    let token = PairingToken {
        controller_did: token_data.controller_did.clone(),
        endpoint: registry_url.to_string(),
        short_code: normalized.clone(),
        session_id: session_data.session_id.clone(),
        ephemeral_pubkey: token_data.ephemeral_pubkey.to_string(),
        expires_at: chrono::DateTime::from_timestamp(token_data.expires_at, 0).unwrap_or(now),
        capabilities: token_data.capabilities.clone(),
    };

    if token.is_expired(now) {
        return Err(PairingError::SessionExpired);
    }

    let (pairing_response, _shared_secret) = PairingResponse::create(
        now,
        &token,
        &material.seed,
        &material.public_key,
        material.device_did.to_string(),
        device_name,
    )
    .map_err(|e| PairingError::KeyExchangeFailed(e.to_string()))?;

    let submit_req = SubmitResponseRequest {
        device_ephemeral_pubkey: Base64UrlEncoded::from_raw(
            pairing_response.device_ephemeral_pubkey,
        ),
        device_signing_pubkey: Base64UrlEncoded::from_raw(pairing_response.device_signing_pubkey),
        curve: pairing_response.curve,
        device_did: pairing_response.device_did.clone(),
        signature: Base64UrlEncoded::from_raw(pairing_response.signature),
        device_name: pairing_response.device_name,
    };

    relay
        .submit_response(registry_url, &session_data.session_id, &submit_req)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    Ok(PairingCompletionResult::Success {
        device_did: DeviceDID::parse(&pairing_response.device_did).map_err(|e| {
            PairingError::AttestationFailed(format!("invalid device DID in response: {e}"))
        })?,
        device_name: None,
    })
}
