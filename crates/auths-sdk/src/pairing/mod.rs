//! Device pairing orchestration.
//!
//! Business logic for validating pairing codes, verifying sessions,
//! and creating device attestations. All presentation concerns
//! (spinners, passphrase prompts, console output) remain in the CLI.

#[cfg(feature = "lan-pairing")]
pub mod lan;

mod delegation;

pub use delegation::{
    JoinerPending, PairingAnchorResult, anchor_pairing_response, build_delegated_join_response,
    finalize_delegated_join,
};

// Re-exports of pairing types from auths-core for CLI consumption
pub use auths_core::pairing::types::{
    Base64UrlEncoded, CreateSessionRequest, SubmitConfirmationRequest, SubmitResponseRequest,
};
pub use auths_core::pairing::{
    PairingResponse, PairingSession, PairingToken, QrOptions, normalize_short_code, render_qr,
};

use auths_core::pairing::SessionStatus;
use auths_core::ports::pairing::PairingRelayClient;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::storage::identity::IdentityStorage;
use auths_verifier::types::CanonicalDid;
use chrono::{DateTime, Utc};

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

/// Outcome of a completed pairing operation.
///
/// Pairing now anchors a KERI delegation rather than creating an attestation, so
/// there is no attestation-fallback path — a failure is a hard error returned via
/// `Result`, not a soft fallback variant.
///
/// Usage:
/// ```ignore
/// match result {
///     PairingCompletionResult::Success { device_did, .. } => println!("Paired {}", device_did),
/// }
/// ```
pub enum PairingCompletionResult {
    /// Pairing completed: the device is a delegated identifier anchored by the root.
    Success {
        /// The delegated device's `did:keri:`.
        device_did: CanonicalDid,
        /// Optional human-readable name of the paired device.
        device_name: Option<String>,
    },
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
    use auths_verifier::types::CanonicalDid;

    let derived = CanonicalDid::from_public_key_did_key(device_pubkey, curve);
    let claimed = CanonicalDid::parse(claimed_did).map_err(|_| PairingError::DidMismatch {
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
        recovery_target: None,
    };

    Ok(PairingSessionRequest {
        session,
        create_request,
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
    let device_did = CanonicalDid::from_public_key_did_key(&parsed.public_key, curve);

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
    pub device_did: CanonicalDid,
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
        token: Box<PairingToken>,
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
            token: Box::new(session.token.clone()),
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

    // The device's custody of its signing key is now proven (verify_response). Anchor
    // the delegated dip it shipped and relay the root's anchoring ixn back so the
    // device can confirm + persist its delegation.
    let anchor = anchor_pairing_response(
        ctx,
        &response.responder_inception_event,
        response.device_name.clone(),
    )?;

    relay
        .submit_confirmation(&registry, &session_id, &anchor.confirmation)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    Ok(PairingCompletionResult::Success {
        device_did: anchor.device_did,
        device_name: anchor.device_name,
    })
}

/// The outcome of a device recovery: a replacement device was paired and the lost
/// device's delegation revoked.
pub struct RecoveryResult {
    /// The newly-paired delegated device's `did:keri:`.
    pub new_device_did: CanonicalDid,
    /// The new device's friendly name, if it supplied one.
    pub new_device_name: Option<String>,
    /// The old device DID whose delegation was revoked.
    pub revoked_old_did: String,
}

/// Recover from a lost/stolen device: pair a replacement delegated device, then
/// revoke the old device's delegation.
///
/// The replacement is paired and anchored **first**, so the identity is never left
/// with zero usable devices; only then is the old delegation revoked. If pairing
/// succeeds but the revoke fails, this returns an error that names the new device so
/// the caller can report both states — the new device stays paired and the old one
/// can be removed manually.
///
/// Args:
/// * `params`: Session parameters for pairing the replacement device.
/// * `relay`: Pairing relay client.
/// * `ctx`: Runtime context (the root identity's registry + signing key).
/// * `now`: Current time (injected by caller).
/// * `old_device_did`: The `did:keri:` of the device being replaced.
/// * `on_status`: Optional progress callback for the pairing phase.
///
/// Usage:
/// ```ignore
/// let r = recover_device(params, &relay, &ctx, now, &old_did, None).await?;
/// println!("paired {}, revoked {}", r.new_device_did, r.revoked_old_did);
/// ```
pub async fn recover_device<R: PairingRelayClient>(
    params: PairingSessionParams,
    relay: &R,
    ctx: &AuthsContext,
    now: DateTime<Utc>,
    old_device_did: &str,
    on_status: Option<&(dyn Fn(PairingStatus) + Send + Sync)>,
) -> Result<RecoveryResult, PairingError> {
    // Pair the replacement first — the identity must never have zero usable devices.
    let PairingCompletionResult::Success {
        device_did,
        device_name,
    } = initiate_online_pairing(params, relay, ctx, now, on_status).await?;

    // Resolve the root's signing alias to author the revocation.
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: controller_did is a validated IdentityDID from IdentityStorage.
    let root_identity_did = IdentityDID::new_unchecked(managed.controller_did.to_string());
    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&root_identity_did)
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;
    let root_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            PairingError::IdentityNotFound(format!(
                "no signing key found for {}",
                managed.controller_did
            ))
        })?;

    // Only now revoke the old delegation.
    crate::domains::device::remove_device(ctx, &root_alias, old_device_did).map_err(|e| {
        PairingError::StorageError(format!(
            "replacement device {device_did} was paired, but revoking the old device \
             {old_device_did} failed: {e}. Remove it manually with \
             `auths device remove {old_device_did}`."
        ))
    })?;

    Ok(RecoveryResult {
        new_device_did: device_did,
        new_device_name: device_name,
        revoked_old_did: old_device_did.to_string(),
    })
}

/// Orchestrate joining a pairing session as a delegated device.
///
/// The joining device generates its own key, builds + self-signs its `dip`
/// (delegated by the session's `controller_did`), ships it in the response, then
/// waits for the initiator to anchor it. On confirmation it verifies the anchor and
/// persists its own KEL + key. A fresh device needs no pre-existing identity — only
/// an initialized (possibly empty) registry + keychain in `ctx`.
///
/// Args:
/// * `ctx`: The joining device's context (its own registry + keychain + passphrase).
/// * `code`: Short code entered by the user (normalized internally).
/// * `registry_url`: Pairing relay server URL.
/// * `relay`: Pairing relay client.
/// * `now`: Current time (injected by caller).
/// * `curve`: Curve for the new device key.
/// * `device_alias`: Keychain alias to store the new device key under.
/// * `device_name`: Optional friendly name to include in the response.
/// * `confirmation_timeout`: How long to wait for the initiator's anchor.
///
/// Usage:
/// ```ignore
/// let result = join_pairing_session(&ctx, code, registry, &relay, now,
///     CurveType::Ed25519, KeyAlias::new_unchecked("laptop"), hostname, ttl).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn join_pairing_session<R: PairingRelayClient>(
    ctx: &AuthsContext,
    code: &str,
    registry_url: &str,
    relay: &R,
    now: DateTime<Utc>,
    curve: auths_crypto::CurveType,
    device_alias: KeyAlias,
    device_name: Option<String>,
    confirmation_timeout: std::time::Duration,
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
        kem_slot: None,
        daemon_spki_sha256: None,
    };

    if token.is_expired(now) {
        return Err(PairingError::SessionExpired);
    }

    let device_name_out = device_name.clone();
    let (submit_req, pending, _shared_secret) =
        build_delegated_join_response(now, &token, curve, device_alias, device_name)?;

    relay
        .submit_response(registry_url, &session_data.session_id, &submit_req)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    let confirmation = relay
        .wait_for_confirmation(registry_url, &session_data.session_id, confirmation_timeout)
        .await
        .map_err(|e| PairingError::StorageError(e.to_string()))?
        .ok_or(PairingError::SessionExpired)?;

    let device_did = finalize_delegated_join(ctx, pending, &confirmation)?;

    Ok(PairingCompletionResult::Success {
        device_did,
        device_name: device_name_out,
    })
}
