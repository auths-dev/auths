//! Delegation wiring for device pairing (Model D).
//!
//! Both the LAN and online pairing transports converge here. A joining device is
//! made a KERI **delegated identifier** of the initiator's root identity:
//!
//! 1. **Joiner** ([`build_delegated_join_response`]) generates its own key, builds
//!    and self-signs a `dip` (delegated inception) naming the root as delegator,
//!    and signs the pairing ECDH response with that **same** key — so SAS and
//!    `verify_response` prove custody of exactly the key in the dip. The signed dip
//!    rides in `responder_inception_event`.
//! 2. **Initiator** ([`anchor_pairing_response`]) parses the dip, confirms it
//!    delegates to *this* root, anchors it (appends the dip + authors the root's
//!    `ixn`), and relays the `ixn` back over the confirmation channel.
//! 3. **Joiner** ([`finalize_delegated_join`]) checks the `ixn` was authored by the
//!    SAS-confirmed root, runs `validate_delegation`, then persists its own KEL and
//!    key. The root never holds the device key.
//!
//! The relay/daemon is an untrusted byte courier — it neither builds nor inspects
//! these events. Integrity comes from the device's own signature on the dip, the
//! SAS-confirmed channel for the returned `ixn`, and `validate_delegation`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::pairing::types::{SubmitConfirmationRequest, SubmitResponseRequest};
use auths_core::pairing::{
    Base64UrlEncoded, GetConfirmationResponse, PairingResponse, PairingToken,
};
use auths_core::storage::keychain::{KeyAlias, KeyRole, extract_public_key_bytes};
use auths_crypto::CurveType;
use auths_id::keri::delegation::{DeviceDipBundle, anchor_received_dip, build_device_dip};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, parse_did_keri, validate_delegation};
use auths_keri::{
    DipEvent, IxnEvent, SourceSeal, decode_signed_dip as keri_decode_signed_dip,
    encode_signed_dip as keri_encode_signed_dip, serialize_source_seal_couples,
};
use auths_verifier::types::CanonicalDid;

use crate::context::AuthsContext;
use crate::pairing::PairingError;

/// Encode a device-signed dip for the `responder_inception_event` wire field.
///
/// The wire form itself ([`auths_keri::WireSignedDip`]) is shared with every
/// other producer (the mobile FFI's dip assembler); this wrapper only maps the
/// error into [`PairingError`].
fn encode_signed_dip(dip: &DipEvent, attachment: &[u8]) -> Result<String, PairingError> {
    keri_encode_signed_dip(dip, attachment)
        .map_err(|e| PairingError::AttestationFailed(format!("encode dip: {e}")))
}

/// Decode a device-signed dip received in `responder_inception_event`.
fn decode_signed_dip(encoded: &str) -> Result<(DipEvent, Vec<u8>), PairingError> {
    keri_decode_signed_dip(encoded)
        .map_err(|e| PairingError::AttestationFailed(format!("decode dip: {e}")))
}

/// Encode the root's anchoring `ixn` for the confirmation channel.
fn encode_anchor_ixn(ixn: &IxnEvent) -> Result<String, PairingError> {
    let json = serde_json::to_vec(ixn)
        .map_err(|e| PairingError::AttestationFailed(format!("encode anchor ixn: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// Decode the root's anchoring `ixn` received over the confirmation channel.
fn decode_anchor_ixn(encoded: &str) -> Result<IxnEvent, PairingError> {
    let json = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| PairingError::AttestationFailed(format!("decode anchor envelope: {e}")))?;
    serde_json::from_slice(&json)
        .map_err(|e| PairingError::AttestationFailed(format!("decode anchor ixn: {e}")))
}

/// Resolve the root identity's signing prefix, alias, and curve from the context.
fn resolve_root_signing(ctx: &AuthsContext) -> Result<(Prefix, KeyAlias, CurveType), PairingError> {
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| PairingError::IdentityNotFound(e.to_string()))?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str())
        .map_err(|e| PairingError::IdentityNotFound(format!("invalid root did:keri: {e}")))?;

    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&managed.controller_did)
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

    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(|e| PairingError::StorageError(format!("resolve root curve: {e}")))?;

    Ok((root_prefix, root_alias, root_curve))
}

/// Joiner-side pairing state held between submitting the response and confirming
/// the anchor. Carries the freshly-generated dip and the device's keys so they can
/// be persisted once the initiator's anchor is verified.
pub struct JoinerPending {
    bundle: DeviceDipBundle,
    device_alias: KeyAlias,
    root_prefix: Prefix,
}

/// Build the joiner's pairing response carrying a freshly-generated delegated dip.
///
/// Generates the device's own key, builds + self-signs its `dip` (delegator = the
/// token's `controller_did`), and signs the pairing ECDH response with that same
/// key. Returns the wire request (with the dip in `responder_inception_event`), the
/// [`JoinerPending`] to finalize once the initiator confirms the anchor, and the
/// ECDH shared secret (the transport keeps it for the SAS ceremony — the same
/// MITM defence as before).
///
/// Args:
/// * `now`: Current time (injected — no `Utc::now()` in the SDK).
/// * `token`: The pairing token looked up by short code (its `controller_did` is the delegating root).
/// * `curve`: Curve for the new device key.
/// * `device_alias`: Keychain alias to persist the device key under (after confirmation).
/// * `device_name`: Optional friendly name to include in the response.
///
/// Usage:
/// ```ignore
/// let (req, pending, shared) = build_delegated_join_response(now, &token, CurveType::Ed25519,
///     KeyAlias::new_unchecked("laptop"), Some("Laptop".into()))?;
/// relay.submit_response(url, &session_id, &req).await?;
/// ```
pub fn build_delegated_join_response(
    now: DateTime<Utc>,
    token: &PairingToken,
    curve: CurveType,
    device_alias: KeyAlias,
    device_name: Option<String>,
) -> Result<(SubmitResponseRequest, JoinerPending, Zeroizing<[u8; 32]>), PairingError> {
    let root_prefix = parse_did_keri(&token.controller_did).map_err(|e| {
        PairingError::IdentityNotFound(format!("token controller did:keri invalid: {e}"))
    })?;

    let bundle = build_device_dip(&root_prefix, curve)
        .map_err(|e| PairingError::AttestationFailed(format!("build device dip: {e}")))?;

    let parsed = auths_crypto::parse_key_material(bundle.current_pkcs8.as_ref())
        .map_err(|e| PairingError::KeyExchangeFailed(format!("parse device key: {e}")))?;
    let device_didkey = CanonicalDid::from_public_key_did_key(&parsed.public_key, curve);

    let (response, shared_secret) = PairingResponse::create(
        now,
        token,
        &parsed.seed,
        &parsed.public_key,
        device_didkey.to_string(),
        device_name,
    )
    .map_err(|e| PairingError::KeyExchangeFailed(e.to_string()))?;

    let responder_inception_event = encode_signed_dip(&bundle.dip, &bundle.attachment)?;

    let submit_req = SubmitResponseRequest {
        device_ephemeral_pubkey: Base64UrlEncoded::from_raw(response.device_ephemeral_pubkey),
        device_signing_pubkey: Base64UrlEncoded::from_raw(response.device_signing_pubkey),
        curve: response.curve,
        device_did: response.device_did.clone(),
        signature: Base64UrlEncoded::from_raw(response.signature),
        device_name: response.device_name,
        subkey_chain: None,
        initiator_inception_event: String::new(),
        responder_inception_event,
        shared_kel_inception_event: None,
    };

    Ok((
        submit_req,
        JoinerPending {
            bundle,
            device_alias,
            root_prefix,
        },
        shared_secret,
    ))
}

/// Confirm the initiator's anchor and persist the device's KEL and key.
///
/// Verifies the relayed `ixn` was authored by the SAS-confirmed delegating root,
/// runs `validate_delegation`, then appends the device's own `dip` to its registry
/// and stores the device key (current + pre-committed next) under `device_alias`.
/// Returns the device's delegated `did:keri`.
///
/// Args:
/// * `ctx`: The joining device's context (its own fresh registry + keychain).
/// * `pending`: State from [`build_delegated_join_response`].
/// * `confirmation`: The initiator's confirmation payload (carries the anchor `ixn`).
///
/// Usage:
/// ```ignore
/// let device_did = finalize_delegated_join(&ctx, pending, &confirmation)?;
/// ```
pub fn finalize_delegated_join(
    ctx: &AuthsContext,
    pending: JoinerPending,
    confirmation: &GetConfirmationResponse,
) -> Result<CanonicalDid, PairingError> {
    if confirmation.aborted {
        return Err(PairingError::SessionNotAvailable(
            "initiator aborted the pairing (SAS mismatch)".to_string(),
        ));
    }
    let encoded = confirmation
        .encrypted_attestation
        .as_deref()
        .ok_or_else(|| {
            PairingError::StorageError("confirmation carried no anchoring event".to_string())
        })?;
    let anchor_ixn = decode_anchor_ixn(encoded)?;

    if anchor_ixn.i != pending.root_prefix {
        return Err(PairingError::AttestationFailed(format!(
            "anchor authored by {} but expected the delegating root {}",
            anchor_ixn.i, pending.root_prefix
        )));
    }

    let JoinerPending {
        mut bundle,
        device_alias,
        ..
    } = pending;

    // Cooperative double-anchor (joiner half): the relayed `ixn` IS the delegator's
    // anchoring event, so the joiner reconstructs the delegate-side `-G` source seal
    // from it, completing the bilateral binding before validating and persisting.
    let source_seal = SourceSeal {
        s: anchor_ixn.s,
        d: anchor_ixn.d.clone(),
    };
    bundle.dip.source_seal = Some(source_seal.clone());

    validate_delegation(&Event::Dip(bundle.dip.clone()), &[Event::Ixn(anchor_ixn)]).map_err(
        |e| PairingError::AttestationFailed(format!("delegation not anchored by the root: {e}")),
    )?;

    let mut attachment = bundle.attachment.clone();
    attachment.extend_from_slice(
        &serialize_source_seal_couples(&[source_seal])
            .map_err(|e| PairingError::AttestationFailed(format!("encode source seal: {e}")))?,
    );

    // A fresh device's registry may not be initialized yet — this is its first event.
    ctx.registry
        .init_if_needed()
        .map_err(|e| PairingError::StorageError(format!("init device registry: {e}")))?;
    ctx.registry
        .append_signed_event(
            &bundle.device_prefix,
            &Event::Dip(bundle.dip.clone()),
            &attachment,
        )
        .map_err(|e| PairingError::StorageError(format!("persist device dip: {e}")))?;

    let pass = ctx
        .passphrase_provider
        .get_passphrase(&format!(
            "Create passphrase for device key '{}':",
            device_alias
        ))
        .map_err(|e| PairingError::StorageError(e.to_string()))?;
    let enc_cur = encrypt_keypair(bundle.current_pkcs8.as_ref(), &pass)
        .map_err(|e| PairingError::StorageError(e.to_string()))?;
    ctx.key_storage
        .store_key(
            &device_alias,
            &bundle.device_did,
            KeyRole::Primary,
            &enc_cur,
        )
        .map_err(|e| PairingError::StorageError(e.to_string()))?;
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", device_alias));
    let enc_next = encrypt_keypair(bundle.next_pkcs8.as_ref(), &pass)
        .map_err(|e| PairingError::StorageError(e.to_string()))?;
    ctx.key_storage
        .store_key(
            &next_alias,
            &bundle.device_did,
            KeyRole::NextRotation,
            &enc_next,
        )
        .map_err(|e| PairingError::StorageError(e.to_string()))?;

    CanonicalDid::parse(bundle.device_did.as_str())
        .map_err(|e| PairingError::AttestationFailed(format!("device did:keri parse: {e}")))
}

/// The initiator's result of anchoring a joiner's delegated dip.
pub struct PairingAnchorResult {
    /// The now-delegated device's `did:keri:`.
    pub device_did: CanonicalDid,
    /// The device's friendly name, echoed from the response.
    pub device_name: Option<String>,
    /// Confirmation payload to relay back to the joiner (carries the anchor `ixn`).
    pub confirmation: SubmitConfirmationRequest,
}

/// Initiator: anchor a joiner's delegated dip received during pairing.
///
/// Parses the device-signed dip from the pairing response, confirms it delegates to
/// *this* root, anchors it on the root KEL (appends the dip + authors the root's
/// `ixn`), and wraps the `ixn` in a confirmation payload to relay back. The device's
/// signature on the dip is validated by the backend on append — this never needs the
/// device's private key.
///
/// Args:
/// * `ctx`: The root identity's context (registry + root signing key).
/// * `responder_inception_event`: The dip envelope from `SubmitResponseRequest`.
/// * `device_name`: Friendly name echoed from the response (for the result).
///
/// Usage:
/// ```ignore
/// let anchor = anchor_pairing_response(&ctx, &response.responder_inception_event, response.device_name.clone())?;
/// relay.submit_confirmation(url, &session_id, &anchor.confirmation).await?;
/// ```
pub fn anchor_pairing_response(
    ctx: &AuthsContext,
    responder_inception_event: &str,
    device_name: Option<String>,
) -> Result<PairingAnchorResult, PairingError> {
    if responder_inception_event.is_empty() {
        return Err(PairingError::AttestationFailed(
            "pairing response carried no delegated inception event".to_string(),
        ));
    }
    let (dip, attachment) = decode_signed_dip(responder_inception_event)?;
    let (root_prefix, root_alias, root_curve) = resolve_root_signing(ctx)?;

    if dip.di != root_prefix {
        return Err(PairingError::AttestationFailed(format!(
            "device dip delegates to {} but this identity is {}",
            dip.di, root_prefix
        )));
    }

    let (device_did_keri, anchor_ixn) = anchor_received_dip(
        ctx.registry.as_ref(),
        &root_prefix,
        &root_alias,
        root_curve,
        &dip,
        &attachment,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(|e| PairingError::AttestationFailed(format!("anchor delegated device: {e}")))?;

    let confirmation = SubmitConfirmationRequest {
        encrypted_attestation: Some(encode_anchor_ixn(&anchor_ixn)?),
        aborted: false,
    };
    let device_did = CanonicalDid::parse(device_did_keri.as_str())
        .map_err(|e| PairingError::AttestationFailed(format!("device did:keri parse: {e}")))?;

    Ok(PairingAnchorResult {
        device_did,
        device_name,
        confirmation,
    })
}
