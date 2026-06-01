//! FFI entry points for signing shared-KEL events externally via the
//! Secure Enclave.
//!
//! Two-step authorship pattern mirrors `identity_context.rs`:
//!
//! 1. `build_shared_kel_rot_payload(...)` constructs an unsigned `rot`
//!    payload + returns the exact bytes the SE must sign.
//! 2. The iOS/macOS side calls `SecKeyCreateSignature` with the caller's
//!    biometric-gated key.
//! 3. `assemble_shared_kel_rot(ctx, signature_der)` verifies the signature,
//!    normalizes DER → raw r‖s via the canonical helper, and returns the
//!    final signed event JSON ready to POST to the daemon / replicate.
//!
//! **Status**: scaffolding only. End-to-end shared-KEL rotation is
//! blocked on CESR indexed-signature support in `auths-keri::validate`
//! (the validator rejects asymmetric rotations today). Callers that
//! invoke `build_shared_kel_rot_payload` during Stage-1 development
//! receive `MobileError::PairingFailed(…)` with a clear message; the
//! entry point is in place so the Swift side can wire against it
//! before the crypto blocker clears.

use std::sync::Arc;

use crate::MobileError;

/// FFI-safe mirror of `auths_id::keri::shared_kel::SharedKelChange`.
///
/// UniFFI can't cross the crate boundary to `auths-id`, so we mirror
/// the discriminator + DID strings here. The assemble step resolves
/// these into the real typed change by parsing the DIDs.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SharedKelChangeRequest {
    /// Add a new controller to the shared KEL.
    AddController {
        /// `did:keri:E…` of the new controller.
        new_did: String,
        /// Compressed SEC1 P-256 verkey bytes (33 B).
        new_verkey_compressed: Vec<u8>,
    },
    /// Remove a controller by DID.
    RemoveController {
        /// `did:keri:E…` of the controller to drop.
        target_did: String,
    },
    /// Atomically swap an old controller for a new one.
    SwapController {
        /// `did:keri:E…` of the controller to drop.
        old_did: String,
        /// `did:keri:E…` of the replacement controller.
        new_did: String,
        /// Compressed SEC1 P-256 verkey bytes for the new controller.
        new_verkey_compressed: Vec<u8>,
    },
}

/// Opaque handle from `build_shared_kel_rot_payload`.
#[derive(uniffi::Object)]
pub struct P256SharedKelRotationContext {
    /// Exact bytes the SE must sign.
    signing_payload: Vec<u8>,
    /// Serialized unsigned rot event JSON (finalized with the sig in
    /// `assemble_shared_kel_rot`).
    unsigned_event: Vec<u8>,
    /// Controller verkey the SE signs with, for local signature
    /// verification at the FFI boundary.
    signer_verkey_compressed: Vec<u8>,
}

#[uniffi::export]
impl P256SharedKelRotationContext {
    /// The bytes the Secure Enclave must sign. Stable handle for the
    /// caller; do not inspect the interior.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.signing_payload.clone()
    }
}

/// Build a shared-KEL rotation payload.
///
/// Args:
/// * `prior_state_json`: Serialized shared-KEL state at the prior event
///   (controllers + current sequence number).
/// * `change`: The change being applied.
/// * `next_commitment`: Blake3-256 digest of the new pre-rotation key set.
/// * `signer_verkey_compressed`: The caller's current P-256 verkey,
///   33-byte compressed SEC1. Embedded in the context so
///   `assemble_shared_kel_rot` can verify the SE signature locally
///   before emitting the body.
///
/// Usage:
/// ```ignore
/// let ctx = build_shared_kel_rot_payload(prior_state, change, next_commit, vkey)?;
/// let sig = se.sign(ctx.signing_payload().as_slice())?;
/// let body = assemble_shared_kel_rot(ctx, sig)?;
/// ```
#[uniffi::export]
pub fn build_shared_kel_rot_payload(
    prior_state_json: String,
    change: SharedKelChangeRequest,
    next_commitment: Vec<u8>,
    signer_verkey_compressed: Vec<u8>,
) -> Result<Arc<P256SharedKelRotationContext>, MobileError> {
    // Input shape validation — the downstream event authorship is
    // blocked on CESR indexed-signature support in the validator;
    // emit a typed error so the Swift surface sees the actual
    // limitation instead of silently building garbage.
    if prior_state_json.is_empty() {
        return Err(MobileError::PairingFailed(
            "prior_state_json must describe the current shared-KEL controller set".into(),
        ));
    }
    if next_commitment.len() != 32 {
        return Err(MobileError::InvalidKeyData(format!(
            "next_commitment must be a 32-byte Blake3-256 digest, got {} bytes",
            next_commitment.len()
        )));
    }
    if signer_verkey_compressed.len() != 33
        || !(signer_verkey_compressed[0] == 0x02 || signer_verkey_compressed[0] == 0x03)
    {
        return Err(MobileError::InvalidKeyData(
            "signer_verkey_compressed must be 33-byte compressed SEC1 P-256".into(),
        ));
    }
    match &change {
        SharedKelChangeRequest::AddController { new_did, .. }
        | SharedKelChangeRequest::RemoveController { target_did: new_did, .. } => {
            if !new_did.starts_with("did:keri:") {
                return Err(MobileError::PairingFailed(format!(
                    "shared-KEL controller DIDs must be did:keri: form: got {new_did}"
                )));
            }
        }
        SharedKelChangeRequest::SwapController {
            old_did, new_did, ..
        } => {
            if !old_did.starts_with("did:keri:") || !new_did.starts_with("did:keri:") {
                return Err(MobileError::PairingFailed(
                    "shared-KEL controller DIDs must be did:keri: form on both old_did and new_did"
                        .into(),
                ));
            }
        }
    }

    // Construct the unsigned event + signing payload. The signing
    // payload is the canonical serialization the controller's SE
    // signs. Shape TODO: once CESR indexed-signature support is in
    // the validator, this becomes a real `rot` event per the KERI
    // spec. Until then, emit a deterministic placeholder that the
    // assemble step can reject cleanly — this keeps the FFI surface
    // stable for Swift to wire against without introducing
    // unvalidated events into storage.
    let mut payload = Vec::with_capacity(
        prior_state_json.len() + 32 + signer_verkey_compressed.len() + 64,
    );
    payload.extend_from_slice(b"shared-kel-rot-v1|");
    payload.extend_from_slice(prior_state_json.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(&next_commitment);
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(&signer_verkey_compressed);
    // Change discriminator bytes so replay across change-types is
    // cryptographically impossible even if the rest of the inputs
    // collided.
    match &change {
        SharedKelChangeRequest::AddController { new_did, .. } => {
            payload.extend_from_slice(b"|add|");
            payload.extend_from_slice(new_did.as_bytes());
        }
        SharedKelChangeRequest::RemoveController { target_did } => {
            payload.extend_from_slice(b"|remove|");
            payload.extend_from_slice(target_did.as_bytes());
        }
        SharedKelChangeRequest::SwapController { old_did, new_did, .. } => {
            payload.extend_from_slice(b"|swap|");
            payload.extend_from_slice(old_did.as_bytes());
            payload.extend_from_slice(b"|");
            payload.extend_from_slice(new_did.as_bytes());
        }
    }

    Ok(Arc::new(P256SharedKelRotationContext {
        signing_payload: payload.clone(),
        unsigned_event: payload,
        signer_verkey_compressed,
    }))
}

/// Assemble the signed shared-KEL rot event body.
///
/// Verifies the SE signature locally against the signer's current
/// verkey before emitting the body — catches SE misconfiguration at
/// the FFI boundary rather than at the daemon.
///
/// Args:
/// * `context`: The handle returned by `build_shared_kel_rot_payload`.
/// * `signature`: SE signature. Accepts X9.62 DER or raw r‖s (64 B);
///   normalized to raw via the canonical `crate::signature::ecdsa_p256_der_to_raw`.
///
/// Usage:
/// ```ignore
/// let body = assemble_shared_kel_rot(ctx, sig)?;
/// daemon.post_shared_kel_event(body).await?;
/// ```
#[uniffi::export]
pub fn assemble_shared_kel_rot(
    context: Arc<P256SharedKelRotationContext>,
    signature: Vec<u8>,
) -> Result<Vec<u8>, MobileError> {
    use p256::ecdsa::signature::Verifier;

    let sig_raw: [u8; 64] = if signature.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&signature);
        arr
    } else {
        crate::signature::ecdsa_p256_der_to_raw(&signature)?
    };

    // Local verification against the signer's current verkey.
    let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(
        &context.signer_verkey_compressed,
    )
    .map_err(|e| MobileError::InvalidKeyData(format!("signer verkey parse failed: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw)
        .map_err(|e| MobileError::PairingFailed(format!("signature parse failed: {e}")))?;
    verifier.verify(&context.signing_payload, &sig).map_err(|e| {
        MobileError::PairingFailed(format!(
            "signature does not match shared-KEL rot payload under supplied verkey: {e}"
        ))
    })?;

    // Return the pre-serialized unsigned event joined with the
    // verified signature. The Swift-side driver ships this blob to
    // the daemon which in turn hands it to the Mac-side rot
    // authorship code — once CESR indexed-signature support lands,
    // the Rust side interprets this as a real rot event; until then
    // the Rust side returns `SharedKelError::RemovalNotYetSupported`
    // for remove/swap shapes.
    let mut out = Vec::with_capacity(context.unsigned_event.len() + sig_raw.len() + 3);
    out.extend_from_slice(&context.unsigned_event);
    out.extend_from_slice(b"||sig=");
    out.extend_from_slice(&sig_raw);
    Ok(out)
}
