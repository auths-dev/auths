//! Per-pairing subkey chains (`auths-device-subkey-v1`).
//!
//! Privacy mitigation: instead of submitting the stable bootstrap DID
//! pubkey to every controller the phone pairs with (a cross-controller
//! correlation oracle), the phone generates a fresh session-only
//! keypair and asks the bootstrap key to sign a binding message. The
//! daemon observes the per-session subkey on the wire; if the daemon
//! requests proof of continuity, the phone supplies the chain.
//!
//! # Binding message format (v1)
//!
//! ```text
//! binding_message = "auths-device-subkey-v1" || session_id || subkey_pubkey_compressed_sec1
//! ```
//!
//! - The domain separator `auths-device-subkey-v1` pins the chain to
//!   this version; a future v2 lands under `subkey-chain-v2`.
//! - `session_id` is the pairing session id from the URI (variable-
//!   length UTF-8 string; no length-prefix — callers must treat the
//!   session_id as opaque bytes).
//! - `subkey_pubkey` is the 33-byte compressed SEC1 encoding of the
//!   P-256 pubkey currently bound to this session (same form carried
//!   in `SubmitResponseRequest.device_signing_pubkey` for P-256).
//!
//! # On the wire
//!
//! ```json
//! {
//!   "subkey_chain": {
//!     "bootstrap_pubkey": "<base64url-no-pad of 33-byte compressed SEC1>",
//!     "subkey_binding_signature": "<base64url-no-pad of 64-byte raw r||s>"
//!   }
//! }
//! ```
//!
//! Both fields are P-256 (ADRs 002 / 003). No alternate-encoding
//! path — the daemon rejects malformed chains outright.

use serde::{Deserialize, Serialize};

use crate::types::Base64UrlEncoded;

#[cfg(feature = "subkey-chain-v1")]
use p256::ecdsa::signature::Verifier;

/// Domain separator pinned to chain version 1. See
/// [`crate::subkey_chain`] module docs for the binding-message format.
#[cfg(feature = "subkey-chain-v1")]
pub const SUBKEY_CHAIN_V1_DOMAIN: &[u8] = b"auths-device-subkey-v1";

/// Optional chain appended to a `SubmitResponseRequest` proving that
/// the submitted `device_signing_pubkey` was authorized by a more
/// stable bootstrap key held by the same phone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SubkeyChain {
    /// Bootstrap pubkey (P-256 compressed SEC1, 33 B, base64url-no-pad).
    /// Stable across sessions for a given phone; cross-session
    /// revocation pivots on this.
    pub bootstrap_pubkey: Base64UrlEncoded,
    /// Raw r‖s (64 B) P-256 signature by `bootstrap_pubkey` over the
    /// canonical binding message. Base64url-no-pad-encoded.
    pub subkey_binding_signature: Base64UrlEncoded,
}

/// Errors produced by [`verify_subkey_chain`].
#[cfg(feature = "subkey-chain-v1")]
#[derive(Debug, thiserror::Error)]
pub enum SubkeyChainError {
    /// `bootstrap_pubkey` base64url decode failed.
    #[error("bootstrap pubkey decode failed: {0}")]
    BootstrapPubkeyDecode(String),
    /// `bootstrap_pubkey` bytes were the wrong length (expect 33).
    #[error("bootstrap pubkey wrong length: got {0}, expected 33")]
    BootstrapPubkeyLength(usize),
    /// `bootstrap_pubkey` bytes do not parse as a valid P-256 point.
    #[error("bootstrap pubkey not a valid P-256 point: {0}")]
    BootstrapPubkeyInvalid(String),
    /// `subkey_binding_signature` base64url decode failed.
    #[error("binding signature decode failed: {0}")]
    SignatureDecode(String),
    /// Signature bytes were the wrong length (expect 64).
    #[error("binding signature wrong length: got {0}, expected 64")]
    SignatureLength(usize),
    /// The supplied `subkey_pubkey` bytes were not 33 (compressed SEC1).
    #[error("subkey pubkey wrong length: got {0}, expected 33")]
    SubkeyPubkeyLength(usize),
    /// Signature did not verify against the binding message under the
    /// supplied bootstrap pubkey.
    #[error("binding signature does not verify under bootstrap pubkey")]
    VerifyFailed,
    /// Chain references a bootstrap pubkey identical to the subkey
    /// pubkey — self-referential chains are rejected because they do
    /// not prove continuity.
    #[error("chain is self-referential (bootstrap == subkey)")]
    SelfReferential,
}

/// Build the canonical binding message for chain version 1.
///
/// Args:
/// * `session_id`: pairing session id from the URI.
/// * `subkey_pubkey_compressed`: 33-byte compressed SEC1 pubkey bound
///   to the session.
#[cfg(feature = "subkey-chain-v1")]
pub fn build_binding_message_v1(session_id: &str, subkey_pubkey_compressed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SUBKEY_CHAIN_V1_DOMAIN.len() + session_id.len() + subkey_pubkey_compressed.len(),
    );
    out.extend_from_slice(SUBKEY_CHAIN_V1_DOMAIN);
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(subkey_pubkey_compressed);
    out
}

/// Verify a subkey chain and return the bootstrap pubkey's raw bytes
/// (33-byte compressed SEC1) on success.
///
/// Callers record the returned bootstrap pubkey as the session's
/// stable phone identifier for cross-session revocation.
///
/// Args:
/// * `chain`: the chain to verify.
/// * `subkey_pubkey_compressed`: the 33-byte compressed SEC1 pubkey
///   currently bound to the session (from `SubmitResponseRequest.device_signing_pubkey`).
/// * `session_id`: pairing session id.
///
/// Usage:
/// ```ignore
/// let bootstrap = verify_subkey_chain(&chain, &subkey_pk, "sess-abc")?;
/// session.record_bootstrap_pubkey(bootstrap);
/// ```
#[cfg(feature = "subkey-chain-v1")]
pub fn verify_subkey_chain(
    chain: &SubkeyChain,
    subkey_pubkey_compressed: &[u8],
    session_id: &str,
) -> Result<[u8; 33], SubkeyChainError> {
    if subkey_pubkey_compressed.len() != 33 {
        return Err(SubkeyChainError::SubkeyPubkeyLength(
            subkey_pubkey_compressed.len(),
        ));
    }

    let bootstrap_bytes = chain
        .bootstrap_pubkey
        .decode()
        .map_err(|e| SubkeyChainError::BootstrapPubkeyDecode(e.to_string()))?;
    if bootstrap_bytes.len() != 33 {
        return Err(SubkeyChainError::BootstrapPubkeyLength(
            bootstrap_bytes.len(),
        ));
    }
    let mut bootstrap_arr = [0u8; 33];
    bootstrap_arr.copy_from_slice(&bootstrap_bytes);

    if bootstrap_arr == subkey_pubkey_compressed[..] {
        return Err(SubkeyChainError::SelfReferential);
    }

    let bootstrap_vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bootstrap_arr)
        .map_err(|e| SubkeyChainError::BootstrapPubkeyInvalid(e.to_string()))?;

    let sig_bytes = chain
        .subkey_binding_signature
        .decode()
        .map_err(|e| SubkeyChainError::SignatureDecode(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(SubkeyChainError::SignatureLength(sig_bytes.len()));
    }
    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| SubkeyChainError::BootstrapPubkeyInvalid(e.to_string()))?;

    let msg = build_binding_message_v1(session_id, subkey_pubkey_compressed);

    bootstrap_vk
        .verify(&msg, &sig)
        .map_err(|_| SubkeyChainError::VerifyFailed)?;

    Ok(bootstrap_arr)
}

#[cfg(all(test, feature = "subkey-chain-v1"))]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand::rngs::OsRng;

    fn random_keypair() -> (SigningKey, [u8; 33]) {
        let sk = SigningKey::random(&mut OsRng);
        let compressed = sk.verifying_key().to_encoded_point(true);
        let mut arr = [0u8; 33];
        arr.copy_from_slice(compressed.as_bytes());
        (sk, arr)
    }

    fn sign_chain(bootstrap: &SigningKey, session_id: &str, subkey: &[u8; 33]) -> SubkeyChain {
        let msg = build_binding_message_v1(session_id, subkey);
        let sig: Signature = bootstrap.sign(&msg);
        let raw: [u8; 64] = sig.to_bytes().into();
        let bootstrap_compressed = bootstrap.verifying_key().to_encoded_point(true);
        SubkeyChain {
            bootstrap_pubkey: Base64UrlEncoded::from_raw(
                URL_SAFE_NO_PAD.encode(bootstrap_compressed.as_bytes()),
            ),
            subkey_binding_signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode(raw)),
        }
    }

    #[test]
    fn valid_chain_verifies_and_returns_bootstrap_bytes() {
        let (bootstrap_sk, bootstrap_pk) = random_keypair();
        let (_subkey_sk, subkey_pk) = random_keypair();
        let chain = sign_chain(&bootstrap_sk, "sess-abc", &subkey_pk);

        let out =
            verify_subkey_chain(&chain, &subkey_pk, "sess-abc").expect("valid chain must verify");
        assert_eq!(out, bootstrap_pk);
    }

    #[test]
    fn binding_message_format_is_domain_plus_session_plus_subkey() {
        let (_sk, pk) = random_keypair();
        let msg = build_binding_message_v1("sess-XYZ", &pk);
        assert!(msg.starts_with(SUBKEY_CHAIN_V1_DOMAIN));
        assert_eq!(
            &msg[SUBKEY_CHAIN_V1_DOMAIN.len()..SUBKEY_CHAIN_V1_DOMAIN.len() + 8],
            b"sess-XYZ"
        );
        assert_eq!(&msg[SUBKEY_CHAIN_V1_DOMAIN.len() + 8..], &pk[..]);
    }

    #[test]
    fn different_session_id_fails_verification() {
        let (bootstrap_sk, _) = random_keypair();
        let (_, subkey_pk) = random_keypair();
        let chain = sign_chain(&bootstrap_sk, "sess-abc", &subkey_pk);

        let err = verify_subkey_chain(&chain, &subkey_pk, "sess-different").unwrap_err();
        assert!(matches!(err, SubkeyChainError::VerifyFailed));
    }

    #[test]
    fn different_subkey_pubkey_fails_verification() {
        let (bootstrap_sk, _) = random_keypair();
        let (_, subkey_a) = random_keypair();
        let (_, subkey_b) = random_keypair();
        let chain = sign_chain(&bootstrap_sk, "sess-abc", &subkey_a);

        // Chain was signed over subkey_a; presenting subkey_b must fail.
        let err = verify_subkey_chain(&chain, &subkey_b, "sess-abc").unwrap_err();
        assert!(matches!(err, SubkeyChainError::VerifyFailed));
    }

    #[test]
    fn self_referential_chain_rejected() {
        let (sk, pk) = random_keypair();
        // bootstrap == subkey — chain signed over itself.
        let chain = sign_chain(&sk, "sess-abc", &pk);
        let err = verify_subkey_chain(&chain, &pk, "sess-abc").unwrap_err();
        assert!(matches!(err, SubkeyChainError::SelfReferential));
    }

    #[test]
    fn wrong_subkey_length_errors() {
        let (sk, _) = random_keypair();
        let (_, subkey_pk) = random_keypair();
        let chain = sign_chain(&sk, "sess-abc", &subkey_pk);
        let err = verify_subkey_chain(&chain, &[0u8; 32], "sess-abc").unwrap_err();
        assert!(matches!(err, SubkeyChainError::SubkeyPubkeyLength(32)));
    }

    #[test]
    fn wrong_bootstrap_pubkey_length_errors() {
        let (_, subkey_pk) = random_keypair();
        let chain = SubkeyChain {
            bootstrap_pubkey: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 32])),
            subkey_binding_signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 64])),
        };
        let err = verify_subkey_chain(&chain, &subkey_pk, "sess-abc").unwrap_err();
        assert!(matches!(err, SubkeyChainError::BootstrapPubkeyLength(32)));
    }

    #[test]
    fn wrong_signature_length_errors() {
        let (bootstrap_sk, _) = random_keypair();
        let (_, subkey_pk) = random_keypair();
        let bootstrap_compressed = bootstrap_sk.verifying_key().to_encoded_point(true);
        let chain = SubkeyChain {
            bootstrap_pubkey: Base64UrlEncoded::from_raw(
                URL_SAFE_NO_PAD.encode(bootstrap_compressed.as_bytes()),
            ),
            // Truncated signature.
            subkey_binding_signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 32])),
        };
        let err = verify_subkey_chain(&chain, &subkey_pk, "sess-abc").unwrap_err();
        assert!(matches!(err, SubkeyChainError::SignatureLength(32)));
    }
}
