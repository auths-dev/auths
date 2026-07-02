//! Generic DSSE signing/verification for arbitrary in-toto Statements.
//!
//! The auths DSSE crypto already exists, but it is reachable only welded to the
//! compliance evidence-pack predicate. This module exposes the same envelope +
//! PAE as a **predicate-agnostic** surface: the caller supplies a complete
//! in-toto Statement (its own `predicateType`), and this signs its DSSE
//! pre-authentication encoding with an agent identity's keychain key. The
//! envelope is byte-compatible with the compliance one, so a verdict statement
//! and a compliance statement verify through the same DSSE path — only the
//! predicate differs.
//!
//! Reuses [`crate::domains::signing::service::dsse_pae`] and the
//! [`DsseEnvelope`] wire type so there is exactly one DSSE envelope shape in the
//! SDK.

use std::sync::Arc;

use auths_core::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_crypto::CurveType;
use auths_keri::KeriPublicKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

use crate::domains::compliance::dsse::{DSSE_INTOTO_PAYLOAD_TYPE, DsseEnvelope, DsseSignature};
use crate::domains::signing::service::dsse_pae;

/// Errors from generic DSSE statement signing/verification.
#[derive(Debug, Error)]
pub enum DsseError {
    /// The caller-supplied statement is not a well-formed in-toto Statement.
    #[error("invalid statement: {0}")]
    InvalidStatement(String),

    /// Signing the DSSE PAE failed (keychain/passphrase).
    #[error("signing failed: {0}")]
    Signing(String),

    /// The envelope or its payload could not be decoded.
    #[error("decode error: {0}")]
    Decode(String),

    /// No signature verified against the pinned key.
    #[error("verification failed: {0}")]
    Verification(String),
}

/// In-band curve tag for a signature (never inferred from byte length).
fn curve_tag(curve: CurveType) -> &'static str {
    match curve {
        CurveType::Ed25519 => "ed25519",
        CurveType::P256 => "p256",
    }
}

/// Parse a curve tag; unknown/missing defaults to P-256 (the workspace default).
fn curve_from_tag(tag: &str) -> CurveType {
    match tag {
        "ed25519" => CurveType::Ed25519,
        _ => CurveType::P256,
    }
}

/// Confirm a JSON value is an in-toto Statement: a `_type` and a `predicateType`
/// string are the defining fields (version-agnostic — accepts Statement v0.1/v1).
fn validate_intoto_statement(value: &serde_json::Value) -> Result<(), DsseError> {
    let has = |k: &str| value.get(k).and_then(|v| v.as_str()).is_some();
    if !has("_type") || !has("predicateType") {
        return Err(DsseError::InvalidStatement(
            "an in-toto Statement must carry string `_type` and `predicateType` fields".into(),
        ));
    }
    Ok(())
}

/// DSSE-sign an in-toto Statement with a keychain identity (e.g. an agent).
///
/// The payload is the caller's complete in-toto Statement JSON; its DSSE PAE is
/// signed under `alias`, and the signature's curve travels in-band. The
/// predicate is entirely the caller's — this is predicate-agnostic.
///
/// Args:
/// * `key_storage` — Keychain holding the signing key.
/// * `passphrase_provider` — Unlocks the key (file-backend keychains).
/// * `keyid` — The signer's `did:keri:`, recorded as the signature `keyid`.
/// * `alias` — Keychain alias of the signing key.
/// * `curve` — The signing key's curve (carried in-band; resolve it, don't guess).
/// * `statement_json` — The complete in-toto Statement to wrap and sign.
///
/// Usage:
/// ```ignore
/// let env = sign_intoto_statement(keychain, &provider, agent_did, &alias, curve, &statement)?;
/// ```
pub fn sign_intoto_statement(
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
    passphrase_provider: &dyn PassphraseProvider,
    keyid: &str,
    alias: &KeyAlias,
    curve: CurveType,
    statement_json: &str,
) -> Result<DsseEnvelope, DsseError> {
    let value: serde_json::Value = serde_json::from_str(statement_json)
        .map_err(|e| DsseError::InvalidStatement(format!("statement is not JSON: {e}")))?;
    validate_intoto_statement(&value)?;

    let payload = statement_json.as_bytes();
    let to_sign = dsse_pae(DSSE_INTOTO_PAYLOAD_TYPE, payload);
    let signer = StorageSigner::new(key_storage);
    let sig = signer
        .sign_with_alias(alias, passphrase_provider, &to_sign)
        .map_err(|e| DsseError::Signing(e.to_string()))?;

    Ok(DsseEnvelope {
        payload_type: DSSE_INTOTO_PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid: keyid.to_string(),
            curve: curve_tag(curve).to_string(),
            sig: BASE64.encode(&sig),
        }],
    })
}

/// Verify a DSSE-wrapped in-toto Statement against a pinned public key, offline.
///
/// Recomputes the PAE over the decoded payload and checks that `pinned_public_key`
/// signed it — the curve travels in-band on each signature, so no curve argument
/// is needed. Returns the parsed in-toto Statement on success; a forged, absent,
/// or wrong-key signature is an `Err`. No network, no keychain.
///
/// Args:
/// * `envelope_json` — The DSSE envelope as produced by [`sign_intoto_statement`].
/// * `pinned_public_key` — The signer's verkey bytes, pinned out of band.
///
/// Usage:
/// ```ignore
/// let statement = verify_intoto_statement(&envelope_json, &agent_pubkey)?;
/// assert_eq!(statement["predicateType"], "https://recurve.dev/verdict/v1");
/// ```
pub fn verify_intoto_statement(
    envelope_json: &str,
    pinned_public_key: &[u8],
) -> Result<serde_json::Value, DsseError> {
    let envelope: DsseEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| DsseError::Decode(format!("envelope is not JSON: {e}")))?;
    let payload = BASE64
        .decode(envelope.payload.as_bytes())
        .map_err(|e| DsseError::Decode(format!("payload base64: {e}")))?;
    let to_verify = dsse_pae(&envelope.payload_type, &payload);

    let verified = envelope.signatures.iter().any(|s| {
        let curve = curve_from_tag(&s.curve);
        let Ok(key) = KeriPublicKey::from_verkey_bytes(pinned_public_key, curve) else {
            return false;
        };
        let Ok(sig) = BASE64.decode(s.sig.as_bytes()) else {
            return false;
        };
        key.verify_signature(&to_verify, &sig).is_ok()
    });

    if !verified {
        return Err(DsseError::Verification(
            "no DSSE signature verified against the pinned key".into(),
        ));
    }

    let statement: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| DsseError::Decode(format!("payload is not JSON: {e}")))?;
    validate_intoto_statement(&statement)?;
    Ok(statement)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_crypto::testing::generate_typed_signer;

    fn intoto_statement(gate: &str) -> String {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "recurve.gate", "digest": {"sha256": "ab".repeat(32)}}],
            "predicateType": "https://recurve.dev/verdict/v1",
            "predicate": {"gate": gate}
        })
        .to_string()
    }

    fn signed_envelope(curve: CurveType, statement: &str) -> (String, Vec<u8>) {
        let signer = generate_typed_signer(curve);
        let payload = statement.as_bytes();
        let pae = dsse_pae(DSSE_INTOTO_PAYLOAD_TYPE, payload);
        let sig = signer.sign(&pae).unwrap();
        let env = DsseEnvelope {
            payload_type: DSSE_INTOTO_PAYLOAD_TYPE.to_string(),
            payload: BASE64.encode(payload),
            signatures: vec![DsseSignature {
                keyid: "did:keri:EAgent".into(),
                curve: curve_tag(curve).to_string(),
                sig: BASE64.encode(&sig),
            }],
        };
        (
            serde_json::to_string(&env).unwrap(),
            signer.public_key().to_vec(),
        )
    }

    #[test]
    fn verify_round_trips_ed25519() {
        let (env, pk) = signed_envelope(CurveType::Ed25519, &intoto_statement("GREEN"));
        let stmt = verify_intoto_statement(&env, &pk).unwrap();
        assert_eq!(stmt["predicateType"], "https://recurve.dev/verdict/v1");
        assert_eq!(stmt["predicate"]["gate"], "GREEN");
    }

    #[test]
    fn verify_round_trips_p256() {
        let (env, pk) = signed_envelope(CurveType::P256, &intoto_statement("GREEN"));
        verify_intoto_statement(&env, &pk).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (env, pk) = signed_envelope(CurveType::Ed25519, &intoto_statement("GREEN"));
        let mut envelope: DsseEnvelope = serde_json::from_str(&env).unwrap();
        // Swap in a different, well-formed statement — the signature no longer binds it.
        envelope.payload = BASE64.encode(intoto_statement("RED").as_bytes());
        let err =
            verify_intoto_statement(&serde_json::to_string(&envelope).unwrap(), &pk).unwrap_err();
        assert!(matches!(err, DsseError::Verification(_)));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (env, _pk) = signed_envelope(CurveType::Ed25519, &intoto_statement("GREEN"));
        let stranger = generate_typed_signer(CurveType::Ed25519)
            .public_key()
            .to_vec();
        let err = verify_intoto_statement(&env, &stranger).unwrap_err();
        assert!(matches!(err, DsseError::Verification(_)));
    }

    #[test]
    fn validate_rejects_non_intoto_statement() {
        // Missing predicateType — not an in-toto Statement.
        let bad = serde_json::json!({"_type": "https://in-toto.io/Statement/v1"});
        assert!(validate_intoto_statement(&bad).is_err());
    }
}
