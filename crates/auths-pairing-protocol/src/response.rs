use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use auths_crypto::{CurveType, TypedSeed};
use auths_keri::KeriPublicKey;

use crate::error::ProtocolError;
use crate::token::PairingToken;

/// A response to a pairing request from the responding device.
///
/// The `curve` field carries the device's signing curve in-band, so verifiers
/// never infer curve from pubkey byte length (a silent-correctness hazard —
/// see `docs/architecture/cryptography.md` → Wire-format Curve Tagging). The
/// serialized value is `"ed25519"` or `"p256"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    pub short_code: String,
    pub device_ephemeral_pubkey: String,
    pub device_signing_pubkey: String,
    /// Curve tag for `device_signing_pubkey` / `signature`. Absent → defaults to `P256`
    /// per the approved Wire-format Curve Tagging rule.
    #[serde(default)]
    pub curve: CurveTag,
    pub device_did: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// Wire-format curve tag for the pairing response.
///
/// Serializes as lowercase `"ed25519"` / `"p256"`. Defaults to `P256` per the
/// workspace-wide curve default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum CurveTag {
    Ed25519,
    #[default]
    P256,
}

impl From<CurveTag> for CurveType {
    fn from(tag: CurveTag) -> Self {
        match tag {
            CurveTag::Ed25519 => CurveType::Ed25519,
            CurveTag::P256 => CurveType::P256,
        }
    }
}

impl From<CurveType> for CurveTag {
    fn from(curve: CurveType) -> Self {
        match curve {
            CurveType::Ed25519 => CurveTag::Ed25519,
            CurveType::P256 => CurveTag::P256,
        }
    }
}

impl PairingResponse {
    /// Create a new pairing response (responder side).
    ///
    /// The device's curve flows through the typed seed — no byte-length guessing.
    /// The emitted `curve` field records the signer's curve so verifiers read it
    /// off the wire instead of inferring from pubkey length.
    ///
    /// Args:
    /// * `now` - Current time for expiry checking
    /// * `token` - The pairing token from the initiating device
    /// * `device_seed` - Typed signing seed (curve carried in-band)
    /// * `device_pubkey` - The responding device's public key (length matches curve)
    /// * `device_did` - The responding device's DID string
    /// * `device_name` - Optional friendly name for the device
    pub fn create(
        now: DateTime<Utc>,
        token: &PairingToken,
        device_seed: &TypedSeed,
        device_pubkey: &[u8],
        device_did: String,
        device_name: Option<String>,
    ) -> Result<(Self, Zeroizing<[u8; 32]>), ProtocolError> {
        if token.is_expired(now) {
            return Err(ProtocolError::Expired);
        }

        let expected_len = device_seed.curve().public_key_len();
        if device_pubkey.len() != expected_len {
            return Err(ProtocolError::KeyExchangeFailed(format!(
                "device_pubkey length {} does not match {} (expected {} bytes)",
                device_pubkey.len(),
                device_seed.curve(),
                expected_len,
            )));
        }

        let device_ecdh_secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let device_ecdh_public = device_ecdh_secret.public_key();

        let initiator_ecdh_bytes = token.ephemeral_pubkey_bytes()?;
        let initiator_pk =
            p256::PublicKey::from_sec1_bytes(&initiator_ecdh_bytes).map_err(|_| {
                ProtocolError::KeyExchangeFailed(
                    "Invalid initiator P-256 ephemeral pubkey (SEC1 decode failed)".to_string(),
                )
            })?;

        let shared = device_ecdh_secret.diffie_hellman(&initiator_pk);
        let shared_bytes: [u8; 32] =
            shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| {
                    ProtocolError::KeyExchangeFailed("Shared secret not 32 bytes".to_string())
                })?;
        let shared_secret = Zeroizing::new(shared_bytes);

        let device_signing_pubkey = URL_SAFE_NO_PAD.encode(device_pubkey);
        let device_ecdh_pubkey_bytes = device_ecdh_public.to_encoded_point(true);
        let device_ephemeral_pubkey_str =
            URL_SAFE_NO_PAD.encode(device_ecdh_pubkey_bytes.as_bytes());

        let mut message = Vec::new();
        message.extend_from_slice(token.session_id.as_bytes());
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_ecdh_bytes);
        message.extend_from_slice(device_ecdh_pubkey_bytes.as_bytes());

        let sig_bytes = typed_sign_sync(device_seed, &message)?;
        let signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let response = PairingResponse {
            short_code: token.short_code.clone(),
            device_ephemeral_pubkey: device_ephemeral_pubkey_str,
            device_signing_pubkey,
            curve: device_seed.curve().into(),
            device_did,
            signature,
            device_name,
        };

        Ok((response, shared_secret))
    }

    /// Verify the response's signature using the curve tag carried on the wire.
    ///
    /// Curve dispatch reads `self.curve` directly — never inferred from pubkey
    /// byte length. See `docs/architecture/cryptography.md` → Wire-format Curve
    /// Tagging.
    pub fn verify(&self, now: DateTime<Utc>, token: &PairingToken) -> Result<(), ProtocolError> {
        if token.is_expired(now) {
            return Err(ProtocolError::Expired);
        }

        let initiator_ecdh_bytes = token.ephemeral_pubkey_bytes()?;
        let device_ecdh_bytes = self.device_ephemeral_pubkey_bytes()?;
        let device_signing_bytes = self.device_signing_pubkey_bytes()?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        let mut message = Vec::new();
        message.extend_from_slice(token.session_id.as_bytes());
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_ecdh_bytes);
        message.extend_from_slice(&device_ecdh_bytes);

        let key = build_keri_public_key(self.curve.into(), &device_signing_bytes)?;
        key.verify_signature(&message, &signature_bytes)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    /// Decode the device's ephemeral P-256 ECDH public key from base64url.
    pub fn device_ephemeral_pubkey_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        URL_SAFE_NO_PAD
            .decode(&self.device_ephemeral_pubkey)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn device_signing_pubkey_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        URL_SAFE_NO_PAD
            .decode(&self.device_signing_pubkey)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

/// Build a typed `KeriPublicKey` from a curve tag + raw bytes. Rejects
/// length/curve mismatches — this is the curve-aware replacement for
/// `match bytes.len() { 32 => …, 33 => … }` at the pairing wire boundary.
fn build_keri_public_key(curve: CurveType, bytes: &[u8]) -> Result<KeriPublicKey, ProtocolError> {
    match curve {
        CurveType::Ed25519 => {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                ProtocolError::KeyExchangeFailed(format!(
                    "Ed25519 pubkey must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
            Ok(KeriPublicKey::Ed25519(arr))
        }
        CurveType::P256 => {
            let arr: [u8; 33] = bytes.try_into().map_err(|_| {
                ProtocolError::KeyExchangeFailed(format!(
                    "P-256 compressed pubkey must be 33 bytes, got {}",
                    bytes.len()
                ))
            })?;
            Ok(KeriPublicKey::P256(arr))
        }
    }
}

/// Sign a message with a typed device seed (sync, no tokio).
///
/// Replaces the earlier `sign_ed25519_sync`: the curve travels with the
/// `TypedSeed`, so the pairing response path is curve-agnostic end-to-end.
fn typed_sign_sync(seed: &TypedSeed, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    auths_crypto::typed_sign(seed, message).map_err(|e| ProtocolError::KeyGenFailed(format!("{e}")))
}

/// Generate a fresh curve-defaulted (P-256) keypair for tests.
///
/// Tests that specifically exercise the Ed25519 branch construct their own
/// `TypedSeed::Ed25519` explicitly.
#[cfg(test)]
fn generate_test_keypair() -> Result<(TypedSeed, Vec<u8>), ProtocolError> {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng as P256Rng;
    use p256::pkcs8::EncodePrivateKey;

    let sk = SigningKey::random(&mut P256Rng);
    #[allow(clippy::disallowed_methods)] // test-only keygen
    let pkcs8 = sk
        .to_pkcs8_der()
        .map_err(|e| ProtocolError::KeyGenFailed(format!("{e}")))?;
    let parsed = auths_crypto::parse_key_material(pkcs8.as_bytes())
        .map_err(|e| ProtocolError::KeyGenFailed(format!("{e}")))?;
    Ok((parsed.seed, parsed.public_key))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::token::PairingToken;

    fn make_token() -> crate::token::PairingSession {
        PairingToken::generate(
            chrono::Utc::now(),
            "did:keri:test123".to_string(),
            "http://localhost:3000".to_string(),
            vec!["sign_commit".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn test_create_and_verify_response_p256() {
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, pubkey) = generate_test_keypair().unwrap();

        let (response, _shared_secret) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:zDnaTest".to_string(),
            Some("Test Device".to_string()),
        )
        .unwrap();

        assert_eq!(response.curve, CurveTag::P256);
        assert!(response.verify(now, &session.token).is_ok());
    }

    #[test]
    fn test_create_and_verify_response_ed25519() {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;

        let now = chrono::Utc::now();
        let session = make_token();
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let parsed = auths_crypto::parse_key_material(pkcs8.as_ref()).unwrap();

        let (response, _shared_secret) = PairingResponse::create(
            now,
            &session.token,
            &parsed.seed,
            &parsed.public_key,
            "did:key:z6MkTest".to_string(),
            Some("Test Device".to_string()),
        )
        .unwrap();

        assert_eq!(response.curve, CurveTag::Ed25519);
        assert!(response.verify(now, &session.token).is_ok());
    }

    #[test]
    fn test_expired_token_rejected() {
        use chrono::Duration;

        let now = chrono::Utc::now();
        let session = PairingToken::generate_with_expiry(
            now,
            "did:keri:test".to_string(),
            "http://localhost:3000".to_string(),
            vec![],
            Duration::seconds(-1),
        )
        .unwrap();
        let (seed, pubkey) = generate_test_keypair().unwrap();

        let result = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:zDnaTest".to_string(),
            None,
        );
        assert!(matches!(result, Err(ProtocolError::Expired)));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, pubkey) = generate_test_keypair().unwrap();

        let (mut response, _) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:zDnaTest".to_string(),
            None,
        )
        .unwrap();

        let mut sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        response.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let result = response.verify(now, &session.token);
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }

    #[test]
    fn test_curve_length_mismatch_rejected() {
        // A P-256 seed paired with a 32-byte pubkey is a length/curve mismatch and
        // must fail at emission time — the curve tag travels with the seed, so the
        // check is local to `create()` and doesn't depend on wire parsing.
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, _good_pubkey) = generate_test_keypair().unwrap();
        let wrong_len_pubkey = vec![0u8; 32];

        let result = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &wrong_len_pubkey,
            "did:key:zDnaTest".to_string(),
            None,
        );
        assert!(matches!(result, Err(ProtocolError::KeyExchangeFailed(_))));
    }

    #[test]
    fn test_shared_secret_matches() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_test_keypair().unwrap();

        let (response, responder_secret) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:zDnaTest".to_string(),
            None,
        )
        .unwrap();

        let device_ecdh_bytes = response.device_ephemeral_pubkey_bytes().unwrap();
        let initiator_secret = session.complete_exchange(&device_ecdh_bytes).unwrap();

        assert_eq!(*initiator_secret, *responder_secret);
    }

    #[test]
    fn test_session_consumed_prevents_reuse() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_test_keypair().unwrap();

        let (response, _) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:zDnaTest".to_string(),
            None,
        )
        .unwrap();

        let device_ecdh_bytes = response.device_ephemeral_pubkey_bytes().unwrap();

        assert!(session.complete_exchange(&device_ecdh_bytes).is_ok());

        let result = session.complete_exchange(&device_ecdh_bytes);
        assert!(matches!(result, Err(ProtocolError::SessionConsumed)));
    }
}
