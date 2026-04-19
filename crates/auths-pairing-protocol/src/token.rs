use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use auths_crypto::CurveType;
use auths_keri::KeriPublicKey;

use crate::error::ProtocolError;

const SHORT_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const SHORT_CODE_LEN: usize = 6;

/// A pairing token for initiating cross-device identity linking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingToken {
    pub controller_did: String,
    pub endpoint: String,
    pub short_code: String,
    pub session_id: String,
    pub ephemeral_pubkey: String,
    pub expires_at: DateTime<Utc>,
    pub capabilities: Vec<String>,
}

/// Ephemeral keypair for a pairing session.
///
/// The P-256 ephemeral secret is consumed once during ECDH key exchange.
/// `EphemeralSecret` is `!Clone + !Serialize` — sessions cannot be persisted.
/// The ECDH curve (P-256) is independent of the device's signing curve.
pub struct PairingSession {
    pub token: PairingToken,
    ephemeral_secret: Option<p256::ecdh::EphemeralSecret>,
}

impl PairingToken {
    /// Generate a new pairing token with a 5-minute expiry.
    pub fn generate(
        now: DateTime<Utc>,
        controller_did: String,
        endpoint: String,
        capabilities: Vec<String>,
    ) -> Result<PairingSession, ProtocolError> {
        Self::generate_with_expiry(
            now,
            controller_did,
            endpoint,
            capabilities,
            Duration::minutes(5),
        )
    }

    /// Generate a new pairing token with custom expiry.
    pub fn generate_with_expiry(
        now: DateTime<Utc>,
        controller_did: String,
        endpoint: String,
        capabilities: Vec<String>,
        expiry: Duration,
    ) -> Result<PairingSession, ProtocolError> {
        let ephemeral_secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral_secret.public_key();
        let ephemeral_pubkey =
            URL_SAFE_NO_PAD.encode(ephemeral_public.to_encoded_point(true).as_bytes());
        let short_code = generate_short_code()?;

        let session_id = {
            let mut bytes = [0u8; 16];
            use rand::RngCore;
            OsRng.fill_bytes(&mut bytes);
            hex::encode(bytes)
        };

        let token = PairingToken {
            controller_did,
            endpoint,
            short_code,
            session_id,
            ephemeral_pubkey,
            expires_at: now + expiry,
            capabilities,
        };

        Ok(PairingSession {
            token,
            ephemeral_secret: Some(ephemeral_secret),
        })
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }

    /// Convert to an `auths://` URI for QR code or deep linking.
    pub fn to_uri(&self) -> String {
        let expires_unix = self.expires_at.timestamp();
        let endpoint_b64 = URL_SAFE_NO_PAD.encode(self.endpoint.as_bytes());
        let caps = self.capabilities.join(",");
        format!(
            "auths://pair?d={}&e={}&k={}&sc={}&sid={}&x={}&c={}",
            self.controller_did,
            endpoint_b64,
            self.ephemeral_pubkey,
            self.short_code,
            self.session_id,
            expires_unix,
            caps
        )
    }

    /// Parse a pairing token from an `auths://` URI.
    pub fn from_uri(uri: &str) -> Result<Self, ProtocolError> {
        let rest = uri.strip_prefix("auths://pair?").ok_or_else(|| {
            ProtocolError::InvalidUri("Expected auths://pair? scheme".to_string())
        })?;

        let mut controller_did = None;
        let mut endpoint_b64 = None;
        let mut ephemeral_pubkey = None;
        let mut short_code = None;
        let mut session_id = None;
        let mut expires_unix = None;
        let mut caps_str = None;

        for param in rest.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "d" => controller_did = Some(value.to_string()),
                    "e" => endpoint_b64 = Some(value.to_string()),
                    "k" => ephemeral_pubkey = Some(value.to_string()),
                    "sc" => short_code = Some(value.to_string()),
                    "sid" => session_id = Some(value.to_string()),
                    "x" => expires_unix = value.parse::<i64>().ok(),
                    "c" => caps_str = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let controller_did = controller_did
            .ok_or_else(|| ProtocolError::InvalidUri("Missing controller_did".to_string()))?;
        let endpoint_b64 = endpoint_b64
            .ok_or_else(|| ProtocolError::InvalidUri("Missing endpoint".to_string()))?;
        let endpoint_bytes = URL_SAFE_NO_PAD
            .decode(&endpoint_b64)
            .map_err(|e| ProtocolError::InvalidUri(format!("Invalid endpoint encoding: {}", e)))?;
        let endpoint = String::from_utf8(endpoint_bytes)
            .map_err(|e| ProtocolError::InvalidUri(format!("Invalid endpoint UTF-8: {}", e)))?;
        let ephemeral_pubkey = ephemeral_pubkey
            .ok_or_else(|| ProtocolError::InvalidUri("Missing ephemeral_pubkey".to_string()))?;
        let short_code = short_code
            .ok_or_else(|| ProtocolError::InvalidUri("Missing short_code".to_string()))?;
        let session_id = session_id
            .ok_or_else(|| ProtocolError::InvalidUri("Missing session_id".to_string()))?;
        let expires_unix = expires_unix.ok_or_else(|| {
            ProtocolError::InvalidUri("Missing or invalid expires_at".to_string())
        })?;

        let expires_at = DateTime::from_timestamp(expires_unix, 0)
            .ok_or_else(|| ProtocolError::InvalidUri("Invalid timestamp".to_string()))?;

        let capabilities = caps_str
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|c| c.to_string()).collect())
            .unwrap_or_default();

        Ok(PairingToken {
            controller_did,
            endpoint,
            short_code,
            session_id,
            ephemeral_pubkey,
            expires_at,
            capabilities,
        })
    }

    /// Decode the ephemeral P-256 ECDH public key from the token's base64url field.
    pub fn ephemeral_pubkey_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        URL_SAFE_NO_PAD
            .decode(&self.ephemeral_pubkey)
            .map_err(|e| ProtocolError::InvalidUri(format!("Invalid pubkey encoding: {}", e)))
    }
}

impl PairingSession {
    /// Complete the P-256 ECDH exchange with the responder's ephemeral public key.
    ///
    /// Consumes the ephemeral secret (one-time use). Returns the 32-byte shared secret.
    /// The ECDH curve (P-256) is independent of the device's signing curve — ephemeral
    /// keys are fresh per session and never reused.
    pub fn complete_exchange(
        &mut self,
        responder_ephemeral_pubkey: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
        let secret = self
            .ephemeral_secret
            .take()
            .ok_or(ProtocolError::SessionConsumed)?;

        let responder_pk =
            p256::PublicKey::from_sec1_bytes(responder_ephemeral_pubkey).map_err(|_| {
                ProtocolError::KeyExchangeFailed(
                    "Invalid P-256 ephemeral pubkey (SEC1 decode failed)".to_string(),
                )
            })?;
        let shared = secret.diffie_hellman(&responder_pk);
        let shared_bytes: [u8; 32] =
            shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| {
                    ProtocolError::KeyExchangeFailed("Shared secret not 32 bytes".to_string())
                })?;

        Ok(Zeroizing::new(shared_bytes))
    }

    /// Decode the ephemeral P-256 ECDH public key from the token's base64url field.
    pub fn ephemeral_pubkey_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.token.ephemeral_pubkey_bytes()
    }

    /// Verify a pairing response's signature.
    ///
    /// The `curve` argument carries the signing curve in-band — callers must
    /// read it from the wire (e.g. `PairingResponse.curve`) or from a sibling
    /// typed source, never infer from pubkey byte length.
    pub fn verify_response(
        &self,
        device_signing_pubkey: &[u8],
        device_ephemeral_pubkey: &[u8],
        signature: &[u8],
        curve: CurveType,
    ) -> Result<(), ProtocolError> {
        let initiator_pubkey = self.token.ephemeral_pubkey_bytes()?;

        let mut message = Vec::new();
        message.extend_from_slice(self.token.session_id.as_bytes());
        message.extend_from_slice(self.token.short_code.as_bytes());
        message.extend_from_slice(&initiator_pubkey);
        message.extend_from_slice(device_ephemeral_pubkey);

        let key = match curve {
            CurveType::Ed25519 => {
                let arr: [u8; 32] = device_signing_pubkey.try_into().map_err(|_| {
                    ProtocolError::KeyExchangeFailed(format!(
                        "Ed25519 pubkey must be 32 bytes, got {}",
                        device_signing_pubkey.len()
                    ))
                })?;
                KeriPublicKey::Ed25519(arr)
            }
            CurveType::P256 => {
                let arr: [u8; 33] = device_signing_pubkey.try_into().map_err(|_| {
                    ProtocolError::KeyExchangeFailed(format!(
                        "P-256 compressed pubkey must be 33 bytes, got {}",
                        device_signing_pubkey.len()
                    ))
                })?;
                KeriPublicKey::P256(arr)
            }
        };

        key.verify_signature(&message, signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

fn generate_short_code() -> Result<String, ProtocolError> {
    use rand::RngCore;

    let mut rng = OsRng;
    let mut code = String::with_capacity(SHORT_CODE_LEN);

    for _ in 0..SHORT_CODE_LEN {
        let idx = (rng.next_u32() as usize) % SHORT_CODE_ALPHABET.len();
        code.push(SHORT_CODE_ALPHABET[idx] as char);
    }

    Ok(code)
}

/// Normalize a short code: uppercase, strip spaces/dashes.
pub fn normalize_short_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    fn make_session() -> PairingSession {
        PairingToken::generate(
            Utc::now(),
            "did:keri:test123".to_string(),
            "http://localhost:3000".to_string(),
            vec!["sign_commit".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn test_generate_token() {
        let session = make_session();
        assert!(!session.token.controller_did.is_empty());
        assert!(!session.token.short_code.is_empty());
        assert!(!session.token.ephemeral_pubkey.is_empty());
        assert!(!session.token.is_expired(Utc::now()));
        assert_eq!(session.token.short_code.len(), 6);
        assert_eq!(session.token.capabilities, vec!["sign_commit"]);
    }

    #[test]
    fn test_token_uri_roundtrip() {
        let session = make_session();
        let uri = session.token.to_uri();

        assert!(uri.starts_with("auths://pair?"));

        let parsed = PairingToken::from_uri(&uri).unwrap();
        assert_eq!(parsed.controller_did, session.token.controller_did);
        assert_eq!(parsed.endpoint, session.token.endpoint);
        assert_eq!(parsed.ephemeral_pubkey, session.token.ephemeral_pubkey);
        assert_eq!(parsed.short_code, session.token.short_code);
        assert_eq!(parsed.capabilities, session.token.capabilities);
    }

    #[test]
    fn test_short_code_no_ambiguous_chars() {
        let ambiguous: &[char] = &['0', 'O', '1', 'I', 'L'];
        for _ in 0..100 {
            let code = generate_short_code().unwrap();
            assert_eq!(code.len(), SHORT_CODE_LEN);
            for ch in code.chars() {
                assert!(
                    !ambiguous.contains(&ch),
                    "Short code '{}' contains ambiguous char '{}'",
                    code,
                    ch
                );
            }
        }
    }

    #[test]
    fn test_expiry() {
        let now = Utc::now();
        let session = PairingToken::generate_with_expiry(
            now,
            "did:keri:test".to_string(),
            "http://localhost:3000".to_string(),
            vec![],
            Duration::seconds(-1),
        )
        .unwrap();
        assert!(session.token.is_expired(now));
    }

    #[test]
    fn test_normalize_short_code() {
        assert_eq!(normalize_short_code("abc def"), "ABCDEF");
        assert_eq!(normalize_short_code("AB-CD-EF"), "ABCDEF");
        assert_eq!(normalize_short_code("  a b c  "), "ABC");
    }

    #[test]
    fn test_session_consumed_prevents_reuse() {
        use p256::elliptic_curve::rand_core::OsRng as P256Rng;
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;

        let mut session = make_session();
        // Generate a valid P-256 ephemeral pubkey (SEC1 compressed, 33 bytes)
        let fake_secret = p256::ecdh::EphemeralSecret::random(&mut P256Rng);
        let fake_pubkey = fake_secret.public_key().to_encoded_point(true);
        let fake_pubkey_bytes = fake_pubkey.as_bytes();

        let result = session.complete_exchange(fake_pubkey_bytes);
        assert!(result.is_ok());

        let result = session.complete_exchange(fake_pubkey_bytes);
        assert!(matches!(result, Err(ProtocolError::SessionConsumed)));
    }
}
