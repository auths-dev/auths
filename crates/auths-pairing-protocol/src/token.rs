use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::error::ProtocolError;

const SHORT_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const SHORT_CODE_LEN: usize = 6;

/// A pairing token for initiating cross-device identity linking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingToken {
    pub controller_did: String,
    pub endpoint: String,
    pub short_code: String,
    pub ephemeral_pubkey: String,
    pub expires_at: DateTime<Utc>,
    pub capabilities: Vec<String>,
}

/// Ephemeral keypair for a pairing session.
///
/// The X25519 secret is consumed once during ECDH key exchange.
/// `EphemeralSecret` is `!Clone + !Serialize` — sessions cannot be persisted.
pub struct PairingSession {
    pub token: PairingToken,
    ephemeral_secret: Option<EphemeralSecret>,
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
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let ephemeral_pubkey = URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes());
        let short_code = generate_short_code()?;

        let token = PairingToken {
            controller_did,
            endpoint,
            short_code,
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
            "auths://pair?d={}&e={}&k={}&sc={}&x={}&c={}",
            self.controller_did,
            endpoint_b64,
            self.ephemeral_pubkey,
            self.short_code,
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
        let mut expires_unix = None;
        let mut caps_str = None;

        for param in rest.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "d" => controller_did = Some(value.to_string()),
                    "e" => endpoint_b64 = Some(value.to_string()),
                    "k" => ephemeral_pubkey = Some(value.to_string()),
                    "sc" => short_code = Some(value.to_string()),
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
            ephemeral_pubkey,
            expires_at,
            capabilities,
        })
    }

    pub fn ephemeral_pubkey_bytes(&self) -> Result<[u8; 32], ProtocolError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.ephemeral_pubkey)
            .map_err(|e| ProtocolError::InvalidUri(format!("Invalid pubkey encoding: {}", e)))?;
        bytes.try_into().map_err(|_| {
            ProtocolError::KeyExchangeFailed("Invalid X25519 pubkey length".to_string())
        })
    }
}

impl PairingSession {
    /// Complete the ECDH exchange with the responder's X25519 public key.
    ///
    /// Consumes the ephemeral secret (one-time use). Returns the 32-byte shared secret.
    pub fn complete_exchange(
        &mut self,
        responder_x25519_pubkey: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
        let secret = self
            .ephemeral_secret
            .take()
            .ok_or(ProtocolError::SessionConsumed)?;

        let responder_pubkey = PublicKey::from(*responder_x25519_pubkey);
        let shared = secret.diffie_hellman(&responder_pubkey);

        Ok(Zeroizing::new(*shared.as_bytes()))
    }

    pub fn ephemeral_pubkey_bytes(&self) -> Result<[u8; 32], ProtocolError> {
        self.token.ephemeral_pubkey_bytes()
    }

    /// Verify a pairing response's Ed25519 signature using `ring` directly.
    pub fn verify_response(
        &self,
        device_ed25519_pubkey: &[u8],
        device_x25519_pubkey: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProtocolError> {
        let initiator_pubkey = self.token.ephemeral_pubkey_bytes()?;

        let mut message = Vec::new();
        message.extend_from_slice(self.token.short_code.as_bytes());
        message.extend_from_slice(&initiator_pubkey);
        message.extend_from_slice(device_x25519_pubkey);

        // curve dispatch via byte length (pairing-boundary ingestion).
        match device_ed25519_pubkey.len() {
            32 => {
                let peer = UnparsedPublicKey::new(&ED25519, device_ed25519_pubkey);
                peer.verify(&message, signature)
                    .map_err(|_| ProtocolError::InvalidSignature)?;
            }
            33 | 65 => {
                auths_crypto::RingCryptoProvider::p256_verify(
                    device_ed25519_pubkey,
                    &message,
                    signature,
                )
                .map_err(|_| ProtocolError::InvalidSignature)?;
            }
            _ => return Err(ProtocolError::InvalidSignature),
        }

        Ok(())
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
        let mut session = make_session();
        let fake_responder_pubkey = [42u8; 32];

        let result = session.complete_exchange(&fake_responder_pubkey);
        assert!(result.is_ok());

        let result = session.complete_exchange(&fake_responder_pubkey);
        assert!(matches!(result, Err(ProtocolError::SessionConsumed)));
    }
}
