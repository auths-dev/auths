use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use auths_crypto::SecureSeed;

use crate::error::ProtocolError;
use crate::response::PairingResponse;
use crate::sas::{self, TransportKey};
use crate::token::{PairingSession, PairingToken};

/// Result of a successfully completed pairing exchange (initiator side).
pub struct CompletedPairing {
    /// The 32-byte X25519 shared secret (zeroized on drop).
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// The peer's Ed25519 signing public key.
    pub peer_signing_pubkey: Vec<u8>,
    /// The peer's DID string.
    pub peer_did: String,
    /// The pairing response for downstream processing.
    pub response: PairingResponse,
    /// The 8-byte SAS for human verification.
    pub sas: [u8; 8],
    /// Single-use transport encryption key.
    pub transport_key: TransportKey,
    /// The initiator's X25519 ephemeral public key.
    pub initiator_x25519_pub: [u8; 32],
}

/// Result of a successful pairing response (responder side).
pub struct ResponderResult {
    pub response: PairingResponse,
    pub shared_secret: Zeroizing<[u8; 32]>,
    pub sas: [u8; 8],
    pub transport_key: TransportKey,
}

/// Transport-agnostic pairing protocol state machine.
///
/// `EphemeralSecret` from x25519-dalek is `!Clone + !Serialize`, so this
/// state machine is inherently ephemeral — it lives in memory only and
/// cannot be persisted across app restarts.
///
/// Usage:
/// ```ignore
/// // Initiator side:
/// let (protocol, token) = PairingProtocol::initiate(now, controller_did, endpoint, caps)?;
/// let token_bytes = serde_json::to_vec(&token)?;
/// // Send token_bytes to peer over transport (HTTP, BLE, QR, etc.)
///
/// // After receiving response bytes from peer:
/// let completed = protocol.complete(now, response_bytes)?;
/// // completed.shared_secret, completed.peer_did are now available
/// ```
pub struct PairingProtocol {
    session: PairingSession,
}

impl PairingProtocol {
    /// Initiate a pairing session.
    ///
    /// Args:
    /// * `now` - Current time (injected, not fetched internally)
    /// * `controller_did` - The initiator's identity DID
    /// * `endpoint` - Registry endpoint URL
    /// * `capabilities` - Capabilities to grant to the paired device
    ///
    /// Usage:
    /// ```ignore
    /// let (protocol, token) = PairingProtocol::initiate(now, did, endpoint, caps)?;
    /// ```
    pub fn initiate(
        now: DateTime<Utc>,
        controller_did: String,
        endpoint: String,
        capabilities: Vec<String>,
    ) -> Result<(Self, PairingToken), ProtocolError> {
        let session = PairingToken::generate(now, controller_did, endpoint, capabilities)?;
        let token = session.token.clone();
        Ok((Self { session }, token))
    }

    /// Complete the pairing exchange with a received response.
    ///
    /// Consumes the protocol state (ephemeral secret is used exactly once).
    ///
    /// Args:
    /// * `now` - Current time for expiry checking
    /// * `response_bytes` - Serialized `PairingResponse` from the peer
    ///
    /// Usage:
    /// ```ignore
    /// let completed = protocol.complete(now, &response_bytes)?;
    /// ```
    pub fn complete(
        mut self,
        now: DateTime<Utc>,
        response_bytes: &[u8],
    ) -> Result<CompletedPairing, ProtocolError> {
        let response: PairingResponse = serde_json::from_slice(response_bytes)?;
        response.verify(now, &self.session.token)?;
        self.complete_inner(now, response)
    }

    /// Complete the pairing exchange with a structured response.
    ///
    /// Args:
    /// * `now` - Current time for expiry checking
    /// * `response` - The peer's `PairingResponse`
    pub fn complete_with_response(
        mut self,
        now: DateTime<Utc>,
        response: PairingResponse,
    ) -> Result<CompletedPairing, ProtocolError> {
        response.verify(now, &self.session.token)?;
        self.complete_inner(now, response)
    }

    fn complete_inner(
        &mut self,
        _now: DateTime<Utc>,
        response: PairingResponse,
    ) -> Result<CompletedPairing, ProtocolError> {
        let initiator_x25519_pub = self.session.ephemeral_pubkey_bytes()?;
        let responder_x25519_pub = response.device_x25519_pubkey_bytes()?;
        let shared_secret = self.session.complete_exchange(&responder_x25519_pub)?;
        let peer_signing_pubkey = response.device_signing_pubkey_bytes()?;
        let peer_did = response.device_did.clone();
        let short_code = &self.session.token.short_code;

        let sas_bytes = sas::derive_sas(
            &shared_secret,
            &initiator_x25519_pub,
            &responder_x25519_pub,
            short_code,
        );
        let transport_key = sas::derive_transport_key(
            &shared_secret,
            &initiator_x25519_pub,
            &responder_x25519_pub,
            short_code,
        );

        Ok(CompletedPairing {
            shared_secret,
            peer_signing_pubkey,
            peer_did,
            response,
            sas: sas_bytes,
            transport_key,
            initiator_x25519_pub,
        })
    }

    /// Get a reference to the pairing token for display/transmission.
    pub fn token(&self) -> &PairingToken {
        &self.session.token
    }
}

/// Responder-side helper: create a response from a received token.
///
/// Args:
/// * `now` - Current time for expiry checking
/// * `token_bytes` - Serialized `PairingToken` from the initiator
/// * `device_seed` - The responding device's Ed25519 seed
/// * `device_pubkey` - The responding device's Ed25519 public key
/// * `device_did` - The responding device's DID string
/// * `device_name` - Optional friendly device name
///
/// Usage:
/// ```ignore
/// let result = respond_to_pairing(now, &token_bytes, &seed, &pk, did, name)?;
/// let response_bytes = serde_json::to_vec(&result.response)?;
/// // Send response_bytes back to initiator, then display result.sas
/// ```
pub fn respond_to_pairing(
    now: DateTime<Utc>,
    token_bytes: &[u8],
    device_seed: &SecureSeed,
    device_pubkey: &[u8; 32],
    device_did: String,
    device_name: Option<String>,
) -> Result<ResponderResult, ProtocolError> {
    let token: PairingToken = serde_json::from_slice(token_bytes)?;
    let (response, shared_secret) = PairingResponse::create(
        now,
        &token,
        device_seed,
        device_pubkey,
        device_did,
        device_name,
    )?;

    let initiator_x25519_pub = token.ephemeral_pubkey_bytes()?;
    let responder_x25519_pub = response.device_x25519_pubkey_bytes()?;
    let short_code = &token.short_code;

    let sas_bytes = sas::derive_sas(
        &shared_secret,
        &initiator_x25519_pub,
        &responder_x25519_pub,
        short_code,
    );
    let transport_key = sas::derive_transport_key(
        &shared_secret,
        &initiator_x25519_pub,
        &responder_x25519_pub,
        short_code,
    );

    Ok(ResponderResult {
        response,
        shared_secret,
        sas: sas_bytes,
        transport_key,
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn generate_test_keypair() -> (SecureSeed, [u8; 32]) {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).unwrap();
        let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
        let seed: [u8; 32] = pkcs8_doc.as_ref()[16..48].try_into().unwrap();
        (SecureSeed::new(seed), public_key)
    }

    #[test]
    fn happy_path_initiate_and_complete() {
        let now = chrono::Utc::now();
        let (protocol, token) = PairingProtocol::initiate(
            now,
            "did:keri:test".to_string(),
            "http://localhost:3000".to_string(),
            vec!["sign_commit".to_string()],
        )
        .unwrap();

        let (seed, pubkey) = generate_test_keypair();
        let token_bytes = serde_json::to_vec(&token).unwrap();
        let responder_result = respond_to_pairing(
            now,
            &token_bytes,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        let response_bytes = serde_json::to_vec(&responder_result.response).unwrap();
        let completed = protocol.complete(now, &response_bytes).unwrap();

        assert_eq!(*completed.shared_secret, *responder_result.shared_secret);
        assert_eq!(completed.peer_did, "did:key:z6MkTest");
        // Both sides derive the same SAS
        assert_eq!(completed.sas, responder_result.sas);
    }

    #[test]
    fn expired_token_fails() {
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

        let token = session.token.clone();
        let protocol = PairingProtocol { session };

        let (seed, pubkey) = generate_test_keypair();
        let (response, _) = PairingResponse::create(
            // Use a time before expiry for creation
            now - Duration::seconds(10),
            &token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        let response_bytes = serde_json::to_vec(&response).unwrap();
        let result = protocol.complete(now, &response_bytes);
        assert!(matches!(result, Err(ProtocolError::Expired)));
    }

    #[test]
    fn invalid_response_bytes_fails() {
        let now = chrono::Utc::now();
        let (protocol, _token) = PairingProtocol::initiate(
            now,
            "did:keri:test".to_string(),
            "http://localhost:3000".to_string(),
            vec![],
        )
        .unwrap();

        let result = protocol.complete(now, b"not valid json");
        assert!(matches!(result, Err(ProtocolError::Serialization(_))));
    }
}
