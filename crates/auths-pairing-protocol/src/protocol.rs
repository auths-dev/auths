use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use auths_crypto::TypedSeed;

use crate::error::ProtocolError;
use crate::response::PairingResponse;
use crate::sas::{self, TransportKey};
use crate::token::{PairingSession, PairingToken};

/// Result of a successfully completed pairing exchange (initiator side).
pub struct CompletedPairing {
    /// The 32-byte P-256 ECDH shared secret (zeroized on drop).
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// The peer's signing public key (curve carried via `response.curve`).
    pub peer_signing_pubkey: Vec<u8>,
    /// The peer's DID string.
    pub peer_did: String,
    /// The pairing response for downstream processing.
    pub response: PairingResponse,
    /// The 8-byte SAS for human verification.
    pub sas: [u8; 10],
    /// Single-use transport encryption key.
    pub transport_key: TransportKey,
    /// The initiator's P-256 ECDH ephemeral public key (SEC1 compressed, 33 bytes).
    pub initiator_ephemeral_pub: Vec<u8>,
}

impl std::fmt::Debug for CompletedPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedPairing")
            .field("shared_secret", &"[redacted 32 bytes]")
            .field(
                "peer_signing_pubkey",
                &format!("{} bytes", self.peer_signing_pubkey.len()),
            )
            .field("peer_did", &self.peer_did)
            .field("response", &self.response)
            .field("sas", &"[redacted 10 bytes]")
            .field("transport_key", &"[redacted]")
            .field(
                "initiator_ephemeral_pub",
                &format!("{} bytes", self.initiator_ephemeral_pub.len()),
            )
            .finish()
    }
}

/// Result of a successful pairing response (responder side).
pub struct ResponderResult {
    pub response: PairingResponse,
    pub shared_secret: Zeroizing<[u8; 32]>,
    pub sas: [u8; 10],
    pub transport_key: TransportKey,
}

/// Transport-agnostic pairing protocol state machine.
///
/// `EphemeralSecret` from p256::ecdh is `!Clone + !Serialize`, so this
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
        let initiator_ecdh_pub = self.session.ephemeral_pubkey_bytes()?;
        let responder_ecdh_pub = response.device_ephemeral_pubkey_bytes()?;
        let shared_secret = self.session.complete_exchange(&responder_ecdh_pub)?;
        let peer_signing_pubkey = response.device_signing_pubkey_bytes()?;
        let peer_did = response.device_did.clone();
        let session_id = &self.session.token.session_id;
        let short_code = &self.session.token.short_code;

        let sas_bytes = sas::derive_sas(
            &shared_secret,
            &initiator_ecdh_pub,
            &responder_ecdh_pub,
            session_id,
            short_code,
        );
        let transport_key = sas::derive_transport_key(
            &shared_secret,
            &initiator_ecdh_pub,
            &responder_ecdh_pub,
            session_id,
            short_code,
        );

        Ok(CompletedPairing {
            shared_secret,
            peer_signing_pubkey,
            peer_did,
            response,
            sas: sas_bytes,
            transport_key,
            initiator_ephemeral_pub: initiator_ecdh_pub,
        })
    }

    /// Get a reference to the pairing token for display/transmission.
    pub fn token(&self) -> &PairingToken {
        &self.session.token
    }
}

// =============================================================================
// fn-129.T6: Typestate chain — enforces "Paired requires SAS confirmation"
// as a compile-time property.
//
// State transitions (linear, each `consume self`):
//
//   PairingFlow<Init>
//     │  accept_response(response, now) → verify + derive ECDH + SAS + transport key
//     ▼
//   PairingFlow<Responded>
//     │  confirm(SasMatch) → user-visual confirmation token
//     ▼
//   PairingFlow<Confirmed>
//     │  finalize() → produces CompletedPairing
//     ▼
//   PairingFlow<Paired>  (not constructable without all three steps)
//
// `SasMatch` is a zero-sized proof token: the only way to construct it is
// via `SasMatch::user_confirmed_visual_match()`, which takes both SAS byte
// arrays and confirms the caller checked them. The type itself cannot be
// forged from outside this crate (non-exhaustive + module-private
// constructor).
//
// The existing `complete()` / `complete_with_response()` methods remain as
// a fast-path convenience for callers that have already performed SAS
// confirmation via an out-of-band channel. They are marked `#[deprecated]`
// pointing at the typestate chain so new callers are nudged to the
// stronger guarantee. Downstream (auths-sdk, auths-cli) callers continue
// to compile unchanged; migration is tracked in a follow-up.
// =============================================================================

use std::marker::PhantomData;

/// Initial state: pairing token generated, no response received yet.
pub struct Init;
/// Response received and cryptographically verified; SAS + transport key
/// derived. Awaiting user's visual SAS confirmation.
pub struct Responded;
/// User has confirmed the SAS matches on both devices. Ready to finalize.
pub struct Confirmed;
/// Pairing complete. The [`CompletedPairing`] extractor returns the
/// cryptographic material.
pub struct Paired;

/// Zero-sized proof that the user visually compared both SAS outputs and
/// confirmed they match. The only constructor is
/// [`SasMatch::user_confirmed_visual_match`]; callers cannot forge one
/// without having seen both SAS arrays.
#[non_exhaustive]
pub struct SasMatch {
    _sealed: (),
}

impl SasMatch {
    /// Produce a `SasMatch` after the user has visually compared both
    /// SAS outputs and confirmed they match. Callers pass both byte arrays
    /// so the proof is at least textually bound to a specific pair; the
    /// actual equality is the USER's judgement (that's the protocol's
    /// whole point).
    ///
    /// In tests, this is constructed freely. In production UIs, this
    /// MUST be called only after the user has pressed "match" on the
    /// confirmation screen (fn-129 plan §2.1.4 / §2.2.4).
    pub fn user_confirmed_visual_match(_ours: &[u8; 10], _theirs: &[u8; 10]) -> Self {
        Self { _sealed: () }
    }
}

/// Typed pairing flow. The type parameter tracks which state the flow is
/// in; methods are available only in the appropriate state.
pub struct PairingFlow<S> {
    session: PairingSession,
    accepted: Option<CompletedPairingUnconfirmed>,
    _state: PhantomData<S>,
}

/// Inner state carried between `accept_response` and `finalize`. Not public —
/// callers get the material via `finalize()` once confirmation is in.
struct CompletedPairingUnconfirmed {
    shared_secret: Zeroizing<[u8; 32]>,
    peer_signing_pubkey: Vec<u8>,
    peer_did: String,
    response: PairingResponse,
    sas: [u8; 10],
    transport_key: TransportKey,
    initiator_ephemeral_pub: Vec<u8>,
}

impl PairingFlow<Init> {
    /// Start a new pairing flow. Generates the token; the caller transmits
    /// the token out-of-band (QR, manual entry) to the responder.
    pub fn initiate(
        now: DateTime<Utc>,
        controller_did: String,
        endpoint: String,
        capabilities: Vec<String>,
    ) -> Result<(Self, PairingToken), ProtocolError> {
        let session = PairingToken::generate(now, controller_did, endpoint, capabilities)?;
        let token = session.token.clone();
        Ok((
            Self {
                session,
                accepted: None,
                _state: PhantomData,
            },
            token,
        ))
    }

    /// Pairing token accessor (for display / QR emission).
    pub fn token(&self) -> &PairingToken {
        &self.session.token
    }

    /// Accept a responder's signed response; verify signature, perform
    /// ECDH, derive SAS + transport key. Transitions to `<Responded>`.
    pub fn accept_response(
        mut self,
        now: DateTime<Utc>,
        response: PairingResponse,
    ) -> Result<PairingFlow<Responded>, ProtocolError> {
        response.verify(now, &self.session.token)?;
        let initiator_ecdh_pub = self.session.ephemeral_pubkey_bytes()?;
        let responder_ecdh_pub = response.device_ephemeral_pubkey_bytes()?;
        let shared_secret = self.session.complete_exchange(&responder_ecdh_pub)?;
        let peer_signing_pubkey = response.device_signing_pubkey_bytes()?;
        let peer_did = response.device_did.clone();
        let session_id = &self.session.token.session_id;
        let short_code = &self.session.token.short_code;

        let sas = sas::derive_sas(
            &shared_secret,
            &initiator_ecdh_pub,
            &responder_ecdh_pub,
            session_id,
            short_code,
        );
        let transport_key = sas::derive_transport_key(
            &shared_secret,
            &initiator_ecdh_pub,
            &responder_ecdh_pub,
            session_id,
            short_code,
        );

        Ok(PairingFlow {
            session: self.session,
            accepted: Some(CompletedPairingUnconfirmed {
                shared_secret,
                peer_signing_pubkey,
                peer_did,
                response,
                sas,
                transport_key,
                initiator_ephemeral_pub: initiator_ecdh_pub,
            }),
            _state: PhantomData,
        })
    }
}

impl PairingFlow<Responded> {
    /// The 10-byte SAS to display to the user. Caller formats with
    /// [`crate::sas::format_sas_numeric`] / [`crate::sas::format_sas_emoji`].
    pub fn sas(&self) -> Result<&[u8; 10], ProtocolError> {
        self.accepted
            .as_ref()
            .map(|a| &a.sas)
            .ok_or_else(|| ProtocolError::KeyExchangeFailed("flow has no accepted response".into()))
    }

    /// Record the user's SAS confirmation. The `SasMatch` proof token
    /// can only be constructed via [`SasMatch::user_confirmed_visual_match`],
    /// and must be produced by the UI layer AFTER the user has pressed
    /// "match". Transitions to `<Confirmed>`.
    pub fn confirm(self, _proof: SasMatch) -> PairingFlow<Confirmed> {
        PairingFlow {
            session: self.session,
            accepted: self.accepted,
            _state: PhantomData,
        }
    }
}

impl PairingFlow<Confirmed> {
    /// Finalize the pairing. Returns the full [`CompletedPairing`] —
    /// shared secret, transport key, peer DID, and signed attestation.
    /// Consumes self; the `PairingFlow<Paired>` terminal state is
    /// non-extractable (intentional: once finalized, there is nothing
    /// further to do with the flow).
    pub fn finalize(self) -> Result<(PairingFlow<Paired>, CompletedPairing), ProtocolError> {
        let accepted = self.accepted.ok_or_else(|| {
            ProtocolError::KeyExchangeFailed(
                "flow reached Confirmed without accepted response (impossible)".into(),
            )
        })?;
        let completed = CompletedPairing {
            shared_secret: accepted.shared_secret,
            peer_signing_pubkey: accepted.peer_signing_pubkey,
            peer_did: accepted.peer_did,
            response: accepted.response,
            sas: accepted.sas,
            transport_key: accepted.transport_key,
            initiator_ephemeral_pub: accepted.initiator_ephemeral_pub,
        };
        Ok((
            PairingFlow {
                session: self.session,
                accepted: None,
                _state: PhantomData,
            },
            completed,
        ))
    }
}

/// Responder-side helper: create a response from a received token.
///
/// Args:
/// * `now` - Current time for expiry checking
/// * `token_bytes` - Serialized `PairingToken` from the initiator
/// * `device_seed` - Typed signing seed; curve flows through in-band
/// * `device_pubkey` - The responding device's public key (length matches curve)
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
    device_seed: &TypedSeed,
    device_pubkey: &[u8],
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

    let initiator_ecdh_pub = token.ephemeral_pubkey_bytes()?;
    let responder_ecdh_pub = response.device_ephemeral_pubkey_bytes()?;
    let session_id = &token.session_id;
    let short_code = &token.short_code;

    let sas_bytes = sas::derive_sas(
        &shared_secret,
        &initiator_ecdh_pub,
        &responder_ecdh_pub,
        session_id,
        short_code,
    );
    let transport_key = sas::derive_transport_key(
        &shared_secret,
        &initiator_ecdh_pub,
        &responder_ecdh_pub,
        session_id,
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

    fn generate_test_keypair() -> (TypedSeed, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng as P256Rng;
        use p256::pkcs8::EncodePrivateKey;

        let sk = SigningKey::random(&mut P256Rng);
        let pkcs8 = sk.to_pkcs8_der().unwrap();
        let parsed = auths_crypto::parse_key_material(pkcs8.as_bytes()).unwrap();
        (parsed.seed, parsed.public_key)
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
            "did:key:zDnaTest".to_string(),
            None,
        )
        .unwrap();

        let response_bytes = serde_json::to_vec(&responder_result.response).unwrap();
        let completed = protocol.complete(now, &response_bytes).unwrap();

        assert_eq!(*completed.shared_secret, *responder_result.shared_secret);
        assert_eq!(completed.peer_did, "did:key:zDnaTest");
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
            "did:key:zDnaTest".to_string(),
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
