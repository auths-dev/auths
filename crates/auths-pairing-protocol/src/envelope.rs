//! `SecureEnvelope` — AEAD-wrapped session payloads (fn-129.T7).
//!
//! Every body the daemon POSTs under a pairing session gets wrapped in this
//! envelope. The envelope binds:
//! - **Ciphertext + tag** to a session-specific AEAD key derived from the
//!   `TransportKey` via HKDF with `ENVELOPE_INFO` domain separation.
//! - **Request context** (session id, path, monotonic counter) as AAD, in
//!   a length-prefixed layout that defeats AAD-confusion attacks.
//!
//! # Committed design decisions
//!
//! - **Nonce scheme:** deterministic counter XOR'd with a per-session
//!   96-bit IV (RFC 8446 §5.3). Doubles as the monotonic-counter replay
//!   defense — one value, not two.
//! - **AEAD primitive:** ChaCha20-Poly1305 for the default build;
//!   AES-256-GCM under `--features cnsa`. Dispatched through
//!   `CryptoProvider::aead_{encrypt,decrypt}` (fn-128.T2) so the swap is
//!   automatic.
//! - **AAD layout (length-prefixed):**
//!   `u32_be(len(session_id)) || session_id || u32_be(len(path)) || path ||
//!    u32_be(len(channel_binding)) || channel_binding || u32_be(counter)`.
//!   Naive concatenation is forbidden (USENIX'23 AEAD-confusion).
//! - **Channel binding (anti-relay):** the session is pinned to the TLS
//!   connection it runs on via the RFC 9266 `tls-exporter` keying material
//!   (see [`crate::channel_binding`]). The exporter is folded into BOTH the
//!   envelope key derivation (so two channels derive different keys) AND the
//!   AAD (so a cross-channel open is rejected explicitly). An envelope sealed
//!   on channel A therefore cannot be opened on channel B — a relayed proof is
//!   refused. This is the load-bearing negative property; without it the
//!   envelope is transport-agnostic and a captured proof replays.
//! - **Max messages per session:** 1024. More than any pairing flow needs;
//!   abort with [`EnvelopeError::SessionExhausted`] at the cap.
//! - **API is async** to match `CryptoProvider`'s async trait surface;
//!   this avoids a sync-over-async executor inside the crate.
//!
//! # Typestate
//!
//! `Envelope<Sealed>` (carries ciphertext) and `Envelope<Open>` (carries
//! plaintext) are separate types; `seal` and `open` can't be swapped.

use std::marker::PhantomData;

use zeroize::{Zeroize, Zeroizing};

use auths_crypto::default_provider;

use crate::channel_binding::{CHANNEL_BINDING_INFO, ChannelBinding, TLS_EXPORTER_LEN};
use crate::domain_separation::ENVELOPE_INFO;
use crate::sas::TransportKey;

/// Hard cap on messages per envelope session. Well above any pairing
/// flow's natural message count.
pub const MAX_MESSAGES_PER_SESSION: u32 = 1024;

/// Errors produced by envelope open/seal.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// AEAD tag did not verify. Could be a wrong key, wrong nonce, or
    /// tampered ciphertext / AAD.
    #[error("envelope authentication failed")]
    TagMismatch,

    /// Counter in incoming envelope ≤ last-seen counter — replay or
    /// out-of-order.
    #[error("envelope counter not strictly monotonic: expected > {expected}, got {got}")]
    CounterNotMonotonic {
        /// Last successfully-opened counter.
        expected: u32,
        /// Counter the incoming envelope carries.
        got: u32,
    },

    /// AAD fields (session_id / path / counter) disagree between sealer and
    /// opener.
    #[error("envelope AAD mismatch")]
    AadMismatch,

    /// The envelope was sealed on a different TLS channel than the one it is
    /// being opened on — its RFC 9266 channel binding does not match this
    /// session's. This is the anti-relay rejection: a proof captured on one
    /// TLS connection and replayed onto another is refused here.
    #[error("envelope channel-binding mismatch — proof relayed onto a different TLS channel")]
    ChannelBindingMismatch,

    /// Session has reached the message cap; must renegotiate a fresh
    /// `TransportKey`.
    #[error("envelope session exhausted (>{MAX_MESSAGES_PER_SESSION} messages)")]
    SessionExhausted,

    /// HKDF-expand of the envelope key failed.
    #[error("envelope key derivation failed: {0}")]
    KeyDerivation(String),

    /// Provider-layer AEAD error that is not a tag mismatch (e.g. invalid
    /// key length).
    #[error("envelope encrypt/decrypt failed: {0}")]
    Cipher(String),
}

/// Phantom type: envelope has been sealed (contains ciphertext).
pub struct Sealed;
/// Phantom type: envelope has been opened (contains plaintext).
pub struct Open;

/// AEAD envelope. State parameter distinguishes sealed-for-transport from
/// opened-for-use. Never deriving `Clone` / `Copy` — a sealed envelope is
/// single-use (counter is one-shot).
pub struct Envelope<S> {
    nonce: [u8; 12],
    counter: u32,
    payload: Vec<u8>,
    aad_session_id: String,
    aad_path: String,
    /// The RFC 9266 channel binding this envelope was sealed under. Carried
    /// for the explicit same-process anti-relay check in [`EnvelopeSession::open`];
    /// it is NOT a wire field — across a transport each endpoint recomputes its
    /// own binding from its own TLS connection, and the binding is folded into
    /// the key + AAD so a cross-channel open fails cryptographically regardless.
    aad_channel_binding: [u8; TLS_EXPORTER_LEN],
    _state: PhantomData<S>,
}

// Manual Debug that redacts payload. Never print plaintext (Open) or
// ciphertext (Sealed) — printing either leaks surface for traffic analysis
// or future plaintext recovery.
impl<S> std::fmt::Debug for Envelope<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("counter", &self.counter)
            .field("session_id", &self.aad_session_id)
            .field("path", &self.aad_path)
            .field(
                "payload",
                &format_args!("<{} bytes redacted>", self.payload.len()),
            )
            .finish()
    }
}

impl<S> Envelope<S> {
    /// Counter value this envelope was sealed under.
    pub fn counter(&self) -> u32 {
        self.counter
    }
    /// Session id this envelope's AAD is bound to.
    pub fn session_id(&self) -> &str {
        &self.aad_session_id
    }
    /// Request path this envelope's AAD is bound to.
    pub fn path(&self) -> &str {
        &self.aad_path
    }
}

impl Envelope<Sealed> {
    /// Raw ciphertext || tag (16 bytes of Poly1305 tag at the end).
    pub fn ciphertext(&self) -> &[u8] {
        &self.payload
    }

    /// Nonce this envelope was sealed under.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
}

impl Envelope<Open> {
    /// Recovered plaintext.
    pub fn plaintext(&self) -> &[u8] {
        &self.payload
    }
}

/// Session-local envelope state. Holds the envelope key (HKDF-derived from
/// the `TransportKey`), the per-session IV, the last-seen counter, and a
/// message budget. Consumed via `&mut self` so nonce reuse within a
/// session is structurally prevented.
pub struct EnvelopeSession {
    key: Zeroizing<[u8; 32]>,
    iv: [u8; 12],
    next_counter: u32,
    last_opened_counter: Option<u32>,
    session_id: String,
    /// The TLS channel this session is bound to (RFC 9266 `tls-exporter`).
    /// Folded into the key derivation and every AAD; an envelope sealed under a
    /// different binding cannot be opened here.
    channel_binding: ChannelBinding,
}

impl EnvelopeSession {
    /// Derive a fresh envelope session from a `TransportKey`, bound to a TLS
    /// channel.
    ///
    /// Args:
    /// * `transport_key`: the session's transport key from
    ///   [`crate::sas::derive_transport_key`].
    /// * `session_id`: the pairing session id (part of every AAD).
    /// * `iv`: per-session 96-bit IV. Produce via `OsRng` at session start;
    ///   transmit out-of-band to the peer.
    /// * `channel_binding`: the RFC 9266 `tls-exporter` value for the TLS
    ///   connection this session runs over (from a
    ///   [`crate::channel_binding::ChannelBindingProvider`] adapter). The
    ///   binding is folded into the envelope key so two TLS channels derive
    ///   different keys; a proof minted on one channel cannot open on another.
    ///   There is no unbound constructor on purpose — an unbound envelope is
    ///   relay-able, so the channel binding is a required argument, not an
    ///   option.
    ///
    /// Usage:
    /// ```ignore
    /// let cb = tls_conn.channel_binding()?; // ChannelBindingProvider adapter
    /// let session = EnvelopeSession::new(&transport_key, session_id, iv, cb).await?;
    /// let env = session.seal("/v1/pairing/sessions/x/response", pt).await?;
    /// ```
    pub async fn new(
        transport_key: &TransportKey,
        session_id: String,
        iv: [u8; 12],
        channel_binding: ChannelBinding,
    ) -> Result<Self, EnvelopeError> {
        let provider = default_provider();
        // Fold the channel binding into the key-derivation `info` so the
        // envelope key is unique per (transport key, TLS channel) pair. Two
        // sessions over different TLS connections derive different keys even
        // with an identical transport key — the cryptographic half of the
        // anti-relay guarantee.
        let mut info =
            Vec::with_capacity(ENVELOPE_INFO.len() + CHANNEL_BINDING_INFO.len() + TLS_EXPORTER_LEN);
        info.extend_from_slice(ENVELOPE_INFO);
        info.extend_from_slice(CHANNEL_BINDING_INFO);
        info.extend_from_slice(channel_binding.as_bytes());
        let okm = provider
            .hkdf_sha256_expand(transport_key.as_bytes(), &[], &info, 32)
            .await
            .map_err(|e| EnvelopeError::KeyDerivation(e.to_string()))?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&okm);
        Ok(Self {
            key: Zeroizing::new(key_bytes),
            iv,
            next_counter: 1,
            last_opened_counter: None,
            session_id,
            channel_binding,
        })
    }

    /// Seal `plaintext`, binding to `path` and the next monotonic counter.
    pub async fn seal(
        &mut self,
        path: &str,
        plaintext: &[u8],
    ) -> Result<Envelope<Sealed>, EnvelopeError> {
        if self.next_counter >= MAX_MESSAGES_PER_SESSION {
            return Err(EnvelopeError::SessionExhausted);
        }
        let counter = self.next_counter;
        self.next_counter = self.next_counter.wrapping_add(1);

        let nonce = nonce_for_counter(&self.iv, counter);
        let aad = build_aad(
            &self.session_id,
            path,
            self.channel_binding.as_bytes(),
            counter,
        );
        let provider = default_provider();
        let ct = provider
            .aead_encrypt(&self.key, &nonce, &aad, plaintext)
            .await
            .map_err(|e| EnvelopeError::Cipher(e.to_string()))?;

        Ok(Envelope {
            nonce,
            counter,
            payload: ct,
            aad_session_id: self.session_id.clone(),
            aad_path: path.to_string(),
            aad_channel_binding: *self.channel_binding.as_bytes(),
            _state: PhantomData,
        })
    }

    /// Open a `Envelope<Sealed>`. Enforces strict-monotonic counter over
    /// the session.
    pub async fn open(
        &mut self,
        path: &str,
        env: Envelope<Sealed>,
    ) -> Result<Envelope<Open>, EnvelopeError> {
        if let Some(last) = self.last_opened_counter
            && env.counter <= last
        {
            return Err(EnvelopeError::CounterNotMonotonic {
                expected: last,
                got: env.counter,
            });
        }

        let nonce = nonce_for_counter(&self.iv, env.counter);
        if nonce != env.nonce {
            return Err(EnvelopeError::AadMismatch);
        }
        if path != env.aad_path {
            return Err(EnvelopeError::AadMismatch);
        }
        if self.session_id != env.aad_session_id {
            return Err(EnvelopeError::AadMismatch);
        }
        // Anti-relay: refuse a proof minted on a different TLS channel. The
        // constant-time compare avoids leaking how close a forged binding is.
        // Even if this explicit check were bypassed, the binding is folded into
        // the key + AAD, so the AEAD `open` below would still fail — this is
        // defense-in-depth with a clear diagnostic.
        {
            use subtle::ConstantTimeEq;
            let matches: bool = self
                .channel_binding
                .as_bytes()
                .ct_eq(&env.aad_channel_binding)
                .into();
            if !matches {
                return Err(EnvelopeError::ChannelBindingMismatch);
            }
        }
        let aad = build_aad(
            &self.session_id,
            path,
            self.channel_binding.as_bytes(),
            env.counter,
        );

        let provider = default_provider();
        let pt = provider
            .aead_decrypt(&self.key, &nonce, &aad, &env.payload)
            .await
            .map_err(|_| EnvelopeError::TagMismatch)?;

        self.last_opened_counter = Some(env.counter);
        Ok(Envelope {
            nonce: env.nonce,
            counter: env.counter,
            payload: pt,
            aad_session_id: env.aad_session_id,
            aad_path: env.aad_path,
            aad_channel_binding: env.aad_channel_binding,
            _state: PhantomData,
        })
    }
}

impl Drop for EnvelopeSession {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

fn nonce_for_counter(iv: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut nonce = *iv;
    let ctr = counter.to_be_bytes();
    nonce[8] ^= ctr[0];
    nonce[9] ^= ctr[1];
    nonce[10] ^= ctr[2];
    nonce[11] ^= ctr[3];
    nonce
}

fn build_aad(session_id: &str, path: &str, channel_binding: &[u8], counter: u32) -> Vec<u8> {
    let sid = session_id.as_bytes();
    let p = path.as_bytes();
    let cb = channel_binding;
    let mut aad = Vec::with_capacity(4 + sid.len() + 4 + p.len() + 4 + cb.len() + 4);
    aad.extend_from_slice(&(sid.len() as u32).to_be_bytes());
    aad.extend_from_slice(sid);
    aad.extend_from_slice(&(p.len() as u32).to_be_bytes());
    aad.extend_from_slice(p);
    aad.extend_from_slice(&(cb.len() as u32).to_be_bytes());
    aad.extend_from_slice(cb);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_binding::ChannelBinding;
    use crate::sas::TransportKey;

    // A stand-in TLS exporter for one channel. Two distinct values model two
    // distinct TLS connections (the per-session property the Go TLS oracle
    // confirms for the RFC 9266 `tls-exporter`).
    fn channel(byte: u8) -> ChannelBinding {
        ChannelBinding::from_exporter(&[byte; TLS_EXPORTER_LEN]).unwrap()
    }

    fn session_with_transport_key() -> (TransportKey, [u8; 12], String) {
        let tk = TransportKey::new([0xA5; 32]);
        let iv = [0x07; 12];
        let session_id = "sess-kat".to_string();
        (tk, iv, session_id)
    }

    #[tokio::test]
    async fn seal_open_round_trip() {
        let (tk, iv, sid) = session_with_transport_key();
        // Same TLS channel on both ends → same binding → opens.
        let mut sender = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xC0))
            .await
            .unwrap();
        let mut receiver = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();

        let env = sender
            .seal("/v1/pairing/sessions/x/response", b"hello world")
            .await
            .unwrap();
        let opened = receiver
            .open("/v1/pairing/sessions/x/response", env)
            .await
            .unwrap();
        assert_eq!(opened.plaintext(), b"hello world");
    }

    /// The load-bearing anti-relay test (RFC 9266 / Track B T0). A proof sealed
    /// on TLS channel A and replayed onto a session bound to TLS channel B is
    /// REJECTED — exactly the relay/MITM the channel binding exists to stop.
    #[tokio::test]
    async fn proof_relayed_onto_different_channel_is_rejected() {
        let (tk, iv, sid) = session_with_transport_key();
        // Channel A mints the proof.
        let mut on_channel_a = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xAA))
            .await
            .unwrap();
        // Channel B (a different TLS connection → different exporter) is where
        // the attacker replays it.
        let mut on_channel_b = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xBB),
        )
        .await
        .unwrap();

        let proof = on_channel_a.seal("/p", b"valid-proof").await.unwrap();
        let err = on_channel_b.open("/p", proof).await.unwrap_err();
        assert!(
            matches!(err, EnvelopeError::ChannelBindingMismatch),
            "a proof relayed onto a foreign TLS channel must be rejected, got {err:?}"
        );
    }

    /// Even if the explicit binding check were stripped, the binding is folded
    /// into the key derivation, so a forged envelope that *claims* the receiver's
    /// binding but was keyed under a different channel still fails the AEAD.
    #[tokio::test]
    async fn forged_binding_label_still_fails_aead() {
        let (tk, iv, sid) = session_with_transport_key();
        let mut on_channel_a = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xAA))
            .await
            .unwrap();
        let mut on_channel_b = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xBB),
        )
        .await
        .unwrap();

        let proof = on_channel_a.seal("/p", b"valid-proof").await.unwrap();
        // Attacker rewrites the carried binding to match the victim channel B,
        // hoping to pass the explicit equality check. The key it was sealed
        // under is still channel A's, so the AEAD tag fails.
        let forged = Envelope {
            nonce: proof.nonce,
            counter: proof.counter,
            payload: proof.payload,
            aad_session_id: proof.aad_session_id,
            aad_path: proof.aad_path,
            aad_channel_binding: [0xBB; TLS_EXPORTER_LEN],
            _state: PhantomData::<Sealed>,
        };
        let err = on_channel_b.open("/p", forged).await.unwrap_err();
        assert!(matches!(err, EnvelopeError::TagMismatch));
    }

    #[tokio::test]
    async fn tampered_tag_yields_tag_mismatch() {
        let (tk, iv, sid) = session_with_transport_key();
        let mut sender = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xC0))
            .await
            .unwrap();
        let mut receiver = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();

        let env = sender.seal("/path", b"payload").await.unwrap();
        // Tamper the last byte (part of the Poly1305 tag).
        let mut ct = env.payload.clone();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let tampered = Envelope {
            nonce: env.nonce,
            counter: env.counter,
            payload: ct,
            aad_session_id: env.aad_session_id,
            aad_path: env.aad_path,
            aad_channel_binding: env.aad_channel_binding,
            _state: PhantomData::<Sealed>,
        };
        let err = receiver.open("/path", tampered).await.unwrap_err();
        assert!(matches!(err, EnvelopeError::TagMismatch));
    }

    #[tokio::test]
    async fn aad_path_mismatch_yields_aad_mismatch_or_tag_mismatch() {
        let (tk, iv, sid) = session_with_transport_key();
        let mut sender = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xC0))
            .await
            .unwrap();
        let mut receiver = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();

        let env = sender.seal("/path-a", b"payload").await.unwrap();
        let err = receiver.open("/path-b", env).await.unwrap_err();
        // The AAD check short-circuits before the AEAD; expect AadMismatch.
        assert!(matches!(err, EnvelopeError::AadMismatch));
    }

    #[tokio::test]
    async fn counter_rollback_rejected() {
        let (tk, iv, sid) = session_with_transport_key();
        let mut sender = EnvelopeSession::new(&tk, sid.clone(), iv, channel(0xC0))
            .await
            .unwrap();
        let mut receiver = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();

        // Seal three messages; open them in order.
        let e1 = sender.seal("/p", b"a").await.unwrap();
        let e2 = sender.seal("/p", b"b").await.unwrap();
        let e3 = sender.seal("/p", b"c").await.unwrap();
        let _ = receiver.open("/p", e1).await.unwrap();
        let _ = receiver.open("/p", e3).await.unwrap();
        // Now try to open the earlier-counter envelope.
        let err = receiver.open("/p", e2).await.unwrap_err();
        assert!(matches!(err, EnvelopeError::CounterNotMonotonic { .. }));
    }

    #[tokio::test]
    async fn cross_session_key_rejected() {
        let iv = [0x07; 12];
        let sid = "sess-cross".to_string();
        let mut sender = EnvelopeSession::new(
            &TransportKey::new([0xA5; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();
        // Different transport key ⇒ different derived envelope key.
        let mut receiver = EnvelopeSession::new(
            &TransportKey::new([0x5A; 32]),
            sid.clone(),
            iv,
            channel(0xC0),
        )
        .await
        .unwrap();

        let env = sender.seal("/p", b"payload").await.unwrap();
        let err = receiver.open("/p", env).await.unwrap_err();
        assert!(matches!(err, EnvelopeError::TagMismatch));
    }
}
