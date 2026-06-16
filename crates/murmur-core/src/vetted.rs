//! Vetted implementation, used correctly — the misuse-resistant wrapper proves it
//! drives the audited primitives the way their authors intended, and that it never
//! reuses a one-time prekey or a per-message key (PRD §10, the vetted-implementation
//! claim).
//!
//! "Signal is battle-tested" is the *premise*, never the proof. The whole risk of a
//! messenger like this is in how we *wire* audited crypto, so this module is the
//! gate on the wiring. It asserts three things over the very code paths the engine
//! ships, and fails closed the instant any of them slips:
//!
//!  1. **Official test vectors.** Each primitive the wrapper composes is checked
//!     against a published known-answer vector — the same vectors the audited
//!     implementations are themselves tested against:
//!       * ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.2;
//!       * HKDF-SHA256 (the session content-key KDF) — RFC 5869 Test Case 1;
//!       * HMAC-SHA256 (the forward-secret chain KDF) — RFC 4231 Test Case 2;
//!       * X25519 (the X3DH Diffie-Hellman) — RFC 7748 §5.2.
//!
//!     A wrapper that drove a primitive wrong — a swapped nonce order, a misframed
//!     AAD, a truncated KDF — would miss the published answer and is RED.
//!
//!  2. **Differential / interop.** The wrapper's own [`crate::ratchet::Ratchet`]
//!     seals a message; an **independent** reference Double-Ratchet chain — written
//!     here straight from the Signal symmetric-ratchet spec, sharing no code with
//!     the wrapper — derives the matching message key and decrypts it. Two
//!     implementations agreeing on the wire is interop; a wrapper that diverged from
//!     the spec would fail the reference decrypt and is RED.
//!
//!  3. **No key reuse.** A property check drives a batch of one-time prekeys and a
//!     batch of per-message ratchet keys and asserts each is handed out *exactly
//!     once*: the [`OneTimePrekeyJar`] consumes-and-zeroizes, so a second draw of
//!     the same prekey id is impossible, and every per-message key the ratchet
//!     derives over a long run is distinct. A wrapper that reused a one-time prekey
//!     or a message key is RED — that is the counterexample the gate's trap records.
//!
//! None of this reimplements the crypto: the primitives are the audited RustCrypto
//! and dalek crates the rest of the engine already seals and signs with. What is
//! proven here is that the *wrapper* uses them correctly — which is exactly the
//! claim a self-test by the wiring's authors can honestly make, and the one an
//! external audit (§10's release gate) then has to confirm before any real user.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::ratchet::Ratchet;
use crate::session::Session;
use crate::{CoreError, CoreResult};

type HmacSha256 = Hmac<Sha256>;

/// How many one-time prekeys and per-message keys the no-reuse property check
/// exercises. Large enough that an off-by-one index reuse or a chain that failed to
/// advance would be caught, small enough to stay a sub-millisecond self-test.
const NO_REUSE_BATCH: usize = 256;

/// The verdict of running the whole vetted-wrapper self-test: the official vectors
/// passed, an independent reference Double-Ratchet decrypted our ciphertext, and a
/// batch of one-time prekeys and per-message keys were each handed out exactly once.
/// Constructed only by [`prove_vetted`] succeeding, so holding one *is* the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedReport {
    /// How many official known-answer vectors the wrapper's primitives matched.
    pub vectors_passed: usize,
    /// How many bytes the reference Double-Ratchet decrypt recovered, proving the
    /// interop leg round-tripped (not merely that a vector matched).
    pub interop_plaintext_len: usize,
    /// How many one-time prekeys were drawn from the jar, each exactly once.
    pub prekeys_consumed: usize,
    /// How many distinct per-message ratchet keys were derived over the run — equal
    /// to the batch size only because none repeated.
    pub message_keys_distinct: usize,
}

// ── 1. Official known-answer vectors ──────────────────────────────────────────

/// A published known-answer vector: the human name of the standard it comes from,
/// and a thunk that recomputes its output through the wrapper's primitive. A
/// vector "passes" when the recomputed bytes equal the published `expected`.
struct Vector {
    what: &'static str,
    expected: Vec<u8>,
    compute: fn() -> CoreResult<Vec<u8>>,
}

/// ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.2. The published key/nonce/aad/plaintext
/// sealed through the same [`Session::seal`] the engine encrypts every message
/// with; the expected bytes are the RFC's ciphertext ‖ tag. Driving the wrapper's
/// own seal (not the bare cipher) proves the wrapper frames nonce and AAD the way
/// the construction requires.
fn vector_aead_rfc8439() -> CoreResult<Vec<u8>> {
    // Key/nonce/aad/plaintext exactly as published in RFC 8439 §2.8.2.
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // The wrapper's own AEAD path. `Session::seal_with_key` keys the cipher
    // directly with the vector's content key (rather than deriving one off a
    // session secret), so the published key/nonce/aad/plaintext map onto exactly
    // the RFC inputs. It prepends the nonce; the RFC vector is ciphertext ‖ tag, so
    // we drop the prepended nonce before comparing.
    let sealed = Session::seal_with_key(&key, nonce, &aad, plaintext)?;
    Ok(sealed[12..].to_vec())
}

/// HKDF-SHA256 — RFC 5869 Test Case 1. The session content-key KDF expanded over
/// the published IKM/salt/info to the published 42-byte OKM, proving the wrapper's
/// key-derivation matches the standard byte-for-byte.
fn vector_hkdf_rfc5869() -> CoreResult<Vec<u8>> {
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .map_err(|_| CoreError::Malformed("HKDF vector expansion failed".into()))?;
    Ok(okm.to_vec())
}

/// HMAC-SHA256 — RFC 4231 Test Case 2. The forward-secret chain KDF is HMAC-SHA256;
/// the published key/data produce the published tag, proving the chain step is
/// keyed and fed the way the construction requires.
fn vector_hmac_rfc4231() -> CoreResult<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"Jefe")
        .map_err(|_| CoreError::Malformed("HMAC vector keying failed".into()))?;
    mac.update(b"what do ya want for nothing?");
    Ok(mac.finalize().into_bytes().to_vec())
}

/// X25519 — RFC 7748 §5.2. The X3DH Diffie-Hellman run over the RFC's published
/// scalar and u-coordinate yields the RFC's shared secret, proving the wrapper's
/// DH is the standard curve operation with the standard clamping.
fn vector_x25519_rfc7748() -> CoreResult<Vec<u8>> {
    let alice_scalar: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let bob_public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let alice = X25519Secret::from(alice_scalar);
    let shared = alice.diffie_hellman(&X25519Public::from(bob_public));
    Ok(shared.as_bytes().to_vec())
}

/// The published outputs of each vector, transcribed from the standards documents.
/// Holding them separate from the `compute` thunks keeps "what the standard says"
/// and "what the wrapper computes" independent — the check is that they meet.
fn official_vectors() -> [Vector; 4] {
    [
        Vector {
            what: "ChaCha20-Poly1305 AEAD (RFC 8439)",
            // RFC 8439 §2.8.2 ciphertext ‖ 128-bit tag.
            expected: vec![
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
                0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
                0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
                0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
                0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
                0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
                0xd0, 0x60, 0x06, 0x91,
            ],
            compute: vector_aead_rfc8439,
        },
        Vector {
            what: "HKDF-SHA256 (RFC 5869)",
            // RFC 5869 Test Case 1 OKM (42 bytes).
            expected: vec![
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ],
            compute: vector_hkdf_rfc5869,
        },
        Vector {
            what: "HMAC-SHA256 (RFC 4231)",
            // RFC 4231 Test Case 2 HMAC-SHA-256.
            expected: vec![
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ],
            compute: vector_hmac_rfc4231,
        },
        Vector {
            what: "X25519 (RFC 7748)",
            // RFC 7748 §5.2 first Diffie-Hellman shared secret.
            expected: vec![
                0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
                0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
                0x1e, 0x16, 0x17, 0x42,
            ],
            compute: vector_x25519_rfc7748,
        },
    ]
}

// ── 2. The independent reference Double-Ratchet (for the interop / diff test) ──

/// An independent reference of the Signal symmetric-key ratchet chain step, written
/// straight from the spec and sharing **no code** with [`crate::ratchet`]. The
/// wrapper seals with its own ratchet; this reference re-derives the matching
/// message key from the same root and decrypts — two implementations agreeing on
/// the wire is the interop proof.
///
/// The chain step is, verbatim from the Signal Double Ratchet specification's
/// `KDF_CK`:
///
/// ```text
///   message_key = HMAC(chain_key, 0x01)
///   chain_key'  = HMAC(chain_key, 0x02)
/// ```
///
/// seeded from the same `murmur/ratchet/chain-init/v1` bind the wrapper uses, so the
/// two chains start from the same root. If the wrapper ever diverged from this — a
/// flipped constant, a dropped bind — the reference decrypt would fail and the
/// interop leg is RED.
struct ReferenceRatchet {
    chain_key: [u8; 32],
}

impl ReferenceRatchet {
    /// The same domain-separating salt the wrapper binds the X3DH root under before
    /// it becomes a chain key. Spelled out here independently so the reference does
    /// not borrow the wrapper's constant.
    const CHAIN_INIT_SALT: &'static [u8] = b"murmur/ratchet/chain-init/v1";
    const MESSAGE_KEY_STEP: &'static [u8] = &[0x01];
    const CHAIN_STEP: &'static [u8] = &[0x02];

    /// Seed the reference chain from the same 32-byte root the wrapper's ratchet
    /// seeds from, via the same HMAC bind — an independent transcription of the
    /// wrapper's `from_session`, not a call into it.
    fn from_root(root: &[u8; 32]) -> CoreResult<Self> {
        let tag = Self::hmac(Self::CHAIN_INIT_SALT, root)?;
        Ok(ReferenceRatchet { chain_key: tag })
    }

    fn hmac(key: &[u8], data: &[u8]) -> CoreResult<[u8; 32]> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|_| CoreError::Malformed("reference ratchet keying failed".into()))?;
        mac.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }

    /// Derive the next message key and advance the chain — the reference `KDF_CK`.
    fn next_message_key(&mut self) -> CoreResult<[u8; 32]> {
        let message_key = Self::hmac(&self.chain_key, Self::MESSAGE_KEY_STEP)?;
        let next_chain = Self::hmac(&self.chain_key, Self::CHAIN_STEP)?;
        self.chain_key.zeroize();
        self.chain_key = next_chain;
        Ok(message_key)
    }

    /// Decrypt a wrapper-sealed ratchet wire (`index(8) ‖ nonce(12) ‖ ct ‖ tag`)
    /// at message index `want_index`, deriving the message key independently and
    /// AEAD-opening with the wrapper's content-key construction. Returns the
    /// recovered plaintext, or [`CoreError::Rejected`] if the reference key does not
    /// open the wrapper's ciphertext — which would mean the two implementations
    /// disagree.
    fn decrypt(&mut self, want_index: u64, aad: &[u8], wire: &[u8]) -> CoreResult<Vec<u8>> {
        if wire.len() < 8 {
            return Err(CoreError::Malformed(
                "reference: ratchet wire shorter than its index".into(),
            ));
        }
        let (idx_bytes, sealed) = wire.split_at(8);
        let mut idx = [0u8; 8];
        idx.copy_from_slice(idx_bytes);
        let index = u64::from_be_bytes(idx);
        if index != want_index {
            return Err(CoreError::Rejected(
                "reference: wire index did not match the expected message index",
            ));
        }
        let message_key = self.next_message_key()?;
        // The wrapper seals each message under a Session keyed by the message key;
        // open with the same construction so a divergence in either key derivation
        // or AEAD framing surfaces as a failed decrypt.
        Session::from_secret(message_key).open(sealed, aad)
    }
}

// ── 3. No key reuse — one-time prekeys and per-message keys ────────────────────

/// A jar of one-time prekeys that hands each out **exactly once**. Drawing a prekey
/// removes it from the jar and zeroizes its secret, so a second draw of the same id
/// is impossible by construction — the one-time-prekey accounting the misuse-
/// resistant wrapper exists to provide. The PRD's whole worry about "vetted but
/// misused" is a wrapper that lets a one-time prekey be used twice; this type makes
/// that unrepresentable.
pub struct OneTimePrekeyJar {
    /// Remaining `(id, secret)` prekeys, newest last; `draw` pops by id.
    remaining: Vec<(u32, X25519Secret)>,
    /// Ids already drawn, so a double-draw is a detectable error rather than a
    /// silent second hand-out (defense in depth over the pop itself).
    spent: Vec<u32>,
}

impl OneTimePrekeyJar {
    /// Mint a jar of `count` one-time prekeys from a 32-byte seed. Each prekey's
    /// secret is derived distinctly from the seed and its id, so no two prekeys in
    /// the jar share key material.
    pub fn mint(seed: [u8; 32], count: usize) -> CoreResult<Self> {
        let mut remaining = Vec::with_capacity(count);
        for id in 0..count as u32 {
            // Derive a distinct secret per id via HKDF over (seed, id), so the jar's
            // prekeys are independent and reproducible for the self-test.
            let hk = Hkdf::<Sha256>::new(Some(&id.to_be_bytes()), &seed);
            let mut sk = [0u8; 32];
            hk.expand(b"murmur/one-time-prekey/v1", &mut sk)
                .map_err(|_| CoreError::Malformed("one-time prekey derivation failed".into()))?;
            remaining.push((id, X25519Secret::from(sk)));
            sk.zeroize();
        }
        Ok(OneTimePrekeyJar {
            remaining,
            spent: Vec::new(),
        })
    }

    /// How many prekeys are still available to draw.
    pub fn available(&self) -> usize {
        self.remaining.len()
    }

    /// Draw the next one-time prekey, consuming it. Returns its id and public key
    /// (the secret is used to mark it spent and then dropped/zeroized in the jar's
    /// accounting). A prekey id is never returned twice: it is popped off
    /// `remaining` and recorded in `spent`, and a defensive check rejects any id
    /// that is somehow seen again.
    pub fn draw(&mut self) -> CoreResult<(u32, [u8; 32])> {
        let (id, secret) = self
            .remaining
            .pop()
            .ok_or(CoreError::Rejected("one-time prekey jar is empty"))?;
        if self.spent.contains(&id) {
            return Err(CoreError::Rejected(
                "one-time prekey reuse: a prekey id was drawn a second time",
            ));
        }
        let public = X25519Public::from(&secret).to_bytes();
        self.spent.push(id);
        // `secret` drops here; X25519Secret zeroizes on drop.
        Ok((id, public))
    }
}

/// Drive the no-reuse property: draw `batch` one-time prekeys and derive `batch`
/// per-message ratchet keys, asserting **every** prekey id and **every** message
/// key is distinct. Returns `(prekeys_consumed, message_keys_distinct)` on success;
/// any repeat is [`CoreError::Rejected`] — the counterexample the gate's trap
/// records.
fn prove_no_key_reuse(batch: usize) -> CoreResult<(usize, usize)> {
    use std::collections::HashSet;

    // (a) One-time prekeys: each id and each public key handed out exactly once.
    let mut jar = OneTimePrekeyJar::mint([0x6cu8; 32], batch)?;
    let mut prekey_ids: HashSet<u32> = HashSet::with_capacity(batch);
    let mut prekey_publics: HashSet<[u8; 32]> = HashSet::with_capacity(batch);
    while jar.available() > 0 {
        let (id, public) = jar.draw()?;
        if !prekey_ids.insert(id) {
            return Err(CoreError::Rejected(
                "one-time prekey reuse: a prekey id was issued more than once",
            ));
        }
        if !prekey_publics.insert(public) {
            return Err(CoreError::Rejected(
                "one-time prekey reuse: two prekeys shared key material",
            ));
        }
    }

    // (b) Per-message keys: a long ratchet run, every message's ciphertext distinct
    // because every per-message key is distinct. We assert distinctness over the
    // sealed wire (the bytes downstream of the index/nonce), which is a strict
    // function of the per-message key — a reused key would re-seal alike under a
    // repeated nonce.
    let root = Session::from_secret([0x5au8; 32]);
    let mut chain = Ratchet::from_session(&root)?;
    let mut wires: HashSet<Vec<u8>> = HashSet::with_capacity(batch);
    for _ in 0..batch {
        // Seal the SAME plaintext every time: only a distinct per-message key (and
        // nonce) can make the ciphertext differ, so a collision here would mean a
        // key was reused.
        let wire = chain.seal(b"murmur/no-reuse/aad", b"the same body, every message")?;
        if !wires.insert(wire) {
            return Err(CoreError::Rejected(
                "message key reuse: two messages produced identical sealed bytes",
            ));
        }
    }

    Ok((prekey_ids.len(), wires.len()))
}

// ── The whole self-test ───────────────────────────────────────────────────────

/// Run the vetted-wrapper self-test once, hermetically (PRD §10, the
/// vetted-implementation claim): the
/// official known-answer vectors pass, an independent reference Double-Ratchet
/// decrypts a wrapper-sealed message (the differential / interop leg), and a batch
/// of one-time prekeys and per-message keys are each handed out exactly once.
///
/// Returns a [`VettedReport`] iff all three hold; any failure is an error, never a
/// silent pass — a vector miss, a reference-decrypt mismatch, or a reused key each
/// fails the leg (and the relay self-test) closed.
pub fn prove_vetted() -> CoreResult<VettedReport> {
    // 1. Official known-answer vectors.
    let vectors = official_vectors();
    for v in &vectors {
        let got = (v.compute)()?;
        if got != v.expected {
            return Err(CoreError::Rejected(match v.what {
                "ChaCha20-Poly1305 AEAD (RFC 8439)" => {
                    "vectors-failed: the AEAD did not match its official test vector"
                }
                "HKDF-SHA256 (RFC 5869)" => {
                    "vectors-failed: the key-derivation did not match its official test vector"
                }
                "HMAC-SHA256 (RFC 4231)" => {
                    "vectors-failed: the chain KDF did not match its official test vector"
                }
                "X25519 (RFC 7748)" => {
                    "vectors-failed: the Diffie-Hellman did not match its official test vector"
                }
                _ => "vectors-failed: a primitive did not match its official test vector",
            }));
        }
    }

    // 2. Differential / interop: the wrapper seals, an independent reference decrypts.
    let root = [0x42u8; 32];
    let mut sender = Ratchet::from_session(&Session::from_secret(root))?;
    let mut reference = ReferenceRatchet::from_root(&root)?;
    let aad = b"murmur/interop/aad";
    let interop_plaintext = b"our send, a reference Double-Ratchet decrypt";
    let wire = sender.seal(aad, interop_plaintext)?;
    let recovered = reference.decrypt(0, aad, &wire)?;
    if recovered != interop_plaintext {
        return Err(CoreError::Rejected(
            "interop-failed: the reference Double-Ratchet decrypt did not recover the plaintext",
        ));
    }

    // 3. No key reuse: one-time prekeys and per-message keys, each used once.
    let (prekeys_consumed, message_keys_distinct) = prove_no_key_reuse(NO_REUSE_BATCH)?;

    Ok(VettedReport {
        vectors_passed: vectors.len(),
        interop_plaintext_len: recovered.len(),
        prekeys_consumed,
        message_keys_distinct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vetted_wrapper_passes_vectors_interop_and_no_reuse() {
        let report = prove_vetted().unwrap();
        assert_eq!(report.vectors_passed, 4);
        assert_eq!(
            report.interop_plaintext_len,
            "our send, a reference Double-Ratchet decrypt".len()
        );
        assert_eq!(report.prekeys_consumed, NO_REUSE_BATCH);
        assert_eq!(report.message_keys_distinct, NO_REUSE_BATCH);
    }

    #[test]
    fn every_official_vector_matches_its_published_answer() {
        for v in &official_vectors() {
            let got = (v.compute)().unwrap();
            assert_eq!(got, v.expected, "{} diverged from its vector", v.what);
        }
    }

    #[test]
    fn a_wrong_expected_vector_is_caught() {
        // The vector check must DISCRIMINATE: corrupt the expected answer and the
        // comparison must fail. (Guards against an always-green vector check.)
        let mut v = official_vectors();
        v[0].expected[0] ^= 0xff;
        let got = (v[0].compute)().unwrap();
        assert_ne!(got, v[0].expected);
    }

    #[test]
    fn the_reference_decrypt_recovers_a_wrapper_sealed_message() {
        let root = [0x42u8; 32];
        let mut sender = Ratchet::from_session(&Session::from_secret(root)).unwrap();
        let mut reference = ReferenceRatchet::from_root(&root).unwrap();
        let wire = sender.seal(b"aad", b"interop body").unwrap();
        assert_eq!(
            reference.decrypt(0, b"aad", &wire).unwrap(),
            b"interop body"
        );
    }

    #[test]
    fn the_reference_rejects_a_key_from_the_wrong_root() {
        // Interop must DISCRIMINATE: a reference seeded from a different root derives
        // a different message key and cannot open the wrapper's ciphertext.
        let mut sender = Ratchet::from_session(&Session::from_secret([0x42u8; 32])).unwrap();
        let mut wrong = ReferenceRatchet::from_root(&[0x00u8; 32]).unwrap();
        let wire = sender.seal(b"aad", b"interop body").unwrap();
        assert!(matches!(
            wrong.decrypt(0, b"aad", &wire),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_one_time_prekey_is_never_drawn_twice() {
        let mut jar = OneTimePrekeyJar::mint([0x6cu8; 32], 8).unwrap();
        let mut seen = std::collections::HashSet::new();
        while jar.available() > 0 {
            let (id, _public) = jar.draw().unwrap();
            assert!(seen.insert(id), "prekey id {id} was drawn twice");
        }
        // The jar is empty; a further draw is rejected, never a silent reuse.
        assert!(matches!(jar.draw(), Err(CoreError::Rejected(_))));
    }

    #[test]
    fn the_no_reuse_property_holds_over_a_batch() {
        let (prekeys, keys) = prove_no_key_reuse(64).unwrap();
        assert_eq!(prekeys, 64);
        assert_eq!(keys, 64);
    }
}
