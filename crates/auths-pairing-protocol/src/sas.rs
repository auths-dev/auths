//! SAS (Short Authentication String) derivation and transport encryption.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::ProtocolError;

/// 256-emoji wordlist — visually distinct, renders on macOS/Windows/Linux terminals.
pub const SAS_EMOJI: [&str; 256] = [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    "🐧", "🐦", "🦆", "🦅", "🦉", "🐺", "🐗", "🐴", "🦄", "🐝", "🐛", "🦋", "🐌", "🐞", "🐜", "🪲",
    "🐢", "🐍", "🦎", "🦂", "🐙", "🦑", "🦐", "🦞", "🐠", "🐡", "🐬", "🦈", "🐳", "🐋", "🐊", "🐆",
    "🐅", "🦓", "🦍", "🦧", "🐘", "🦛", "🦏", "🐪", "🦒", "🦘", "🦬", "🐃", "🐂", "🐄", "🐎", "🐖",
    "🐏", "🐑", "🐐", "🦌", "🐕", "🐩", "🦮", "🐈", "🐓", "🦃", "🦤", "🦚", "🦜", "🦢", "🦩", "🕊️",
    "🐇", "🦝", "🦨", "🦡", "🦫", "🦦", "🦥", "🐁", "🐀", "🐿️", "🦔", "🌵", "🎄", "🌲", "🌳", "🌴",
    "🪵", "🌱", "🌿", "☘️", "🍀", "🎍", "🪴", "🎋", "🍃", "🍂", "🍁", "🌾", "🌺", "🌻", "🌹", "🥀",
    "🌷", "🌼", "💐", "🍄", "🌰", "🎃", "🌎", "🌍", "🌏", "🌕", "🌖", "🌗", "🌘", "🌑", "🌒", "🌓",
    "🌔", "🌙", "⭐", "🌟", "💫", "✨", "☀️", "🌤️", "⛅", "🌥️", "🌦️", "🌧️", "⛈️", "🌩️", "🌨️", "❄️",
    "☃️", "⛄", "🌬️", "💨", "🌪️", "🌫️", "🌊", "💧", "💦", "🔥", "🎯", "🏀", "🏈", "⚾", "🥎", "🎾",
    "🏐", "🏉", "🥏", "🎱", "🏓", "🏸", "🏒", "🥊", "🎿", "⛷️", "🏂", "🪂", "🏋️", "🤸", "⛹️", "🤺",
    "🏇", "🧘", "🏄", "🏊", "🚣", "🧗", "🚴", "🏆", "🥇", "🥈", "🥉", "🏅", "🎖️", "🎪", "🎨", "🎭",
    "🎹", "🥁", "🎷", "🎺", "🎸", "🪕", "🎻", "🎬", "🎮", "🕹️", "🎲", "🧩", "🔮", "🪄", "🧿", "🎰",
    "🚀", "✈️", "🛸", "🚁", "🛶", "⛵", "🚤", "🛥️", "🚂", "🚃", "🚄", "🚅", "🚆", "🚇", "🚈", "🚊",
    "🏠", "🏡", "🏢", "🏣", "🏤", "🏥", "🏦", "🏨", "🏩", "🏪", "🏫", "🏬", "🏭", "🏯", "🏰", "💒",
    "🗼", "🗽", "⛪", "🕌", "🛕", "🕍", "⛩️", "🕋", "⛲", "⛺", "🌁", "🗻", "🌋", "🗾", "🏕️", "🎠",
];

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Derive 8 SAS bytes from the ECDH shared secret, both ephemeral public keys, and short code.
///
/// Args:
/// * `shared_secret`: The 32-byte X25519 shared secret.
/// * `initiator_pub`: The initiator's X25519 ephemeral public key.
/// * `responder_pub`: The responder's X25519 ephemeral public key.
/// * `short_code`: The session's short code (binds SAS to session).
///
/// Usage:
/// ```ignore
/// let sas = derive_sas(&shared_secret, &init_pub, &resp_pub, "ABC123");
/// ```
pub fn derive_sas(
    shared_secret: &[u8; 32],
    initiator_pub: &[u8],
    responder_pub: &[u8],
    short_code: &str,
) -> [u8; 8] {
    let salt = build_salt(initiator_pub, responder_pub);
    let info = build_info(b"auths-pairing-sas-v1", short_code);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut out = [0u8; 8];
    // 8 bytes is always within HKDF-SHA256 output limit (max 8160 bytes)
    let _ = hk.expand(&info, &mut out);
    out
}

/// Format SAS bytes 0-3 as 4 emoji separated by double spaces.
pub fn format_sas_emoji(sas_bytes: &[u8; 8]) -> String {
    sas_bytes[..4]
        .iter()
        .map(|&b| SAS_EMOJI[b as usize])
        .collect::<Vec<_>>()
        .join("  ")
}

/// Format SAS bytes 4-7 as a 6-digit numeric code `XXX-XXX`.
pub fn format_sas_numeric(sas_bytes: &[u8; 8]) -> String {
    let val =
        u32::from_be_bytes([sas_bytes[4], sas_bytes[5], sas_bytes[6], sas_bytes[7]]) % 1_000_000;
    format!("{:03}-{:03}", val / 1000, val % 1000)
}

/// Single-use transport encryption key derived from the ECDH shared secret.
///
/// Wraps a 32-byte key in `Zeroizing` and enforces single use via move semantics.
/// `encrypt()` takes `self` by value — a second call is a compile error.
pub struct TransportKey(Zeroizing<[u8; 32]>);

impl TransportKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    /// Encrypt plaintext with ChaCha20-Poly1305. Consumes the key (single use).
    ///
    /// Output format: `[nonce:12][ciphertext+tag]`
    pub fn encrypt(mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.0)
            .map_err(|_| ProtocolError::EncryptionFailed("invalid key".into()))?;
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| ProtocolError::EncryptionFailed("encryption failed".into()))?;

        self.0.zeroize();

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Access the raw key bytes (for the responder side that needs them for decryption).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Decrypt ciphertext produced by `TransportKey::encrypt()`.
///
/// Args:
/// * `ciphertext`: The `[nonce:12][ciphertext+tag]` blob.
/// * `transport_key`: The 32-byte transport key.
pub fn decrypt_from_transport(
    ciphertext: &[u8],
    transport_key: &[u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(ProtocolError::DecryptionFailed(
            "ciphertext too short".into(),
        ));
    }
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(transport_key)
        .map_err(|_| ProtocolError::DecryptionFailed("invalid key".into()))?;
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| ProtocolError::DecryptionFailed("decryption failed".into()))
}

/// Derive a single-use transport key from the ECDH shared secret.
///
/// Uses the same HKDF salt (both ephemeral public keys) but a different info string
/// for domain separation from the SAS derivation.
///
/// Args:
/// * `shared_secret`: The 32-byte X25519 shared secret.
/// * `initiator_pub`: The initiator's X25519 ephemeral public key.
/// * `responder_pub`: The responder's X25519 ephemeral public key.
/// * `short_code`: The session's short code.
pub fn derive_transport_key(
    shared_secret: &[u8; 32],
    initiator_pub: &[u8],
    responder_pub: &[u8],
    short_code: &str,
) -> TransportKey {
    let salt = build_salt(initiator_pub, responder_pub);
    let info = build_info(b"auths-pairing-transport-v1", short_code);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0u8; 32];
    // 32 bytes is always within HKDF-SHA256 output limit (max 8160 bytes)
    let _ = hk.expand(&info, &mut key);
    TransportKey::new(key)
}

fn build_salt(initiator_pub: &[u8], responder_pub: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(initiator_pub.len() + responder_pub.len());
    salt.extend_from_slice(initiator_pub);
    salt.extend_from_slice(responder_pub);
    salt
}

fn build_info(domain: &[u8], short_code: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain.len() + short_code.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(short_code.as_bytes());
    info
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const TEST_SECRET: [u8; 32] = [0x42; 32];
    const TEST_INIT_PUB: [u8; 32] = [0x01; 32];
    const TEST_RESP_PUB: [u8; 32] = [0x02; 32];
    const TEST_SHORT_CODE: &str = "ABC123";

    #[test]
    fn sas_determinism() {
        let a = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let b = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn sas_divergence_different_secret() {
        let a = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let b = derive_sas(&[0xFF; 32], &TEST_INIT_PUB, &TEST_RESP_PUB, TEST_SHORT_CODE);
        assert_ne!(a, b);
    }

    #[test]
    fn sas_divergence_different_pubkeys() {
        let a = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let b = derive_sas(&TEST_SECRET, &[0x03; 32], &TEST_RESP_PUB, TEST_SHORT_CODE);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation() {
        let sas = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let tk = derive_transport_key(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        assert_ne!(&sas[..], &tk.as_bytes()[..8]);
    }

    #[test]
    fn emoji_format() {
        let sas = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let emoji = format_sas_emoji(&sas);
        let parts: Vec<&str> = emoji.split("  ").collect();
        assert_eq!(parts.len(), 4);
        for part in &parts {
            assert!(SAS_EMOJI.contains(part), "emoji {part} not in wordlist");
        }
    }

    #[test]
    fn numeric_format() {
        let sas = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let numeric = format_sas_numeric(&sas);
        let re = regex_lite::Regex::new(r"^\d{3}-\d{3}$").unwrap();
        assert!(re.is_match(&numeric), "numeric format wrong: {numeric}");
    }

    #[test]
    fn emoji_wordlist_integrity() {
        assert_eq!(SAS_EMOJI.len(), 256);
        let set: HashSet<&str> = SAS_EMOJI.iter().copied().collect();
        assert_eq!(set.len(), 256, "duplicate emoji in wordlist");
    }

    #[test]
    fn transport_encryption_roundtrip() {
        let tk = derive_transport_key(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let key_bytes = *tk.as_bytes();
        let plaintext = b"test attestation payload";
        let ciphertext = tk.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
        let decrypted = decrypt_from_transport(&ciphertext, &key_bytes).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn transport_encryption_wrong_key() {
        let tk = derive_transport_key(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let ciphertext = tk.encrypt(b"secret").unwrap();
        let result = decrypt_from_transport(&ciphertext, &[0xFF; 32]);
        assert!(matches!(result, Err(ProtocolError::DecryptionFailed(_))));
    }

    #[test]
    fn sas_test_vector() {
        // Hardcoded test vector to prevent implementation drift.
        // If this fails, the HKDF inputs or info string changed.
        let sas = derive_sas(
            &TEST_SECRET,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        assert_eq!(sas, [189, 58, 161, 90, 151, 221, 243, 229]);
        assert_eq!(format_sas_emoji(&sas), "🎪  🦬  🏉  🦔");
        assert_eq!(format_sas_numeric(&sas), "905-509");
    }

    #[test]
    fn mitm_simulation_produces_different_sas() {
        // MITM has two separate shared secrets (one with each party).
        // Even with the same short_code, the SAS values diverge because
        // the shared secrets are different.
        let real_shared = [0x42u8; 32];
        let attacker_shared_a = [0xAA; 32];
        let attacker_shared_b = [0xBB; 32];

        let sas_real = derive_sas(
            &real_shared,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );
        let sas_mitm_a = derive_sas(
            &attacker_shared_a,
            &TEST_INIT_PUB,
            &[0x03; 32],
            TEST_SHORT_CODE,
        );
        let sas_mitm_b = derive_sas(
            &attacker_shared_b,
            &[0x04; 32],
            &TEST_RESP_PUB,
            TEST_SHORT_CODE,
        );

        assert_ne!(sas_real, sas_mitm_a);
        assert_ne!(sas_real, sas_mitm_b);
        assert_ne!(sas_mitm_a, sas_mitm_b);
    }

    #[test]
    fn transport_key_decrypt_short_ciphertext() {
        let result = decrypt_from_transport(&[0u8; 10], &[0u8; 32]);
        assert!(matches!(result, Err(ProtocolError::DecryptionFailed(_))));
    }
}
