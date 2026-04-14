//! SSH cryptographic operations: key parsing, SSHSIG creation, and wire-format encoding.

mod encoding;
mod error;
mod keys;
mod signatures;

pub use encoding::{encode_mpint_for_agent, encode_ssh_pubkey, encode_ssh_signature};
pub use error::CryptoError;
pub use keys::{
    SecureSeed, build_ed25519_pkcs8_v2_from_seed, extract_pubkey_from_key_bytes,
    extract_seed_from_pkcs8,
};
pub use signatures::{construct_sshsig_pem, construct_sshsig_signed_data, create_sshsig};
