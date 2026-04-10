//! SSHSIG envelope parsing for SSH signature verification.
//!
//! Parses `-----BEGIN SSH SIGNATURE-----` PEM blocks into their binary
//! components per the [SSHSIG protocol](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig).
//!
//! Supports both `ssh-ed25519` and `ecdsa-sha2-nistp256` key types.

use base64::Engine;

use crate::commit_error::CommitVerificationError;
use crate::core::DevicePublicKey;

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const ED25519_KEY_TYPE: &str = "ssh-ed25519";
const ECDSA_P256_KEY_TYPE: &str = "ecdsa-sha2-nistp256";
const PEM_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const PEM_END: &str = "-----END SSH SIGNATURE-----";

/// SSH key algorithm detected from the SSHSIG envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyType {
    /// Ed25519 (32-byte key, 64-byte signature).
    Ed25519,
    /// ECDSA with NIST P-256 (uncompressed 65-byte key, 64-byte r||s signature).
    EcdsaP256,
}

/// Parsed SSHSIG envelope fields.
///
/// Usage:
/// ```ignore
/// let envelope = parse_sshsig_pem(pem_text)?;
/// assert_eq!(envelope.namespace, "git");
/// ```
#[derive(Debug)]
pub struct SshSigEnvelope {
    /// The namespace the signature was created for (e.g. "git").
    pub namespace: String,
    /// The hash algorithm used (e.g. "sha512" or "sha256").
    pub hash_algorithm: String,
    /// The SSH key algorithm used.
    pub key_type: SshKeyType,
    /// Public key extracted from the envelope (32 bytes Ed25519, or 65 bytes P-256 uncompressed).
    pub public_key: DevicePublicKey,
    /// Raw signature bytes (64 bytes for both Ed25519 and P-256 r||s).
    pub signature: Vec<u8>,
}

/// Parse an SSH signature PEM block into its components.
///
/// Args:
/// * `pem`: The full PEM text including BEGIN/END markers.
///
/// Usage:
/// ```ignore
/// let envelope = parse_sshsig_pem(pem_text)?;
/// ```
pub fn parse_sshsig_pem(pem: &str) -> Result<SshSigEnvelope, CommitVerificationError> {
    let b64_body = extract_pem_body(pem)?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64_body)
        .map_err(|e| CommitVerificationError::SshSigParseFailed(format!("base64 decode: {e}")))?;
    parse_sshsig_binary(&der)
}

fn extract_pem_body(pem: &str) -> Result<String, CommitVerificationError> {
    let mut in_body = false;
    let mut body = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == PEM_BEGIN {
            in_body = true;
            continue;
        }
        if trimmed == PEM_END {
            break;
        }
        if in_body {
            body.push_str(trimmed);
        }
    }

    if body.is_empty() {
        return Err(CommitVerificationError::SshSigParseFailed(
            "no PEM body found".into(),
        ));
    }
    Ok(body)
}

fn parse_sshsig_binary(data: &[u8]) -> Result<SshSigEnvelope, CommitVerificationError> {
    let mut cursor = Cursor::new(data);

    // Magic preamble: raw "SSHSIG" (6 bytes, NOT length-prefixed)
    let magic = cursor.read_raw(6)?;
    if magic != SSHSIG_MAGIC {
        return Err(CommitVerificationError::SshSigParseFailed(
            "invalid magic bytes".into(),
        ));
    }

    // Version: u32 BE
    let version = cursor.read_u32()?;
    if version != SSHSIG_VERSION {
        return Err(CommitVerificationError::SshSigParseFailed(format!(
            "unsupported version: {version}"
        )));
    }

    // Public key blob (SSH wire format, length-prefixed)
    let pubkey_blob = cursor.read_string()?;
    let (key_type, public_key) = parse_pubkey_blob(&pubkey_blob)?;

    // Namespace
    let namespace_bytes = cursor.read_string()?;
    let namespace = String::from_utf8(namespace_bytes).map_err(|e| {
        CommitVerificationError::SshSigParseFailed(format!("invalid namespace UTF-8: {e}"))
    })?;
    if namespace.is_empty() {
        return Err(CommitVerificationError::SshSigParseFailed(
            "empty namespace".into(),
        ));
    }

    // Reserved (ignored)
    let _reserved = cursor.read_string()?;

    // Hash algorithm
    let hash_algo_bytes = cursor.read_string()?;
    let hash_algorithm = String::from_utf8(hash_algo_bytes).map_err(|e| {
        CommitVerificationError::SshSigParseFailed(format!("invalid hash algorithm UTF-8: {e}"))
    })?;

    // Signature blob (SSH wire format, length-prefixed)
    let sig_blob = cursor.read_string()?;
    let signature = parse_sig_blob(&sig_blob, key_type)?;

    Ok(SshSigEnvelope {
        namespace,
        hash_algorithm,
        key_type,
        public_key,
        signature,
    })
}

fn parse_pubkey_blob(
    blob: &[u8],
) -> Result<(SshKeyType, DevicePublicKey), CommitVerificationError> {
    let mut cursor = Cursor::new(blob);

    let key_type_bytes = cursor.read_string()?;
    let key_type_str = String::from_utf8(key_type_bytes).map_err(|e| {
        CommitVerificationError::SshSigParseFailed(format!("invalid key type UTF-8: {e}"))
    })?;

    match key_type_str.as_str() {
        ED25519_KEY_TYPE => {
            let raw_key = cursor.read_string()?;
            if raw_key.len() != 32 {
                return Err(CommitVerificationError::SshSigParseFailed(format!(
                    "invalid Ed25519 key length: expected 32, got {}",
                    raw_key.len()
                )));
            }
            Ok((
                SshKeyType::Ed25519,
                DevicePublicKey::try_new(auths_crypto::CurveType::Ed25519, &raw_key)
                    .map_err(|e| CommitVerificationError::SshSigParseFailed(e.to_string()))?,
            ))
        }
        ECDSA_P256_KEY_TYPE => {
            let curve_name_bytes = cursor.read_string()?;
            let curve_name = String::from_utf8(curve_name_bytes).map_err(|e| {
                CommitVerificationError::SshSigParseFailed(format!("invalid curve name UTF-8: {e}"))
            })?;
            if curve_name != "nistp256" {
                return Err(CommitVerificationError::SshSigParseFailed(format!(
                    "unexpected curve name: {curve_name}"
                )));
            }
            let ec_point = cursor.read_string()?;
            if ec_point.len() != 65 || ec_point[0] != 0x04 {
                return Err(CommitVerificationError::SshSigParseFailed(format!(
                    "invalid P-256 EC point: expected 65-byte uncompressed (0x04 prefix), got {} bytes",
                    ec_point.len()
                )));
            }
            Ok((
                SshKeyType::EcdsaP256,
                DevicePublicKey::try_new(auths_crypto::CurveType::P256, &ec_point)
                    .map_err(|e| CommitVerificationError::SshSigParseFailed(e.to_string()))?,
            ))
        }
        other => Err(CommitVerificationError::UnsupportedKeyType {
            found: other.to_string(),
        }),
    }
}

fn parse_sig_blob(
    blob: &[u8],
    expected_key_type: SshKeyType,
) -> Result<Vec<u8>, CommitVerificationError> {
    let mut cursor = Cursor::new(blob);

    let sig_type_bytes = cursor.read_string()?;
    let sig_type = String::from_utf8(sig_type_bytes).map_err(|e| {
        CommitVerificationError::SshSigParseFailed(format!("invalid sig type UTF-8: {e}"))
    })?;

    match expected_key_type {
        SshKeyType::Ed25519 => {
            if sig_type != ED25519_KEY_TYPE {
                return Err(CommitVerificationError::UnsupportedKeyType { found: sig_type });
            }
            let raw_sig = cursor.read_string()?;
            if raw_sig.len() != 64 {
                return Err(CommitVerificationError::SshSigParseFailed(format!(
                    "invalid Ed25519 signature length: expected 64, got {}",
                    raw_sig.len()
                )));
            }
            Ok(raw_sig)
        }
        SshKeyType::EcdsaP256 => {
            if sig_type != ECDSA_P256_KEY_TYPE {
                return Err(CommitVerificationError::UnsupportedKeyType { found: sig_type });
            }
            let inner_blob = cursor.read_string()?;
            parse_ecdsa_sig_inner(&inner_blob)
        }
    }
}

/// Parse ECDSA signature inner blob (mpint r + mpint s) into raw 64-byte r||s.
fn parse_ecdsa_sig_inner(blob: &[u8]) -> Result<Vec<u8>, CommitVerificationError> {
    let mut cursor = Cursor::new(blob);
    let r = mpint_to_fixed(&mut cursor, 32)?;
    let s = mpint_to_fixed(&mut cursor, 32)?;
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    Ok(raw)
}

/// Read an SSH mpint and convert to a fixed-width big-endian byte array.
fn mpint_to_fixed(
    cursor: &mut Cursor<'_>,
    size: usize,
) -> Result<Vec<u8>, CommitVerificationError> {
    let bytes = cursor.read_string()?;
    let trimmed = if !bytes.is_empty() && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        &bytes[..]
    };
    if trimmed.len() > size {
        return Err(CommitVerificationError::SshSigParseFailed(format!(
            "mpint too large: {} bytes, max {size}",
            trimmed.len()
        )));
    }
    let mut fixed = vec![0u8; size];
    let offset = size - trimmed.len();
    fixed[offset..].copy_from_slice(trimmed);
    Ok(fixed)
}

// Minimal binary cursor for SSH wire format parsing.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_raw(&mut self, n: usize) -> Result<&'a [u8], CommitVerificationError> {
        if self.pos + n > self.data.len() {
            return Err(CommitVerificationError::SshSigParseFailed(format!(
                "unexpected EOF at offset {} (need {n} bytes, have {})",
                self.pos,
                self.data.len() - self.pos
            )));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32, CommitVerificationError> {
        let bytes = self.read_raw(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_string(&mut self) -> Result<Vec<u8>, CommitVerificationError> {
        let len = self.read_u32()? as usize;
        Ok(self.read_raw(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_sshsig(
        key: &[u8; 32],
        sig: &[u8; 64],
        namespace: &str,
        hash_algo: &str,
    ) -> Vec<u8> {
        let mut blob = Vec::new();

        // Magic
        blob.extend_from_slice(b"SSHSIG");
        // Version
        blob.extend_from_slice(&1u32.to_be_bytes());

        // Public key blob
        let mut pk_blob = Vec::new();
        let kt = b"ssh-ed25519";
        pk_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pk_blob.extend_from_slice(kt);
        pk_blob.extend_from_slice(&(key.len() as u32).to_be_bytes());
        pk_blob.extend_from_slice(key);
        blob.extend_from_slice(&(pk_blob.len() as u32).to_be_bytes());
        blob.extend_from_slice(&pk_blob);

        // Namespace
        blob.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
        blob.extend_from_slice(namespace.as_bytes());

        // Reserved
        blob.extend_from_slice(&0u32.to_be_bytes());

        // Hash algorithm
        blob.extend_from_slice(&(hash_algo.len() as u32).to_be_bytes());
        blob.extend_from_slice(hash_algo.as_bytes());

        // Signature blob
        let mut sig_blob = Vec::new();
        let st = b"ssh-ed25519";
        sig_blob.extend_from_slice(&(st.len() as u32).to_be_bytes());
        sig_blob.extend_from_slice(st);
        sig_blob.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        sig_blob.extend_from_slice(sig);
        blob.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes());
        blob.extend_from_slice(&sig_blob);

        blob
    }

    fn wrap_pem(binary: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(binary);
        let wrapped: String = b64
            .chars()
            .collect::<Vec<_>>()
            .chunks(70)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN SSH SIGNATURE-----\n{wrapped}\n-----END SSH SIGNATURE-----\n")
    }

    #[test]
    fn parse_valid_envelope() {
        let key = [0x42u8; 32];
        let sig = [0xABu8; 64];
        let binary = build_test_sshsig(&key, &sig, "git", "sha512");
        let pem = wrap_pem(&binary);

        let envelope = parse_sshsig_pem(&pem).unwrap();
        assert_eq!(envelope.namespace, "git");
        assert_eq!(envelope.hash_algorithm, "sha512");
        assert_eq!(
            envelope.public_key.curve(),
            auths_crypto::CurveType::Ed25519
        );
        assert_eq!(envelope.public_key.as_bytes(), &key);
        assert_eq!(envelope.signature, sig);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut binary = build_test_sshsig(&[0; 32], &[0; 64], "git", "sha512");
        binary[0] = b'X'; // corrupt magic
        let pem = wrap_pem(&binary);

        let err = parse_sshsig_pem(&pem).unwrap_err();
        assert!(err.to_string().contains("invalid magic"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut binary = build_test_sshsig(&[0; 32], &[0; 64], "git", "sha512");
        // Version is at offset 6..10, set to 2
        binary[6..10].copy_from_slice(&2u32.to_be_bytes());
        let pem = wrap_pem(&binary);

        let err = parse_sshsig_pem(&pem).unwrap_err();
        assert!(err.to_string().contains("unsupported version"));
    }

    #[test]
    fn rejects_empty_namespace() {
        let binary = build_test_sshsig(&[0; 32], &[0; 64], "", "sha512");
        let pem = wrap_pem(&binary);

        let err = parse_sshsig_pem(&pem).unwrap_err();
        assert!(err.to_string().contains("empty namespace"));
    }

    #[test]
    fn rejects_non_ed25519_key_type() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"SSHSIG");
        blob.extend_from_slice(&1u32.to_be_bytes());

        // RSA public key blob
        let mut pk_blob = Vec::new();
        let kt = b"ssh-rsa";
        pk_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pk_blob.extend_from_slice(kt);
        let fake_key = [0u8; 32];
        pk_blob.extend_from_slice(&(fake_key.len() as u32).to_be_bytes());
        pk_blob.extend_from_slice(&fake_key);
        blob.extend_from_slice(&(pk_blob.len() as u32).to_be_bytes());
        blob.extend_from_slice(&pk_blob);

        let pem = wrap_pem(&blob);
        let err = parse_sshsig_pem(&pem).unwrap_err();
        match err {
            CommitVerificationError::UnsupportedKeyType { found } => {
                assert_eq!(found, "ssh-rsa");
            }
            other => panic!("expected UnsupportedKeyType, got: {other}"),
        }
    }

    #[test]
    fn rejects_empty_pem() {
        let err = parse_sshsig_pem("").unwrap_err();
        assert!(err.to_string().contains("no PEM body"));
    }

    #[test]
    fn rejects_truncated_data() {
        let binary = build_test_sshsig(&[0; 32], &[0; 64], "git", "sha512");
        let pem = wrap_pem(&binary[..20]); // truncate
        let err = parse_sshsig_pem(&pem).unwrap_err();
        assert!(err.to_string().contains("unexpected EOF"));
    }
}
