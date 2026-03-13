use base64::{Engine, engine::general_purpose::STANDARD};

use crate::error::TransparencyError;
use crate::types::MerkleHash;

/// Ed25519 algorithm byte per C2SP signed-note spec.
const ALG_ED25519: u8 = 0x01;

/// Compute a C2SP key ID from a key name and Ed25519 public key.
///
/// `key_id = SHA-256(key_name + "\n" + 0x01 + pubkey)[0..4]`
///
/// Args:
/// * `key_name` — The log's key name (e.g., "auths.dev/log").
/// * `pubkey` — 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let key_id = compute_key_id("auths.dev/log", &pubkey_bytes);
/// ```
pub fn compute_key_id(key_name: &str, pubkey: &[u8; 32]) -> [u8; 4] {
    let mut data = Vec::with_capacity(key_name.len() + 1 + 1 + 32);
    data.extend_from_slice(key_name.as_bytes());
    data.push(b'\n');
    data.push(ALG_ED25519);
    data.extend_from_slice(pubkey);

    let hash = MerkleHash::sha256(&data);
    let mut id = [0u8; 4];
    id.copy_from_slice(&hash.as_bytes()[..4]);
    id
}

/// Build a C2SP signature line: `— <key_name> <base64(alg_byte + key_id + signature)>`.
///
/// Args:
/// * `key_name` — The signer's key name.
/// * `key_id` — 4-byte key ID from [`compute_key_id`].
/// * `signature` — 64-byte Ed25519 signature.
///
/// Usage:
/// ```ignore
/// let line = build_signature_line("auths.dev/log", &key_id, &sig_bytes);
/// ```
pub fn build_signature_line(key_name: &str, key_id: &[u8; 4], signature: &[u8; 64]) -> String {
    let mut sig_data = Vec::with_capacity(1 + 4 + 64);
    sig_data.push(ALG_ED25519);
    sig_data.extend_from_slice(key_id);
    sig_data.extend_from_slice(signature);
    let encoded = STANDARD.encode(&sig_data);
    format!("\u{2014} {key_name} {encoded}\n")
}

/// Parse a C2SP signed note into its body and signature components.
///
/// A signed note has the format:
/// ```text
/// <body lines>\n
/// \n
/// — <key_name> <base64(alg + key_id + sig)>\n
/// ```
///
/// Args:
/// * `note` — The full signed note text.
///
/// Usage:
/// ```ignore
/// let (body, sigs) = parse_signed_note(note_text)?;
/// ```
pub fn parse_signed_note(note: &str) -> Result<(String, Vec<NoteSignature>), TransparencyError> {
    // Signature lines start with em-dash (U+2014)
    let sig_marker = "\u{2014} ";

    let mut body_end = None;
    let mut sig_start = None;

    for (i, line) in note.lines().enumerate() {
        if line.starts_with(sig_marker) && sig_start.is_none() {
            sig_start = Some(i);
            if body_end.is_none() {
                body_end = Some(i);
            }
        }
    }

    let lines: Vec<&str> = note.lines().collect();

    let body_end_idx = body_end
        .ok_or_else(|| TransparencyError::InvalidNote("no signature lines found".into()))?;

    // Body is everything before the first signature line, trimming trailing empty line
    let mut body_lines = &lines[..body_end_idx];
    if body_lines.last() == Some(&"") {
        body_lines = &body_lines[..body_lines.len() - 1];
    }
    let body = body_lines.join("\n") + "\n";

    let mut signatures = Vec::new();
    for line in &lines[body_end_idx..] {
        if let Some(rest) = line.strip_prefix(sig_marker) {
            let sig = parse_signature_line(rest)?;
            signatures.push(sig);
        }
    }

    Ok((body, signatures))
}

/// A parsed signature from a signed note.
#[derive(Debug, Clone)]
pub struct NoteSignature {
    /// The signer's key name.
    pub key_name: String,
    /// Algorithm byte (0x01 for Ed25519).
    pub algorithm: u8,
    /// 4-byte key ID.
    pub key_id: [u8; 4],
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

fn parse_signature_line(line: &str) -> Result<NoteSignature, TransparencyError> {
    let space_idx = line
        .find(' ')
        .ok_or_else(|| TransparencyError::InvalidNote("malformed signature line".into()))?;

    let key_name = &line[..space_idx];
    let b64 = &line[space_idx + 1..];

    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|e| TransparencyError::InvalidNote(format!("base64 decode: {e}")))?;

    if raw.len() < 5 {
        return Err(TransparencyError::InvalidNote(
            "signature data too short".into(),
        ));
    }

    let algorithm = raw[0];
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&raw[1..5]);
    let signature = raw[5..].to_vec();

    Ok(NoteSignature {
        key_name: key_name.to_string(),
        algorithm,
        key_id,
        signature,
    })
}

/// Serialize a signed note from body text and signatures.
///
/// Args:
/// * `body` — The note body (must end with `\n`).
/// * `signatures` — Formatted signature lines from [`build_signature_line`].
///
/// Usage:
/// ```ignore
/// let note = serialize_signed_note(&body, &[sig_line]);
/// ```
pub fn serialize_signed_note(body: &str, signatures: &[String]) -> String {
    let mut out =
        String::with_capacity(body.len() + signatures.iter().map(|s| s.len()).sum::<usize>() + 1);
    out.push_str(body);
    out.push('\n');
    for sig in signatures {
        out.push_str(sig);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_computation() {
        let pubkey = [0xab; 32];
        let key_id = compute_key_id("auths.dev/log", &pubkey);
        assert_eq!(key_id.len(), 4);

        // Deterministic
        let key_id2 = compute_key_id("auths.dev/log", &pubkey);
        assert_eq!(key_id, key_id2);

        // Different key name → different ID
        let key_id3 = compute_key_id("other.dev/log", &pubkey);
        assert_ne!(key_id, key_id3);
    }

    #[test]
    fn signature_line_format() {
        let key_id = [0x01, 0x02, 0x03, 0x04];
        let sig = [0xaa; 64];
        let line = build_signature_line("auths.dev/log", &key_id, &sig);

        assert!(line.starts_with("\u{2014} auths.dev/log "));
        assert!(line.ends_with('\n'));

        // Verify the base64 decodes to alg + key_id + sig
        let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
        let decoded = STANDARD.decode(parts[2]).unwrap();
        assert_eq!(decoded[0], ALG_ED25519);
        assert_eq!(&decoded[1..5], &key_id);
        assert_eq!(&decoded[5..], &sig);
    }

    #[test]
    fn signed_note_roundtrip() {
        let body = "auths.dev/log\n42\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n";
        let key_id = [0x01, 0x02, 0x03, 0x04];
        let sig = [0xcc; 64];
        let sig_line = build_signature_line("auths.dev/log", &key_id, &sig);
        let note = serialize_signed_note(body, &[sig_line]);

        let (parsed_body, parsed_sigs) = parse_signed_note(&note).unwrap();
        assert_eq!(parsed_body, body);
        assert_eq!(parsed_sigs.len(), 1);
        assert_eq!(parsed_sigs[0].key_name, "auths.dev/log");
        assert_eq!(parsed_sigs[0].algorithm, ALG_ED25519);
        assert_eq!(parsed_sigs[0].key_id, key_id);
        assert_eq!(parsed_sigs[0].signature, sig.to_vec());
    }

    #[test]
    fn parse_note_rejects_no_signatures() {
        let note = "just body\nno sigs\n";
        assert!(parse_signed_note(note).is_err());
    }
}
