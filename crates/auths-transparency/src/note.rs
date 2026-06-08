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

/// Compute a C2SP key ID for an **ECDSA-P256** signer from its DER-encoded SPKI key.
///
/// Per the C2SP signed-note spec the ECDSA key ID is the truncated SHA-256 of the
/// DER-encoded SubjectPublicKeyInfo — a DIFFERENT input from the Ed25519 formula
/// in [`compute_key_id`] (which hashes `name || 0x0A || 0x01 || pubkey`). Computing
/// an ECDSA hint with the Ed25519 formula yields a key ID that never matches the
/// signature line, so the signer's key can never be selected.
///
/// Args:
/// * `spki_der` — DER-encoded SubjectPublicKeyInfo for the ECDSA-P256 key.
///
/// Usage:
/// ```ignore
/// let key_id = compute_ecdsa_key_id(&rekor_spki_der);
/// ```
pub fn compute_ecdsa_key_id(spki_der: &[u8]) -> [u8; 4] {
    let hash = MerkleHash::sha256(spki_der);
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
    let (body, sig_lines) = split_note(note)?;
    let mut signatures = Vec::with_capacity(sig_lines.len());
    for line in &sig_lines {
        signatures.push(parse_signature_line(line)?);
    }
    Ok((body, signatures))
}

/// Split a signed note into its body and the text of each signature line (the
/// part AFTER the `— ` marker). Shared by [`parse_signed_note`] (auths' internal
/// alg-byte layout) and [`parse_signed_note_c2sp`] (the standard C2SP wire layout
/// used by Sigstore Rekor and C2SP-conformant witnesses). Body framing — three
/// lines plus a trailing `\n`, blank separator excluded — is identical for both.
fn split_note(note: &str) -> Result<(String, Vec<String>), TransparencyError> {
    let sig_marker = "\u{2014} ";
    let lines: Vec<&str> = note.lines().collect();

    let body_end_idx = lines
        .iter()
        .position(|l| l.starts_with(sig_marker))
        .ok_or_else(|| TransparencyError::InvalidNote("no signature lines found".into()))?;

    // Body is everything before the first signature line, trimming the blank
    // separator line so it is byte-identical to `Checkpoint::to_note_body()`.
    let mut body_lines = &lines[..body_end_idx];
    if body_lines.last() == Some(&"") {
        body_lines = &body_lines[..body_lines.len() - 1];
    }
    let body = body_lines.join("\n") + "\n";

    let sig_lines = lines[body_end_idx..]
        .iter()
        .filter_map(|l| l.strip_prefix(sig_marker).map(str::to_string))
        .collect();

    Ok((body, sig_lines))
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

/// A signature parsed in the **standard C2SP** signed-note wire layout:
/// `base64(key_id[4] || signature)`, with NO leading algorithm byte. Sigstore
/// Rekor and every C2SP-conformant witness emit this layout. (Contrast
/// [`NoteSignature`], whose leading algorithm byte is an auths-internal extension
/// produced by [`build_signature_line`] — using that parser on a standard note
/// misaligns the key ID and signature by one byte.)
#[derive(Debug, Clone)]
pub struct C2spSignature {
    /// The signer's key name (text after `— `, before the first space).
    pub key_name: String,
    /// 4-byte key ID (big-endian uint32) identifying the signer's key.
    pub key_id: [u8; 4],
    /// Raw signature bytes (for ECDSA: the ASN.1 DER ECDSA-Sig-Value).
    pub signature: Vec<u8>,
}

/// Parse a signed note whose signatures use the standard C2SP wire layout.
///
/// Returns the note body (ending in `\n`, byte-identical to
/// [`crate::checkpoint::Checkpoint::to_note_body`]) and each signature as a
/// [`C2spSignature`] (`key_id[4] || signature`, no algorithm byte). Use this for
/// external logs (Sigstore Rekor) and C2SP witnesses; use [`parse_signed_note`]
/// for auths' own alg-byte-prefixed checkpoints.
///
/// Args:
/// * `note` — The full signed-note text.
///
/// Usage:
/// ```ignore
/// let (body, sigs) = parse_signed_note_c2sp(rekor_checkpoint)?;
/// ```
pub fn parse_signed_note_c2sp(
    note: &str,
) -> Result<(String, Vec<C2spSignature>), TransparencyError> {
    let (body, sig_lines) = split_note(note)?;
    let mut signatures = Vec::with_capacity(sig_lines.len());
    for line in &sig_lines {
        signatures.push(parse_c2sp_signature_line(line)?);
    }
    Ok((body, signatures))
}

fn parse_c2sp_signature_line(line: &str) -> Result<C2spSignature, TransparencyError> {
    let space_idx = line
        .find(' ')
        .ok_or_else(|| TransparencyError::InvalidNote("malformed signature line".into()))?;

    let key_name = &line[..space_idx];
    let b64 = &line[space_idx + 1..];

    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|e| TransparencyError::InvalidNote(format!("base64 decode: {e}")))?;

    // Standard C2SP layout: 4-byte key ID followed by the signature. Require at
    // least one signature byte beyond the key ID.
    if raw.len() < 5 {
        return Err(TransparencyError::InvalidNote(
            "signature data too short".into(),
        ));
    }

    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&raw[..4]);
    let signature = raw[4..].to_vec();

    Ok(C2spSignature {
        key_name: key_name.to_string(),
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

    #[test]
    fn ecdsa_key_id_matches_rekor_hint() {
        // Rekor production-shard SPKI (same constant pinned in
        // `TrustConfig::default_config`).
        const REKOR_PROD_PUBKEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";
        let der = STANDARD.decode(REKOR_PROD_PUBKEY_B64).unwrap();
        // Reference vector: the key-ID hint carried in every Rekor checkpoint
        // signature line ("wNI9aj…" base64 → 0xc0d23d6a).
        assert_eq!(compute_ecdsa_key_id(&der), [0xc0, 0xd2, 0x3d, 0x6a]);
    }

    #[test]
    fn ecdsa_and_ed25519_key_ids_use_distinct_formulas() {
        // ECDSA hashes the DER SPKI; Ed25519 hashes name||0x0A||0x01||pubkey.
        // The same 32 bytes routed through each formula must differ — guarding
        // against an accidental reuse of the Ed25519 path for ECDSA.
        let bytes = [0x11u8; 32];
        let ed = compute_key_id("rekor.sigstore.dev", &bytes);
        let ec = compute_ecdsa_key_id(&bytes);
        assert_ne!(ed, ec);
    }

    #[test]
    fn c2sp_signature_standard_layout_roundtrip() {
        // Standard layout: base64(key_id[4] || sig), NO leading algorithm byte.
        let key_id = [0xc0, 0xd2, 0x3d, 0x6a];
        let sig = vec![0x30u8, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd];
        let mut blob = Vec::new();
        blob.extend_from_slice(&key_id);
        blob.extend_from_slice(&sig);
        let note = format!(
            "rekor.sigstore.dev - 1\n42\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n\n\u{2014} rekor.sigstore.dev {}\n",
            STANDARD.encode(&blob)
        );
        let (body, sigs) = parse_signed_note_c2sp(&note).unwrap();
        assert_eq!(
            body,
            "rekor.sigstore.dev - 1\n42\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n"
        );
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].key_name, "rekor.sigstore.dev");
        assert_eq!(sigs[0].key_id, key_id);
        assert_eq!(sigs[0].signature, sig);
    }
}
