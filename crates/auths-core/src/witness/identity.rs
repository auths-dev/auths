//! Stable, persisted witness signing identity.
//!
//! A witness AID must survive restarts to be pinnable in anyone's `b[]`; a fresh
//! key per launch makes the commons unbuildable. This module loads a curve-tagged
//! signing seed from a `0600` keystore (or generates and persists one on explicit
//! request) and reconstructs the [`TypedSignerKey`]. Loading fails **closed**: a
//! missing or corrupt keystore is a hard error, never a silently-minted fresh key.
//!
//! The key backend is deliberately a simple file/env seed, not the interactive
//! platform keychain (a server has no login session). A future KMS/HSM backend is
//! tracked separately.

// The `witness-server` feature is auths-core's I/O-bearing slice (it runs the HTTP
// server + sqlite storage); this keystore module performs local file I/O within
// that feature, not in the sans-IO core path — hence the std::fs allowances here.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::Path;

use auths_crypto::{CurveType, TypedSeed, TypedSignerKey};
use serde::{Deserialize, Serialize};

/// Typed failure from witness-identity load/persist.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessIdentityError {
    /// No keystore at the given path (and creation was not requested).
    #[error("witness identity keystore not found at {path}; pass --generate to create one")]
    NotFound {
        /// The keystore path that does not exist.
        path: String,
    },

    /// The keystore exists but could not be parsed.
    #[error("witness identity keystore at {path} is corrupt: {reason}")]
    Corrupt {
        /// The keystore path.
        path: String,
        /// Why it could not be parsed.
        reason: String,
    },

    /// Refused to overwrite an existing keystore on generate.
    #[error("witness identity keystore already exists at {path}; refusing to overwrite")]
    AlreadyExists {
        /// The keystore path that already exists.
        path: String,
    },

    /// Filesystem error reading or writing the keystore.
    #[error("witness identity keystore I/O at {path}: {source}")]
    Io {
        /// The keystore path.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The seed material does not form a valid signing key.
    #[error("invalid witness signing key: {0}")]
    InvalidKey(String),

    /// The curve tag was not one we support.
    #[error("unknown curve tag {0:?}; expected \"ed25519\" or \"p256\"")]
    UnknownCurve(String),
}

/// On-disk witness identity: an in-band curve tag plus a hex signing seed.
#[derive(Serialize, Deserialize)]
struct WitnessIdentityFile {
    /// Curve tag — `"ed25519"` or `"p256"` (in-band, never inferred from length).
    curve: String,
    /// Hex-encoded 32-byte signing seed/scalar.
    seed: String,
}

fn curve_tag(curve: CurveType) -> &'static str {
    match curve {
        CurveType::Ed25519 => "ed25519",
        CurveType::P256 => "p256",
    }
}

fn parse_curve(tag: &str) -> Result<CurveType, WitnessIdentityError> {
    match tag {
        "ed25519" => Ok(CurveType::Ed25519),
        "p256" => Ok(CurveType::P256),
        other => Err(WitnessIdentityError::UnknownCurve(other.to_string())),
    }
}

fn signer_from_seed(
    curve: CurveType,
    seed_bytes: [u8; 32],
) -> Result<TypedSignerKey, WitnessIdentityError> {
    let seed = match curve {
        CurveType::Ed25519 => TypedSeed::Ed25519(seed_bytes),
        CurveType::P256 => TypedSeed::P256(seed_bytes),
    };
    TypedSignerKey::from_seed(seed).map_err(|e| WitnessIdentityError::InvalidKey(e.to_string()))
}

fn decode_seed(
    seed_hex: &str,
    on_bad: impl Fn(String) -> WitnessIdentityError,
) -> Result<[u8; 32], WitnessIdentityError> {
    let bytes = hex::decode(seed_hex.trim()).map_err(|e| on_bad(format!("seed not hex: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| on_bad(format!("seed must be 32 bytes, got {}", bytes.len())))
}

/// Load a persisted witness signing key, failing closed.
///
/// Args:
/// * `path`: Path to the curve-tagged keystore written by
///   [`generate_and_persist_witness_signer`].
///
/// Usage:
/// ```ignore
/// let signer = load_witness_signer(Path::new("witness-identity.json"))?;
/// ```
pub fn load_witness_signer(path: &Path) -> Result<TypedSignerKey, WitnessIdentityError> {
    let p = path.display().to_string();
    if !path.exists() {
        return Err(WitnessIdentityError::NotFound { path: p });
    }
    let bytes = std::fs::read(path).map_err(|e| WitnessIdentityError::Io {
        path: p.clone(),
        source: e,
    })?;
    let file: WitnessIdentityFile =
        serde_json::from_slice(&bytes).map_err(|e| WitnessIdentityError::Corrupt {
            path: p.clone(),
            reason: e.to_string(),
        })?;
    let curve = parse_curve(&file.curve)?;
    let seed_bytes = decode_seed(&file.seed, |reason| WitnessIdentityError::Corrupt {
        path: p.clone(),
        reason,
    })?;
    signer_from_seed(curve, seed_bytes)
}

/// Generate a fresh witness signing key, persist it at `0600`, and return it.
///
/// Refuses to overwrite an existing keystore, so a stray `--generate` cannot
/// silently replace a published identity.
///
/// Args:
/// * `path`: Where to write the keystore (parent dirs are created).
/// * `curve`: Signing curve for the new identity.
///
/// Usage:
/// ```ignore
/// let signer = generate_and_persist_witness_signer(path, CurveType::P256)?;
/// ```
pub fn generate_and_persist_witness_signer(
    path: &Path,
    curve: CurveType,
) -> Result<TypedSignerKey, WitnessIdentityError> {
    let p = path.display().to_string();
    if path.exists() {
        return Err(WitnessIdentityError::AlreadyExists { path: p });
    }
    let (seed_bytes, _pubkey) = super::server::generate_keypair_for_curve(curve)
        .map_err(|e| WitnessIdentityError::InvalidKey(e.to_string()))?;
    let signer = signer_from_seed(curve, seed_bytes)?;

    let file = WitnessIdentityFile {
        curve: curve_tag(curve).to_string(),
        seed: hex::encode(seed_bytes),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| WitnessIdentityError::Corrupt {
        path: p.clone(),
        reason: e.to_string(),
    })?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| WitnessIdentityError::Io {
            path: p.clone(),
            source: e,
        })?;
    }
    write_secret_file(path, &json).map_err(|e| WitnessIdentityError::Io { path: p, source: e })?;
    Ok(signer)
}

/// Reconstruct a witness signing key from an env-injected hex seed (no file).
///
/// For binary/container deployments that inject the key out-of-band rather than
/// from a mounted keystore.
///
/// Args:
/// * `curve`: Signing curve of the injected seed.
/// * `seed_hex`: Hex-encoded 32-byte seed.
///
/// Usage:
/// ```ignore
/// let signer = witness_signer_from_seed_hex(CurveType::P256, &env_seed)?;
/// ```
pub fn witness_signer_from_seed_hex(
    curve: CurveType,
    seed_hex: &str,
) -> Result<TypedSignerKey, WitnessIdentityError> {
    let seed_bytes = decode_seed(seed_hex, WitnessIdentityError::InvalidKey)?;
    signer_from_seed(curve, seed_bytes)
}

/// Write `bytes` to `path`, creating it new with owner-only (`0600`) perms on unix.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn run_roundtrip(curve: CurveType) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness-identity.json");

        let generated = generate_and_persist_witness_signer(&path, curve).unwrap();
        let loaded = load_witness_signer(&path).unwrap();

        // Identity is stable across reload: same curve + same public key → same AID.
        assert_eq!(generated.curve(), loaded.curve());
        assert_eq!(generated.public_key(), loaded.public_key());
    }

    #[test]
    fn roundtrip_ed25519_is_stable() {
        run_roundtrip(CurveType::Ed25519);
    }

    #[test]
    fn roundtrip_p256_is_stable() {
        run_roundtrip(CurveType::P256);
    }

    #[test]
    fn missing_keystore_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        assert!(matches!(
            load_witness_signer(&path),
            Err(WitnessIdentityError::NotFound { .. })
        ));
    }

    #[test]
    fn corrupt_keystore_is_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert!(matches!(
            load_witness_signer(&path),
            Err(WitnessIdentityError::Corrupt { .. })
        ));
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness-identity.json");
        generate_and_persist_witness_signer(&path, CurveType::P256).unwrap();
        assert!(matches!(
            generate_and_persist_witness_signer(&path, CurveType::P256),
            Err(WitnessIdentityError::AlreadyExists { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness-identity.json");
        generate_and_persist_witness_signer(&path, CurveType::P256).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "keystore must be owner-only");
    }

    #[test]
    fn env_seed_matches_file_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness-identity.json");
        let from_file = generate_and_persist_witness_signer(&path, CurveType::Ed25519).unwrap();

        // Re-read the persisted seed and reconstruct via the env path.
        let bytes = std::fs::read(&path).unwrap();
        let file: WitnessIdentityFile = serde_json::from_slice(&bytes).unwrap();
        let from_env = witness_signer_from_seed_hex(CurveType::Ed25519, &file.seed).unwrap();

        assert_eq!(from_file.public_key(), from_env.public_key());
    }
}
