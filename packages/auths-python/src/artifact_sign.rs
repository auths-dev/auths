use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_sdk::context::AuthsContext;
use auths_sdk::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactMetadata, ArtifactSource};
use auths_sdk::signing::{
    ArtifactSigningParams, SigningKeyMaterial, sign_artifact as sdk_sign_artifact,
};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use pyo3::exceptions::{PyFileNotFoundError, PyRuntimeError};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

use crate::identity::{make_keychain_config, resolve_passphrase};

struct FileArtifact {
    path: PathBuf,
}

impl ArtifactSource for FileArtifact {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        let mut file = std::fs::File::open(&self.path)
            .map_err(|e| ArtifactError::Io(format!("{}: {e}", self.path.display())))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| ArtifactError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: hex::encode(hasher.finalize()),
        })
    }

    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> {
        let digest = self.digest()?;
        let meta = std::fs::metadata(&self.path)
            .map_err(|e| ArtifactError::Metadata(format!("{}: {e}", self.path.display())))?;
        Ok(ArtifactMetadata {
            artifact_type: "file".to_string(),
            digest,
            name: self
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string()),
            size: Some(meta.len()),
        })
    }
}

struct BytesArtifact {
    data: Vec<u8>,
}

impl ArtifactSource for BytesArtifact {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        Ok(ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: hex::encode(hasher.finalize()),
        })
    }

    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> {
        let digest = self.digest()?;
        Ok(ArtifactMetadata {
            artifact_type: "bytes".to_string(),
            digest,
            name: None,
            size: Some(self.data.len() as u64),
        })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyArtifactResult {
    #[pyo3(get)]
    pub attestation_json: String,
    #[pyo3(get)]
    pub rid: String,
    #[pyo3(get)]
    pub digest: String,
    #[pyo3(get)]
    pub file_size: u64,
}

#[pymethods]
impl PyArtifactResult {
    fn __repr__(&self) -> String {
        let size = human_size(self.file_size);
        let rid_short = if self.rid.len() > 24 {
            &self.rid[..24]
        } else {
            &self.rid
        };
        format!("ArtifactResult(rid='{rid_short}...', size={size})")
    }
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn build_context_and_sign(
    artifact: Arc<dyn ArtifactSource>,
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
    note: Option<String>,
) -> PyResult<PyArtifactResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str, repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(GitRegistryBackend::open_existing(config).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "[AUTHS_REGISTRY_ERROR] Failed to open registry: {e}"
        ))
    })?);

    let keychain = get_platform_keychain_with_config(&env_config).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] Keychain error: {e}"))
    })?;
    let keychain = Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = KeyAlias::new(identity_key_alias).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] Invalid key alias: {e}"))
    })?;

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock)
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    let file_size = artifact
        .metadata()
        .map(|m| m.size.unwrap_or(0))
        .unwrap_or(0);

    let params = ArtifactSigningParams {
        artifact,
        identity_key: Some(SigningKeyMaterial::Alias(alias.clone())),
        device_key: SigningKeyMaterial::Alias(alias),
        expires_in_days,
        note,
    };

    let result = sdk_sign_artifact(params, &ctx).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "[AUTHS_SIGNING_FAILED] Artifact signing failed: {e}"
        ))
    })?;

    Ok(PyArtifactResult {
        attestation_json: result.attestation_json,
        rid: result.rid,
        digest: result.digest,
        file_size,
    })
}

/// Sign a file artifact, producing a dual-signed attestation.
///
/// Args:
/// * `file_path`: Path to the file to sign.
/// * `identity_key_alias`: Keychain alias for the identity key.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `expires_in_days`: Optional expiry in days.
/// * `note`: Optional human-readable note.
///
/// Usage:
/// ```ignore
/// let result = sign_artifact(py, "release.tar.gz", "main", "~/.auths", None, None, None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (file_path, identity_key_alias, repo_path, passphrase=None, expires_in_days=None, note=None))]
pub fn sign_artifact(
    py: Python<'_>,
    file_path: &str,
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
    note: Option<String>,
) -> PyResult<PyArtifactResult> {
    let path = PathBuf::from(shellexpand::tilde(file_path).as_ref());
    if !path.exists() {
        return Err(PyFileNotFoundError::new_err(format!(
            "Artifact not found: '{file_path}'. Check the path and ensure the file exists."
        )));
    }

    let artifact = Arc::new(FileArtifact { path });
    let alias = identity_key_alias.to_string();
    let rp = repo_path.to_string();

    py.allow_threads(move || {
        build_context_and_sign(artifact, &alias, &rp, passphrase, expires_in_days, note)
    })
}

/// Sign raw bytes, producing a dual-signed attestation.
///
/// Args:
/// * `data`: The raw bytes to sign.
/// * `identity_key_alias`: Keychain alias for the identity key.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `expires_in_days`: Optional expiry in days.
/// * `note`: Optional human-readable note.
///
/// Usage:
/// ```ignore
/// let result = sign_artifact_bytes(py, b"manifest data", "main", "~/.auths", None, None, None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (data, identity_key_alias, repo_path, passphrase=None, expires_in_days=None, note=None))]
pub fn sign_artifact_bytes(
    py: Python<'_>,
    data: &[u8],
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
    note: Option<String>,
) -> PyResult<PyArtifactResult> {
    let artifact = Arc::new(BytesArtifact {
        data: data.to_vec(),
    });
    let alias = identity_key_alias.to_string();
    let rp = repo_path.to_string();

    py.allow_threads(move || {
        build_context_and_sign(artifact, &alias, &rp, passphrase, expires_in_days, note)
    })
}
