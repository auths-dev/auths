use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, get_platform_keychain_with_config};
use auths_crypto::decode_seed_hex;
use auths_sdk::context::AuthsContext;
use auths_sdk::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactMetadata, ArtifactSource};
use auths_sdk::signing::{
    ArtifactSigningParams, SigningKeyMaterial, sign_artifact as sdk_sign_artifact,
    sign_artifact_raw,
};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use chrono::Utc;
use napi_derive::napi;
use sha2::{Digest, Sha256};

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_passphrase};

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

#[napi(object)]
#[derive(Clone)]
pub struct NapiArtifactResult {
    pub attestation_json: String,
    pub rid: String,
    pub digest: String,
    pub file_size: i64,
}

fn build_context_and_sign(
    artifact: Arc<dyn ArtifactSource>,
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
    expires_in: Option<i64>,
    note: Option<String>,
    commit_sha: Option<String>,
) -> napi::Result<NapiArtifactResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(GitRegistryBackend::open_existing(config).map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to open registry: {e}"),
        )
    })?);

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
    let keychain = Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = KeyAlias::new(identity_key_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Invalid key alias: {e}")))?;

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
        .unwrap_or(0) as i64;

    let params = ArtifactSigningParams {
        artifact,
        identity_key: Some(SigningKeyMaterial::Alias(alias.clone())),
        device_key: SigningKeyMaterial::Alias(alias),
        expires_in: expires_in.map(|s| s as u64),
        note,
        commit_sha,
    };

    let result = sdk_sign_artifact(params, &ctx).map_err(|e| {
        format_error(
            "AUTHS_SIGNING_FAILED",
            format!("Artifact signing failed: {e}"),
        )
    })?;

    Ok(NapiArtifactResult {
        attestation_json: result.attestation_json,
        rid: result.rid.to_string(),
        digest: result.digest,
        file_size,
    })
}

#[napi]
pub fn sign_artifact(
    file_path: String,
    identity_key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
    expires_in: Option<i64>,
    note: Option<String>,
    commit_sha: Option<String>,
) -> napi::Result<NapiArtifactResult> {
    let path = PathBuf::from(shellexpand::tilde(&file_path).as_ref());
    if !path.exists() {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Artifact not found: '{file_path}'. Check the path and ensure the file exists."
            ),
        ));
    }

    let artifact = Arc::new(FileArtifact { path });
    build_context_and_sign(
        artifact,
        &identity_key_alias,
        &repo_path,
        passphrase,
        expires_in,
        note,
        commit_sha,
    )
}

#[napi]
pub fn sign_artifact_bytes(
    data: napi::bindgen_prelude::Buffer,
    identity_key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
    expires_in: Option<i64>,
    note: Option<String>,
    commit_sha: Option<String>,
) -> napi::Result<NapiArtifactResult> {
    let artifact = Arc::new(BytesArtifact {
        data: data.to_vec(),
    });
    build_context_and_sign(
        artifact,
        &identity_key_alias,
        &repo_path,
        passphrase,
        expires_in,
        note,
        commit_sha,
    )
}

/// Sign raw bytes with a raw Ed25519 private key, producing a dual-signed attestation.
///
/// No keychain or filesystem access required.
///
/// Args:
/// * `data`: The raw bytes to sign.
/// * `private_key_hex`: Ed25519 seed as hex string (64 chars = 32 bytes).
/// * `identity_did`: Identity DID string (must be `did:keri:` format).
/// * `expires_in`: Optional duration in seconds until expiration.
/// * `note`: Optional human-readable note.
///
/// Usage:
/// ```ignore
/// let result = sign_artifact_bytes_raw(buffer, "abcd...".into(), "did:keri:E...".into(), None, None)?;
/// ```
#[napi]
pub fn sign_artifact_bytes_raw(
    data: napi::bindgen_prelude::Buffer,
    private_key_hex: String,
    identity_did: String,
    expires_in: Option<i64>,
    note: Option<String>,
    commit_sha: Option<String>,
) -> napi::Result<NapiArtifactResult> {
    let seed = decode_seed_hex(&private_key_hex)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid private key: {e}")))?;

    let did = IdentityDID::parse(&identity_did)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid identity DID: {e}")))?;

    let expires_in_u64 = expires_in
        .map(|v| {
            if v < 0 {
                Err(format_error(
                    "AUTHS_INVALID_INPUT",
                    "expiresIn must be non-negative".to_string(),
                ))
            } else {
                Ok(v as u64)
            }
        })
        .transpose()?;

    let now = Utc::now();
    let data_len = data.len();

    let result = sign_artifact_raw(
        now,
        &seed,
        &did,
        data.as_ref(),
        expires_in_u64,
        note,
        commit_sha,
    )
    .map_err(|e| {
        format_error(
            "AUTHS_SIGNING_FAILED",
            format!("Artifact signing failed: {e}"),
        )
    })?;

    Ok(NapiArtifactResult {
        attestation_json: result.attestation_json,
        rid: result.rid.to_string(),
        digest: result.digest,
        file_size: data_len as i64,
    })
}
