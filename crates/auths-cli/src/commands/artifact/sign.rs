use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_id::attestation::export::AttestationSink;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::context::AuthsContext;
use auths_sdk::signing::{ArtifactSigningParams, SigningKeyMaterial, sign_artifact_attestation};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

use super::file::FileArtifact;

/// Execute the `artifact sign` command.
#[allow(clippy::too_many_arguments)]
pub fn handle_sign(
    file: &Path,
    output: Option<PathBuf>,
    identity_key_alias: Option<&str>,
    device_key_alias: &str,
    expires_in_days: Option<i64>,
    note: Option<String>,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let repo_path = auths_id::storage::layout::resolve_repo_path(repo_opt)?;

    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(&repo_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage =
        get_platform_keychain_with_config(env_config).context("Failed to initialize keychain")?;

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(Arc::from(key_storage))
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .passphrase_provider(passphrase_provider)
        .build();

    let params = ArtifactSigningParams {
        artifact: Arc::new(FileArtifact::new(file)),
        identity_key: identity_key_alias
            .map(|a| SigningKeyMaterial::Alias(KeyAlias::new_unchecked(a))),
        device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(device_key_alias)),
        expires_in_days: expires_in_days.map(|d| d as u32),
        note,
    };

    let result = sign_artifact_attestation(params, &ctx)
        .with_context(|| format!("Failed to sign artifact {:?}", file))?;

    let output_path = output.unwrap_or_else(|| {
        let mut p = file.to_path_buf();
        let new_name = format!(
            "{}.auths.json",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    std::fs::write(&output_path, &result.attestation_json)
        .with_context(|| format!("Failed to write signature to {:?}", output_path))?;

    println!(
        "Signed {:?} -> {:?}",
        file.file_name().unwrap_or_default(),
        output_path
    );
    println!("  RID:    {}", result.rid);
    println!("  Digest: sha256:{}", result.digest);

    Ok(())
}
