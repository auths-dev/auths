use std::path::PathBuf;
use std::sync::Arc;

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, KeyRole, get_platform_keychain_with_config};
use auths_id::identity::helpers::{encode_seed_as_pkcs8, extract_seed_bytes};
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::storage::attestation::AttestationSource;
use auths_sdk::context::AuthsContext;
use auths_sdk::device::link_device;
use auths_sdk::types::{DeviceLinkConfig, IdentityRotationConfig};
use auths_sdk::workflows::rotation::rotate_identity;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Capability;
use auths_verifier::types::DeviceDID;
use napi_derive::napi;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_key_alias, resolve_passphrase};
use crate::types::{
    NapiAgentIdentityBundle, NapiDelegatedAgentBundle, NapiIdentityResult, NapiRotationResult,
};

fn init_backend(repo: &PathBuf) -> napi::Result<Arc<GitRegistryBackend>> {
    let config = RegistryConfig::single_tenant(repo);
    let backend = GitRegistryBackend::from_config_unchecked(config);
    backend.init_if_needed().map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to initialize registry: {e}"),
        )
    })?;
    Ok(Arc::new(backend))
}

fn open_backend(repo: &PathBuf) -> napi::Result<Arc<GitRegistryBackend>> {
    let config = RegistryConfig::single_tenant(repo);
    let backend = GitRegistryBackend::open_existing(config).map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to open registry: {e}"),
        )
    })?;
    Ok(Arc::new(backend))
}

#[napi]
pub fn create_identity(
    key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiIdentityResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let alias = KeyAlias::new(&key_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Invalid key alias: {e}")))?;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = init_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let (identity_did, result_alias) =
        initialize_registry_identity(backend, &alias, &provider, keychain.as_ref(), None).map_err(
            |e| {
                format_error(
                    "AUTHS_IDENTITY_ERROR",
                    format!("Identity creation failed: {e}"),
                )
            },
        )?;

    let pub_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain.as_ref(),
        &result_alias,
        &provider,
    )
    .map_err(|e| {
        format_error(
            "AUTHS_CRYPTO_ERROR",
            format!("Public key extraction failed: {e}"),
        )
    })?;

    Ok(NapiIdentityResult {
        did: identity_did.to_string(),
        key_alias: result_alias.to_string(),
        public_key_hex: hex::encode(pub_bytes),
    })
}

#[napi]
pub fn create_agent_identity(
    agent_name: String,
    capabilities: Vec<String>,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiAgentIdentityBundle> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = init_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| {
            Capability::parse(c).map_err(|e| {
                format_error(
                    "AUTHS_INVALID_INPUT",
                    format!("Invalid capability '{c}': {e}"),
                )
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let (identity_did, result_alias) =
        initialize_registry_identity(backend.clone(), &alias, &provider, keychain.as_ref(), None)
            .map_err(|e| {
            format_error(
                "AUTHS_IDENTITY_ERROR",
                format!("Agent identity creation failed: {e}"),
            )
        })?;

    let pub_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain.as_ref(),
        &result_alias,
        &provider,
    )
    .map_err(|e| {
        format_error(
            "AUTHS_CRYPTO_ERROR",
            format!("Public key extraction failed: {e}"),
        )
    })?;

    // Use link_device to produce a proper signed self-attestation,
    // following the same pattern as delegate_agent.
    let link_config = DeviceLinkConfig {
        identity_key_alias: result_alias.clone(),
        device_key_alias: Some(result_alias.clone()),
        device_did: None,
        capabilities: parsed_caps,
        expires_in_days: None,
        note: Some(format!("Agent: {}", agent_name)),
        payload: None,
    };

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage.clone())
        .passphrase_provider(provider)
        .build();

    let result = link_device(link_config, &ctx, clock.as_ref()).map_err(|e| {
        format_error(
            "AUTHS_IDENTITY_ERROR",
            format!("Agent self-attestation failed: {e}"),
        )
    })?;

    let device_did = DeviceDID(result.device_did.to_string());
    let attestations = attestation_storage
        .load_attestations_for_device(&device_did)
        .map_err(|e| {
            format_error(
                "AUTHS_REGISTRY_ERROR",
                format!("Failed to load attestation: {e}"),
            )
        })?;

    let attestation = attestations.last().ok_or_else(|| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            "No attestation found after self-attestation",
        )
    })?;

    let attestation_json = serde_json::to_string(attestation).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Serialization failed: {e}"),
        )
    })?;

    Ok(NapiAgentIdentityBundle {
        agent_did: identity_did.to_string(),
        key_alias: result_alias.to_string(),
        attestation_json,
        public_key_hex: hex::encode(pub_bytes),
        repo_path: Some(repo.to_string_lossy().to_string()),
    })
}

#[napi]
pub fn delegate_agent(
    agent_name: String,
    capabilities: Vec<String>,
    parent_repo_path: String,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
    identity_did: Option<String>,
) -> napi::Result<NapiDelegatedAgentBundle> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &parent_repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&parent_repo_path).as_ref());
    let backend = open_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let parent_alias = if let Some(ref did) = identity_did {
        resolve_key_alias(did, keychain.as_ref())?
    } else {
        let aliases = keychain
            .list_aliases()
            .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
        aliases
            .into_iter()
            .find(|a| !a.as_str().contains("--next-"))
            .ok_or_else(|| {
                format_error("AUTHS_KEY_NOT_FOUND", "No identity key found in keychain")
            })?
    };

    let agent_alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Key generation failed: {e}")))?;
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Key parsing failed: {e}")))?;
    let agent_pubkey = keypair.public_key().as_ref().to_vec();

    let (parent_did, _, _) = keychain
        .load_key(&parent_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Key load failed: {e}")))?;

    let seed = extract_seed_bytes(pkcs8.as_ref())
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Seed extraction failed: {e}")))?;
    let seed_pkcs8 = encode_seed_as_pkcs8(seed)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("PKCS8 encoding failed: {e}")))?;
    let encrypted = encrypt_keypair(&seed_pkcs8, &passphrase_str)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Key encryption failed: {e}")))?;
    keychain
        .store_key(
            &agent_alias,
            &parent_did,
            KeyRole::DelegatedAgent,
            &encrypted,
        )
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Key storage failed: {e}")))?;

    let parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| {
            Capability::parse(c).map_err(|e| {
                format_error(
                    "AUTHS_INVALID_INPUT",
                    format!("Invalid capability '{c}': {e}"),
                )
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let link_config = DeviceLinkConfig {
        identity_key_alias: parent_alias,
        device_key_alias: Some(agent_alias.clone()),
        device_did: None,
        capabilities: parsed_caps,
        expires_in_days,
        note: Some(format!("Agent: {}", agent_name)),
        payload: None,
    };

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage.clone())
        .passphrase_provider(provider)
        .build();

    let result = link_device(link_config, &ctx, clock.as_ref()).map_err(|e| {
        format_error(
            "AUTHS_IDENTITY_ERROR",
            format!("Agent provisioning failed: {e}"),
        )
    })?;

    let device_did = DeviceDID(result.device_did.to_string());
    let attestations = attestation_storage
        .load_attestations_for_device(&device_did)
        .map_err(|e| {
            format_error(
                "AUTHS_REGISTRY_ERROR",
                format!("Failed to load attestation: {e}"),
            )
        })?;

    let attestation = attestations.last().ok_or_else(|| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            "No attestation found after provisioning",
        )
    })?;

    let attestation_json = serde_json::to_string(attestation).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Serialization failed: {e}"),
        )
    })?;

    Ok(NapiDelegatedAgentBundle {
        agent_did: result.device_did.to_string(),
        key_alias: agent_alias.to_string(),
        attestation_json,
        public_key_hex: hex::encode(&agent_pubkey),
        repo_path: Some(repo.to_string_lossy().to_string()),
    })
}

#[napi]
pub fn rotate_identity_keys(
    repo_path: String,
    identity_key_alias: Option<String>,
    next_key_alias: Option<String>,
    passphrase: Option<String>,
) -> napi::Result<NapiRotationResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = open_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = identity_key_alias
        .as_deref()
        .map(|a| resolve_key_alias(a, keychain.as_ref()))
        .transpose()?;

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    let next_alias = next_key_alias
        .as_deref()
        .map(|a| {
            KeyAlias::new(a).map_err(|e| {
                format_error(
                    "AUTHS_KEY_NOT_FOUND",
                    format!("Invalid next key alias: {e}"),
                )
            })
        })
        .transpose()?;

    let rotation_config = IdentityRotationConfig {
        repo_path: repo,
        identity_key_alias: alias,
        next_key_alias: next_alias,
    };

    let result = rotate_identity(rotation_config, &ctx, clock.as_ref())
        .map_err(|e| format_error("AUTHS_ROTATION_ERROR", format!("Key rotation failed: {e}")))?;

    Ok(NapiRotationResult {
        controller_did: result.controller_did.to_string(),
        new_key_fingerprint: result.new_key_fingerprint,
        previous_key_fingerprint: result.previous_key_fingerprint,
        sequence: result.sequence as i64,
    })
}

#[napi]
pub fn get_identity_public_key(
    identity_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<String> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let did = auths_verifier::types::IdentityDID::new(&identity_did);
    let aliases = keychain
        .list_aliases_for_identity(&did)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Key lookup failed: {e}")))?;
    let alias = aliases.first().ok_or_else(|| {
        format_error(
            "AUTHS_KEY_NOT_FOUND",
            format!("No key found for identity '{identity_did}'"),
        )
    })?;
    let pub_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain.as_ref(),
        alias,
        &provider,
    )
    .map_err(|e| {
        format_error(
            "AUTHS_CRYPTO_ERROR",
            format!("Public key extraction failed: {e}"),
        )
    })?;
    Ok(hex::encode(pub_bytes))
}
