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

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_key_alias, resolve_passphrase};
use crate::types::{
    NapiAgentIdentityBundle, NapiDelegatedAgentBundle, NapiIdentityResult, NapiInMemoryKeypair,
    NapiRotationResult,
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

    let (identity_did, result_alias) = initialize_registry_identity(
        backend,
        &alias,
        &provider,
        keychain.as_ref(),
        None,
        auths_crypto::CurveType::default(),
    )
    .map_err(|e| {
        format_error(
            "AUTHS_IDENTITY_ERROR",
            format!("Identity creation failed: {e}"),
        )
    })?;

    let (pub_bytes, _curve) = auths_core::storage::keychain::extract_public_key_bytes(
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
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: agent_name is user-provided, format produces valid alias
    let alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);
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

    let (identity_did, result_alias) = initialize_registry_identity(
        backend.clone(),
        &alias,
        &provider,
        keychain.as_ref(),
        None,
        auths_crypto::CurveType::default(),
    )
    .map_err(|e| {
        format_error(
            "AUTHS_IDENTITY_ERROR",
            format!("Agent identity creation failed: {e}"),
        )
    })?;

    let (pub_bytes, _curve) = auths_core::storage::keychain::extract_public_key_bytes(
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
        expires_in: None,
        note: Some(format!("Agent: {}", agent_name)),
        payload: None,
    };

    let provider = Arc::new(provider);
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

    #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from SDK setup result
    let device_did = DeviceDID::new_unchecked(result.device_did.to_string());
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
    expires_in: Option<i64>,
    identity_did: Option<String>,
    curve: Option<String>,
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

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: agent_name is user-provided, format produces valid alias
    let agent_alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    // Curve defaults to P-256 per workspace convention (fn-115/116). Callers
    // may pass `curve: "Ed25519"` for Radicle-compat agents.
    let curve_choice = match curve.as_deref() {
        Some("Ed25519") | Some("ed25519") => auths_crypto::CurveType::Ed25519,
        _ => auths_crypto::CurveType::P256,
    };
    let generated = auths_id::keri::inception::generate_keypair_for_init(curve_choice)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Key generation failed: {e}")))?;
    let agent_pubkey = generated.public_key.clone();

    let (parent_did, _, _) = keychain
        .load_key(&parent_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Key load failed: {e}")))?;

    let seed = extract_seed_bytes(generated.pkcs8.as_ref())
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
        expires_in: expires_in.map(|s| s as u64),
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

    #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from SDK setup result
    let device_did = DeviceDID::new_unchecked(result.device_did.to_string());
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

    let did = auths_verifier::types::IdentityDID::parse(&identity_did)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?;
    let aliases = keychain
        .list_aliases_for_identity_with_role(&did, KeyRole::Primary)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Key lookup failed: {e}")))?;
    let alias = aliases.first().ok_or_else(|| {
        format_error(
            "AUTHS_KEY_NOT_FOUND",
            format!("No primary key found for identity '{identity_did}'"),
        )
    })?;
    let (pub_bytes, _curve) = auths_core::storage::keychain::extract_public_key_bytes(
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

/// Generate an in-memory Ed25519 keypair without keychain, Git, or filesystem access.
///
/// Args:
/// (no arguments)
///
/// Usage:
/// ```ignore
/// let kp = generate_inmemory_keypair()?;
/// // kp.private_key_hex, kp.public_key_hex, kp.did
/// ```
#[napi]
pub fn generate_inmemory_keypair(curve: Option<String>) -> napi::Result<NapiInMemoryKeypair> {
    // Default P-256 per workspace convention; callers that need Ed25519
    // (e.g. Radicle compat) pass `curve: "Ed25519"`.
    let curve_choice = match curve.as_deref() {
        Some("Ed25519") | Some("ed25519") => auths_crypto::CurveType::Ed25519,
        _ => auths_crypto::CurveType::P256,
    };
    let generated = auths_id::keri::inception::generate_keypair_for_init(curve_choice)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Key generation failed: {e}")))?;

    let seed = extract_seed_bytes(generated.pkcs8.as_ref())
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Seed extraction failed: {e}")))?;

    let did =
        auths_verifier::types::DeviceDID::from_public_key(&generated.public_key, curve_choice)
            .to_string();

    Ok(NapiInMemoryKeypair {
        private_key_hex: hex::encode(seed),
        public_key_hex: hex::encode(&generated.public_key),
        did,
    })
}
