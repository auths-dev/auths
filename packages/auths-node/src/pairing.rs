use napi_derive::napi;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::storage::identity::IdentityStorage;
use auths_pairing_daemon::{
    MockNetworkDiscovery, MockNetworkInterfaces, PairingDaemonBuilder, PairingDaemonHandle,
    RateLimiter,
};
use auths_sdk::pairing::{
    PairingAttestationParams, PairingSessionParams, build_pairing_session_request,
    create_pairing_attestation,
};
use auths_storage::git::{RegistryAttestationStorage, RegistryIdentityStorage};
use chrono::Utc;

use crate::error::format_error;
use crate::helpers::{get_keychain, make_env_config, resolve_passphrase, resolve_repo_path};

fn pairing_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create pairing tokio runtime")
    })
}

static ACTIVE_SESSION: OnceLock<Mutex<Option<ActivePairing>>> = OnceLock::new();

struct ActivePairing {
    handle: PairingDaemonHandle,
    server_task: tokio::task::JoinHandle<()>,
}

fn session_store() -> &'static Mutex<Option<ActivePairing>> {
    ACTIVE_SESSION.get_or_init(|| Mutex::new(None))
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiPairingSession {
    pub session_id: String,
    pub short_code: String,
    pub endpoint: String,
    pub token: String,
    pub controller_did: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiPairingResponse {
    pub device_did: String,
    pub device_name: Option<String>,
    pub device_public_key_hex: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiPairingResult {
    pub device_did: String,
    pub device_name: Option<String>,
    pub attestation_rid: String,
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn create_pairing_session(
    repo_path: String,
    capabilities_json: Option<String>,
    timeout_secs: Option<u32>,
    bind_address: Option<String>,
    enable_mdns: Option<bool>,
    passphrase: Option<String>,
) -> napi::Result<NapiPairingSession> {
    let _pp = resolve_passphrase(passphrase);
    let repo = resolve_repo_path(Some(repo_path));
    let bind_addr: IpAddr = bind_address
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    let timeout = timeout_secs.unwrap_or(300) as u64;
    let mdns = enable_mdns.unwrap_or(true);

    let capabilities: Vec<String> = if let Some(json) = capabilities_json {
        serde_json::from_str(&json).unwrap_or_else(|_| vec!["sign:commit".to_string()])
    } else {
        vec!["sign:commit".to_string()]
    };

    let identity_storage = RegistryIdentityStorage::new(repo.clone());
    let managed = identity_storage
        .load_identity()
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
    let controller_did = managed.controller_did.to_string();

    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
    let session_req = build_pairing_session_request(
        now,
        PairingSessionParams {
            controller_did: controller_did.clone(),
            registry: "local".to_string(),
            capabilities,
            expiry_secs: timeout,
        },
    )
    .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let session_id = session_req.create_request.session_id.clone();
    let short_code = session_req.create_request.short_code.clone();

    let mut builder = PairingDaemonBuilder::new().with_rate_limiter(RateLimiter::new(100));

    let mock_addr = SocketAddr::new(bind_addr, 0);
    builder = builder.with_network(MockNetworkInterfaces(bind_addr));

    if !mdns {
        builder = builder.with_discovery(MockNetworkDiscovery(mock_addr));
    }

    let daemon = builder
        .build(session_req.create_request)
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let token = daemon.token().to_string();
    let (router, handle) = daemon.into_parts();

    let rt = pairing_runtime();
    let (endpoint_tx, endpoint_rx) = std::sync::mpsc::channel();

    let server_task = rt.spawn(async move {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_addr, 0))
            .await
            .expect("failed to bind pairing server");
        let local_addr = listener.local_addr().expect("failed to get local addr");
        let endpoint = format!("http://{}:{}", local_addr.ip(), local_addr.port());
        let _ = endpoint_tx.send(endpoint);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    let endpoint = endpoint_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| {
            format_error("AUTHS_PAIRING_ERROR", "Server failed to start within 5s")
        })?;

    let mut store = session_store()
        .lock()
        .map_err(|_| format_error("AUTHS_PAIRING_ERROR", "Session lock poisoned"))?;
    *store = Some(ActivePairing {
        handle,
        server_task,
    });

    Ok(NapiPairingSession {
        session_id,
        short_code,
        endpoint,
        token,
        controller_did,
    })
}

#[napi]
pub fn wait_for_pairing_response(timeout_secs: Option<u32>) -> napi::Result<NapiPairingResponse> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(300) as u64);

    let handle = {
        let mut store = session_store()
            .lock()
            .map_err(|_| format_error("AUTHS_PAIRING_ERROR", "Session lock poisoned"))?;
        let session = store.take().ok_or_else(|| {
            format_error(
                "AUTHS_PAIRING_ERROR",
                "No active pairing session. Call createPairingSession first.",
            )
        })?;
        session.handle
    };

    let rt = pairing_runtime();
    let result = rt.block_on(handle.wait_for_response(timeout));

    match result {
        Ok(response) => {
            let device_did = response.device_did.clone();
            let device_name = response.device_name.clone();
            let device_pk_hex =
                hex::encode(response.device_signing_pubkey.decode().unwrap_or_default());
            Ok(NapiPairingResponse {
                device_did,
                device_name,
                device_public_key_hex: device_pk_hex,
            })
        }
        Err(e) => Err(format_error("AUTHS_PAIRING_TIMEOUT", e)),
    }
}

#[napi]
pub fn stop_pairing_session() -> napi::Result<()> {
    let mut store = session_store()
        .lock()
        .map_err(|_| format_error("AUTHS_PAIRING_ERROR", "Session lock poisoned"))?;
    if let Some(session) = store.take() {
        session.server_task.abort();
    }
    Ok(())
}

#[napi]
pub fn join_pairing_session(
    short_code: String,
    endpoint: String,
    token: String,
    repo_path: String,
    device_name: Option<String>,
    passphrase: Option<String>,
) -> napi::Result<NapiPairingResponse> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo_path(Some(repo_path.clone()));
    let env_config = make_env_config(&passphrase_str, &repo_path);

    let identity_storage = RegistryIdentityStorage::new(repo.clone());
    let managed = identity_storage
        .load_identity()
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let controller_identity_did =
        IdentityDID::new_unchecked(managed.controller_did.to_string());

    let keychain = get_keychain(&env_config)?;
    let aliases = keychain
        .list_aliases_for_identity(&controller_identity_did)
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
    let key_alias_str = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| format_error("AUTHS_PAIRING_ERROR", "No signing key found"))?;

    let (_did, _role, encrypted_key) = keychain
        .load_key(&key_alias_str)
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let pkcs8_bytes =
        auths_core::crypto::signer::decrypt_keypair(&encrypted_key, &passphrase_str)
            .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let (seed, pubkey_32) = auths_crypto::parse_ed25519_key_material(&pkcs8_bytes)
        .ok()
        .and_then(|(seed, maybe_pk)| maybe_pk.map(|pk| (seed, pk)))
        .or_else(|| {
            let seed = auths_crypto::parse_ed25519_seed(&pkcs8_bytes).ok()?;
            let pk =
                auths_core::crypto::provider_bridge::ed25519_public_key_from_seed_sync(&seed)
                    .ok()?;
            Some((seed, pk))
        })
        .ok_or_else(|| {
            format_error("AUTHS_PAIRING_ERROR", "Failed to parse Ed25519 key material")
        })?;

    let device_did = auths_verifier::types::DeviceDID::from_ed25519(&pubkey_32);

    let rt = pairing_runtime();
    let lookup_url = format!("{}/v1/pairing/sessions/by-code/{}", endpoint, short_code);

    let session_data: serde_json::Value = rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .get(&lookup_url)
            .send()
            .await
            .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))
    })?;

    let _session_id = session_data["session_id"]
        .as_str()
        .ok_or_else(|| format_error("AUTHS_PAIRING_ERROR", "No session_id in response"))?
        .to_string();

    let token_data = &session_data["token"];
    let controller_did_str = token_data["controller_did"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let ephemeral_pubkey_str = token_data["ephemeral_pubkey"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let capabilities: Vec<String> = token_data["capabilities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let expires_at = token_data["expires_at"].as_i64().unwrap_or(0);

    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
    let pairing_token = auths_core::pairing::PairingToken {
        controller_did: controller_did_str,
        endpoint: endpoint.clone(),
        short_code: short_code.clone(),
        ephemeral_pubkey: ephemeral_pubkey_str,
        expires_at: chrono::DateTime::from_timestamp(expires_at, 0).unwrap_or(now),
        capabilities,
    };

    let secure_seed = auths_crypto::SecureSeed::new(*seed.as_bytes());
    let (pairing_response, _shared_secret) =
        auths_core::pairing::PairingResponse::create(
            now,
            &pairing_token,
            &secure_seed,
            &pubkey_32,
            device_did.to_string(),
            device_name.clone(),
        )
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let submit_req = auths_core::pairing::types::SubmitResponseRequest {
        device_x25519_pubkey: auths_core::pairing::types::Base64UrlEncoded::from_raw(
            pairing_response.device_x25519_pubkey,
        ),
        device_signing_pubkey: auths_core::pairing::types::Base64UrlEncoded::from_raw(
            pairing_response.device_signing_pubkey,
        ),
        device_did: pairing_response.device_did.clone(),
        signature: auths_core::pairing::types::Base64UrlEncoded::from_raw(
            pairing_response.signature,
        ),
        device_name: pairing_response.device_name,
    };

    let session_id_for_submit = _session_id;
    let submit_url = format!(
        "{}/v1/pairing/sessions/{}/response",
        endpoint, session_id_for_submit
    );

    rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .post(&submit_url)
            .header("X-Pairing-Token", &token)
            .json(&submit_req)
            .send()
            .await
            .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format_error(
                "AUTHS_PAIRING_ERROR",
                format!("Submit response failed: {} {}", status, body),
            ));
        }
        Ok::<(), napi::Error>(())
    })?;

    Ok(NapiPairingResponse {
        device_did: device_did.to_string(),
        device_name,
        device_public_key_hex: hex::encode(pubkey_32),
    })
}

#[napi]
pub fn complete_pairing(
    device_did: String,
    device_public_key_hex: String,
    repo_path: String,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
) -> napi::Result<NapiPairingResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo_path(Some(repo_path.clone()));
    let env_config = make_env_config(&passphrase_str, &repo_path);

    let capabilities: Vec<String> = if let Some(json) = capabilities_json {
        serde_json::from_str(&json).unwrap_or_else(|_| vec!["sign:commit".to_string()])
    } else {
        vec!["sign:commit".to_string()]
    };

    let device_pubkey = hex::decode(&device_public_key_hex).map_err(|e| {
        format_error("AUTHS_PAIRING_ERROR", format!("Invalid public key hex: {e}"))
    })?;

    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo.clone()));

    let managed = identity_storage
        .load_identity()
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
    let controller_identity_did =
        IdentityDID::new_unchecked(managed.controller_did.to_string());

    let keychain = get_keychain(&env_config)?;
    let aliases = keychain
        .list_aliases_for_identity(&controller_identity_did)
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;
    let identity_key_alias_str = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| format_error("AUTHS_PAIRING_ERROR", "No signing key found"))?;
    let identity_key_alias = KeyAlias::new_unchecked(identity_key_alias_str);

    let key_storage: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
    let provider = Arc::new(
        auths_core::signing::PrefilledPassphraseProvider::new(&passphrase_str),
    );

    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
    let params = PairingAttestationParams {
        identity_storage: identity_storage.clone(),
        key_storage: key_storage.clone(),
        device_pubkey: &device_pubkey,
        device_did_str: &device_did,
        capabilities: &capabilities,
        identity_key_alias: &identity_key_alias,
        passphrase_provider: provider,
    };

    let attestation = create_pairing_attestation(&params, now)
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    let attestation_storage = RegistryAttestationStorage::new(&repo);
    use auths_id::attestation::AttestationSink;
    attestation_storage
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(
            attestation.clone(),
        ))
        .map_err(|e| format_error("AUTHS_PAIRING_ERROR", e))?;

    Ok(NapiPairingResult {
        device_did,
        device_name: None,
        attestation_rid: attestation.rid.to_string(),
    })
}
