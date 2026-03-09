use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole};
use auths_id::storage::identity::IdentityStorage;
use auths_pairing_daemon::{
    MockNetworkDiscovery, MockNetworkInterfaces, PairingDaemonBuilder, PairingDaemonHandle,
    RateLimiter,
};
use auths_sdk::pairing::{
    PairingAttestationParams, PairingSessionParams, build_pairing_session_request,
    create_pairing_attestation,
};
use auths_storage::git::RegistryAttestationStorage;
use auths_storage::git::RegistryIdentityStorage;
use chrono::Utc;

use crate::identity::{make_keychain_config, resolve_passphrase};
use crate::runtime::runtime;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn get_keychain(
    passphrase: &str,
    repo_path: &str,
) -> PyResult<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>> {
    let env_config = make_keychain_config(passphrase, repo_path);
    auths_core::storage::keychain::get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))
}

#[pyclass]
pub struct PyPairingHandle {
    handle: Option<PairingDaemonHandle>,
    server_task: Option<tokio::task::JoinHandle<()>>,
    endpoint: String,
}

#[pymethods]
impl PyPairingHandle {
    fn wait_for_response(
        &mut self,
        py: Python<'_>,
        timeout_secs: u64,
    ) -> PyResult<(String, Option<String>, String, String)> {
        let handle = self.handle.take().ok_or_else(|| {
            PyRuntimeError::new_err(
                "[AUTHS_PAIRING_ERROR] Handle already consumed (wait_for_response called twice)",
            )
        })?;
        let timeout = Duration::from_secs(timeout_secs);

        py.allow_threads(move || {
            let rt = runtime();
            let result = rt.block_on(handle.wait_for_response(timeout));
            match result {
                Ok(response) => {
                    let device_did = response.device_did.clone();
                    let device_name = response.device_name.clone();
                    let device_pk_hex =
                        hex::encode(response.device_signing_pubkey.decode().unwrap_or_default());
                    let caps_json =
                        serde_json::to_string(&Vec::<String>::new()).unwrap_or_default();
                    Ok((device_did, device_name, device_pk_hex, caps_json))
                }
                Err(e) => Err(PyRuntimeError::new_err(format!(
                    "[AUTHS_PAIRING_TIMEOUT] {e}"
                ))),
            }
        })
    }

    fn stop(&mut self) -> PyResult<()> {
        self.handle.take();
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _ty: Option<&Bound<'_, PyAny>>,
        _val: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.stop()?;
        Ok(false)
    }

    #[getter]
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[pyfunction]
#[pyo3(signature = (repo_path, capabilities_json=None, timeout_secs=300, bind_address="0.0.0.0", enable_mdns=true, passphrase=None))]
pub fn create_pairing_session_ffi(
    py: Python<'_>,
    repo_path: &str,
    capabilities_json: Option<String>,
    timeout_secs: u64,
    bind_address: &str,
    enable_mdns: bool,
    passphrase: Option<String>,
) -> PyResult<(String, String, String, String, String, PyPairingHandle)> {
    let _passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let bind_addr: IpAddr = bind_address
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    let capabilities: Vec<String> = if let Some(json) = capabilities_json {
        serde_json::from_str(&json).unwrap_or_else(|_| vec!["sign:commit".to_string()])
    } else {
        vec!["sign:commit".to_string()]
    };

    py.allow_threads(move || {
        let identity_storage = RegistryIdentityStorage::new(repo.clone());
        let managed = identity_storage
            .load_identity()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
        let controller_did = managed.controller_did.to_string();

        #[allow(clippy::disallowed_methods)] // Presentation boundary
        let now = Utc::now();
        let session_req = build_pairing_session_request(
            now,
            PairingSessionParams {
                controller_did: controller_did.clone(),
                registry: "local".to_string(),
                capabilities: capabilities.clone(),
                expiry_secs: timeout_secs,
            },
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        let session_id = session_req.create_request.session_id.clone();
        let short_code = session_req.create_request.short_code.clone();

        let mut builder = PairingDaemonBuilder::new().with_rate_limiter(RateLimiter::new(100));

        let mock_addr = SocketAddr::new(bind_addr, 0);
        builder = builder.with_network(MockNetworkInterfaces(bind_addr));

        if !enable_mdns {
            builder = builder.with_discovery(MockNetworkDiscovery(mock_addr));
        }

        let daemon = builder
            .build(session_req.create_request)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        let token = daemon.token().to_string();
        let (router, handle) = daemon.into_parts();

        let rt = runtime();
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
                PyRuntimeError::new_err("[AUTHS_PAIRING_ERROR] Server failed to start within 5s")
            })?;

        let py_handle = PyPairingHandle {
            handle: Some(handle),
            server_task: Some(server_task),
            endpoint: endpoint.clone(),
        };

        Ok((
            session_id,
            short_code,
            endpoint,
            token,
            controller_did,
            py_handle,
        ))
    })
}

#[pyfunction]
#[pyo3(signature = (short_code, endpoint, token, repo_path, device_name=None, passphrase=None))]
pub fn join_pairing_session_ffi(
    py: Python<'_>,
    short_code: &str,
    endpoint: &str,
    token: &str,
    repo_path: &str,
    device_name: Option<String>,
    passphrase: Option<String>,
) -> PyResult<(String, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let short_code = short_code.to_string();
    let endpoint = endpoint.to_string();
    let token = token.to_string();

    py.allow_threads(move || {
        let identity_storage = RegistryIdentityStorage::new(repo.clone());
        let managed = identity_storage
            .load_identity()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        let controller_identity_did =
            IdentityDID::new_unchecked(managed.controller_did.to_string());

        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let aliases = keychain
            .list_aliases_for_identity_with_role(&controller_identity_did, KeyRole::Primary)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
        let key_alias = aliases.into_iter().next().ok_or_else(|| {
            PyRuntimeError::new_err("[AUTHS_PAIRING_ERROR] No primary signing key found")
        })?;

        let (_did, _role, encrypted_key) = keychain
            .load_key(&key_alias)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        let pkcs8_bytes =
            auths_core::crypto::signer::decrypt_keypair(&encrypted_key, &passphrase_str)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

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
                PyRuntimeError::new_err(
                    "[AUTHS_PAIRING_ERROR] Failed to parse Ed25519 key material",
                )
            })?;

        let device_did = auths_verifier::types::DeviceDID::from_ed25519(&pubkey_32);

        let rt = runtime();
        let lookup_url = format!("{}/v1/pairing/sessions/by-code/{}", endpoint, short_code);

        let session_data: serde_json::Value = rt.block_on(async {
            let client = reqwest::Client::new();
            let resp = client
                .get(&lookup_url)
                .send()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))
        })?;

        let session_id = session_data["session_id"]
            .as_str()
            .ok_or_else(|| {
                PyRuntimeError::new_err("[AUTHS_PAIRING_ERROR] No session_id in response")
            })?
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

        #[allow(clippy::disallowed_methods)] // Presentation boundary
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
        let (pairing_response, _shared_secret) = auths_core::pairing::PairingResponse::create(
            now,
            &pairing_token,
            &secure_seed,
            &pubkey_32,
            device_did.to_string(),
            device_name.clone(),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

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

        let submit_url = format!("{}/v1/pairing/sessions/{}/response", endpoint, session_id);

        rt.block_on(async {
            let client = reqwest::Client::new();
            let resp = client
                .post(&submit_url)
                .header("X-Pairing-Token", &token)
                .json(&submit_req)
                .send()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(PyRuntimeError::new_err(format!(
                    "[AUTHS_PAIRING_ERROR] Submit response failed: {} {}",
                    status, body
                )));
            }
            Ok::<(), PyErr>(())
        })?;

        Ok((device_did.to_string(), device_name))
    })
}

#[pyfunction]
#[pyo3(signature = (device_did, device_public_key_hex, repo_path, capabilities_json=None, passphrase=None))]
pub fn complete_pairing_ffi(
    py: Python<'_>,
    device_did: &str,
    device_public_key_hex: &str,
    repo_path: &str,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
) -> PyResult<(String, Option<String>, String)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let device_did = device_did.to_string();
    let device_pk_hex = device_public_key_hex.to_string();
    let capabilities: Vec<String> = if let Some(json) = capabilities_json {
        serde_json::from_str(&json).unwrap_or_else(|_| vec!["sign:commit".to_string()])
    } else {
        vec!["sign:commit".to_string()]
    };

    py.allow_threads(move || {
        let device_pubkey = hex::decode(&device_pk_hex).map_err(|e| {
            PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] Invalid public key hex: {e}"))
        })?;

        let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
            Arc::new(RegistryIdentityStorage::new(repo.clone()));

        let managed = identity_storage
            .load_identity()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
        let controller_identity_did =
            IdentityDID::new_unchecked(managed.controller_did.to_string());

        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let aliases = keychain
            .list_aliases_for_identity_with_role(&controller_identity_did, KeyRole::Primary)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;
        let identity_key_alias_str = aliases.into_iter().next().ok_or_else(|| {
            PyRuntimeError::new_err("[AUTHS_PAIRING_ERROR] No primary signing key found")
        })?;
        let identity_key_alias = KeyAlias::new_unchecked(identity_key_alias_str);

        let key_storage: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
            Arc::from(keychain);
        let provider = Arc::new(auths_core::signing::PrefilledPassphraseProvider::new(
            &passphrase_str,
        ));

        #[allow(clippy::disallowed_methods)] // Presentation boundary
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
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        let attestation_storage = RegistryAttestationStorage::new(&repo);
        use auths_id::attestation::AttestationSink;
        attestation_storage
            .export(
                &auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation.clone()),
            )
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_PAIRING_ERROR] {e}")))?;

        Ok((device_did, None, attestation.rid.to_string()))
    })
}
