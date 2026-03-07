use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::runtime::runtime;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to create HTTP client")
    })
}

#[derive(Serialize)]
struct ExchangeRequest {
    attestation_chain: serde_json::Value,
    root_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_capabilities: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Exchange an attestation chain for a Bearer token via the OIDC bridge.
///
/// Args:
/// * `bridge_url`: The OIDC bridge base URL.
/// * `chain_json`: JSON string of the attestation chain array.
/// * `root_public_key`: Hex-encoded Ed25519 public key.
/// * `capabilities`: List of requested capability strings.
///
/// Usage:
/// ```ignore
/// let token = get_token(py, "https://bridge.example.com", "[...]", "abcd...", vec![])?;
/// ```
#[pyfunction]
pub fn get_token(
    py: Python<'_>,
    bridge_url: String,
    chain_json: String,
    root_public_key: String,
    capabilities: Vec<String>,
) -> PyResult<String> {
    let chain: serde_json::Value = serde_json::from_str(&chain_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid chain JSON: {e}"))
    })?;

    let url = format!("{}/token", bridge_url.trim_end_matches('/'));
    let request_body = ExchangeRequest {
        attestation_chain: chain,
        root_public_key,
        requested_capabilities: if capabilities.is_empty() {
            None
        } else {
            Some(capabilities)
        },
    };

    py.allow_threads(|| {
        runtime().block_on(async {
            let response = http_client()
                .post(&url)
                .json(&request_body)
                .send()
                .await
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                        "bridge unreachable: {e}"
                    ))
                })?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "token exchange failed (HTTP {status}): {body}"
                )));
            }

            let token_resp: TokenResponse = response.json().await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("invalid response: {e}"))
            })?;

            Ok(token_resp.access_token)
        })
    })
}
