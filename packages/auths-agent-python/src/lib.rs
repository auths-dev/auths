//! Python bindings for Auths agent identity and MCP token exchange.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Request body for the OIDC bridge token exchange.
#[derive(Serialize)]
struct ExchangeRequest {
    attestation_chain: serde_json::Value,
    root_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_capabilities: Option<Vec<String>>,
}

/// Response from the OIDC bridge.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Exchange an attestation chain for a Bearer token via the OIDC bridge.
///
/// Args:
///     bridge_url: The OIDC bridge base URL.
///     chain_json: JSON string of the attestation chain array.
///     root_public_key: Hex-encoded Ed25519 public key.
///     capabilities: List of requested capability strings.
///
/// Returns:
///     The JWT access token string.
#[pyfunction]
fn get_token(
    bridge_url: String,
    chain_json: String,
    root_public_key: String,
    capabilities: Vec<String>,
) -> PyResult<String> {
    let chain: serde_json::Value = serde_json::from_str(&chain_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid chain JSON: {e}")))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("failed to create runtime: {e}")))?;

    rt.block_on(async {
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

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("HTTP client error: {e}")))?;

        let response = client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("bridge unreachable: {e}")))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("token exchange failed (HTTP {status}): {body}"),
            ));
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("invalid response: {e}")))?;

        Ok(token_resp.access_token)
    })
}

/// Python module definition.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_token, m)?)?;
    Ok(())
}
