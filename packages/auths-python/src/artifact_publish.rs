use std::sync::OnceLock;

use pyo3::exceptions::{PyConnectionError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::runtime::runtime;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("failed to create HTTP client")
    })
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyArtifactPublishResult {
    #[pyo3(get)]
    pub attestation_rid: String,
    #[pyo3(get)]
    pub package_name: Option<String>,
    #[pyo3(get)]
    pub signer_did: String,
}

#[pymethods]
impl PyArtifactPublishResult {
    fn __repr__(&self) -> String {
        let rid_short = if self.attestation_rid.len() > 20 {
            format!("{}...", &self.attestation_rid[..20])
        } else {
            self.attestation_rid.clone()
        };
        let did_tail = if self.signer_did.len() > 12 {
            &self.signer_did[self.signer_did.len() - 12..]
        } else {
            &self.signer_did
        };
        let pkg = match &self.package_name {
            Some(p) => format!(", pkg={p:?}"),
            None => String::new(),
        };
        format!("ArtifactPublishResult(rid='{rid_short}'{pkg}, signer='…{did_tail}')")
    }
}

/// Publish a signed artifact attestation to a registry.
///
/// Args:
/// * `attestation_json`: The attestation JSON string from `sign_artifact`.
/// * `registry_url`: Base URL of the target registry.
/// * `package_name`: Optional ecosystem-prefixed package identifier (e.g. `"npm:react@18.3.0"`).
///
/// Usage:
/// ```ignore
/// let result = publish_artifact(py, att_json, "https://registry.example.com", None)?;
/// println!("Published: {}", result.attestation_rid);
/// ```
#[pyfunction]
#[pyo3(signature = (attestation_json, registry_url, package_name=None))]
pub fn publish_artifact(
    _py: Python<'_>,
    attestation_json: String,
    registry_url: String,
    package_name: Option<String>,
) -> PyResult<PyArtifactPublishResult> {
    let attestation: serde_json::Value = serde_json::from_str(&attestation_json)
        .map_err(|e| PyValueError::new_err(format!("invalid attestation JSON: {e}")))?;

    let url = format!(
        "{}/v1/artifacts/publish",
        registry_url.trim_end_matches('/')
    );

    {
        runtime().block_on(async move {
            let mut body = serde_json::json!({ "attestation": attestation });
            if let Some(ref name) = package_name {
                body["package_name"] = serde_json::Value::String(name.clone());
            }

            let response = http_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| PyConnectionError::new_err(format!("registry unreachable: {e}")))?;

            match response.status().as_u16() {
                201 => {
                    #[derive(serde::Deserialize)]
                    struct PublishResponse {
                        attestation_rid: String,
                        package_name: Option<String>,
                        signer_did: String,
                    }
                    let resp: PublishResponse = response.json().await.map_err(|e| {
                        PyRuntimeError::new_err(format!("[AUTHS_NETWORK_ERROR] Invalid registry response: {e}"))
                    })?;
                    Ok(PyArtifactPublishResult {
                        attestation_rid: resp.attestation_rid,
                        package_name: resp.package_name,
                        signer_did: resp.signer_did,
                    })
                }
                409 => Err(PyRuntimeError::new_err(
                    "[AUTHS_REGISTRY_ERROR] Duplicate attestation: artifact attestation already published (duplicate RID)",
                )),
                422 => {
                    let body = response.text().await.unwrap_or_default();
                    Err(PyRuntimeError::new_err(format!(
                        "[AUTHS_VERIFICATION_FAILED] Verification failed: {body}"
                    )))
                }
                status => {
                    let body = response.text().await.unwrap_or_default();
                    Err(PyRuntimeError::new_err(format!(
                        "[AUTHS_NETWORK_ERROR] Registry error ({status}): {body}"
                    )))
                }
            }
        })
    }
}
