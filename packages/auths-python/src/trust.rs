use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

use auths_core::trust::pinned::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
use auths_id::identity::resolve::{DefaultDidResolver, DidResolver};
use chrono::Utc;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn store_path(repo_path: &str) -> PathBuf {
    resolve_repo(repo_path).join("known_identities.json")
}

fn parse_trust_level(s: &str) -> PyResult<TrustLevel> {
    match s {
        "tofu" => Ok(TrustLevel::Tofu),
        "manual" => Ok(TrustLevel::Manual),
        "org_policy" => Ok(TrustLevel::OrgPolicy),
        _ => Err(PyValueError::new_err(format!(
            "Invalid trust_level '{}': must be one of 'tofu', 'manual', 'org_policy'",
            s
        ))),
    }
}

fn trust_level_str(tl: &TrustLevel) -> &'static str {
    match tl {
        TrustLevel::Tofu => "tofu",
        TrustLevel::Manual => "manual",
        TrustLevel::OrgPolicy => "org_policy",
    }
}

#[pyfunction]
#[pyo3(signature = (did, repo_path, label=None, trust_level="manual"))]
pub fn pin_identity(
    py: Python<'_>,
    did: &str,
    repo_path: &str,
    label: Option<String>,
    trust_level: &str,
) -> PyResult<(String, Option<String>, String, String, Option<u64>, String)> {
    let tl = parse_trust_level(trust_level)?;
    let did = did.to_string();
    let repo = repo_path.to_string();
    let label = label;

    py.allow_threads(move || {
        let store = PinnedIdentityStore::new(store_path(&repo));
        let repo_path = resolve_repo(&repo);

        let resolver = DefaultDidResolver::with_repo(&repo_path);
        let public_key_hex = match resolver.resolve(&did) {
            Ok(resolved) => hex::encode(resolved.public_key().as_bytes()),
            Err(_) => {
                // If DID can't be resolved, use a placeholder — the pin still works
                // for trust-on-first-use patterns where the key isn't known yet
                String::new()
            }
        };

        // Check if already pinned — if so, update label by remove + re-pin
        if let Ok(Some(existing)) = store.lookup(&did) {
            let _ = store.remove(&did);
            let now = Utc::now();
            let pin = PinnedIdentity {
                did: did.clone(),
                public_key_hex: if public_key_hex.is_empty() {
                    existing.public_key_hex
                } else {
                    public_key_hex
                },
                kel_tip_said: existing.kel_tip_said,
                kel_sequence: existing.kel_sequence,
                first_seen: existing.first_seen,
                origin: label.clone().unwrap_or_else(|| existing.origin),
                trust_level: tl.clone(),
            };
            store
                .pin(pin.clone())
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))?;
            let pinned_at = now.to_rfc3339();
            return Ok((
                pin.did,
                label,
                trust_level_str(&pin.trust_level).to_string(),
                pin.first_seen.to_rfc3339(),
                pin.kel_sequence,
                pinned_at,
            ));
        }

        let now = Utc::now();
        let pin = PinnedIdentity {
            did: did.clone(),
            public_key_hex,
            kel_tip_said: None,
            kel_sequence: None,
            first_seen: now,
            origin: label.clone().unwrap_or_else(|| "manual".to_string()),
            trust_level: tl.clone(),
        };

        store
            .pin(pin)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))?;

        let pinned_at = now.to_rfc3339();
        Ok((
            did,
            label,
            trust_level_str(&tl).to_string(),
            now.to_rfc3339(),
            None,
            pinned_at,
        ))
    })
}

#[pyfunction]
#[pyo3(signature = (did, repo_path))]
pub fn remove_pinned_identity(
    py: Python<'_>,
    did: &str,
    repo_path: &str,
) -> PyResult<()> {
    let did = did.to_string();
    let repo = repo_path.to_string();

    py.allow_threads(move || {
        let store = PinnedIdentityStore::new(store_path(&repo));
        store
            .remove(&did)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))?;
        Ok(())
    })
}

#[pyfunction]
#[pyo3(signature = (repo_path,))]
pub fn list_pinned_identities(
    py: Python<'_>,
    repo_path: &str,
) -> PyResult<String> {
    let repo = repo_path.to_string();

    py.allow_threads(move || {
        let store = PinnedIdentityStore::new(store_path(&repo));
        let entries = store
            .list()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))?;

        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "did": e.did,
                    "label": e.origin,
                    "trust_level": trust_level_str(&e.trust_level),
                    "first_seen": e.first_seen.to_rfc3339(),
                    "kel_sequence": e.kel_sequence,
                    "pinned_at": e.first_seen.to_rfc3339(),
                })
            })
            .collect();

        serde_json::to_string(&json_entries)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))
    })
}

#[pyfunction]
#[pyo3(signature = (did, repo_path))]
pub fn get_pinned_identity(
    py: Python<'_>,
    did: &str,
    repo_path: &str,
) -> PyResult<Option<(String, Option<String>, String, String, Option<u64>, String)>> {
    let did = did.to_string();
    let repo = repo_path.to_string();

    py.allow_threads(move || {
        let store = PinnedIdentityStore::new(store_path(&repo));
        let entry = store
            .lookup(&did)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_TRUST_ERROR] {e}")))?;

        Ok(entry.map(|e| {
            (
                e.did,
                Some(e.origin),
                trust_level_str(&e.trust_level).to_string(),
                e.first_seen.to_rfc3339(),
                e.kel_sequence,
                e.first_seen.to_rfc3339(),
            )
        }))
    })
}
