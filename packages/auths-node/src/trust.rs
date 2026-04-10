use std::path::PathBuf;
use std::sync::Arc;

use auths_core::trust::pinned::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
use auths_id::identity::resolve::{DefaultDidResolver, DidResolver, RegistryDidResolver};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use auths_verifier::PublicKeyHex;
use napi_derive::napi;

use crate::error::format_error;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn store_path(repo_path: &str) -> PathBuf {
    resolve_repo(repo_path).join("known_identities.json")
}

fn parse_trust_level(s: &str) -> napi::Result<TrustLevel> {
    match s {
        "tofu" => Ok(TrustLevel::Tofu),
        "manual" => Ok(TrustLevel::Manual),
        "org_policy" => Ok(TrustLevel::OrgPolicy),
        _ => Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Invalid trust_level '{}': must be one of 'tofu', 'manual', 'org_policy'",
                s
            ),
        )),
    }
}

fn trust_level_str(tl: &TrustLevel) -> &'static str {
    match tl {
        TrustLevel::Tofu => "tofu",
        TrustLevel::Manual => "manual",
        TrustLevel::OrgPolicy => "org_policy",
    }
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiPinnedIdentity {
    pub did: String,
    pub label: Option<String>,
    pub trust_level: String,
    pub first_seen: String,
    pub kel_sequence: Option<u32>,
    pub pinned_at: String,
}

#[napi]
pub fn pin_identity(
    did: String,
    repo_path: String,
    label: Option<String>,
    trust_level: Option<String>,
) -> napi::Result<NapiPinnedIdentity> {
    let tl = parse_trust_level(&trust_level.unwrap_or_else(|| "manual".to_string()))?;
    let store = PinnedIdentityStore::new(store_path(&repo_path));
    let repo = resolve_repo(&repo_path);

    let resolved = DefaultDidResolver::with_repo(&repo)
        .resolve(&did)
        .or_else(|_| {
            let backend: Arc<dyn auths_id::ports::registry::RegistryBackend + Send + Sync> =
                Arc::new(GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo),
                ));
            RegistryDidResolver::new(backend).resolve(&did)
        })
        .map_err(|e| {
            format_error(
                "AUTHS_TRUST_ERROR",
                format!("Cannot resolve public key for {did}: {e}"),
            )
        })?;
    #[allow(clippy::disallowed_methods)] // INVARIANT: hex::encode always produces valid hex
    let public_key_hex = PublicKeyHex::new_unchecked(hex::encode(resolved.public_key_bytes()));

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();

    if let Ok(Some(existing)) = store.lookup(&did) {
        let _ = store.remove(&did);
        let pin = PinnedIdentity {
            did: did.clone(),
            public_key_hex: if public_key_hex.as_ref().is_empty() {
                existing.public_key_hex
            } else {
                public_key_hex
            },
            kel_tip_said: existing.kel_tip_said,
            kel_sequence: existing.kel_sequence,
            first_seen: existing.first_seen,
            origin: label.clone().unwrap_or(existing.origin),
            trust_level: tl.clone(),
        };
        store
            .pin(pin.clone())
            .map_err(|e| format_error("AUTHS_TRUST_ERROR", e))?;
        return Ok(NapiPinnedIdentity {
            did: pin.did,
            label,
            trust_level: trust_level_str(&pin.trust_level).to_string(),
            first_seen: pin.first_seen.to_rfc3339(),
            kel_sequence: pin.kel_sequence.map(|s| s as u32),
            pinned_at: now.to_rfc3339(),
        });
    }

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
        .map_err(|e| format_error("AUTHS_TRUST_ERROR", e))?;

    Ok(NapiPinnedIdentity {
        did,
        label,
        trust_level: trust_level_str(&tl).to_string(),
        first_seen: now.to_rfc3339(),
        kel_sequence: None,
        pinned_at: now.to_rfc3339(),
    })
}

#[napi]
pub fn remove_pinned_identity(did: String, repo_path: String) -> napi::Result<()> {
    let store = PinnedIdentityStore::new(store_path(&repo_path));
    store
        .remove(&did)
        .map_err(|e| format_error("AUTHS_TRUST_ERROR", e))?;
    Ok(())
}

#[napi]
pub fn list_pinned_identities(repo_path: String) -> napi::Result<String> {
    let store = PinnedIdentityStore::new(store_path(&repo_path));
    let entries = store
        .list()
        .map_err(|e| format_error("AUTHS_TRUST_ERROR", e))?;

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

    serde_json::to_string(&json_entries).map_err(|e| format_error("AUTHS_TRUST_ERROR", e))
}

#[napi]
pub fn get_pinned_identity(
    did: String,
    repo_path: String,
) -> napi::Result<Option<NapiPinnedIdentity>> {
    let store = PinnedIdentityStore::new(store_path(&repo_path));
    let entry = store
        .lookup(&did)
        .map_err(|e| format_error("AUTHS_TRUST_ERROR", e))?;

    Ok(entry.map(|e| NapiPinnedIdentity {
        did: e.did,
        label: Some(e.origin),
        trust_level: trust_level_str(&e.trust_level).to_string(),
        first_seen: e.first_seen.to_rfc3339(),
        kel_sequence: e.kel_sequence.map(|s| s as u32),
        pinned_at: e.first_seen.to_rfc3339(),
    }))
}
