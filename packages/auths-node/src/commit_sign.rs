use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_sdk::workflows::signing::{
    CommitSigningContext, CommitSigningParams, CommitSigningWorkflow,
};
use napi_derive::napi;

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_passphrase};

#[napi(object)]
#[derive(Clone)]
pub struct NapiCommitSignPemResult {
    pub signature_pem: String,
    pub method: String,
    pub namespace: String,
}

#[napi]
pub fn sign_commit(
    data: napi::bindgen_prelude::Buffer,
    identity_key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiCommitSignPemResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
    let keychain = Arc::from(keychain);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());

    let params = CommitSigningParams::new(&identity_key_alias, "git", data.to_vec()).with_repo_path(repo);

    let signing_ctx = CommitSigningContext {
        key_storage: keychain,
        passphrase_provider: provider,
        agent_signing: Arc::new(auths_sdk::ports::agent::NoopAgentProvider),
    };

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let now = chrono::Utc::now();

    let pem = CommitSigningWorkflow::execute(&signing_ctx, params, now).map_err(|e| {
        format_error(
            "AUTHS_SIGNING_FAILED",
            format!("Commit signing failed: {e}"),
        )
    })?;

    Ok(NapiCommitSignPemResult {
        signature_pem: pem,
        method: "direct".to_string(),
        namespace: "git".to_string(),
    })
}
