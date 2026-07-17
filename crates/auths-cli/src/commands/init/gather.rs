//! Configuration gathering functions for the init command.

use anyhow::{Context, Result, anyhow};
use std::path::Path;
use std::sync::Arc;

use auths_infra_http::HttpRegistryClient;
use auths_sdk::keychain::{KeyAlias, KeyStorage, get_platform_keychain};
use auths_sdk::ports::AttestationSource;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_sdk::types::{CiEnvironment, CiIdentityConfig, CreateDeveloperIdentityConfig};

use super::InitCommand;
use super::helpers::{
    check_git_version, detect_ci_environment, get_auths_repo_path, select_agent_capabilities,
};
use super::prompts::{prompt_for_alias, prompt_for_conflict_policy, prompt_for_git_scope};
use crate::ux::format::Output;

pub(crate) fn gather_developer_config(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
    registry_path: &Path,
) -> Result<(
    Box<dyn KeyStorage + Send + Sync>,
    CreateDeveloperIdentityConfig,
)> {
    out.print_info("Checking prerequisites...");
    let keychain = check_keychain_access(out)?;
    check_git_version(out)?;
    out.print_success("Prerequisites OK");
    out.newline();

    let alias = prompt_for_alias(interactive, cmd)?;
    let conflict_policy = prompt_for_conflict_policy(interactive, cmd, registry_path, out)?;
    let git_scope = prompt_for_git_scope(interactive, cmd.git_scope)?;

    let mut builder = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked(&alias))
        .with_conflict_policy(conflict_policy)
        .with_git_signing_scope(git_scope);

    if cmd.register {
        // --register is opt-in and there is no default registry, so it must name one.
        let registry = crate::commands::verify_helpers::require_registry(cmd.registry.clone())?;
        builder = builder.with_registration(&registry);
    }

    Ok((keychain, builder.build()))
}

#[allow(clippy::type_complexity)]
pub(crate) fn gather_ci_config(
    out: &Output,
    repo_opt: Option<&Path>,
) -> Result<(
    Option<String>,
    CiIdentityConfig,
    Box<dyn KeyStorage + Send + Sync>,
    String,
)> {
    out.print_info("Detecting CI environment...");
    let ci_env = detect_ci_environment();
    if let Some(ref vendor) = ci_env {
        out.print_success(&format!("Detected: {}", vendor));
    } else {
        out.print_warn("No CI environment detected, proceeding anyway");
    }
    out.newline();

    let registry_path = match repo_opt {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()
            .context("Failed to determine current working directory")?
            .join(".auths-ci"),
    };
    let keychain_file = registry_path.join("keys.enc");
    #[allow(clippy::disallowed_methods)] // CLI boundary: CI passphrase from env
    let (passphrase, passphrase_source) = match std::env::var("AUTHS_PASSPHRASE") {
        Ok(p) => (p, "the AUTHS_PASSPHRASE environment variable"),
        Err(_) => (
            auths_sdk::types::generate_ci_passphrase(),
            "a generated per-identity ephemeral passphrase",
        ),
    };
    preflight_passphrase(&passphrase, passphrase_source)?;

    // Persist the CI key to an encrypted file co-located with the registry so a
    // separate `auths sign` process can load it — the in-memory backend would lose
    // the key the moment `init` exits. Setting these here also makes the vars present
    // for the rest of this process and matches the copy-pasteable env block we print.
    // SAFETY: single-threaded CLI context; vars read immediately below and by the SDK context.
    unsafe {
        std::env::set_var("AUTHS_KEYCHAIN_BACKEND", "file");
        std::env::set_var("AUTHS_KEYCHAIN_FILE", &keychain_file);
        std::env::set_var("AUTHS_PASSPHRASE", &passphrase);
    }
    let keychain = get_platform_keychain()
        .map_err(|e| anyhow!("Failed to get file-backed keychain: {}", e))?;

    out.print_info(&format!("Using keychain: {}", keychain.backend_name()));

    let config = CiIdentityConfig {
        ci_environment: map_ci_environment(&ci_env),
        registry_path,
        keychain_file,
        passphrase: passphrase.clone(),
    };

    Ok((ci_env, config, keychain, passphrase))
}

pub(crate) fn gather_agent_config(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
) -> Result<(
    Box<dyn KeyStorage + Send + Sync>,
    auths_sdk::types::CreateAgentIdentityConfig,
)> {
    out.print_info("Setting capability scope...");
    let capabilities = select_agent_capabilities(interactive, out)?;
    let cap_names: Vec<String> = capabilities.iter().map(|c| c.name.clone()).collect();
    out.print_success(&format!("Capabilities: {}", cap_names.join(", ")));
    out.newline();

    let parsed_caps: Vec<auths_verifier::Capability> = cap_names
        .into_iter()
        .filter_map(|s| auths_verifier::Capability::parse(&s).ok())
        .collect();

    out.print_info("Checking prerequisites...");
    let keychain = check_keychain_access(out)?;
    out.print_success("Prerequisites OK");
    out.newline();

    let registry_path = get_auths_repo_path()?;

    let config = auths_sdk::types::CreateAgentIdentityConfig::builder(
        KeyAlias::new_unchecked("agent"),
        &registry_path,
    )
    .with_capabilities(parsed_caps)
    .with_expiry(365 * 24 * 3600)
    .dry_run(cmd.dry_run)
    .build();

    Ok((keychain, config))
}

pub(crate) fn submit_registration(
    repo_path: &Path,
    registry_url: Option<&str>,
    proof_url: Option<String>,
    skip: bool,
    out: &Output,
) -> Option<String> {
    if skip {
        out.print_info("Registration skipped (pass --register to publish to the registry)");
        return None;
    }
    // There is no default registry, and `gather` already refuses --register
    // without one — so reaching here without a URL is unreachable, not fatal.
    let Some(registry_url) = registry_url else {
        out.print_warn("Registration skipped: no registry configured (--registry <url>)");
        return None;
    };

    out.print_info("Publishing identity to Auths Registry...");
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            out.print_warn(&format!("Could not create async runtime: {e}"));
            return None;
        }
    };

    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(repo_path),
    ));
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(repo_path));
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> = attestation_store;

    let registry_client = HttpRegistryClient::new();

    match rt.block_on(
        auths_sdk::domains::identity::registration::register_identity(
            identity_storage,
            backend,
            attestation_source,
            registry_url,
            proof_url,
            &registry_client,
        ),
    ) {
        Ok(outcome) => {
            out.print_success(&format!("Identity registered at {}", outcome.registry));
            Some(outcome.registry)
        }
        Err(auths_sdk::error::RegistrationError::AlreadyRegistered) => {
            out.print_success("Already registered on this registry");
            Some(registry_url.to_string())
        }
        Err(auths_sdk::error::RegistrationError::QuotaExceeded) => {
            out.print_warn("Registration quota exceeded. Run `auths id register` to retry later.");
            None
        }
        Err(auths_sdk::error::RegistrationError::NetworkError(_)) => {
            out.print_warn(
                "Could not reach the registry (offline?). Your local setup is complete.",
            );
            out.println("  Run `auths id register` when you're back online.");
            None
        }
        Err(
            e @ (auths_sdk::error::RegistrationError::InvalidDidFormat { .. }
            | auths_sdk::error::RegistrationError::IdentityLoadError(_)
            | auths_sdk::error::RegistrationError::RegistryReadError(_)
            | auths_sdk::error::RegistrationError::SerializationError(_)),
        ) => {
            out.print_warn(&format!("Could not prepare registration payload: {e}"));
            out.println("  Run `auths id register` to retry.");
            None
        }
        Err(e) => {
            out.print_warn(&format!("Registration failed: {e}"));
            None
        }
    }
}

pub(crate) fn ensure_registry_dir(registry_path: &Path) -> Result<()> {
    if !registry_path.exists() {
        std::fs::create_dir_all(registry_path).with_context(|| {
            format!(
                "Failed to create registry directory: {}",
                registry_path.display()
            )
        })?;
    }
    if git2::Repository::open(registry_path).is_err() {
        git2::Repository::init(registry_path).with_context(|| {
            format!(
                "Failed to initialize git repository: {}",
                registry_path.display()
            )
        })?;
    }
    auths_sdk::domains::identity::service::install_registry_hook(registry_path);
    Ok(())
}

pub(crate) fn check_keychain_access(out: &Output) -> Result<Box<dyn KeyStorage + Send + Sync>> {
    match get_platform_keychain() {
        Ok(keychain) => {
            out.println(&format!(
                "  Keychain: {} (accessible)",
                out.success(keychain.backend_name())
            ));
            preflight_env_passphrase(&*keychain)?;
            Ok(keychain)
        }
        Err(e) => Err(anyhow!("Keychain not accessible: {}", e)),
    }
}

/// Preflight a passphrase against the strength policy before any setup side
/// effect, so the failure lands at the prerequisites step with the input named —
/// not mid-flow behind a generic storage error.
pub(crate) fn preflight_passphrase(passphrase: &str, source_name: &str) -> Result<()> {
    auths_sdk::keychain::validate_passphrase(passphrase).map_err(|e| {
        anyhow!(
            "The passphrase from {source_name} fails the strength policy: {e}\n  \
             Use at least 12 characters with 3 of 4 character classes \
             (lowercase, uppercase, digit, symbol)."
        )
    })
}

/// Validate an env-supplied passphrase up front for software keychain backends.
/// Hardware backends (Secure Enclave) never use a passphrase, so nothing is
/// checked — and an interactive prompt is validated at point of use instead.
fn preflight_env_passphrase(keychain: &(dyn KeyStorage + Send + Sync)) -> Result<()> {
    if keychain.is_hardware_backend() {
        return Ok(());
    }
    #[allow(clippy::disallowed_methods)] // CLI boundary: env read for preflight
    match std::env::var("AUTHS_PASSPHRASE") {
        Ok(passphrase) => {
            preflight_passphrase(&passphrase, "the AUTHS_PASSPHRASE environment variable")
        }
        Err(_) => Ok(()),
    }
}

pub(crate) fn map_ci_environment(detected: &Option<String>) -> CiEnvironment {
    auths_sdk::domains::ci::map_ci_environment(detected)
}
