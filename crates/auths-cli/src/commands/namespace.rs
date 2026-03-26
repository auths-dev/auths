use std::io::{self, Write};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use auths_core::ports::namespace::{Ecosystem, PackageName};
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
use auths_crypto::AuthsErrorInfo;
use auths_id::storage::identity::IdentityStorage;
use auths_id::storage::layout;
use auths_infra_http::resolve_verified_platform_context;
use auths_sdk::namespace_registry::NamespaceVerifierRegistry;
use auths_sdk::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::workflows::namespace::{
    DelegateNamespaceCommand, TransferNamespaceCommand, initiate_namespace_claim,
    parse_claim_response, parse_lookup_response, sign_namespace_delegate, sign_namespace_transfer,
};
use auths_storage::git::RegistryIdentityStorage;
use auths_verifier::CanonicalDid;

/// Manage namespace claims in package ecosystems.
#[derive(Parser, Debug, Clone)]
pub struct NamespaceCommand {
    #[clap(subcommand)]
    pub subcommand: NamespaceSubcommand,
}

/// Subcommands for managing namespace claims and delegations.
#[derive(Subcommand, Debug, Clone)]
pub enum NamespaceSubcommand {
    /// Claim a namespace in a package ecosystem.
    ///
    /// Requires a verified platform claim (run `auths id claim github` first).
    /// The system reads your verified platform identity from the registry —
    /// no self-asserted usernames.
    Claim {
        /// Package ecosystem (e.g. npm, crates.io, pypi)
        #[arg(long)]
        ecosystem: String,

        /// Package name to claim
        #[arg(long)]
        package_name: String,

        /// Registry URL (defaults to the public registry)
        #[arg(long)]
        registry_url: Option<String>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        signer_alias: Option<String>,
    },

    /// Delegate namespace authority to another identity
    Delegate {
        /// Package ecosystem (e.g. npm, crates.io, pypi)
        #[arg(long)]
        ecosystem: String,

        /// Package name
        #[arg(long)]
        package_name: String,

        /// DID of the identity to delegate to
        #[arg(long)]
        delegate_did: String,

        /// Registry URL (defaults to the public registry)
        #[arg(long)]
        registry_url: Option<String>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        signer_alias: Option<String>,
    },

    /// Transfer namespace ownership to another identity
    Transfer {
        /// Package ecosystem (e.g. npm, crates.io, pypi)
        #[arg(long)]
        ecosystem: String,

        /// Package name
        #[arg(long)]
        package_name: String,

        /// DID of the new owner
        #[arg(long)]
        new_owner_did: String,

        /// Registry URL (defaults to the public registry)
        #[arg(long)]
        registry_url: Option<String>,

        /// Alias of the signing key in keychain
        #[arg(long)]
        signer_alias: Option<String>,
    },

    /// Look up namespace information
    Lookup {
        /// Package ecosystem (e.g. npm, crates.io, pypi)
        #[arg(long)]
        ecosystem: String,

        /// Package name
        #[arg(long)]
        package_name: String,

        /// Registry URL (defaults to the public registry)
        #[arg(long)]
        registry_url: Option<String>,
    },
}

impl ExecutableCommand for NamespaceCommand {
    #[allow(clippy::disallowed_methods)]
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_namespace(self.clone(), ctx)
    }
}

fn resolve_registry_url(registry_url: Option<String>) -> String {
    registry_url.unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

fn load_identity_and_alias(
    ctx: &CliConfig,
    signer_alias: Option<String>,
) -> Result<(auths_verifier::types::IdentityDID, KeyAlias)> {
    let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
    let identity_storage = RegistryIdentityStorage::new(repo_path);
    let managed_identity = identity_storage
        .load_identity()
        .context("Failed to load identity. Run `auths init` first.")?;

    let controller_did = managed_identity.controller_did;

    let alias_str = signer_alias.unwrap_or_else(|| {
        let prefix = controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap_or(controller_did.as_str());
        format!(
            "ns-{}",
            prefix
                .chars()
                .filter(|c| c.is_alphanumeric())
                .take(20)
                .collect::<String>()
                .to_lowercase()
        )
    });

    let key_alias = KeyAlias::new_unchecked(alias_str);
    Ok((controller_did, key_alias))
}

fn post_signed_entry(registry_url: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let url = format!("{}/v1/log/entries", registry_url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .with_context(|| format!("Failed to POST to {url}"))?;

    let status = response.status();
    let response_text = response
        .text()
        .context("Failed to read registry response")?;

    if !status.is_success() {
        return Err(anyhow!(
            "Registry returned HTTP {}: {}",
            status,
            response_text
        ));
    }

    serde_json::from_str(&response_text).context("Failed to parse registry response")
}

/// Handles `namespace` commands for managing package namespace claims.
#[allow(clippy::disallowed_methods)] // CLI boundary: Utc::now() injected here
pub fn handle_namespace(cmd: NamespaceCommand, ctx: &CliConfig) -> Result<()> {
    match cmd.subcommand {
        NamespaceSubcommand::Claim {
            ecosystem,
            package_name,
            registry_url,
            signer_alias,
        } => {
            let registry_url = resolve_registry_url(registry_url);
            let (controller_did, key_alias) = load_identity_and_alias(ctx, signer_alias)?;
            let signer = StorageSigner::new(get_platform_keychain()?);
            let passphrase_provider = ctx.passphrase_provider.clone();

            let eco = Ecosystem::parse(&ecosystem).context("Failed to parse ecosystem")?;
            let pkg = PackageName::parse(&package_name).context("Failed to parse package name")?;

            #[allow(clippy::disallowed_methods)]
            // INVARIANT: controller_did from storage is always valid
            let canonical_did = CanonicalDid::new_unchecked(controller_did.as_str());

            // Fetch verified platform claims from the registry — no self-asserted usernames.
            let rt_prefetch =
                tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
            let platform = rt_prefetch
                .block_on(resolve_verified_platform_context(
                    &registry_url,
                    controller_did.as_str(),
                ))
                .map_err(|e| anyhow!("{}", e))?;

            let registry = NamespaceVerifierRegistry::with_defaults();
            let verifier = registry
                .require(eco)
                .context("No verifier available for this ecosystem")?;

            println!("Verifying ownership of {}/{}...\n", eco, package_name);

            let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

            let mut session = rt
                .block_on(initiate_namespace_claim(
                    chrono::Utc::now(),
                    verifier.as_ref(),
                    eco,
                    pkg,
                    canonical_did,
                    platform,
                ))
                .context("Failed to initiate namespace verification")?;

            println!("  {}\n", session.challenge.instructions);

            // Try verification — on OwnershipNotConfirmed, progressively
            // prompt for additional credentials (e.g. PyPI username)
            let max_retries = 3;
            let mut result = None;

            for attempt in 0..max_retries {
                match rt.block_on(session.complete_ref(
                    chrono::Utc::now(),
                    verifier.as_ref(),
                    &signer,
                    passphrase_provider.as_ref(),
                    &key_alias,
                )) {
                    Ok(r) => {
                        result = Some(r);
                        break;
                    }
                    Err(auths_sdk::workflows::namespace::NamespaceError::VerificationFailed(
                        ref verify_err,
                    )) => {
                        use auths_core::ports::namespace::NamespaceVerifyError;
                        match verify_err {
                            NamespaceVerifyError::OwnershipNotConfirmed { ecosystem, .. }
                                if attempt + 1 < max_retries =>
                            {
                                // Progressive prompting: ask for ecosystem-specific username
                                match *ecosystem {
                                    Ecosystem::Pypi if session.platform.pypi_username.is_none() => {
                                        eprintln!(
                                            "\nAutomatic verification didn't match. \
                                             Let's try your PyPI username."
                                        );
                                        print!("What's your PyPI username? ");
                                        io::stdout().flush().ok();
                                        let mut username = String::new();
                                        let _ = io::stdin().read_line(&mut username);
                                        let username = username.trim().to_string();
                                        if !username.is_empty() {
                                            session.platform.pypi_username = Some(username);
                                            eprintln!("Retrying with PyPI username...\n");
                                        }
                                        continue;
                                    }
                                    Ecosystem::Npm if session.platform.npm_username.is_none() => {
                                        eprintln!(
                                            "\nAutomatic verification didn't match. \
                                             Let's try your npm username."
                                        );
                                        print!("What's your npm username? ");
                                        io::stdout().flush().ok();
                                        let mut username = String::new();
                                        let _ = io::stdin().read_line(&mut username);
                                        let username = username.trim().to_string();
                                        if !username.is_empty() {
                                            session.platform.npm_username = Some(username);
                                            eprintln!("Retrying with npm username...\n");
                                        }
                                        continue;
                                    }
                                    _ => {
                                        eprintln!(
                                            "\nVerification not confirmed. Did you complete the step above?"
                                        );
                                        print!("Press Enter to retry, or Ctrl+C to cancel...");
                                        io::stdout().flush().ok();
                                        let _ = io::stdin().read_line(&mut String::new());
                                        continue;
                                    }
                                }
                            }
                            _ => {
                                eprintln!("\n✗ Verification failed [{}]", verify_err.error_code());
                                eprintln!("  {verify_err}");
                                if let Some(hint) = verify_err.suggestion() {
                                    eprintln!("\n  Hint: {hint}");
                                }
                                return Err(anyhow!("{}", verify_err));
                            }
                        }
                    }
                    Err(e) => return Err(e).context("Namespace verification failed"),
                }
            }

            let result = result
                .ok_or_else(|| anyhow!("Verification failed after {max_retries} attempts"))?;

            println!("\nChecking... ✓ Verified!\n");
            println!("Claiming namespace {}/{}...", eco, package_name);

            let response = post_signed_entry(&registry_url, result.signed_entry.to_request_body())?;

            let claim_result = parse_claim_response(
                eco.as_str(),
                &package_name,
                controller_did.as_str(),
                &response,
            );

            println!("\n✓ Namespace {}/{} claimed", eco, package_name);
            println!("  Log sequence: {}", claim_result.log_sequence);

            Ok(())
        }

        NamespaceSubcommand::Delegate {
            ecosystem,
            package_name,
            delegate_did,
            registry_url,
            signer_alias,
        } => {
            let registry_url = resolve_registry_url(registry_url);
            let (controller_did, key_alias) = load_identity_and_alias(ctx, signer_alias)?;
            let signer = StorageSigner::new(get_platform_keychain()?);
            let passphrase_provider = ctx.passphrase_provider.clone();

            println!(
                "Delegating namespace {}/{} to {}...",
                ecosystem, package_name, delegate_did
            );

            let sdk_cmd = DelegateNamespaceCommand {
                ecosystem: ecosystem.clone(),
                package_name: package_name.clone(),
                delegate_did: delegate_did.clone(),
                registry_url: registry_url.clone(),
            };

            let signed = sign_namespace_delegate(
                &sdk_cmd,
                &controller_did,
                &signer,
                passphrase_provider.as_ref(),
                &key_alias,
            )
            .context("Failed to sign namespace delegation")?;

            post_signed_entry(&registry_url, signed.to_request_body())?;

            println!("\nNamespace delegation successful!");
            println!("   Ecosystem:  {}", ecosystem);
            println!("   Package:    {}", package_name);
            println!("   Delegate:   {}", delegate_did);

            Ok(())
        }

        NamespaceSubcommand::Transfer {
            ecosystem,
            package_name,
            new_owner_did,
            registry_url,
            signer_alias,
        } => {
            let registry_url = resolve_registry_url(registry_url);
            let (controller_did, key_alias) = load_identity_and_alias(ctx, signer_alias)?;
            let signer = StorageSigner::new(get_platform_keychain()?);
            let passphrase_provider = ctx.passphrase_provider.clone();

            println!(
                "Transferring namespace {}/{} to {}...",
                ecosystem, package_name, new_owner_did
            );

            let sdk_cmd = TransferNamespaceCommand {
                ecosystem: ecosystem.clone(),
                package_name: package_name.clone(),
                new_owner_did: new_owner_did.clone(),
                registry_url: registry_url.clone(),
            };

            let signed = sign_namespace_transfer(
                &sdk_cmd,
                &controller_did,
                &signer,
                passphrase_provider.as_ref(),
                &key_alias,
            )
            .context("Failed to sign namespace transfer")?;

            post_signed_entry(&registry_url, signed.to_request_body())?;

            println!("\nNamespace transfer successful!");
            println!("   Ecosystem:  {}", ecosystem);
            println!("   Package:    {}", package_name);
            println!("   New Owner:  {}", new_owner_did);

            Ok(())
        }

        NamespaceSubcommand::Lookup {
            ecosystem,
            package_name,
            registry_url,
        } => {
            let registry_url = resolve_registry_url(registry_url);

            println!("Looking up namespace {}/{}...", ecosystem, package_name);

            let url = format!(
                "{}/v1/namespaces/{}/{}",
                registry_url.trim_end_matches('/'),
                ecosystem,
                package_name
            );

            let client = reqwest::blocking::Client::new();
            let response = client
                .get(&url)
                .send()
                .with_context(|| format!("Failed to GET {url}"))?;

            if response.status() == reqwest::StatusCode::NOT_FOUND {
                println!("\nNamespace {}/{} is not claimed.", ecosystem, package_name);
                return Ok(());
            }

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().unwrap_or_default();
                return Err(anyhow!("Registry returned HTTP {}: {}", status, body));
            }

            let body: serde_json::Value = response
                .json()
                .context("Failed to parse registry response")?;

            let info = parse_lookup_response(&ecosystem, &package_name, &body);

            println!("\nNamespace: {}/{}", info.ecosystem, info.package_name);
            println!("   Owner: {}", info.owner_did);
            if info.delegates.is_empty() {
                println!("   Delegates: (none)");
            } else {
                println!("   Delegates:");
                for d in &info.delegates {
                    println!("     - {}", d);
                }
            }

            Ok(())
        }
    }
}
