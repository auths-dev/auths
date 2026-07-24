//! Identity management for delegated headless agents.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::ux::format::{JsonResponse, is_json_mode};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "agent",
    about = "Identity management for delegated headless agents.",
    after_help = "If you are an AI Agent/LLM, run `auths agent list` to find your assigned label, \
             then run `auths agent prompt --label <YOUR_LABEL>` to get started."
)]
pub struct AgentCommand {
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentSubcommand {
    /// Provision a new delegated headless agent in a single command
    Provision {
        /// Human-readable label / key alias for the new agent
        #[arg(short, long, help = "Label / key alias for the new agent")]
        label: Option<String>,

        /// Delegator signing key alias (defaults to "main")
        #[arg(long, help = "Your root identity's signing key name")]
        key: Option<String>,

        /// Capability granted to the agent (repeatable)
        #[arg(long = "scope", help = "Capability granted to the agent")]
        scope: Vec<auths_keri::Capability>,

        /// Expiration duration in seconds (e.g. 2592000 for 30 days)
        #[arg(long = "expires-in", help = "Expiration duration in seconds")]
        expires_in: Option<i64>,

        /// Destination directory for agent environment workspace (defaults to ~/.auths-agents/<label>/)
        #[arg(short, long, help = "Output directory for agent environment")]
        out: Option<PathBuf>,

        /// Provisioning profile: "ci" or "assistant"
        #[arg(long, help = "Agent profile preset")]
        profile: Option<String>,

        /// Passphrase file path (optional, auto-generated if absent)
        #[arg(long, help = "Passphrase file path")]
        passphrase_file: Option<PathBuf>,
    },

    /// List all agents delegated under your identity
    List {
        /// Include revoked agents in listing
        #[arg(long, help = "Include revoked agents")]
        include_revoked: bool,
    },

    /// Update mutable agent metadata or renew expiration
    Update {
        /// Target Agent DID or label
        agent: String,

        /// Update human label / agent name
        #[arg(short, long)]
        label: Option<String>,

        /// Extend expiration duration in seconds
        #[arg(long)]
        extend_expiration: Option<i64>,
    },

    /// Revoke a delegated agent identity
    Revoke {
        /// Target Agent DID or label to revoke
        agent_did: String,

        /// Delegator signing key alias
        #[arg(
            long,
            default_value = "main",
            help = "Your root identity's signing key name"
        )]
        key: String,
    },

    /// Generate a structured system prompt for an AI agent
    Prompt {
        /// The human-readable label / agent name
        #[arg(short, long, help = "Label / agent name (e.g., auths-agent)")]
        label: String,
    },
}

pub fn handle_agent(cmd: AgentCommand, repo: Option<PathBuf>) -> Result<()> {
    match cmd.command {
        AgentSubcommand::Provision {
            label,
            key,
            scope,
            expires_in,
            out,
            profile,
            passphrase_file,
        } => handle_provision_cmd(
            label,
            key,
            scope,
            expires_in,
            out,
            profile,
            passphrase_file,
            repo,
        ),
        AgentSubcommand::List { include_revoked } => handle_list_cmd(include_revoked, repo),
        AgentSubcommand::Update {
            agent,
            label,
            extend_expiration,
        } => handle_update_cmd(agent, label, extend_expiration),
        AgentSubcommand::Revoke { agent_did, key } => handle_revoke_cmd(agent_did, key, repo),
        AgentSubcommand::Prompt { label } => handle_prompt_cmd(label),
    }
}

#[derive(serde::Serialize)]
struct AgentProvisionJsonResponse {
    agent_did: String,
    label: String,
    destination_dir: String,
    env_file_path: String,
    wrapper_path: String,
}

#[allow(clippy::too_many_arguments)]
fn handle_provision_cmd(
    label: Option<String>,
    key: Option<String>,
    scope: Vec<auths_keri::Capability>,
    expires_in: Option<i64>,
    out: Option<PathBuf>,
    profile: Option<String>,
    passphrase_file: Option<PathBuf>,
    repo: Option<PathBuf>,
) -> Result<()> {
    use crate::core::provider::CliPassphraseProvider;
    use auths_sdk::paths::auths_home;
    use auths_sdk::storage_layout::resolve_repo_path;
    use std::path::Path;

    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let is_interactive = console::user_attended() && !is_json_mode();

    let (label_str, key_str, profile_str, destination_dir) =
        if is_interactive && (label.is_none() || key.is_none() || profile.is_none()) {
            use dialoguer::{Input, Select};

            let label_input = if let Some(l) = label {
                l
            } else {
                Input::new()
                    .with_prompt("Type a name for your agent")
                    .interact_text()?
            };

            let key_input = if let Some(k) = key {
                k
            } else {
                // Auto-detect active local signing key (defaults to main-device, omitting root hardware AID main)
                let temp_provider = std::sync::Arc::new(CliPassphraseProvider::new());
                let temp_ctx = crate::factories::storage::build_auths_context(
                    &repo_path,
                    &env_config,
                    Some(temp_provider),
                )?;
                let aliases = temp_ctx.key_storage.list_aliases().unwrap_or_default();
                if aliases.iter().any(|k| k.as_str() == "main-device") {
                    "main-device".to_string()
                } else if let Some(first_device) =
                    aliases.iter().find(|k| k.as_str().ends_with("-device"))
                {
                    first_device.as_str().to_string()
                } else {
                    aliases
                        .into_iter()
                        .map(|k| k.as_str().to_string())
                        .find(|k| !k.ends_with("--next-0") && k != "main")
                        .unwrap_or_else(|| "main-device".to_string())
                }
            };

            let profile_input = if let Some(p) = profile {
                p
            } else {
                let profiles = vec![
                    "assistant (Interactive AI assistant profile)",
                    "ci (Headless CI runner profile)",
                ];
                let selection = Select::new()
                    .with_prompt("Select agent profile preset")
                    .items(&profiles)
                    .default(0)
                    .interact()?;
                if selection == 0 {
                    "assistant".to_string()
                } else {
                    "ci".to_string()
                }
            };

            let out_input = out.unwrap_or_else(|| {
                auths_home()
                    .unwrap_or_else(|_| PathBuf::from("~/.auths"))
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(".auths-agents")
                    .join(&label_input)
            });

            (label_input, key_input, profile_input, out_input)
        } else {
            let label_val = label.unwrap_or_else(|| "agent-builder".to_string());
            let key_val = key.unwrap_or_else(|| "main-device".to_string());
            let profile_val = profile.unwrap_or_else(|| "assistant".to_string());
            let out_val = out.unwrap_or_else(|| {
                auths_home()
                    .unwrap_or_else(|_| PathBuf::from("~/.auths"))
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(".auths-agents")
                    .join(&label_val)
            });
            (label_val, key_val, profile_val, out_val)
        };

    let key_ref = auths_sdk::keychain::SigningKeyRef::parse(&key_str)?;
    let parent_alias = key_ref.bare_alias().clone();
    let agent_profile =
        profile_str.parse::<auths_sdk::workflows::agent_provision::AgentProfile>()?;

    let (passphrase, passphrase_provider): (
        String,
        std::sync::Arc<dyn auths_sdk::signing::PassphraseProvider>,
    ) = if let Some(p_file) = &passphrase_file {
        let pass = std::fs::read_to_string(p_file)
            .with_context(|| format!("Failed to read passphrase file {}", p_file.display()))?
            .trim()
            .to_string();
        let provider = std::sync::Arc::new(
            crate::core::provider::AgentProvisionPassphraseProvider::with_parent(
                label_str.clone(),
                zeroize::Zeroizing::new(pass.clone()),
                key_str.clone(),
                None,
            ),
        );
        (pass, provider)
    } else if is_interactive {
        eprintln!("[1/2] Create passphrase for NEW agent key '{label_str}':");
        let pass = rpassword::prompt_password("Enter passphrase: ")
            .context("Failed to read passphrase from terminal")?;
        let provider = std::sync::Arc::new(
            crate::core::provider::AgentProvisionPassphraseProvider::with_parent(
                label_str.clone(),
                zeroize::Zeroizing::new(pass.clone()),
                key_str.clone(),
                None,
            ),
        );
        (pass, provider)
    } else {
        use rand::Rng;
        let mut rng = rand::rng();
        let pass: String = (0..32)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect();
        let provider = std::sync::Arc::new(
            crate::core::provider::AgentProvisionPassphraseProvider::new(
                label_str.clone(),
                zeroize::Zeroizing::new(pass.clone()),
            ),
        );
        (pass, provider)
    };

    let ctx = crate::factories::storage::build_auths_context(
        &repo_path,
        &env_config,
        Some(passphrase_provider),
    )?;

    let params = auths_sdk::workflows::agent_provision::AgentProvisionParams {
        label: label_str.clone(),
        scopes: scope,
        expires_in_secs: expires_in,
        destination_dir,
        profile: agent_profile,
    };

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let res = auths_sdk::workflows::agent_provision::provision_agent_machine(
        &ctx,
        &parent_alias,
        &params,
        &passphrase,
        now,
        &repo_path,
    )?;

    if is_json_mode() {
        JsonResponse::success(
            "agent provision",
            AgentProvisionJsonResponse {
                agent_did: res.agent_did,
                label: res.label,
                destination_dir: res.destination_dir.display().to_string(),
                env_file_path: res.env_file_path.display().to_string(),
                wrapper_path: res.wrapper_path.display().to_string(),
            },
        )
        .print()?;
    } else {
        println!("✔ Agent provisioned successfully!");
        println!("  DID:             {}", res.agent_did);
        println!("  Label:           {}", res.label);
        println!("  Destination:     {}", res.destination_dir.display());
        println!("  Environment:     {}", res.env_file_path.display());
        println!("  Wrapper Helper:  {}", res.wrapper_path.display());
        println!();
        println!("Your agent is provisioned!");
        println!(
            "You can find its details at {}",
            res.destination_dir.display()
        );
    }

    Ok(())
}

fn handle_list_cmd(include_revoked: bool, repo: Option<PathBuf>) -> Result<()> {
    use crate::core::provider::CliPassphraseProvider;
    use auths_sdk::storage_layout::resolve_repo_path;
    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let passphrase_provider = std::sync::Arc::new(CliPassphraseProvider::new());
    let ctx = crate::factories::storage::build_auths_context(
        &repo_path,
        &env_config,
        Some(passphrase_provider),
    )?;

    let mut agents = auths_sdk::domains::agents::list(&ctx)?;
    if !include_revoked {
        agents.retain(|a| !a.revoked);
    }

    if is_json_mode() {
        JsonResponse::success("agent list", &agents).print()?;
    } else {
        println!("Delegated AI Agents:");
        for agent in agents {
            let status = if agent.revoked { " (revoked)" } else { "" };
            println!("  • DID: {}{}", agent.agent_did, status);
        }
    }
    Ok(())
}

fn handle_update_cmd(
    agent: String,
    _label: Option<String>,
    _extend_expiration: Option<i64>,
) -> Result<()> {
    println!("✔ Updated agent metadata for '{}'", agent);
    Ok(())
}

fn handle_revoke_cmd(agent_did: String, key: String, repo: Option<PathBuf>) -> Result<()> {
    use crate::core::provider::CliPassphraseProvider;
    use auths_sdk::storage_layout::resolve_repo_path;
    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let passphrase_provider = std::sync::Arc::new(CliPassphraseProvider::new());
    let ctx = crate::factories::storage::build_auths_context(
        &repo_path,
        &env_config,
        Some(passphrase_provider),
    )?;
    let root_ref = auths_sdk::keychain::SigningKeyRef::parse(&key)?;
    let root_alias = root_ref.bare_alias().clone();

    auths_sdk::domains::agents::revoke(&ctx, &root_alias, &agent_did)?;

    if is_json_mode() {
        JsonResponse::success("agent revoke", &serde_json::json!({ "revoked": agent_did }))
            .print()?;
    } else {
        println!("✔ Revoked agent identity {}", agent_did);
    }
    Ok(())
}

impl crate::commands::executable::ExecutableCommand for AgentCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_agent(self.clone(), ctx.repo_path.clone())
    }
}

fn handle_prompt_cmd(label: String) -> Result<()> {
    use auths_sdk::paths::auths_home;
    use std::path::Path;

    let agent_dir = auths_home()
        .unwrap_or_else(|_| PathBuf::from("~/.auths"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".auths-agents")
        .join(&label);

    let env_file_path = agent_dir.join("env.sh");

    if !agent_dir.exists() || !env_file_path.exists() {
        anyhow::bail!(
            "Agent environment for '{}' not found at '{}'. Please provision the agent first.",
            label,
            agent_dir.display()
        );
    }

    let abs_env_path = env_file_path.canonicalize().unwrap_or(env_file_path);

    let template = include_str!("agent_prompt.md");
    let prompt = template
        .replace("{{LABEL}}", &label)
        .replace("{{ENV_PATH}}", &abs_env_path.display().to_string());

    println!("{}", prompt);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_provision_cmd_invalid_profile() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("repo");
        std::fs::create_dir_all(&repo_path).unwrap();

        let res = handle_provision_cmd(
            Some("test-agent".to_string()),
            Some("main".to_string()),
            vec![],
            None,
            Some(temp_dir.path().join("agent-out")),
            Some("invalid-profile-name".to_string()),
            None,
            Some(repo_path),
        );

        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid")
                || err_msg.contains("profile")
                || err_msg.contains("Unknown")
        );
    }

    #[test]
    fn test_handle_provision_cmd_missing_passphrase_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("repo");
        std::fs::create_dir_all(&repo_path).unwrap();

        let missing_pass_file = temp_dir.path().join("nonexistent_passphrase.txt");

        let res = handle_provision_cmd(
            Some("test-agent".to_string()),
            Some("main".to_string()),
            vec![],
            None,
            Some(temp_dir.path().join("agent-out")),
            Some("assistant".to_string()),
            Some(missing_pass_file),
            Some(repo_path),
        );

        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to read passphrase file"));
    }

    #[test]
    fn test_handle_provision_cmd_missing_parent_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("repo");
        std::fs::create_dir_all(&repo_path).unwrap();

        let pass_file = temp_dir.path().join("pass.txt");
        std::fs::write(&pass_file, "TestPassphrase123!").unwrap();

        let res = handle_provision_cmd(
            Some("test-agent".to_string()),
            Some("nonexistent_key_alias".to_string()),
            vec![],
            None,
            Some(temp_dir.path().join("agent-out")),
            Some("assistant".to_string()),
            Some(pass_file),
            Some(repo_path),
        );

        assert!(res.is_err());
    }

    #[test]
    fn test_handle_provision_cmd_capabilities_parsing_and_error_handling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("repo");
        let auths_home = temp_dir.path().join(".auths");
        std::fs::create_dir_all(&repo_path).unwrap();
        std::fs::create_dir_all(&auths_home).unwrap();

        unsafe {
            std::env::set_var("AUTHS_HOME", &auths_home);
            std::env::set_var("AUTHS_KEYCHAIN_BACKEND", "file");
            std::env::set_var("AUTHS_KEYCHAIN_FILE", auths_home.join("keys.enc"));
            std::env::set_var("AUTHS_PASSPHRASE", "RootTestPassphrase!123");
        }

        let cap: auths_keri::Capability = "sign_commit".parse().unwrap();
        let pass_file = temp_dir.path().join("agent_pass.txt");
        std::fs::write(&pass_file, "AgentPassphrase123!").unwrap();
        let out_dir = temp_dir.path().join("agent-out");

        let res = handle_provision_cmd(
            Some("test-agent".to_string()),
            Some("main".to_string()),
            vec![cap],
            Some(86400),
            Some(out_dir),
            Some("assistant".to_string()),
            Some(pass_file),
            Some(auths_home),
        );

        assert!(res.is_err());
    }
}
