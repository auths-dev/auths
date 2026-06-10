//! `auths id agent …` — manage AI agents as KERI delegated identifiers.
//!
//! An agent is a KERI delegated AID (`dip` delegated by your root identity, anchored
//! by the root's `ixn`) — the same mechanism as a delegated device, not a bearer
//! token or a standalone identity. This is the thin presentation layer; all business
//! logic lives in `auths_sdk::domains::agents`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::KeyAlias;
use auths_sdk::signing::PassphraseProvider;

use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Manage AI agents delegated by your identity.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Manage AI agents (KERI delegated identifiers).",
    after_help = "Examples:
  auths id agent add --label deploy-bot --key my-key   # Delegate a new agent"
)]
pub struct AgentCommand {
    #[clap(subcommand)]
    pub subcommand: AgentSubcommand,
}

/// Agent subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AgentSubcommand {
    /// Delegate a new agent as a KERI delegated identifier of your root identity.
    Add {
        /// Label — also the keychain alias the new agent key is stored under.
        #[arg(long, help = "Label / keychain alias for the new agent key.")]
        label: String,

        /// Your root identity's signing key name (the delegator).
        #[arg(long, help = "Your root identity's signing key name (the delegator).")]
        key: String,

        /// Curve for the new agent key (defaults to P-256, the project default).
        #[arg(
            long,
            default_value = "p256",
            help = "Curve for the new agent key (p256 or ed25519)."
        )]
        curve: String,

        /// Capability to grant the agent (repeatable). Empty = unrestricted.
        #[arg(long = "scope", help = "Capability to grant the agent (repeatable).")]
        scope: Vec<auths_keri::Capability>,

        /// Expire the agent this many seconds from now (delegator-anchored).
        #[arg(long = "expires-in", help = "Expire the agent after N seconds.")]
        expires_in: Option<i64>,
    },

    /// Rotate a delegated agent's key (`drt`), anchored by your root identity.
    Rotate {
        /// The agent's `did:keri:` to rotate.
        #[arg(help = "The agent's did:keri to rotate.")]
        agent_did: String,

        /// Your root identity's signing key name (the delegator that anchors the rotation).
        #[arg(long, help = "Your root identity's signing key name (the delegator).")]
        key: String,
    },

    /// Revoke a delegated agent (anchors a revocation seal in your root's KEL).
    Revoke {
        /// The agent's `did:keri:` to revoke.
        #[arg(help = "The agent's did:keri to revoke.")]
        agent_did: String,

        /// Your root identity's signing key name (the delegator).
        #[arg(long, help = "Your root identity's signing key name (the delegator).")]
        key: String,
    },

    /// List the agents this identity has delegated (excludes devices).
    List {
        /// Include revoked agents in the listing.
        #[arg(long, help = "Include revoked agents.")]
        include_revoked: bool,
    },
}

/// JSON response for `id agent add`.
#[derive(Debug, Serialize)]
struct AgentAddResponse {
    agent_did: String,
    agent_prefix: String,
}

/// Dispatch an `auths id agent …` subcommand.
///
/// Args:
/// * `cmd`: The parsed agent command.
/// * `repo_path`: Resolved registry repository path.
/// * `env_config`: Environment configuration for context building.
/// * `passphrase_provider`: Passphrase source for key access.
///
/// Usage:
/// ```ignore
/// handle_agent(cmd, repo_path, &env_config, passphrase_provider)?;
/// ```
pub fn handle_agent(
    cmd: AgentCommand,
    repo_path: PathBuf,
    env_config: &EnvironmentConfig,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
) -> Result<()> {
    match cmd.subcommand {
        AgentSubcommand::Add {
            label,
            key,
            curve,
            scope,
            expires_in,
        } => {
            let curve = parse_curve(&curve)?;
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let root_alias = KeyAlias::new_unchecked(key);
            let agent_alias = KeyAlias::new_unchecked(label);
            // Clock at the presentation boundary (the SDK/core never call Utc::now()).
            #[allow(clippy::disallowed_methods)]
            let expires_at = expires_in.map(|secs| chrono::Utc::now().timestamp() + secs);
            let result = auths_sdk::domains::agents::add_scoped(
                &ctx,
                &root_alias,
                &agent_alias,
                curve,
                &scope,
                expires_at,
            )
            .map_err(anyhow::Error::new)?;
            // The delegation advanced the root KEL — restamp the trailer file's
            // Auths-Anchor-Seq (best-effort; doctor surfaces a stale hook setup).
            let _ = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(&ctx, &repo_path);

            if is_json_mode() {
                JsonResponse::success(
                    "id agent add",
                    AgentAddResponse {
                        agent_did: result.agent_did.clone(),
                        agent_prefix: result.agent_prefix.clone(),
                    },
                )
                .print()?;
            } else {
                println!("✓ Agent delegated as a KERI delegated identifier:");
                println!("  {}", result.agent_did);
                println!("\nThe root anchored this agent's delegation in its KEL.");
            }
            Ok(())
        }

        AgentSubcommand::Rotate { agent_did, key } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let root_alias = KeyAlias::new_unchecked(key);
            auths_sdk::domains::agents::rotate(&ctx, &root_alias, &agent_did)
                .map_err(anyhow::Error::new)?;
            // The delegation advanced the root KEL — restamp the trailer file's
            // Auths-Anchor-Seq (best-effort; doctor surfaces a stale hook setup).
            let _ = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(&ctx, &repo_path);

            if is_json_mode() {
                JsonResponse::success(
                    "id agent rotate",
                    serde_json::json!({ "agent_did": agent_did, "rotated": true }),
                )
                .print()?;
            } else {
                println!("✓ Agent key rotated (drt anchored by the root): {agent_did}");
            }
            Ok(())
        }

        AgentSubcommand::Revoke { agent_did, key } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let root_alias = KeyAlias::new_unchecked(key);
            auths_sdk::domains::agents::revoke(&ctx, &root_alias, &agent_did)
                .map_err(anyhow::Error::new)?;
            // The delegation advanced the root KEL — restamp the trailer file's
            // Auths-Anchor-Seq (best-effort; doctor surfaces a stale hook setup).
            let _ = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(&ctx, &repo_path);

            if is_json_mode() {
                JsonResponse::success(
                    "id agent revoke",
                    serde_json::json!({ "agent_did": agent_did, "revoked": true }),
                )
                .print()?;
            } else {
                println!("✓ Agent revoked (revocation anchored in the root KEL): {agent_did}");
            }
            Ok(())
        }

        AgentSubcommand::List { include_revoked } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let agents = auths_sdk::domains::agents::list(&ctx).map_err(anyhow::Error::new)?;
            let shown: Vec<_> = agents
                .into_iter()
                .filter(|a| include_revoked || !a.revoked)
                .collect();

            if is_json_mode() {
                let data: Vec<_> = shown
                    .iter()
                    .map(|a| serde_json::json!({ "agent_did": a.agent_did, "revoked": a.revoked }))
                    .collect();
                JsonResponse::success("id agent list", serde_json::json!({ "agents": data }))
                    .print()?;
            } else if shown.is_empty() {
                println!("No agents delegated by this identity.");
            } else {
                println!("Delegated agents:");
                for a in &shown {
                    let status = if a.revoked { " (revoked)" } else { "" };
                    println!("  {}{}", a.agent_did, status);
                }
            }
            Ok(())
        }
    }
}

/// Parse a curve name (`ed25519` / `p256`) into a [`CurveType`](auths_crypto::CurveType).
fn parse_curve(s: &str) -> Result<auths_crypto::CurveType> {
    match s.to_ascii_lowercase().as_str() {
        "p256" | "p-256" => Ok(auths_crypto::CurveType::P256),
        "ed25519" => Ok(auths_crypto::CurveType::Ed25519),
        other => Err(anyhow::anyhow!(
            "unknown curve {:?}: expected p256 or ed25519",
            other
        )),
    }
}
