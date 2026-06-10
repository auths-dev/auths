//! Agent identity config + TOML preview types.
//!
//! The standalone-`icp` agent provisioning (`provision_agent_identity`) was retired
//! in Epic E: an agent is now a KERI **delegated identifier** (`dip` delegated by a
//! root/org, anchored by the root's `ixn`), created with `auths id agent add`
//! (SDK `agents::add`) — not a standalone root identity stamped with an `Agent`
//! attestation. What remains here is the configuration shape and the
//! `auths-agent.toml` formatter still used by the `init` dry-run preview.

use std::path::PathBuf;

use auths_core::storage::keychain::IdentityDID;

/// Storage mode for an agent identity.
#[derive(Debug, Clone)]
pub enum AgentStorageMode {
    /// Persistent storage at a filesystem path.
    /// Defaults to `~/.auths-agent` if `repo_path` is `None`.
    Persistent {
        /// Repository path; `None` selects the default `~/.auths-agent`.
        repo_path: Option<PathBuf>,
    },
    /// In-memory storage for ephemeral/stateless containers (Fargate, Docker).
    /// Agent identity lives only for the process lifetime.
    InMemory,
}

/// Configuration describing an agent identity (for previews / config files).
#[derive(Debug, Clone)]
pub struct AgentProvisioningConfig {
    /// Human-readable agent name (e.g., "ci-bot", "release-agent").
    pub agent_name: String,
    /// Capabilities to grant (e.g., `sign_commit`, `pr:create`).
    pub capabilities: Vec<auths_keri::Capability>,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<u64>,
    /// DID of the root/org that delegates this agent.
    pub delegated_by: Option<IdentityDID>,
    /// Storage mode (persistent or ephemeral).
    pub storage_mode: AgentStorageMode,
}

/// Render an `auths-agent.toml` preview for the given agent config.
///
/// Args:
/// * `did`: The agent's `did:keri:` (or a `<pending>` placeholder in a dry run).
/// * `key_alias`: The keychain alias the agent key is stored under.
/// * `config`: The agent configuration to render.
///
/// Usage:
/// ```ignore
/// let toml = format_agent_toml("did:keri:E...", "agent-key", &config);
/// ```
pub fn format_agent_toml(did: &str, key_alias: &str, config: &AgentProvisioningConfig) -> String {
    let caps = config
        .capabilities
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = format!(
        "# Auths Agent Configuration\n\
         # An agent is a KERI delegated identifier (dip) — create with `auths id agent add`\n\n\
         [agent]\n\
         name = \"{}\"\n\
         did = \"{}\"\n\
         key_alias = \"{}\"\n\
         signer_type = \"Agent\"\n",
        config.agent_name, did, key_alias,
    );

    if let Some(ref delegator) = config.delegated_by {
        out.push_str(&format!("delegated_by = \"{}\"\n", delegator));
    }

    out.push_str(&format!("\n[capabilities]\ngranted = [{}]\n", caps));

    if let Some(secs) = config.expires_in {
        out.push_str(&format!("\n[expiry]\nexpires_in = {}\n", secs));
    }

    out
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // INVARIANT: tests construct IdentityDID via new_unchecked with literal DIDs
mod tests {
    use super::*;

    #[test]
    fn format_agent_toml_with_all_fields() {
        let config = AgentProvisioningConfig {
            agent_name: "ci-bot".to_string(),
            capabilities: vec![
                auths_keri::Capability::sign_commit(),
                auths_keri::Capability::parse("pr:create").unwrap(),
            ],
            expires_in: Some(86400),
            delegated_by: Some(IdentityDID::new_unchecked("did:keri:Eabc123")),
            storage_mode: AgentStorageMode::Persistent { repo_path: None },
        };
        let toml = format_agent_toml("did:keri:Eagent", "agent-key", &config);
        assert!(toml.contains("name = \"ci-bot\""));
        assert!(toml.contains("did = \"did:keri:Eagent\""));
        assert!(toml.contains("delegated_by = \"did:keri:Eabc123\""));
        assert!(toml.contains("\"sign_commit\", \"pr:create\""));
        assert!(toml.contains("expires_in = 86400"));
    }

    #[test]
    fn format_agent_toml_minimal() {
        let config = AgentProvisioningConfig {
            agent_name: "solo".to_string(),
            capabilities: vec![],
            expires_in: None,
            delegated_by: None,
            storage_mode: AgentStorageMode::InMemory,
        };
        let toml = format_agent_toml("did:keri:E1", "k", &config);
        assert!(!toml.contains("delegated_by"));
        assert!(!toml.contains("[expiry]"));
    }

    #[test]
    fn init_dryrun_shows_delegated_agent() {
        // The `init --agent` dry-run renders this preview; after Epic E it must
        // present a *delegated* identifier (not a standalone identity) and name the
        // delegating root when one is supplied.
        let config = AgentProvisioningConfig {
            agent_name: "deploy-bot".to_string(),
            capabilities: vec![auths_keri::Capability::sign_commit()],
            expires_in: None,
            delegated_by: Some(IdentityDID::new_unchecked("did:keri:Eroot")),
            storage_mode: AgentStorageMode::Persistent { repo_path: None },
        };
        let toml = format_agent_toml("did:keri:E<pending>", "agent-key", &config);
        assert!(
            toml.contains("delegated identifier"),
            "dry-run must frame the agent as a delegated identifier"
        );
        assert!(
            toml.contains("delegated_by = \"did:keri:Eroot\""),
            "dry-run must name the delegating root"
        );
    }
}
