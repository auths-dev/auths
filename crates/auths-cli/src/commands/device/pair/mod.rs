//! Device pairing commands.
//!
//! Provides commands to initiate and join device pairing sessions
//! for cross-device identity linking using X25519 ECDH key exchange.

mod common;
mod join;
#[cfg(feature = "lan-pairing")]
mod lan;
#[cfg(feature = "lan-pairing")]
mod lan_server;
mod offline;
mod online;

use anyhow::Result;
use auths_core::config::EnvironmentConfig;
use clap::Parser;

/// Default registry URL for local development.
#[cfg(not(feature = "lan-pairing"))]
const DEFAULT_REGISTRY: &str = "http://localhost:3000";

#[derive(Parser, Debug, Clone)]
#[command(about = "Link devices to your identity")]
pub struct PairCommand {
    /// Join an existing pairing session using a short code
    #[clap(long, value_name = "CODE")]
    pub join: Option<String>,

    /// Registry URL for pairing relay (omit for LAN mode)
    #[clap(long, value_name = "URL")]
    pub registry: Option<String>,

    /// Don't display QR code (only show short code)
    #[clap(long, hide_short_help = true)]
    pub no_qr: bool,

    /// Custom timeout in seconds for the pairing session (default: 300 = 5 minutes)
    #[clap(
        long,
        visible_alias = "expiry",
        value_name = "SECONDS",
        default_value = "300"
    )]
    pub timeout: u64,

    /// Skip registry server (offline mode, for testing)
    #[clap(long, hide_short_help = true)]
    pub offline: bool,

    /// Capabilities to grant the paired device (comma-separated)
    #[clap(
        long,
        value_delimiter = ',',
        default_value = "sign_commit",
        hide_short_help = true
    )]
    pub capabilities: Vec<String>,

    /// Disable mDNS advertisement/discovery in LAN mode
    #[cfg(feature = "lan-pairing")]
    #[clap(long, hide_short_help = true)]
    pub no_mdns: bool,
}

/// Dispatch table:
///
/// | Flags                        | Behavior                              |
/// |------------------------------|---------------------------------------|
/// | `pair` (no flags)            | LAN mode: start local server, show QR |
/// | `pair --registry URL`        | Online mode (existing)                |
/// | `pair --join CODE`           | LAN join: mDNS discover -> join       |
/// | `pair --join CODE --registry`| Online join (existing)                |
/// | `pair --offline`             | Offline mode (no network)             |
pub fn handle_pair(cmd: PairCommand, env_config: &EnvironmentConfig) -> Result<()> {
    match (&cmd.join, &cmd.registry, cmd.offline) {
        // Offline mode takes priority
        (None, _, true) => {
            offline::handle_initiate_offline(cmd.no_qr, cmd.timeout, &cmd.capabilities)
        }

        // Join with explicit registry -> online join
        (Some(code), Some(registry), _) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(join::handle_join(code, registry, env_config))
        }

        // Join without registry -> LAN join via mDNS
        #[cfg(feature = "lan-pairing")]
        (Some(code), None, _) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(lan::handle_join_lan(code, env_config))
        }

        // Join without registry and no LAN feature -> use default registry
        #[cfg(not(feature = "lan-pairing"))]
        (Some(code), None, _) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(join::handle_join(code, DEFAULT_REGISTRY, env_config))
        }

        // Initiate with explicit registry -> online mode
        (None, Some(registry), _) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(online::handle_initiate_online(
                registry,
                cmd.no_qr,
                cmd.timeout,
                &cmd.capabilities,
                env_config,
            ))
        }

        // Initiate without registry -> LAN mode
        #[cfg(feature = "lan-pairing")]
        (None, None, false) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(lan::handle_initiate_lan(
                cmd.no_qr,
                cmd.no_mdns,
                cmd.timeout,
                &cmd.capabilities,
                env_config,
            ))
        }

        // Initiate without registry and no LAN feature -> use default registry
        #[cfg(not(feature = "lan-pairing"))]
        (None, None, false) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(online::handle_initiate_online(
                DEFAULT_REGISTRY,
                cmd.no_qr,
                cmd.timeout,
                &cmd.capabilities,
                env_config,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_core::pairing::normalize_short_code;

    #[test]
    fn test_code_normalization() {
        let codes = vec![
            ("AB3DEF", "AB3DEF"),
            ("ab3def", "AB3DEF"),
            ("AB3 DEF", "AB3DEF"),
            ("AB3-DEF", "AB3DEF"),
            ("a b 3 d e f", "AB3DEF"),
        ];

        for (input, expected) in codes {
            let normalized = normalize_short_code(input);
            assert_eq!(normalized, expected, "Input: '{}'", input);
        }
    }
}
