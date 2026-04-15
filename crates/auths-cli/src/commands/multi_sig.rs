//! `auths multi-sig` subcommand group — file-based multi-sig event aggregation.
//!
//! Wraps the SDK `workflows::multi_sig` module. Produces and consumes two
//! on-disk formats:
//!   - `UnsignedEventBundle` — canonical bytes + signer metadata; each device
//!     reads this before signing.
//!   - `IndexedSignature` — one partial signature per device.
//!
//! The final `combine` step validates threshold satisfaction and emits a
//! ready-to-append `SignedEvent`.

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

use auths_keri::{IndexedSignature, SignedEvent, Threshold};
use auths_sdk::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_sdk::workflows::multi_sig::{
    begin_multi_sig_event, combine, read_partial, sign_partial, write_partial,
};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

/// `auths multi-sig ...` — aggregate indexed signatures for multi-device
/// KEL events.
#[derive(Args, Debug)]
pub struct MultiSigCommand {
    #[command(subcommand)]
    pub subcommand: MultiSigSubcommand,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
pub enum MultiSigSubcommand {
    /// Create an unsigned-event bundle for distribution to signers.
    Begin {
        /// Path to the JSON-encoded finalized `SignedEvent` (signatures empty).
        #[arg(long)]
        event: PathBuf,

        /// Comma-separated signer aliases, in slot order.
        #[arg(long, value_delimiter = ',')]
        signers: Vec<String>,

        /// Output path for the unsigned bundle.
        #[arg(long)]
        output: PathBuf,
    },

    /// Sign an unsigned bundle with a single device key.
    Sign {
        /// Path to the unsigned-event bundle.
        #[arg(long)]
        unsigned: PathBuf,

        /// Keychain alias of the signing key.
        #[arg(long)]
        key_alias: String,

        /// Slot index for the indexed signature (0-based).
        #[arg(long)]
        index: u32,

        /// Output path for the partial signature.
        #[arg(long)]
        output: PathBuf,
    },

    /// Combine partial signatures into a SignedEvent, enforcing the threshold.
    Combine {
        /// Path to the unsigned-event bundle.
        #[arg(long)]
        unsigned: PathBuf,

        /// Comma-separated paths to partial signature files.
        #[arg(long, value_delimiter = ',')]
        partials: Vec<PathBuf>,

        /// Expected threshold (scalar `"2"` or fractions `"1/2,1/2,1/2"`).
        #[arg(long)]
        threshold: String,

        /// Number of signer slots expected (device_count).
        #[arg(long)]
        key_count: usize,

        /// Output path for the combined SignedEvent JSON.
        #[arg(long)]
        output: PathBuf,
    },
}

impl ExecutableCommand for MultiSigCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.subcommand {
            MultiSigSubcommand::Begin {
                event,
                signers,
                output,
            } => {
                let raw = std::fs::read(event)
                    .with_context(|| format!("reading event from {event:?}"))?;
                let signed: SignedEvent = serde_json::from_slice(&raw)
                    .with_context(|| format!("parsing SignedEvent from {event:?}"))?;
                let aliases: Vec<KeyAlias> = signers
                    .iter()
                    .map(|s| KeyAlias::new_unchecked(s.to_string()))
                    .collect();
                let bundle = begin_multi_sig_event(&signed, &aliases, output)
                    .with_context(|| "begin_multi_sig_event failed")?;
                println!(
                    "[OK] Unsigned bundle written to {:?} (SAID {}, {} signer slots)",
                    output,
                    bundle.said,
                    aliases.len()
                );
                Ok(())
            }

            &MultiSigSubcommand::Sign {
                ref unsigned,
                ref key_alias,
                index,
                ref output,
            } => {
                let keychain: Arc<dyn auths_sdk::keychain::KeyStorage + Send + Sync> = Arc::from(
                    get_platform_keychain_with_config(&ctx.env_config)
                        .context("Failed to access keychain")?,
                );
                let alias = KeyAlias::new_unchecked(key_alias.clone());
                let partial = sign_partial(
                    unsigned,
                    &alias,
                    index,
                    ctx.passphrase_provider.as_ref(),
                    keychain.as_ref(),
                )
                .with_context(|| "sign_partial failed")?;
                write_partial(&partial, output)
                    .with_context(|| format!("writing partial to {output:?}"))?;
                println!(
                    "[OK] Partial signature written to {:?} (index {}, {} bytes)",
                    output,
                    partial.index,
                    partial.sig.len()
                );
                Ok(())
            }

            &MultiSigSubcommand::Combine {
                ref unsigned,
                ref partials,
                ref threshold,
                key_count,
                ref output,
            } => {
                let expected_kt: Threshold =
                    crate::commands::init::parse_threshold_cli(threshold, key_count)?;
                let loaded: Result<Vec<IndexedSignature>> = partials
                    .iter()
                    .map(|p| read_partial(p).map_err(|e| anyhow!("reading partial {:?}: {e}", p)))
                    .collect();
                let loaded = loaded?;
                let signed =
                    combine(unsigned, loaded, &expected_kt).with_context(|| "combine failed")?;
                let body = serde_json::to_vec_pretty(&signed)
                    .with_context(|| "serializing SignedEvent")?;
                std::fs::write(output, &body)
                    .with_context(|| format!("writing combined event to {output:?}"))?;
                println!(
                    "[OK] Combined SignedEvent written to {:?} ({} signatures)",
                    output,
                    signed.signatures.len()
                );
                Ok(())
            }
        }
    }
}
