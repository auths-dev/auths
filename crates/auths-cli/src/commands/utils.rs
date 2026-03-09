use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use ring::signature::KeyPair;
use std::convert::TryInto;
use std::path::PathBuf;

use auths_crypto::{ed25519_pubkey_to_did_key, openssh_pub_to_raw_ed25519};
use auths_id::identity::helpers::{encode_seed_as_pkcs8, load_keypair_from_der_or_seed};

use crate::commands::device::verify_attestation::handle_verify_attestation;

/// Top-level wrapper to group utility subcommands
#[derive(Parser, Debug, Clone)]
#[command(name = "util", about = "Utility commands for common operations.")]
pub struct UtilCommand {
    #[command(subcommand)]
    pub command: UtilSubcommand,
}

/// All available utility subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum UtilSubcommand {
    /// Derive an identity ID from a raw Ed25519 seed.
    DeriveDid {
        #[arg(
            long,
            help = "The 32-byte Ed25519 seed encoded as a 64-character hex string."
        )]
        seed_hex: String,
    },

    /// Convert an OpenSSH Ed25519 public key to a did:key identifier.
    #[command(name = "pubkey-to-did")]
    PubkeyToDid {
        /// The full OpenSSH public key line (e.g. "ssh-ed25519 AAAA... comment").
        #[arg(help = "OpenSSH Ed25519 public key line.")]
        openssh_pub: String,
    },

    /// Verify an authorization signature from a file using an explicit issuer public key.
    VerifyAttestation {
        /// Path to the authorization JSON file.
        #[arg(long, value_parser, value_name = "FILE_PATH")]
        attestation_file: PathBuf,

        /// Issuer's Ed25519 public key (32 bytes) as a hex string (64 characters).
        #[arg(long, value_name = "HEX_PUBKEY")]
        issuer_pubkey: String,
    },
}

pub fn handle_util(cmd: UtilCommand) -> Result<()> {
    match cmd.command {
        UtilSubcommand::DeriveDid { seed_hex } => {
            // Decode hex string to bytes
            let bytes =
                hex::decode(seed_hex.trim()).context("Failed to decode seed from hex string")?;
            // Validate length
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "Seed must be exactly 32 bytes (64 hex characters), got {} bytes",
                    bytes.len()
                ));
            }

            // Convert Vec<u8> to [u8; 32]
            #[allow(clippy::expect_used)] // INVARIANT: length validated to be 32 bytes on line 59
            let seed: [u8; 32] = bytes.try_into().expect("Length already checked");

            // Create keypair from seed by encoding as PKCS#8 first
            let pkcs8_der =
                encode_seed_as_pkcs8(&seed).context("Failed to encode seed as PKCS#8")?;
            let keypair = load_keypair_from_der_or_seed(&pkcs8_der)
                .context("Failed to construct Ed25519 keypair from seed")?;

            // Get public key bytes
            let pubkey_bytes = keypair.public_key().as_ref();
            let pubkey_fixed: [u8; 32] = pubkey_bytes
                .try_into()
                .context("Failed to convert public key to fixed array")?; // Should not fail

            let did = ed25519_pubkey_to_did_key(&pubkey_fixed);
            if crate::ux::format::is_json_mode() {
                crate::ux::format::JsonResponse::success(
                    "derive-did",
                    &serde_json::json!({ "did": did }),
                )
                .print()?;
            } else {
                println!("✅ Identity ID: {}", did);
            }
            Ok(())
        }

        UtilSubcommand::PubkeyToDid { openssh_pub } => {
            let raw = openssh_pub_to_raw_ed25519(&openssh_pub)
                .map_err(anyhow::Error::from)
                .context("Failed to parse OpenSSH public key")?;
            let did = ed25519_pubkey_to_did_key(&raw);
            if crate::ux::format::is_json_mode() {
                crate::ux::format::JsonResponse::success(
                    "pubkey-to-did",
                    &serde_json::json!({ "did": did }),
                )
                .print()?;
            } else {
                println!("{}", did);
            }
            Ok(())
        }

        UtilSubcommand::VerifyAttestation {
            attestation_file,
            issuer_pubkey,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(handle_verify_attestation(&attestation_file, &issuer_pubkey))
        }
    }
}

impl crate::commands::executable::ExecutableCommand for UtilCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_util(self.clone())
    }
}
