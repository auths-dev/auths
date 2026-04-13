use crate::ux::format::is_json_mode;
use anyhow::{Context, Result, anyhow};
use auths_keri::witness::SignedReceipt;
use auths_sdk::trust::{PinnedIdentity, PinnedIdentityStore, RootsFile, TrustLevel, TrustPolicy};
use auths_verifier::Capability;
use auths_verifier::core::Attestation;
use auths_verifier::verify::{
    verify_chain_with_witnesses, verify_with_capability, verify_with_keys,
};
use auths_verifier::witness::WitnessVerifyConfig;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process;

/// Trust policy for identity verification.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CliTrustPolicy {
    /// Trust-on-first-use: prompt interactively on first encounter.
    #[default]
    Tofu,
    /// Explicit trust: require identity in pinned store or roots.json.
    Explicit,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Verify device authorization signatures.")]
pub struct VerifyCommand {
    /// Path to authorization JSON file, or "-" to read from stdin.
    #[arg(long, value_parser, required = true)]
    pub attestation: String,

    /// Signer public key in hex format (64 hex chars = 32 bytes).
    ///
    /// If provided, bypasses trust resolution and uses this key directly.
    /// Takes precedence over --signer and trust policy.
    #[arg(long = "signer-key", value_parser)]
    pub issuer_pk: Option<String>,

    /// Signer identity ID for trust-based key resolution.
    ///
    /// Looks up the public key from pinned identity store or roots.json.
    /// Uses --trust policy to determine behavior for unknown identities.
    #[arg(long = "signer", visible_alias = "issuer-did", value_parser)]
    pub issuer_did: Option<String>,

    /// Trust policy for unknown identities.
    ///
    /// Resolution precedence:
    ///   1. --issuer-pk (direct key, bypasses trust)
    ///   2. Pinned identity store (~/.auths/known_identities.json)
    ///   3. Repository roots.json (.auths/roots.json)
    ///   4. TOFU prompt (if TTY) or explicit rejection (if non-TTY)
    ///
    /// Defaults: tofu on TTY, explicit on non-TTY (CI).
    #[arg(long, value_enum)]
    pub trust: Option<CliTrustPolicy>,

    /// Path to roots.json file for explicit trust.
    ///
    /// Overrides default .auths/roots.json lookup.
    #[arg(long = "roots-file", value_parser)]
    pub roots_file: Option<PathBuf>,

    /// Require attestation to have a specific capability (sign-commit, sign-release, manage-members, rotate-keys).
    #[arg(long = "require-capability")]
    pub require_capability: Option<String>,

    /// Path to witness signatures JSON file.
    #[arg(long = "witness-signatures")]
    pub witness_receipts: Option<PathBuf>,

    /// Number of witnesses required (default: 1).
    #[arg(long = "witnesses-required", default_value = "1")]
    pub witness_threshold: usize,

    /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
    #[arg(long, num_args = 1..)]
    pub witness_keys: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResult {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_quorum: Option<auths_verifier::witness::WitnessQuorum>,
}

/// Handle verify command. Returns Ok(()) on success, Err on error.
/// Uses exit codes: 0=valid, 1=invalid, 2=error
pub async fn handle_verify(cmd: VerifyCommand) -> Result<()> {
    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
    let result = run_verify(now, &cmd).await;

    match result {
        Ok(verify_result) => {
            if is_json_mode() {
                println!("{}", serde_json::to_string(&verify_result)?);
            }

            if verify_result.valid {
                // Exit code 0 for valid
                Ok(())
            } else {
                // Exit code 1 for invalid attestation
                if !is_json_mode() {
                    eprintln!(
                        "Attestation verification failed: {}",
                        verify_result.error.as_deref().unwrap_or("unknown error")
                    );
                }
                process::exit(1);
            }
        }
        Err(e) => {
            // Exit code 2 for errors (file not found, parse error, etc.)
            if is_json_mode() {
                let error_result = VerifyResult {
                    valid: false,
                    error: Some(e.to_string()),
                    issuer: None,
                    subject: None,
                    required_capability: cmd.require_capability.clone(),
                    available_capabilities: None,
                    witness_quorum: None,
                };
                println!("{}", serde_json::to_string(&error_result)?);
            } else {
                eprintln!("Error: {}", e);
            }
            process::exit(2);
        }
    }
}

/// Determine effective trust policy.
///
/// If explicitly set via --trust, use that.
/// Otherwise: TOFU on TTY, Explicit on non-TTY (CI).
fn effective_trust_policy(cmd: &VerifyCommand) -> TrustPolicy {
    match cmd.trust {
        Some(CliTrustPolicy::Tofu) => TrustPolicy::Tofu,
        Some(CliTrustPolicy::Explicit) => TrustPolicy::Explicit,
        None => {
            if io::stdin().is_terminal() {
                TrustPolicy::Tofu
            } else {
                TrustPolicy::Explicit
            }
        }
    }
}

/// Wrap raw pubkey bytes from a trust store (pin or roots.json) into a curve-tagged
/// `DevicePublicKey`. Infers the curve from length via `CurveType::from_public_key_len`.
fn bytes_to_device_public_key(
    bytes: &[u8],
    source: &str,
) -> Result<auths_verifier::DevicePublicKey> {
    let curve = auths_crypto::CurveType::from_public_key_len(bytes.len())
        .ok_or_else(|| anyhow!("Invalid {} public key length: {}", source, bytes.len()))?;
    auths_verifier::DevicePublicKey::try_new(curve, bytes)
        .map_err(|e| anyhow!("Invalid {} public key: {e}", source))
}

/// Resolve the issuer public key from various sources.
///
/// Resolution precedence:
/// 1. `--issuer-pk` (direct key, bypasses trust)
/// 2. Pinned identity store
/// 3. `roots.json` file
/// 4. Trust policy (TOFU prompt or explicit rejection)
fn resolve_issuer_key(
    now: chrono::DateTime<Utc>,
    cmd: &VerifyCommand,
    att: &Attestation,
) -> Result<auths_verifier::DevicePublicKey> {
    // 1. Direct key takes precedence
    if let Some(ref pk_hex) = cmd.issuer_pk {
        let pk_bytes =
            hex::decode(pk_hex).context("Invalid hex string provided for issuer public key")?;
        let curve = auths_crypto::CurveType::from_public_key_len(pk_bytes.len())
            .ok_or_else(|| anyhow!("Invalid issuer public key length: {}", pk_bytes.len()))?;
        return auths_verifier::DevicePublicKey::try_new(curve, &pk_bytes)
            .map_err(|e| anyhow!("Invalid issuer public key: {e}"));
    }

    // Determine the DID to look up
    let did = cmd.issuer_did.as_deref().unwrap_or(att.issuer.as_str());

    // Get trust policy
    let policy = effective_trust_policy(cmd);
    let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());

    // 2. Check pinned identity store first
    if let Some(pin) = store.lookup(did)? {
        if !is_json_mode() {
            println!("Using pinned identity: {}", did);
        }
        return bytes_to_device_public_key(&pin.public_key_bytes()?, "pinned identity");
    }

    // 3. Check roots.json file
    let roots_path = cmd.roots_file.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .join(".auths/roots.json")
    });

    if roots_path.exists() {
        let roots = RootsFile::load(&roots_path)?;
        if let Some(root) = roots.find(did) {
            if !is_json_mode() {
                println!(
                    "Using root from {}: {}",
                    roots_path.display(),
                    root.note.as_deref().unwrap_or(did)
                );
            }
            // Pin from roots.json for future use
            let pin = PinnedIdentity {
                did: did.to_string(),
                public_key_hex: root.public_key_hex.clone(),
                kel_tip_said: root.kel_tip_said.clone(),
                kel_sequence: None,
                first_seen: now,
                origin: format!("roots.json:{}", roots_path.display()),
                trust_level: TrustLevel::OrgPolicy,
            };
            store.pin(pin)?;
            return bytes_to_device_public_key(&root.public_key_bytes()?, "roots.json");
        }
    }

    // 4. Apply trust policy
    match policy {
        TrustPolicy::Tofu => {
            // Need to extract key from attestation for TOFU
            // The attestation itself doesn't contain the issuer's public key directly,
            // so we need it from --issuer-pk or the user needs to provide it
            anyhow::bail!(
                "Unknown identity '{}'. Provide --signer-key to trust on first use, \
                 or add to .auths/roots.json for explicit trust.",
                did
            );
        }
        TrustPolicy::Explicit => {
            anyhow::bail!(
                "Unknown identity '{}' and trust policy is 'explicit'.\n\
                 Options:\n  \
                 1. Add to .auths/roots.json in the repository\n  \
                 2. Pin manually: auths trust pin --did {} --key <hex>\n  \
                 3. Provide --signer-key <hex> to bypass trust resolution",
                did,
                did
            );
        }
    }
}

use crate::commands::verify_helpers::parse_witness_keys;

async fn run_verify(now: chrono::DateTime<Utc>, cmd: &VerifyCommand) -> Result<VerifyResult> {
    // 1. Read attestation from file or stdin
    let attestation_bytes = if cmd.attestation == "-" {
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read attestation from stdin")?;
        buffer
    } else {
        let path = PathBuf::from(&cmd.attestation);
        fs::read(&path).with_context(|| format!("Failed to read attestation file: {:?}", path))?
    };

    // 2. Deserialize attestation JSON
    let att: Attestation =
        serde_json::from_slice(&attestation_bytes).context("Failed to parse JSON attestation")?;

    if !is_json_mode() {
        println!(
            "Verifying attestation: issuer={}, subject={}",
            att.issuer, att.subject
        );
    }

    // 3. Resolve issuer public key
    let issuer_pk = resolve_issuer_key(now, cmd, &att)?;

    let required_capability: Option<Capability> = cmd.require_capability.as_ref().map(|cap| {
        cap.parse::<Capability>().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(2);
        })
    });

    // 5. Verify the attestation (with or without capability check)
    let verify_result = if let Some(ref cap) = required_capability {
        verify_with_capability(&att, cap, &issuer_pk).await
    } else {
        verify_with_keys(&att, &issuer_pk).await
    };

    match verify_result {
        Ok(_) => {
            // 6. If witness receipts are provided, do witness chain verification
            let witness_quorum = if let Some(ref receipts_path) = cmd.witness_receipts {
                let receipts_bytes = fs::read(receipts_path).with_context(|| {
                    format!("Failed to read witness receipts: {:?}", receipts_path)
                })?;
                let receipts: Vec<SignedReceipt> = serde_json::from_slice(&receipts_bytes)
                    .context("Failed to parse witness receipts JSON")?;
                let witness_keys = parse_witness_keys(&cmd.witness_keys)?;

                let config = WitnessVerifyConfig {
                    receipts: &receipts,
                    witness_keys: &witness_keys,
                    threshold: cmd.witness_threshold,
                };

                let report =
                    verify_chain_with_witnesses(std::slice::from_ref(&att), &issuer_pk, &config)
                        .await
                        .context("Witness chain verification failed")?;

                if !report.is_valid() {
                    if !is_json_mode()
                        && let auths_verifier::VerificationStatus::InsufficientWitnesses {
                            required,
                            verified,
                        } = &report.status
                    {
                        eprintln!("Witness quorum not met: {}/{} verified", verified, required);
                    }
                    return Ok(VerifyResult {
                        valid: false,
                        error: Some(format!(
                            "Witness quorum not met: {}/{} verified",
                            report.witness_quorum.as_ref().map_or(0, |q| q.verified),
                            cmd.witness_threshold
                        )),
                        issuer: Some(att.issuer.to_string()),
                        subject: Some(att.subject.to_string()),
                        required_capability: cmd.require_capability.clone(),
                        available_capabilities: None,
                        witness_quorum: report.witness_quorum,
                    });
                }

                if !is_json_mode()
                    && let Some(ref q) = report.witness_quorum
                {
                    println!("Witness quorum met: {}/{} verified", q.verified, q.required);
                }

                report.witness_quorum
            } else {
                None
            };

            if !is_json_mode() {
                println!("Attestation verified successfully.");
                if let Some(ref cap_str) = cmd.require_capability {
                    println!("Required capability '{}' is present.", cap_str);
                }
            }
            Ok(VerifyResult {
                valid: true,
                error: None,
                issuer: Some(att.issuer.to_string()),
                subject: Some(att.subject.to_string()),
                required_capability: cmd.require_capability.clone(),
                available_capabilities: None,
                witness_quorum,
            })
        }
        Err(auths_verifier::error::AttestationError::MissingCapability {
            required,
            available,
        }) => {
            let available_strs: Vec<String> =
                available.iter().map(|c| format!("{:?}", c)).collect();
            Ok(VerifyResult {
                valid: false,
                error: Some(format!(
                    "Missing required capability: {:?}. Available: {:?}",
                    required, available
                )),
                issuer: Some(att.issuer.to_string()),
                subject: Some(att.subject.to_string()),
                required_capability: Some(format!("{:?}", required)),
                available_capabilities: Some(available_strs),
                witness_quorum: None,
            })
        }
        Err(e) => Ok(VerifyResult {
            valid: false,
            error: Some(e.to_string()),
            issuer: Some(att.issuer.to_string()),
            subject: Some(att.subject.to_string()),
            required_capability: cmd.require_capability.clone(),
            available_capabilities: None,
            witness_quorum: None,
        }),
    }
}

/// Legacy handler for backward compatibility (kept for potential internal use).
pub async fn handle_verify_attestation(
    attestation_path: &PathBuf,
    issuer_pubkey_hex: &str,
) -> Result<()> {
    println!("Verifying attestation from file: {:?}", attestation_path);
    println!(
        "   Using issuer public key (hex): {}...",
        &issuer_pubkey_hex[..8.min(issuer_pubkey_hex.len())]
    );

    let attestation_bytes = fs::read(attestation_path)
        .with_context(|| format!("Failed to read attestation file: {:?}", attestation_path))?;

    let att: Attestation = serde_json::from_slice(&attestation_bytes).with_context(|| {
        format!(
            "Failed to parse JSON attestation from file: {:?}",
            attestation_path
        )
    })?;
    println!(
        "   Attestation loaded successfully. Issuer: {}, Subject: {}",
        att.issuer, att.subject
    );

    let issuer_pk_bytes = hex::decode(issuer_pubkey_hex)
        .context("Invalid hex string provided for issuer public key")?;
    let issuer_pk = bytes_to_device_public_key(&issuer_pk_bytes, "issuer")?;

    match verify_with_keys(&att, &issuer_pk).await {
        Ok(_) => {
            println!("Attestation verified successfully.");
            Ok(())
        }
        Err(e) => Err(anyhow!("Attestation verification failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_result_serializes_correctly() {
        let result = VerifyResult {
            valid: true,
            error: None,
            issuer: Some("did:key:issuer".to_string()),
            subject: Some("did:key:subject".to_string()),
            required_capability: None,
            available_capabilities: None,
            witness_quorum: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"issuer\":\"did:key:issuer\""));
    }

    #[test]
    fn verify_result_error_serializes_correctly() {
        let result = VerifyResult {
            valid: false,
            error: Some("signature mismatch".to_string()),
            issuer: None,
            subject: None,
            required_capability: None,
            available_capabilities: None,
            witness_quorum: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":false"));
        assert!(json.contains("\"error\":\"signature mismatch\""));
    }

    #[test]
    fn verify_result_with_capability_serializes_correctly() {
        let result = VerifyResult {
            valid: false,
            error: Some("Missing capability".to_string()),
            issuer: Some("did:key:issuer".to_string()),
            subject: Some("did:key:subject".to_string()),
            required_capability: Some("SignRelease".to_string()),
            available_capabilities: Some(vec!["SignCommit".to_string()]),
            witness_quorum: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"required_capability\":\"SignRelease\""));
        assert!(json.contains("\"available_capabilities\":[\"SignCommit\"]"));
    }
}
