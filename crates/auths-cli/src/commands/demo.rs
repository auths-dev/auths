use std::io::Write as _;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use tempfile::NamedTempFile;

use auths_sdk::domains::signing::service::{
    ArtifactSigningParams, SigningKeyMaterial, sign_artifact,
};
use auths_sdk::keychain::KeyAlias;

use crate::commands::artifact::file::FileArtifact;
use crate::commands::executable::ExecutableCommand;
use crate::commands::key_detect::auto_detect_device_key;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::Output;

#[derive(Debug, clap::Args)]
#[command(about = "Sign and verify a demo artifact — works offline, no registry needed")]
pub struct DemoCommand {}

impl ExecutableCommand for DemoCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let out = Output::new();

        // 1. Create a temp file with known content
        let mut tmp = NamedTempFile::new().context("failed to create temp file")?;
        writeln!(tmp, "Hello, Auths!").context("failed to write demo content")?;
        let path = tmp.path().to_path_buf();

        // 2. Auto-detect the device key alias (errors out cleanly if identity missing)
        let device_key_alias = auto_detect_device_key(ctx.repo_path.as_deref(), &ctx.env_config)
            .context("No identity found — run `auths init` first")?;

        // 3. Build SDK context
        let repo_path = auths_sdk::storage_layout::resolve_repo_path(ctx.repo_path.clone())?;
        let sdk_ctx = build_auths_context(
            &repo_path,
            &ctx.env_config,
            Some(ctx.passphrase_provider.clone()),
        )?;

        // 4. Sign using SDK directly (no intermediate CLI output)
        let t_sign = Instant::now();
        let sign_result = sign_artifact(
            ArtifactSigningParams {
                artifact: Arc::new(FileArtifact::new(&path)),
                identity_key: None,
                device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(&device_key_alias)),
                expires_in: None,
                note: Some("auths demo — local only".into()),
                commit_sha: None,
            },
            &sdk_ctx,
        )
        .map_err(|e| anyhow!("{}", e))?;
        let sign_ms = t_sign.elapsed().as_millis();

        // 5. Verify: parse attestation and confirm digest integrity (fully local)
        let t_verify = Instant::now();
        let attestation: Value = serde_json::from_str(&sign_result.attestation_json)
            .context("failed to parse attestation")?;
        let stored_digest = attestation
            .pointer("/payload/digest/hex")
            .and_then(|v| v.as_str())
            .context("attestation missing payload digest")?;
        if stored_digest != sign_result.digest {
            anyhow::bail!(
                "demo verification failed: digest mismatch\n  expected: {}\n  got:      {}",
                sign_result.digest,
                stored_digest
            );
        }
        let verify_ms = t_verify.elapsed().as_millis();

        // 6. Extract issuer DID from the attestation
        let issuer = attestation
            .pointer("/issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");

        // 7. Print result banner
        out.print_heading("Auths Demo");
        out.println("");
        out.key_value("Your identity", issuer);
        out.key_value("Signed in    ", &format!("{}ms", sign_ms));
        out.key_value("Verified in  ", &format!("{}ms", verify_ms));
        out.println("");
        out.print_success("No network required.");

        Ok(())
    }
}
