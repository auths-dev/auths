use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde_json::Value;

use auths_sdk::domains::signing::service::sign_artifact_ephemeral;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::Output;

/// Synthetic commit SHA stamped into the demo attestation.
///
/// `sign_artifact_ephemeral` binds provenance to a 40/64-hex commit SHA, but the
/// demo signs ad-hoc bytes rather than a real commit — this recognizable placeholder
/// keeps the call valid without pretending to reference a real commit.
const DEMO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, clap::Args)]
#[command(about = "Sign and verify a demo artifact — works offline, no setup or registry needed")]
pub struct DemoCommand {}

impl ExecutableCommand for DemoCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        let out = Output::new();
        let data = b"Hello, Auths!\n";

        // Sign with an ephemeral in-process key: no identity, no keychain, no Secure
        // Enclave — so the "aha" works the instant the binary is installed and never
        // blocks on a Touch ID prompt (even on a TTY-less CI shell).
        let t_sign = Instant::now();
        let sign_result = sign_artifact_ephemeral(
            Utc::now(),
            data,
            Some("demo.txt".into()),
            DEMO_COMMIT_SHA.into(),
            None,
            Some("auths demo — local only".into()),
            None,
        )
        .map_err(|e| anyhow!("{}", e))?;
        let sign_ms = t_sign.elapsed().as_millis();

        // Verify locally: the digest the attestation commits to must match what we signed.
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

        let issuer = attestation
            .pointer("/issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");

        out.print_heading("Auths Demo");
        out.println("");
        out.println(&out.key_value("Demo identity", issuer));
        out.println(&out.key_value("Signed in", &format!("{sign_ms}ms")));
        out.println(&out.key_value("Verified in", &format!("{verify_ms}ms")));
        out.println("");
        out.print_success("Signed + verified locally — no network, no setup required.");
        out.println("");
        out.println(
            "This used a throwaway demo key. Run `auths init` to sign with your real identity.",
        );

        Ok(())
    }
}
