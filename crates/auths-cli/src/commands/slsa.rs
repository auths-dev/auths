use anyhow::{Context, Result};
use auths_sdk::domains::signing::ci_env::{CiEnvironment, CiPlatform, detect_ci_environment};
use clap::Args;
use serde_json::json;

#[derive(Args, Debug)]
pub struct SlsaGenerateArgs {
    /// Path to artifact file
    #[arg(short, long)]
    pub artifact: String,

    /// Output SLSA provenance JSON file path
    #[arg(short, long, default_value = "provenance.slsa.json")]
    pub output: String,

    /// Force SLSA level tag (default auto-detect: L3 in verified CI, L1 in local dev)
    #[arg(long)]
    pub level: Option<u8>,
}

/// Strongly-typed SLSA provenance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlsaLevel {
    L1,
    L3,
}

impl SlsaLevel {
    pub fn resolve(requested: Option<u8>, ci_env: Option<&CiEnvironment>) -> Result<Self> {
        let is_github = matches!(ci_env, Some(env) if env.platform == CiPlatform::GithubActions);

        match (requested, is_github) {
            (Some(3), false) => {
                anyhow::bail!(
                    "SLSA Level 3 provenance requires a verified isolated CI runner (GitHub Actions with OIDC token)"
                );
            }
            (Some(3), true) => Ok(SlsaLevel::L3),
            (Some(1), _) => Ok(SlsaLevel::L1),
            (Some(other), _) => anyhow::bail!("Unsupported SLSA level: {}", other),
            (None, true) => Ok(SlsaLevel::L3),
            (None, false) => Ok(SlsaLevel::L1),
        }
    }

    pub fn build_type(&self) -> &'static str {
        match self {
            SlsaLevel::L1 => "https://auths.dev/build-types/slsa-l1/v1",
            SlsaLevel::L3 => "https://auths.dev/build-types/slsa-l3/v1",
        }
    }
}

/// Generates an in-toto SLSA provenance statement for a release artifact.
pub async fn run_slsa_generate(args: SlsaGenerateArgs) -> Result<()> {
    let artifact_bytes = std::fs::read(&args.artifact)
        .with_context(|| format!("Failed to read artifact file at {}", args.artifact))?;

    let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, &artifact_bytes).as_ref());

    let ci_env = detect_ci_environment();
    let level = SlsaLevel::resolve(args.level, ci_env.as_ref())?;

    let builder_id = match ci_env.as_ref() {
        Some(env) if env.platform == CiPlatform::GithubActions => {
            format!(
                "{}/{}",
                std::env::var("GITHUB_SERVER_URL").unwrap_or_default(),
                env.repository.as_deref().unwrap_or_default()
            )
        }
        _ => "https://auths.dev/builder/local".to_string(),
    };

    let provenance = json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{
            "name": args.artifact,
            "digest": { "sha256": digest }
        }],
        "builder": { "id": builder_id },
        "buildType": level.build_type(),
        "invocation": {
            "configSource": {
                "uri": match ci_env.as_ref().and_then(|e| e.repository.as_deref()) {
                    Some(repo) => format!("git+https://github.com/{}", repo),
                    None => "local".into(),
                },
                "entryPoint": "auths slsa generate"
            }
        }
    });

    std::fs::write(&args.output, serde_json::to_string_pretty(&provenance)?).with_context(
        || {
            format!(
                "Failed to write SLSA provenance statement to {}",
                args.output
            )
        },
    )?;

    println!(
        "SLSA Level {:?} provenance statement generated: {}",
        level, args.output
    );
    Ok(())
}
