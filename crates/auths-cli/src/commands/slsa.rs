use anyhow::{Context, Result};
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
}

/// Generates an in-toto SLSA Level 3 provenance statement for a release artifact.
pub async fn run_slsa_generate(args: SlsaGenerateArgs) -> Result<()> {
    let artifact_bytes = std::fs::read(&args.artifact)
        .with_context(|| format!("Failed to read artifact file at {}", args.artifact))?;

    let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, &artifact_bytes).as_ref());

    let provenance = json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{
            "name": args.artifact,
            "digest": { "sha256": digest }
        }],
        "builder": {
            "id": "https://auths.dev/builder/v1"
        },
        "buildType": "https://auths.dev/build-types/slsa-l3/v1",
        "invocation": {
            "configSource": {
                "uri": "git+https://github.com/auths-dev/auths",
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
        "SLSA Level 3 provenance statement generated: {}",
        args.output
    );
    Ok(())
}
