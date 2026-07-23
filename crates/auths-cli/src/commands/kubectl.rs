use anyhow::{Context, Result};
use clap::Args;
use chrono::{Duration, Utc};
use auths_rp::Audience;
use auths_sdk::workflows::auth::create_k8s_exec_credential;

#[derive(Args, Debug)]
pub struct KubectlTokenArgs {
    /// Kubernetes cluster name or identifier
    #[arg(short, long)]
    pub cluster: String,

    /// Key alias to sign presentation token
    #[arg(short, long)]
    pub key: Option<String>,

    /// Expiration TTL in seconds (default 3600 = 1 hour)
    #[arg(long, default_value_t = 3600)]
    pub ttl_seconds: i64,
}

/// Executes Kubernetes client exec credential plugin authentication for `kubectl`.
pub async fn run_kubectl_token(args: KubectlTokenArgs) -> Result<()> {
    let aud_str = format!("k8s:cluster:{}", args.cluster.trim());
    let cluster_aud = Audience::parse(&aud_str).context("Invalid Kubernetes cluster audience")?;
    let key_alias = args.key.as_deref().unwrap_or("main");
    let now = Utc::now();

    let response = create_k8s_exec_credential(
        "did:keri:local",
        &cluster_aud,
        key_alias,
        Duration::seconds(args.ttl_seconds),
        now,
    ).context("Failed to generate Auths Kubernetes ExecCredential token")?;

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
