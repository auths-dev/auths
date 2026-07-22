use anyhow::Result;
use clap::Args;
use serde_json::json;

#[derive(Args, Debug)]
pub struct KubectlTokenArgs {
    /// Kubernetes cluster name or identifier
    #[arg(short, long)]
    pub cluster: String,
}

/// Executes Kubernetes client exec credential plugin authentication for `kubectl`.
pub async fn run_kubectl_token(args: KubectlTokenArgs) -> Result<()> {
    let response = json!({
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "kind": "ExecCredential",
        "status": {
            "token": format!("auths-presentation-token-for-{}", args.cluster),
            "expirationTimestamp": "2030-01-01T00:00:00Z"
        }
    });

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
