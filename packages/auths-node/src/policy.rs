use napi_derive::napi;

use auths_policy::{
    CanonicalCapability, CanonicalDid, CompiledPolicy, EvalContext, SignerType,
    compile_from_json, enforce_simple,
};
use chrono::Utc;

use crate::error::format_error;

#[napi(object)]
#[derive(Clone)]
pub struct NapiPolicyDecision {
    pub outcome: String,
    pub reason: String,
    pub message: String,
}

#[napi]
pub fn compile_policy(policy_json: String) -> napi::Result<String> {
    let compiled = compile_from_json(policy_json.as_bytes()).map_err(|errors| {
        let msgs: Vec<String> = errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.message))
            .collect();
        format_error(
            "AUTHS_POLICY_COMPILE_ERROR",
            format!("Policy compilation failed: {}", msgs.join("; ")),
        )
    })?;

    serde_json::to_string(&compiled).map_err(|e| {
        format_error("AUTHS_POLICY_SERIALIZE_ERROR", e)
    })
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_policy(
    policy_json: String,
    issuer: String,
    subject: String,
    capabilities: Option<Vec<String>>,
    role: Option<String>,
    revoked: Option<bool>,
    expires_at: Option<String>,
    repo: Option<String>,
    environment: Option<String>,
    signer_type: Option<String>,
    delegated_by: Option<String>,
    chain_depth: Option<u32>,
) -> napi::Result<NapiPolicyDecision> {
    let compiled: CompiledPolicy =
        serde_json::from_str(&policy_json).map_err(|e| {
            format_error("AUTHS_POLICY_DESERIALIZE_ERROR", e)
        })?;

    let issuer_did = CanonicalDid::parse(&issuer).map_err(|e| {
        format_error("AUTHS_POLICY_INVALID_DID", format!("Invalid issuer DID: {e}"))
    })?;
    let subject_did = CanonicalDid::parse(&subject).map_err(|e| {
        format_error("AUTHS_POLICY_INVALID_DID", format!("Invalid subject DID: {e}"))
    })?;

    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
    let mut ctx = EvalContext::new(now, issuer_did, subject_did)
        .revoked(revoked.unwrap_or(false));

    if let Some(caps) = capabilities {
        for cap_str in &caps {
            let cap = CanonicalCapability::parse(cap_str).map_err(|e| {
                format_error(
                    "AUTHS_POLICY_INVALID_CAPABILITY",
                    format!("Invalid capability '{cap_str}': {e}"),
                )
            })?;
            ctx = ctx.capability(cap);
        }
    }

    if let Some(r) = role {
        ctx = ctx.role(r);
    }

    if let Some(exp) = expires_at {
        let ts: chrono::DateTime<Utc> = exp.parse().map_err(|_| {
            format_error(
                "AUTHS_POLICY_INVALID_TIMESTAMP",
                format!("Invalid expires_at RFC 3339: {exp}"),
            )
        })?;
        ctx = ctx.expires_at(ts);
    }

    if let Some(r) = repo {
        ctx = ctx.repo(r);
    }

    if let Some(env) = environment {
        ctx = ctx.environment(env);
    }

    if let Some(st) = signer_type {
        let parsed = match st.to_lowercase().as_str() {
            "human" => SignerType::Human,
            "agent" => SignerType::Agent,
            "workload" => SignerType::Workload,
            _ => {
                return Err(format_error(
                    "AUTHS_POLICY_INVALID_SIGNER_TYPE",
                    format!("Invalid signer_type: '{st}'. Must be 'human', 'agent', or 'workload'"),
                ));
            }
        };
        ctx = ctx.signer_type(parsed);
    }

    if let Some(d) = delegated_by {
        let did = CanonicalDid::parse(&d).map_err(|e| {
            format_error("AUTHS_POLICY_INVALID_DID", format!("Invalid delegated_by DID: {e}"))
        })?;
        ctx = ctx.delegated_by(did);
    }

    if let Some(depth) = chain_depth {
        ctx = ctx.chain_depth(depth);
    }

    let decision = enforce_simple(&compiled, &ctx);

    Ok(NapiPolicyDecision {
        outcome: decision.outcome.to_string().to_lowercase(),
        reason: format!("{:?}", decision.reason),
        message: decision.message,
    })
}
