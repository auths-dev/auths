//! A legible "what you are authorizing" summary derived from the exact bytes being signed.
//!
//! A signer should be able to see what a signature authorizes, not just a digest. For the paths
//! whose signed bytes are legible — a signed action request, a git commit — this derives a
//! human-readable summary deterministically from those exact bytes, so the summary cannot drift
//! from what is signed. For bytes whose content is not legible from the signature (an artifact
//! attestation binds a digest, not the file content), the summary names the digest rather than
//! silently showing nothing.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// What a signer is authorizing, derived from the exact bytes being signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationSummary {
    /// A signed action request: the action, the signing identity, and the legible payload
    /// fields (e.g. an agent capability call's capability, budget, and target).
    Action {
        /// The action being authorized.
        action_type: String,
        /// The identity signing the action.
        identity: String,
        /// The action payload's top-level fields, rendered as key/value pairs.
        details: Vec<(String, String)>,
    },
    /// A git commit's message — the legible content being authorized. The commit's git `author`
    /// line is deliberately excluded: it is an unverified self-claim, and the authorizing identity
    /// is always the verdict's cryptographically-verified signer, never the git author.
    Commit {
        /// The commit message.
        message: String,
    },
    /// Signed bytes whose content is not legible from the signature (e.g. an artifact
    /// attestation binds a digest, not content). The digest is named so consent is never
    /// silently blank; content consent must be established out of band.
    Opaque {
        /// Lowercase hex SHA-256 of the signed bytes.
        digest_hex: String,
    },
}

impl AuthorizationSummary {
    /// Derive a legible summary from the exact bytes a signature will cover.
    ///
    /// Recognizes a signed action request (canonical JSON with `type`/`identity`/`payload`) and
    /// a git commit object; anything else is summarized by its SHA-256 digest rather than
    /// silently shown as nothing.
    ///
    /// Args:
    /// * `signed_bytes`: the bytes the signature covers.
    ///
    /// Usage:
    /// ```ignore
    /// let summary = AuthorizationSummary::from_signed_bytes(&payload);
    /// println!("Authorizing: {summary}");
    /// ```
    pub fn from_signed_bytes(signed_bytes: &[u8]) -> Self {
        if let Some(action) = parse_action(signed_bytes) {
            return action;
        }
        if let Some(commit) = parse_commit(signed_bytes) {
            return commit;
        }
        AuthorizationSummary::Opaque {
            digest_hex: hex::encode(Sha256::digest(signed_bytes)),
        }
    }
}

/// Parse signed action-request bytes (canonical JSON carrying `type`, `identity`, `payload`).
fn parse_action(bytes: &[u8]) -> Option<AuthorizationSummary> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let action_type = obj.get("type")?.as_str()?.to_string();
    let identity = obj.get("identity")?.as_str()?.to_string();
    let payload = obj.get("payload")?;
    let details = payload
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), render_scalar(v)))
                .collect()
        })
        .unwrap_or_default();
    Some(AuthorizationSummary::Action {
        action_type,
        identity,
        details,
    })
}

/// Parse a git commit object (`tree …` header, a blank line, then the message). The `author`
/// line is intentionally not read — it is an unverified self-claim, not the authorizing identity.
fn parse_commit(bytes: &[u8]) -> Option<AuthorizationSummary> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.starts_with("tree ") {
        return None;
    }
    let message = text
        .split_once("\n\n")
        .map(|(_, m)| m.trim_end().to_string())
        .unwrap_or_default();
    Some(AuthorizationSummary::Commit { message })
}

/// Render a JSON value as a compact display string (strings unquoted, others as JSON).
fn render_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl fmt::Display for AuthorizationSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationSummary::Action {
                action_type,
                identity,
                details,
            } => {
                write!(f, "action {action_type} by {identity}")?;
                for (k, v) in details {
                    write!(f, "; {k}={v}")?;
                }
                Ok(())
            }
            AuthorizationSummary::Commit { message } => {
                let subject = message.lines().next().unwrap_or("");
                write!(f, "commit: {subject}")
            }
            AuthorizationSummary::Opaque { digest_hex } => {
                write!(f, "opaque payload sha256:{digest_hex}")
            }
        }
    }
}
