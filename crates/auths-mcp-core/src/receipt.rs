//! Signed per-call receipts (PRD §4 G4). Every brokered call — allowed or refused
//! — emits a receipt: who acted, under which grant, on what action, with what
//! verdict, and the running spend total. The audit trail is cryptographic — the
//! receipt names the agent's signed-call proof (a git commit `auths verify`
//! independently accepts), and the receipt body's own digest binds the verdict to
//! that proof.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::gate::{ToolCall, Verdict};

/// One receipt for a brokered `tools/call`. It records the authenticated identity
/// (device = the delegated agent, identity = the parent root the grant is anchored
/// to), the action, the verdict, and the running spend. The `proof_ref` names the
/// agent's signed-call artifact — the object `auths verify` independently accepts —
/// so a stranger can re-derive the verdict from the chain alone.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    /// The acting agent (the delegated `device`), a `did:keri:`.
    pub device: String,
    /// The parent/delegator root identity the grant is anchored to, a `did:keri:`.
    pub identity: String,
    /// The tool the call targeted.
    pub tool: String,
    /// Hash of the canonical `tools/call` bytes that were judged (hex SHA-256).
    pub action_hash: String,
    /// The reference to the agent's signed-call proof `auths verify` accepts — the
    /// git commit SHA over the canonical call.
    pub proof_ref: String,
    /// The gate's verdict for this call.
    pub verdict: Verdict,
    /// The payment rail this metered call settled on (cross-rail attribution, D8) —
    /// `None` for a non-metered call. The receipt naming its rail is what proves the
    /// counter is CROSS-RAIL, not a per-rail silo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// The rail-native reference the metered cost was EXTRACTED from (e.g. a Stripe
    /// charge id `ch_…`), present only when the cost came from the rail's RESPONSE
    /// rather than a known transcript number. Naming it in the receipt is what proves
    /// the settle is rail-response-authoritative: a stranger re-derives the metered
    /// cost from the recorded response by this reference, not from an agent-declared
    /// number (the metered-rail cost extraction, PRD §11). `None` for a call whose cost
    /// is not extracted from a rail response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charge_ref: Option<String>,
    /// The ceiling RESERVED for this call before the rail was touched (the
    /// pre-authorization hold). `0` for a non-metered call. The reserved-vs-settled
    /// split proves the slack (`reserved − settled-delta`) was released, not consumed.
    #[serde(default)]
    pub reserved_cents: u64,
    /// Cumulative CROSS-RAIL SETTLED spend (cents) after this call — the running total
    /// summed across all rails (the verifier-held monotonic counter). This is the
    /// `cross_rail_cumulative` the receipt reports.
    pub cumulative_cents: u64,
    /// When the call was judged.
    pub at: DateTime<Utc>,
}

/// Errors emitting or verifying a receipt.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("could not canonicalize the receipt body: {0}")]
    Canonicalization(String),
    #[error("could not sign the receipt: {0}")]
    Signing(String),
    #[error("receipt signature did not verify: {0}")]
    Verification(String),
}

impl Receipt {
    /// Build the receipt for a judged call. The cryptographic anchor is the
    /// agent's signed-call proof (`proof_ref` — the git commit `auths verify`
    /// accepts, device=agent, identity=parent-root); this records that decision
    /// with the running total and binds it to the canonical action.
    #[allow(clippy::too_many_arguments)]
    pub fn for_call(
        device: &str,
        identity: &str,
        call: &ToolCall,
        proof_ref: &str,
        verdict: Verdict,
        rail: Option<&str>,
        charge_ref: Option<&str>,
        reserved_cents: u64,
        cumulative_cents: u64,
        at: DateTime<Utc>,
    ) -> Self {
        let action_hash = hex_sha256(&call.canonical_bytes());
        Receipt {
            device: device.to_string(),
            identity: identity.to_string(),
            tool: call.tool.clone(),
            action_hash,
            proof_ref: proof_ref.to_string(),
            verdict,
            rail: rail.map(str::to_string),
            charge_ref: charge_ref.map(str::to_string),
            reserved_cents,
            cumulative_cents,
            at,
        }
    }

    /// The canonical (RFC-8785) receipt body bytes — the stable serialization a
    /// verifier re-derives the digest over.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        json_canon::to_string(self)
            .map(String::into_bytes)
            .map_err(|e| ReceiptError::Canonicalization(e.to_string()))
    }

    /// The receipt body digest (hex SHA-256) — a stable id for this receipt.
    pub fn digest(&self) -> Result<String, ReceiptError> {
        Ok(hex_sha256(&self.canonical_bytes()?))
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_call() -> ToolCall {
        ToolCall {
            tool: "read_file".into(),
            args: serde_json::json!({ "path": "README.md" }),
            cost_cents: 0,
        }
    }

    #[test]
    fn receipt_records_device_and_identity() {
        let r = Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &sample_call(),
            "abc123",
            Verdict::Allowed,
            None,
            None,
            0,
            0,
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        );
        assert_eq!(r.device, "did:keri:Eagent");
        assert_eq!(r.identity, "did:keri:Eroot");
        assert_eq!(r.tool, "read_file");
        assert_eq!(r.proof_ref, "abc123");
        assert_eq!(r.action_hash.len(), 64);
    }

    #[test]
    fn receipt_carries_rail_and_reserved_split() {
        // A metered paid call's receipt names its rail and carries the reserved-vs-
        // settled split — the cross-rail attribution + slack-release evidence (D8).
        let call = ToolCall {
            tool: "paid_call".into(),
            args: serde_json::json!({ "q": "b" }),
            cost_cents: 150,
        };
        let r = Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "abc123",
            Verdict::Allowed,
            Some("x402"),
            None,
            200, // reserved a $2.00 ceiling
            450, // cross-rail settled total after this call
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        );
        assert_eq!(r.rail.as_deref(), Some("x402"));
        assert_eq!(r.reserved_cents, 200);
        assert_eq!(r.cumulative_cents, 450);
        // The rail survives the canonical round-trip the verifier re-derives over.
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"rail\":\"x402\""));
    }

    #[test]
    fn receipt_names_the_extracted_charge_reference() {
        // A metered call whose cost was EXTRACTED from the rail's response names the
        // rail-native reference (a Stripe charge id) in its receipt — the evidence that
        // the settle is rail-response-authoritative, not an agent-declared number
        // (the metered-rail cost extraction, PRD §11).
        let call = ToolCall {
            tool: "paid_call".into(),
            args: serde_json::json!({ "endpoint": "/charge" }),
            cost_cents: 300,
        };
        let r = Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "abc123",
            Verdict::Allowed,
            Some("stripe"),
            Some("ch_3MmlLrLkdIwHu7ix0snN0B15"),
            300,
            300,
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        );
        assert_eq!(r.charge_ref.as_deref(), Some("ch_3MmlLrLkdIwHu7ix0snN0B15"));
        // The charge id survives the canonical round-trip a stranger re-derives over.
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"charge_ref\":\"ch_3MmlLrLkdIwHu7ix0snN0B15\""));
        assert!(json.contains("\"rail\":\"stripe\""));
    }

    #[test]
    fn receipt_digest_is_stable() {
        let r = Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &sample_call(),
            "abc123",
            Verdict::Allowed,
            None,
            None,
            0,
            0,
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        );
        let d1 = r.digest().unwrap();
        let d2 = r.digest().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }
}
