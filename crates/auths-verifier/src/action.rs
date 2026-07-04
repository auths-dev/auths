//! Typed action envelope for signed actions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Typed action envelope for signed actions.
///
/// Compatible with the existing Python SDK wire format (version "1.0").
/// The `signature` field is excluded from the canonical signing data.
///
/// Args:
/// * `version`: Protocol version string (currently "1.0").
/// * `action_type`: The type of action being performed.
/// * `identity`: DID of the signing identity.
/// * `payload`: Arbitrary JSON payload.
/// * `timestamp`: RFC3339 timestamp string.
/// * `signature`: Hex-encoded Ed25519 signature over the canonical signing data.
/// * `attestation_chain`: Optional chain of attestations for verification.
/// * `environment`: Optional environment claim for gateway verification.
///
/// Usage:
/// ```ignore
/// let envelope = ActionEnvelope {
///     version: "1.0".into(),
///     action_type: "sign_commit".into(),
///     identity: "did:keri:Eabc123".into(),
///     payload: serde_json::json!({"hash": "abc123"}),
///     timestamp: "2024-01-01T00:00:00Z".into(),
///     signature: "deadbeef...".into(),
///     attestation_chain: None,
///     environment: None,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionEnvelope {
    /// Protocol version string.
    pub version: String,
    /// The type of action being performed.
    #[serde(rename = "type")]
    pub action_type: String,
    /// DID of the signing identity.
    pub identity: String,
    /// Arbitrary JSON payload.
    pub payload: Value,
    /// RFC3339 timestamp string.
    pub timestamp: String,
    /// Hex-encoded Ed25519 signature over the canonical signing data.
    pub signature: String,
    /// Optional chain of attestations for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_chain: Option<Value>,
    /// Optional environment claim for gateway verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Value>,
}

/// The subset of `ActionEnvelope` fields that are signed.
///
/// Excludes `signature`, `attestation_chain`, and `environment`.
#[derive(Debug, Serialize)]
pub struct ActionSigningData<'a> {
    /// Protocol version string.
    pub version: &'a str,
    /// The type of action being performed.
    #[serde(rename = "type")]
    pub action_type: &'a str,
    /// DID of the signing identity.
    pub identity: &'a str,
    /// Arbitrary JSON payload.
    pub payload: &'a Value,
    /// RFC3339 timestamp string.
    pub timestamp: &'a str,
}

impl ActionEnvelope {
    /// Extracts the signing data from this envelope.
    pub fn signing_data(&self) -> ActionSigningData<'_> {
        ActionSigningData {
            version: &self.version,
            action_type: &self.action_type,
            identity: &self.identity,
            payload: &self.payload,
            timestamp: &self.timestamp,
        }
    }

    /// Produces the canonical JSON bytes for signature verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let data = self.signing_data();
        json_canon::to_string(&data)
            .map(|s| s.into_bytes())
            .map_err(|e| format!("canonicalization failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The raw-seed `sign_action` → `verify_action_envelope` roundtrip the
    /// Python bindings wrap, reproduced at the crate level: sign canonical bytes
    /// with a raw Ed25519 seed and verify with the seed's RFC-8032 public key
    /// after a JSON wire round-trip.
    #[test]
    fn raw_seed_action_sign_verify_roundtrip() {
        use auths_crypto::{RingCryptoProvider, TypedSeed, typed_public_key, typed_sign};

        let seed = [0xaau8; 32]; // Python test's TEST_SEED_HEX = "a" * 64
        let ts = TypedSeed::Ed25519(seed);
        let pk = typed_public_key(&ts).expect("derive Ed25519 public key from seed");

        // sign_action
        let mut env = ActionEnvelope {
            version: "1.0".into(),
            action_type: "tool_call".into(),
            identity: "did:keri:ETest123".into(),
            payload: serde_json::json!({"tool": "read_file", "path": "/etc/config.json"}),
            timestamp: "2026-07-04T00:00:00Z".into(),
            signature: String::new(),
            attestation_chain: None,
            environment: None,
        };
        let canonical = env.canonical_bytes().expect("canonical bytes at sign time");
        let sig = typed_sign(&ts, &canonical).expect("sign canonical bytes");
        env.signature = hex::encode(&sig);

        // wire round-trip (serialize → reparse), as the envelope crosses the boundary
        let wire = serde_json::to_string(&env).expect("serialize envelope");
        let parsed: ActionEnvelope = serde_json::from_str(&wire).expect("reparse envelope");

        // verify_action_envelope
        let canonical2 = parsed.canonical_bytes().expect("canonical bytes at verify time");
        assert_eq!(
            canonical, canonical2,
            "canonical signing bytes changed across the JSON wire round-trip"
        );
        let sig2 = hex::decode(&parsed.signature).expect("decode signature hex");
        RingCryptoProvider::ed25519_verify(&pk, &canonical2, &sig2)
            .expect("raw-seed sign_action -> verify_action_envelope must round-trip");
    }

    #[test]
    fn roundtrip_serialization() {
        let envelope = ActionEnvelope {
            version: "1.0".into(),
            action_type: "sign_commit".into(),
            identity: "did:keri:Eabc123".into(),
            payload: serde_json::json!({"hash": "abc123"}),
            timestamp: "2024-01-01T00:00:00Z".into(),
            signature: "deadbeef".into(),
            attestation_chain: None,
            environment: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: ActionEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, parsed);
    }

    #[test]
    fn type_field_renamed_in_json() {
        let envelope = ActionEnvelope {
            version: "1.0".into(),
            action_type: "sign_commit".into(),
            identity: "did:keri:Eabc123".into(),
            payload: serde_json::json!({}),
            timestamp: "2024-01-01T00:00:00Z".into(),
            signature: "deadbeef".into(),
            attestation_chain: None,
            environment: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"type\":"));
        assert!(!json.contains("\"action_type\":"));
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let envelope = ActionEnvelope {
            version: "1.0".into(),
            action_type: "sign_commit".into(),
            identity: "did:keri:Eabc123".into(),
            payload: serde_json::json!({}),
            timestamp: "2024-01-01T00:00:00Z".into(),
            signature: "deadbeef".into(),
            attestation_chain: None,
            environment: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("attestation_chain"));
        assert!(!json.contains("environment"));
    }

    #[test]
    fn wire_compat_with_python_sdk_format() {
        let python_wire = serde_json::json!({
            "version": "1.0",
            "type": "sign_commit",
            "identity": "did:keri:Eabc123",
            "payload": {"hash": "abc123"},
            "timestamp": "2024-01-01T00:00:00Z",
            "signature": "deadbeef"
        });

        let envelope: ActionEnvelope = serde_json::from_value(python_wire.clone()).unwrap();
        assert_eq!(envelope.version, "1.0");
        assert_eq!(envelope.action_type, "sign_commit");

        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert_eq!(python_wire, reserialized);
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let envelope = ActionEnvelope {
            version: "1.0".into(),
            action_type: "sign_commit".into(),
            identity: "did:keri:Eabc123".into(),
            payload: serde_json::json!({"hash": "abc123"}),
            timestamp: "2024-01-01T00:00:00Z".into(),
            signature: "different_sig".into(),
            attestation_chain: Some(serde_json::json!([])),
            environment: Some(serde_json::json!({"region": "us-east-1"})),
        };

        let canonical = String::from_utf8(envelope.canonical_bytes().unwrap()).unwrap();
        assert!(!canonical.contains("signature"));
        assert!(!canonical.contains("attestation_chain"));
        assert!(!canonical.contains("environment"));
        assert!(canonical.contains("\"version\""));
        assert!(canonical.contains("\"type\""));
    }
}
