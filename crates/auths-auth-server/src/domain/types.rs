//! Domain types for auth challenge sessions.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A challenge issued to authenticate a user via their KERI identity.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// Unique session identifier.
    pub id: Uuid,
    /// 32 random bytes, hex-encoded.
    pub nonce: String,
    /// Origin domain — the mobile app signs over nonce + domain to prevent phishing.
    pub domain: String,
    /// When the challenge was created.
    pub created_at: DateTime<Utc>,
    /// When the challenge expires.
    pub expires_at: DateTime<Utc>,
}

impl AuthChallenge {
    /// Returns true if the challenge has expired relative to `now`.
    ///
    /// Args:
    /// * `now`: The current time to compare against `expires_at`.
    ///
    /// Usage:
    /// ```ignore
    /// if challenge.is_expired(Utc::now()) { return Err(...); }
    /// ```
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }

    /// Produces the canonical JSON bytes the signer must have signed.
    ///
    /// The payload is `{"domain": ..., "nonce": ...}` serialized with
    /// `json-canon` (RFC 8785 deterministic ordering).
    ///
    /// Usage:
    /// ```ignore
    /// let bytes = challenge.canonical_payload()?;
    /// public_key.verify(&bytes, &sig)?;
    /// ```
    pub fn canonical_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload = serde_json::json!({
            "domain": &self.domain,
            "nonce": &self.nonce,
        });
        json_canon::to_vec(&payload)
    }
}

/// Status of an authentication session.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum SessionStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "verified")]
    Verified {
        did: String,
        verified_at: DateTime<Utc>,
    },
    #[serde(rename = "expired")]
    Expired,
}

/// A full authentication session: a challenge plus its current status.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub challenge: AuthChallenge,
    pub status: SessionStatus,
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_challenge(domain: &str, nonce: &str) -> AuthChallenge {
        let now = Utc::now();
        AuthChallenge {
            id: Uuid::new_v4(),
            nonce: nonce.to_string(),
            domain: domain.to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(300),
        }
    }

    #[test]
    fn canonical_payload_is_deterministic_json() {
        let challenge = make_challenge("bank.example.com", "abc123");
        let bytes = challenge.canonical_payload().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["domain"], "bank.example.com");
        assert_eq!(json["nonce"], "abc123");

        // RFC 8785: keys sorted lexicographically — "domain" before "nonce"
        let raw = String::from_utf8(bytes).unwrap();
        let domain_pos = raw.find("\"domain\"").unwrap();
        let nonce_pos = raw.find("\"nonce\"").unwrap();
        assert!(domain_pos < nonce_pos, "keys must be in sorted order");
    }

    #[test]
    fn canonical_payload_contains_only_domain_and_nonce() {
        let challenge = make_challenge("example.com", "deadbeef");
        let bytes = challenge.canonical_payload().unwrap();
        let json: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&bytes).unwrap();

        let keys: Vec<&String> = json.keys().collect();
        assert_eq!(keys, vec!["domain", "nonce"]);
    }

    #[test]
    fn is_expired_at_exact_boundary() {
        let now = Utc::now();
        let challenge = AuthChallenge {
            id: Uuid::new_v4(),
            nonce: "n".to_string(),
            domain: "d".to_string(),
            created_at: now - Duration::seconds(300),
            expires_at: now,
        };

        // At the exact boundary, `now > expires_at` is false
        assert!(!challenge.is_expired(now));

        // One millisecond past the boundary
        assert!(challenge.is_expired(now + Duration::milliseconds(1)));

        // One millisecond before the boundary
        assert!(!challenge.is_expired(now - Duration::milliseconds(1)));
    }
}
