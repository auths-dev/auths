//! Routed KERI message types: Query, Reply, Prod, Bare, Exchange Inception, Exchange.
//!
//! These message types enable inter-agent communication, discovery, and
//! credential exchange in the KERI protocol. They are NOT key events —
//! they don't appear in the KEL.

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::types::{Prefix, Said, VersionString};

/// Query message — requests information from a peer.
///
/// Spec field order: `[v, t, d, dt, r, rr, q]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QryMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// ISO-8601 datetime with microseconds and UTC offset
    pub dt: String,
    /// Route (delimited path string)
    pub r: String,
    /// Return route (for response routing)
    #[serde(default)]
    pub rr: String,
    /// Query parameters
    #[serde(default)]
    pub q: serde_json::Value,
}

impl Serialize for QryMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "qry")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("rr", &self.rr)?;
        map.serialize_entry("q", &self.q)?;
        map.end()
    }
}

/// Reply message — response to a query.
///
/// Spec field order: `[v, t, d, dt, r, a]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpyMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// ISO-8601 datetime
    pub dt: String,
    /// Route
    pub r: String,
    /// Attribute map (response data)
    #[serde(default)]
    pub a: serde_json::Value,
}

impl Serialize for RpyMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "rpy")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

/// Prod message — prompts a peer for information (similar to query).
///
/// Spec field order: `[v, t, d, dt, r, rr, q]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// ISO-8601 datetime
    pub dt: String,
    /// Route
    pub r: String,
    /// Return route
    #[serde(default)]
    pub rr: String,
    /// Query parameters
    #[serde(default)]
    pub q: serde_json::Value,
}

impl Serialize for ProMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "pro")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("rr", &self.rr)?;
        map.serialize_entry("q", &self.q)?;
        map.end()
    }
}

/// Bare message — unsolicited response (similar to reply).
///
/// Spec field order: `[v, t, d, dt, r, a]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BarMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// ISO-8601 datetime
    pub dt: String,
    /// Route
    pub r: String,
    /// Attribute map
    #[serde(default)]
    pub a: serde_json::Value,
}

impl Serialize for BarMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "bar")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

/// Exchange inception message — initiates an exchange protocol.
///
/// Spec field order: `[v, t, d, u, i, ri, dt, r, q, a]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XipMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// UUID salty nonce (cryptographic strength random)
    #[serde(default)]
    pub u: String,
    /// Sender AID
    pub i: Prefix,
    /// Receiver AID
    pub ri: Prefix,
    /// ISO-8601 datetime
    pub dt: String,
    /// Route
    pub r: String,
    /// Query parameters
    #[serde(default)]
    pub q: serde_json::Value,
    /// Attribute map
    #[serde(default)]
    pub a: serde_json::Value,
}

impl Serialize for XipMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "xip")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("u", &self.u)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("ri", &self.ri)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("q", &self.q)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

/// Exchange message — peer-to-peer exchange (credential, data).
///
/// Spec field order: `[v, t, d, i, ri, x, p, dt, r, q, a]`
///
/// Note: The `x` field here is the Exchange SAID (spec-defined), NOT a signature.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExnMessage {
    /// Version string
    pub v: VersionString,
    /// SAID
    #[serde(default)]
    pub d: Said,
    /// Sender AID
    pub i: Prefix,
    /// Receiver AID
    pub ri: Prefix,
    /// Exchange SAID (unique digest for exchange transaction — NOT a signature)
    #[serde(default)]
    pub x: Said,
    /// Prior message SAID
    #[serde(default)]
    pub p: Said,
    /// ISO-8601 datetime
    pub dt: String,
    /// Route
    pub r: String,
    /// Query parameters
    #[serde(default)]
    pub q: serde_json::Value,
    /// Attribute map
    #[serde(default)]
    pub a: serde_json::Value,
}

impl Serialize for ExnMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(11))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "exn")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("ri", &self.ri)?;
        map.serialize_entry("x", &self.x)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", &self.r)?;
        map.serialize_entry("q", &self.q)?;
        map.serialize_entry("a", &self.a)?;
        map.end()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn qry_message_roundtrip() {
        let msg = QryMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/kel".into(),
            rr: "/receipt".into(),
            q: serde_json::json!({"i": "EPrefix123"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"qry\""));
        let parsed: QryMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.r, "/kel");
    }

    #[test]
    fn rpy_message_roundtrip() {
        let msg = RpyMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/kel".into(),
            a: serde_json::json!({"data": "value"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"rpy\""));
        let parsed: RpyMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn xip_message_roundtrip() {
        let msg = XipMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            u: "nonce123".into(),
            i: Prefix::new_unchecked("ESender".into()),
            ri: Prefix::new_unchecked("EReceiver".into()),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/credential/issue".into(),
            q: serde_json::json!({}),
            a: serde_json::json!({}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"xip\""));
        let parsed: XipMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.i.as_str(), "ESender");
    }

    #[test]
    fn exn_message_roundtrip() {
        let msg = ExnMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked("ESender".into()),
            ri: Prefix::new_unchecked("EReceiver".into()),
            x: Said::new_unchecked("EExchangeSaid".into()),
            p: Said::default(),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/credential/present".into(),
            q: serde_json::json!({}),
            a: serde_json::json!({}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"exn\""));
        assert!(json.contains("\"x\":\"EExchangeSaid\""));
        let parsed: ExnMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.x.as_str(), "EExchangeSaid");
    }

    #[test]
    fn bar_message_roundtrip() {
        let msg = BarMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/notify".into(),
            a: serde_json::json!({"status": "ok"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"bar\""));
        let parsed: BarMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn pro_message_roundtrip() {
        let msg = ProMessage {
            v: VersionString::placeholder(),
            d: Said::default(),
            dt: "2024-01-01T00:00:00.000000+00:00".into(),
            r: "/prod".into(),
            rr: "/reply".into(),
            q: serde_json::json!({}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"pro\""));
        let parsed: ProMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }
}
