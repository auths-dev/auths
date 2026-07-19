//! The AWN wire types.
//!
//! The anchor tuple `⟨seed_id, b_k, k, cum_k, τ_k⟩` (paper §9) is the same
//! object as the shipped `activity/v1` attestation (D4). This module defines it
//! once, with parse-don't-validate newtypes and in-band curve tags — never
//! length dispatch (CLAUDE.md wire-format rule).

use auths_crypto::CurveType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AnchorError;

/// Domain tag mixed into the seed-id preimage so a `SeedId` can never collide
/// with any other 32-byte digest the system computes.
const SEED_DOMAIN: &[u8] = b"auths-anchor/seed/v1";

/// Version tag on the message the party signs (`sig_Ia`).
pub(crate) const PARTY_MESSAGE_VERSION: &str = "auths-anchor/party/v1";

/// Version tag on the message each witness cosigns.
pub(crate) const COSIGN_MESSAGE_VERSION: &str = "auths-anchor/cosign/v1";

/// Stable identifier of one agent-under-mandate spend chain.
///
/// `H(root_aid ‖ agent_aid ‖ scope_seal_said)` — derivable by any holder of the
/// public delegation, no per-record data required (paper §9, D4). The type is
/// opaque so per-epoch blinding is an additive variant later, not a schema
/// break (answers §7 "stable vs blinded seed_id").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeedId([u8; 32]);

impl SeedId {
    /// Derive a seed id from the public delegation triple.
    ///
    /// Args:
    /// * `root_aid`: the principal's root identity (`did:keri:…`).
    /// * `agent_aid`: the delegated agent identity (`did:keri:…`).
    /// * `scope_seal_said`: the SAID of the delegator's scope-anchoring event.
    ///
    /// Usage:
    /// ```
    /// # use auths_anchor::SeedId;
    /// let a = SeedId::derive("did:keri:root", "did:keri:agent", "ESeal");
    /// let b = SeedId::derive("did:keri:root", "did:keri:agent", "ESeal");
    /// assert_eq!(a, b);
    /// ```
    pub fn derive(root_aid: &str, agent_aid: &str, scope_seal_said: &str) -> Self {
        let mut h = Sha256::new();
        h.update(SEED_DOMAIN);
        for part in [root_aid, agent_aid, scope_seal_said] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        let digest: [u8; 32] = h.finalize().into();
        Self(digest)
    }

    /// Wrap raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a lowercase-hex seed id of exactly 32 bytes.
    ///
    /// Args:
    /// * `s`: the hex string.
    pub fn from_hex(s: &str) -> Result<Self, AnchorError> {
        Ok(Self(decode_hex32(s)?))
    }
}

impl Serialize for SeedId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SeedId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A spend-log chain head `b_k` — a 32-byte commitment to the whole private
/// log without revealing any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Head([u8; 32]);

impl Head {
    /// Wrap raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a lowercase-hex head of exactly 32 bytes.
    ///
    /// Args:
    /// * `s`: the hex string (the `activity/v1` `head` field once past genesis).
    pub fn from_hex(s: &str) -> Result<Self, AnchorError> {
        Ok(Self(decode_hex32(s)?))
    }
}

impl Serialize for Head {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Head {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// The party signature `sig_Ia` over an anchor request, curve-tagged in-band.
///
/// The public key travels with the signature so a duplicity proof is
/// verifiable offline by strangers (I-DUP-3, A6). Tying the key to the seed's
/// root identity is a separate KEL check the acceptance rule performs against
/// `key_state`; the embedded key alone proves the cryptographic contradiction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartySignature {
    /// The signing curve — the only curve tag; verification dispatches on it.
    pub curve: CurveType,
    /// The party verifying key (32-byte Ed25519, or 33-byte compressed P-256).
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// The raw signature (64 bytes: Ed25519, or P-256 `r‖s`).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// One current verifying key of a controller, resolved from the KEL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentKey {
    /// The key's curve.
    pub curve: CurveType,
    /// Raw verifying-key bytes (32-byte Ed25519 or 33-byte compressed P-256).
    pub public_key: Vec<u8>,
}

/// The controller's current keys at an anchor's time, resolved from the KEL by
/// the caller.
///
/// This decouples the pure acceptance rule from KERI replay: the node builds it
/// with [`ControllerKeys::from_key_state`], the rule only compares against it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControllerKeys {
    /// The keys authorized to sign anchors right now (`kt=1`: any one suffices).
    pub current: Vec<CurrentKey>,
}

impl ControllerKeys {
    /// True iff `(curve, public_key)` is one of the current keys, compared by
    /// curve tag and full bytes — never by length.
    ///
    /// Args:
    /// * `curve`: the candidate key's curve.
    /// * `public_key`: the candidate key's raw bytes.
    pub fn contains(&self, curve: CurveType, public_key: &[u8]) -> bool {
        self.current
            .iter()
            .any(|k| k.curve == curve && k.public_key == public_key)
    }
}

/// Operator metadata for a witness, as plain strings so the WASM-safe
/// verification half needs no KERI dependency. The node maps these onto
/// `auths_keri::witness::independence::OperatorAttributes` for the honesty
/// ceiling (see [`crate::finalize::honesty_ceiling_of`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorInfo {
    /// The operating entity (distinct-operator axis of the diversity floor).
    pub operator: String,
    /// Legal operator organization.
    pub organization: String,
    /// Operating jurisdiction (e.g. `US`, `EU`).
    pub jurisdiction: String,
    /// Infrastructure zone (e.g. `aws/us-west-2`).
    pub infrastructure: String,
}

/// One declared member of a witness set `𝒲`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRef {
    /// Human-readable witness name (matches the cosignature's `witness_name`).
    pub name: String,
    /// The witness Ed25519 verifying key (witnesses cosign with Ed25519).
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Optional operator metadata, present when a diversity floor is enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<OperatorInfo>,
}

/// A pointer to the witness set `𝒲` the party commits to, anchored in the KEL
/// (I-TRUST-3). Carried inside every anchor so a co-signing witness knows the
/// exact set it is a member of and the threshold that finalizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSetRef {
    /// SAID of the witness-set event the delegator anchored in its KEL.
    pub said: String,
    /// The finalization threshold `t` of the `t`-of-`N` set.
    pub threshold: u32,
}

/// The resolved witness set — the declared members plus the threshold — carried
/// by-value in a [`FinalizedAnchor`] so finalization verifies offline (I-FINAL-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSet {
    /// SAID; must equal the anchor's [`WitnessSetRef::said`].
    pub said: String,
    /// Finalization threshold `t`.
    pub threshold: u32,
    /// The declared members (the `N`).
    pub members: Vec<WitnessRef>,
}

impl WitnessSet {
    /// Find a declared member by name.
    ///
    /// Args:
    /// * `name`: the witness name to look up.
    pub fn member(&self, name: &str) -> Option<&WitnessRef> {
        self.members.iter().find(|w| w.name == name)
    }
}

/// The anchor tuple — the only thing a witness ever sees (I-TRUST-1) and the
/// submission a party makes (`AnchorReq` is this same object with its
/// `sig_party` set).
///
/// This is the shipped `activity/v1` attestation under protocol names (D4):
/// `index` = `count`, `head` = `head`, `cumulative` = `cumulative_cents`,
/// `timestamp` = `as_of.ts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// The spend chain this anchor extends.
    pub seed_id: SeedId,
    /// Monotone record index `k` (== `activity/v1` `count`).
    pub index: u64,
    /// Chain head `b_k` (== `activity/v1` `head`).
    pub head: Head,
    /// Cumulative settled cents `cum_k` (widened from the `u64` on the wire).
    pub cumulative: u128,
    /// When the aggregate was computed `τ_k` (== `activity/v1` `as_of.ts`).
    pub timestamp: DateTime<Utc>,
    /// Pointer to the witness set anchored in the KEL (I-TRUST-3).
    pub witness_set: WitnessSetRef,
    /// The party signature `sig_Ia` over the tuple, curve-tagged (I-DUP-3).
    pub sig_party: PartySignature,
}

/// The submission a party makes to a witness. Identical to [`Anchor`] — named
/// separately only where a spec reference (`AnchorReq`, paper §9.2) reads
/// clearer.
pub type AnchorReq = Anchor;

impl Anchor {
    /// The canonical bytes the party signs (`sig_party` excluded).
    ///
    /// RFC-8785 canonical JSON over the tuple with a domain-separating version
    /// tag and second-resolution timestamp, so the message is deterministic and
    /// cannot be replayed as any other AWN message.
    pub fn party_signing_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        let value = serde_json::json!({
            "v": PARTY_MESSAGE_VERSION,
            "seedId": self.seed_id.to_hex(),
            "index": self.index,
            "head": self.head.to_hex(),
            "cumulative": self.cumulative.to_string(),
            "ts": self.timestamp.timestamp(),
            "witnessSet": { "said": self.witness_set.said, "threshold": self.witness_set.threshold },
        });
        canonical_bytes(&value)
    }

    /// The canonical bytes each witness cosigns (the whole tuple, including the
    /// party signature — a cosignature attests the party authorized this exact
    /// anchor).
    pub fn cosign_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        let value = serde_json::json!({
            "v": COSIGN_MESSAGE_VERSION,
            "seedId": self.seed_id.to_hex(),
            "index": self.index,
            "head": self.head.to_hex(),
            "cumulative": self.cumulative.to_string(),
            "ts": self.timestamp.timestamp(),
            "witnessSet": { "said": self.witness_set.said, "threshold": self.witness_set.threshold },
            "sigParty": {
                "curve": self.sig_party.curve.to_string(),
                "publicKey": hex::encode(&self.sig_party.public_key),
                "signature": hex::encode(&self.sig_party.signature),
            },
        });
        canonical_bytes(&value)
    }
}

/// A finalized anchor: an [`Anchor`] with ≥ `t` distinct co-signatures from its
/// declared witness set plus each cosigner's log-inclusion proof. Offline- and
/// by-value-checkable exactly like a treasury proof (D5, I-VERIFY-1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedAnchor {
    /// The finalized tuple.
    pub anchor: Anchor,
    /// The resolved declared set (its `said` must match `anchor.witness_set`).
    pub witness_set: WitnessSet,
    /// Witness cosignatures over [`Anchor::cosign_bytes`]. Reuses the shipped
    /// transparency cosignature container.
    pub cosignatures: Vec<auths_transparency::WitnessCosignature>,
    /// Per-cosigner inclusion proof that the anchor leaf is in that witness's
    /// append-only log.
    pub inclusion: Vec<auths_transparency::InclusionProof>,
}

/// RFC-8785 canonicalize a JSON value into signing bytes.
fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, AnchorError> {
    json_canon::to_string(value)
        .map(String::into_bytes)
        .map_err(|e| AnchorError::Canonicalization(e.to_string()))
}

/// Decode a lowercase-hex string that must be exactly 32 bytes.
fn decode_hex32(s: &str) -> Result<[u8; 32], AnchorError> {
    let raw = hex::decode(s).map_err(|e| AnchorError::Encoding(e.to_string()))?;
    let got = raw.len();
    raw.try_into().map_err(|_| AnchorError::BadLength { got })
}

/// Serde helper: `Vec<u8>` as a lowercase-hex string.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_id_is_deterministic_and_domain_separated() {
        let a = SeedId::derive("root", "agent", "seal");
        let b = SeedId::derive("root", "agent", "seal");
        assert_eq!(a, b);
        // Field-boundary framing: "ro"+"otagentseal" must not collide with
        // "root"+"agent"+"seal".
        let c = SeedId::derive("ro", "otagent", "seal");
        assert_ne!(a, c);
    }

    #[test]
    fn seed_id_hex_round_trips() {
        let s = SeedId::derive("root", "agent", "seal");
        assert_eq!(SeedId::from_hex(&s.to_hex()).unwrap(), s);
    }

    #[test]
    fn head_rejects_wrong_length() {
        let err = Head::from_hex(&hex::encode([0u8; 16])).unwrap_err();
        assert!(matches!(err, AnchorError::BadLength { got: 16 }));
    }

    #[test]
    fn party_and_cosign_messages_differ_by_domain() {
        let anchor = super::super::test_support::sample_anchor(1);
        let party = anchor.party_signing_bytes().unwrap();
        let cosign = anchor.cosign_bytes().unwrap();
        assert_ne!(party, cosign);
        assert!(String::from_utf8_lossy(&party).contains(PARTY_MESSAGE_VERSION));
        assert!(String::from_utf8_lossy(&cosign).contains(COSIGN_MESSAGE_VERSION));
    }
}
