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

    /// Structural validity: at least one member, unique names, unique keys,
    /// `1 ≤ threshold ≤ members.len()`. A set failing any of these can make
    /// [`Self::member`] resolve the wrong key or a threshold unreachable, so
    /// verification refuses it before trusting anything it declares.
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.members.is_empty() {
            return Err(AnchorError::SetInvalid("no members".into()));
        }
        if self.threshold == 0 || self.threshold as usize > self.members.len() {
            return Err(AnchorError::SetInvalid(format!(
                "threshold {} outside 1..={}",
                self.threshold,
                self.members.len()
            )));
        }
        let mut names: Vec<&str> = self.members.iter().map(|m| m.name.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|w| w[0] == w[1]) {
            return Err(AnchorError::SetInvalid("duplicate member name".into()));
        }
        let mut keys: Vec<&[u8]> = self
            .members
            .iter()
            .map(|m| m.public_key.as_slice())
            .collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(AnchorError::SetInvalid("duplicate member key".into()));
        }
        Ok(())
    }

    /// The self-addressing identifier of this set's content.
    ///
    /// Canonical form: members sorted by name, each as
    /// `{name, publicKey, operator?}`, plus the threshold, saidified with the
    /// shipped section-SAID primitive (Blake3-256, CESR-encoded — the same
    /// digest KELs use). A verifier recomputes this and compares it to the
    /// SAID the anchor commits to; a set whose content does not hash to its
    /// claimed SAID proves nothing.
    ///
    /// Usage:
    /// ```ignore
    /// let said = set.computed_said()?;
    /// if said != anchor.witness_set.said { /* refuse */ }
    /// ```
    pub fn computed_said(&self) -> Result<String, AnchorError> {
        let mut members = self.members.clone();
        members.sort_by(|a, b| a.name.cmp(&b.name));
        let members_json: Vec<serde_json::Value> = members
            .iter()
            .map(|m| {
                let mut obj = serde_json::Map::new();
                obj.insert("name".into(), serde_json::Value::String(m.name.clone()));
                obj.insert(
                    "publicKey".into(),
                    serde_json::Value::String(hex::encode(&m.public_key)),
                );
                if let Some(op) = &m.operator {
                    obj.insert(
                        "operator".into(),
                        serde_json::json!({
                            "operator": op.operator,
                            "organization": op.organization,
                            "jurisdiction": op.jurisdiction,
                            "infrastructure": op.infrastructure,
                        }),
                    );
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        let section = serde_json::json!({
            "d": "",
            "kind": "auths-anchor/witness-set/v1",
            "threshold": self.threshold,
            "members": members_json,
        });
        let said = auths_keri::compute_section_said(&section)
            .map_err(|e| AnchorError::Canonicalization(e.to_string()))?;
        Ok(said.to_string())
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
    /// Whole-second precision only: signing bytes commit to seconds, so a
    /// sub-second wire value would be malleable without invalidating the
    /// signature. Deserialization truncates; the acceptance rule refuses any
    /// in-process value that still carries sub-second precision.
    #[serde(with = "ts_seconds")]
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

/// One cosigner's proof that it logged the anchor: the witness's *signed*
/// checkpoint plus a Merkle inclusion proof rooted in that checkpoint.
///
/// A bare inclusion proof against a self-stated root proves membership in
/// *some* tree anyone could build; only a root inside a checkpoint signed by
/// the declared member key ties the anchor to that witness's append-only log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedInclusion {
    /// The cosigning witness this inclusion belongs to (a declared member name).
    #[serde(rename = "witnessName")]
    pub witness_name: String,
    /// The witness's signed log checkpoint. Its signature is verified under the
    /// declared member key — never the key the checkpoint itself carries.
    pub checkpoint: auths_transparency::SignedCheckpoint,
    /// Inclusion of the anchor leaf, rooted in `checkpoint`'s root.
    pub proof: auths_transparency::InclusionProof,
}

/// A finalized anchor: an [`Anchor`] with ≥ `t` distinct co-signatures from its
/// declared witness set plus each counted cosigner's logged inclusion.
/// Offline- and by-value-checkable exactly like a treasury proof (D5,
/// I-VERIFY-1) — with the declared set proven self-addressing before any of
/// its keys are trusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedAnchor {
    /// The finalized tuple.
    pub anchor: Anchor,
    /// The resolved declared set. Its content must hash to the SAID the anchor
    /// commits to ([`WitnessSet::computed_said`]).
    pub witness_set: WitnessSet,
    /// Witness cosignatures over [`Anchor::cosign_bytes`]. Reuses the shipped
    /// transparency cosignature container.
    pub cosignatures: Vec<auths_transparency::WitnessCosignature>,
    /// Per-cosigner logged inclusion; a cosigner without one is not counted
    /// toward the threshold.
    pub inclusion: Vec<LoggedInclusion>,
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

/// Serde helper: an RFC-3339 timestamp truncated to whole seconds on both
/// directions, so sub-second precision is unrepresentable on the wire and the
/// serialized form always matches what the signature commits to.
mod ts_seconds {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        let parsed = DateTime::parse_from_rfc3339(&raw).map_err(serde::de::Error::custom)?;
        let secs = parsed.timestamp();
        DateTime::<Utc>::from_timestamp(secs, 0)
            .ok_or_else(|| serde::de::Error::custom("timestamp out of range"))
    }
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
