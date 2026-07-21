//! Declaring the spend-anchor witness set in the identity's KEL (I-TRUST-3).
//!
//! A relying party may only hold a `t`-of-`N` quorum to a witness set the
//! party provably committed to. The commitment is one `ixn` on the identity's
//! own KEL anchoring the set's content SAID
//! ([`auths_anchor::WitnessSet::computed_said`]) as a digest seal. Verifiers
//! resolve that seal independently ([`auths_anchor::find_witness_set_seal`])
//! and refuse any anchor whose set the KEL never declared — closing the
//! circularity of a set that only the anchor itself asserts.

use std::str::FromStr;

use auths_anchor::{AnchorError, WitnessRef, WitnessSet};
use auths_core::storage::keychain::{KeyAlias, KeyRole, extract_public_key_bytes};
use auths_crypto::CurveType;
use auths_id::error::InitError;
use auths_id::keri::delegation::author_root_anchor_ixn;
use auths_id::keri::parse_did_keri;
use auths_keri::{Said, Seal};
use thiserror::Error;

use crate::context::AuthsContext;

/// Errors from witness-set declaration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WitnessSetError {
    /// A member spec could not be parsed into a witness reference.
    #[error("invalid witness member spec {spec:?}: {reason}")]
    InvalidMemberSpec {
        /// The spec as supplied.
        spec: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The assembled set fails structural validation or cannot be saidified.
    #[error("witness set rejected: {0}")]
    Set(#[source] AnchorError),

    /// No managed identity exists to anchor the declaration under.
    #[error("no managed identity to declare a witness set under: {0}")]
    NoIdentity(String),

    /// The identity signing key could not be resolved or read.
    #[error("identity signing key unavailable: {0}")]
    Key(#[source] auths_core::AgentError),

    /// Authoring the anchoring `ixn` failed.
    #[error("anchoring the witness-set declaration failed: {0}")]
    Anchor(#[source] InitError),
}

/// The result of anchoring a witness-set declaration in the identity's KEL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredWitnessSet {
    /// The declared set's content SAID — what verifiers resolve from the KEL.
    pub set_said: String,
    /// The SAID of the anchoring `ixn`.
    pub ixn_said: String,
    /// The anchoring `ixn`'s KEL sequence number.
    pub sequence: u128,
}

/// Parse one witness-member spec of the form `NAME=KEY`.
///
/// `KEY` carries its curve in-band, in any of the accepted forms: a
/// CESR-qualified verkey, a `did:key:`, or `<curve>:<hex>` naming the curve
/// explicitly (the same spellings [`CurveType`] parses). Bare hex is accepted
/// as Ed25519 because witness cosignatures and log checkpoints pin that curve
/// today (the signed-note format) — an untagged member key can only be the
/// checkpoint-signing curve. The decoded key length must match the tagged
/// curve, so a mis-tagged key is refused at parse time as a routing error,
/// never mis-verified later as a bad signature.
///
/// Args:
/// * `spec`: the member spec, e.g. `w1=1AAI…`, `w1=did:key:z…`, or `w1=<hex>`.
///
/// Usage:
/// ```ignore
/// let member = parse_witness_member("network=did:key:z6Mk...")?;
/// ```
pub fn parse_witness_member(spec: &str) -> Result<WitnessRef, WitnessSetError> {
    let invalid = |reason: String| WitnessSetError::InvalidMemberSpec {
        spec: spec.to_string(),
        reason,
    };
    let (name, key) = spec
        .split_once('=')
        .ok_or_else(|| invalid("expected `NAME=KEY`".to_string()))?;
    let name = name.trim();
    let key = key.trim();
    if name.is_empty() {
        return Err(invalid("empty member name".to_string()));
    }
    let (curve, public_key) = decode_member_key(key).map_err(invalid)?;
    if public_key.len() != curve.public_key_len() {
        return Err(invalid(format!(
            "a {curve} key is {} bytes, got {}",
            curve.public_key_len(),
            public_key.len()
        )));
    }
    Ok(WitnessRef {
        name: name.to_string(),
        curve,
        public_key,
        operator: None,
    })
}

/// Decode a member key with its in-band curve tag: CESR verkey, `did:key:`,
/// `<curve>:<hex>`, or bare hex (Ed25519 — the checkpoint-signing curve).
fn decode_member_key(key: &str) -> Result<(CurveType, Vec<u8>), String> {
    if let Ok(parsed) = auths_keri::KeriPublicKey::parse(key) {
        return Ok((parsed.curve(), parsed.raw_bytes().to_vec()));
    }
    if key.starts_with("did:key:") {
        let decoded = auths_crypto::did_key_decode(key).map_err(|e| e.to_string())?;
        return Ok((decoded.curve(), decoded.bytes().to_vec()));
    }
    if let Some((tag, hex_part)) = key.split_once(':') {
        let curve = CurveType::from_str(tag).map_err(|e| e.to_string())?;
        let bytes = hex::decode(hex_part).map_err(|e| format!("hex key: {e}"))?;
        return Ok((curve, bytes));
    }
    let bytes = hex::decode(key).map_err(|_| {
        "expected a CESR verkey, a did:key, `<curve>:<hex>`, or bare hex".to_string()
    })?;
    Ok((CurveType::Ed25519, bytes))
}

/// Assemble a validated, self-addressed witness set from member specs.
///
/// Args:
/// * `member_specs`: `NAME=KEY` specs ([`parse_witness_member`]).
/// * `threshold`: the finalization threshold `t` of the `t`-of-`N` set.
///
/// Usage:
/// ```ignore
/// let set = build_witness_set(&specs, 2)?;
/// println!("{}", set.said);
/// ```
pub fn build_witness_set(
    member_specs: &[String],
    threshold: u32,
) -> Result<WitnessSet, WitnessSetError> {
    let members = member_specs
        .iter()
        .map(|spec| parse_witness_member(spec))
        .collect::<Result<Vec<_>, _>>()?;
    let mut set = WitnessSet {
        said: String::new(),
        threshold,
        members,
    };
    set.validate().map_err(WitnessSetError::Set)?;
    set.said = set.computed_said().map_err(WitnessSetError::Set)?;
    Ok(set)
}

/// Resolve the signing alias for a declaration: the explicit alias when given,
/// else the managed identity's Primary keychain alias.
///
/// Args:
/// * `ctx`: Auths context (identity storage + keychain).
/// * `explicit`: an alias the caller named, if any.
///
/// Usage:
/// ```ignore
/// let alias = resolve_declaration_alias(&ctx, args.key)?;
/// ```
pub fn resolve_declaration_alias(
    ctx: &AuthsContext,
    explicit: Option<String>,
) -> Result<KeyAlias, WitnessSetError> {
    if let Some(alias) = explicit {
        return Ok(KeyAlias::new_unchecked(alias));
    }
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| WitnessSetError::NoIdentity(e.to_string()))?;
    let primaries = ctx
        .key_storage
        .list_aliases_for_identity_with_role(&managed.controller_did, KeyRole::Primary)
        .map_err(WitnessSetError::Key)?;
    primaries.into_iter().next().ok_or_else(|| {
        WitnessSetError::NoIdentity(format!(
            "no primary signing key in the keychain for {}",
            managed.controller_did
        ))
    })
}

/// Declare a witness set: validate it, compute its content SAID, and author
/// one `ixn` on the managed identity's KEL anchoring that SAID as a digest
/// seal, signed by the identity's current key. The commit is immediate.
///
/// Args:
/// * `ctx`: Auths context (registry, keychain, identity storage, passphrase).
/// * `key_alias`: keychain alias of the identity's signing key.
/// * `set`: the witness set to declare ([`build_witness_set`]).
///
/// Usage:
/// ```ignore
/// let set = build_witness_set(&specs, 2)?;
/// let declared = declare_witness_set(&ctx, &alias, &set)?;
/// println!("anchored {} at ixn {}", declared.set_said, declared.ixn_said);
/// ```
pub fn declare_witness_set(
    ctx: &AuthsContext,
    key_alias: &KeyAlias,
    set: &WitnessSet,
) -> Result<DeclaredWitnessSet, WitnessSetError> {
    set.validate().map_err(WitnessSetError::Set)?;
    let set_said = set.computed_said().map_err(WitnessSetError::Set)?;

    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| WitnessSetError::NoIdentity(e.to_string()))?;
    let root_prefix = parse_did_keri(&managed.controller_did.to_string())
        .map_err(|e| WitnessSetError::NoIdentity(e.to_string()))?;
    let (_public_key, curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        key_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(WitnessSetError::Key)?;

    let ixn = author_root_anchor_ixn(
        ctx.registry.as_ref(),
        &root_prefix,
        key_alias,
        curve,
        vec![Seal::Digest {
            d: Said::new_unchecked(set_said.clone()),
        }],
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(WitnessSetError::Anchor)?;

    Ok(DeclaredWitnessSet {
        set_said,
        ixn_said: ixn.d.as_str().to_string(),
        sequence: ixn.s.value(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_key(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    #[test]
    fn bare_hex_member_defaults_to_the_checkpoint_curve() {
        let member = parse_witness_member(&format!("w1={}", hex_key(1, 32))).unwrap();
        assert_eq!(member.name, "w1");
        assert_eq!(member.curve, CurveType::Ed25519);
        assert_eq!(member.public_key, vec![1u8; 32]);
    }

    #[test]
    fn curve_tagged_hex_member_parses() {
        let ed = parse_witness_member(&format!("w1=ed25519:{}", hex_key(2, 32))).unwrap();
        assert_eq!(ed.curve, CurveType::Ed25519);
        let p = parse_witness_member(&format!("w2=p256:{}", hex_key(3, 33))).unwrap();
        assert_eq!(p.curve, CurveType::P256);
    }

    #[test]
    fn wrong_length_for_the_tagged_curve_is_refused() {
        let err = parse_witness_member(&format!("w1=ed25519:{}", hex_key(2, 33))).unwrap_err();
        assert!(matches!(err, WitnessSetError::InvalidMemberSpec { .. }));
        let err = parse_witness_member(&format!("w1={}", hex_key(2, 16))).unwrap_err();
        assert!(matches!(err, WitnessSetError::InvalidMemberSpec { .. }));
    }

    #[test]
    fn missing_equals_and_empty_name_are_refused() {
        assert!(matches!(
            parse_witness_member("just-a-name"),
            Err(WitnessSetError::InvalidMemberSpec { .. })
        ));
        assert!(matches!(
            parse_witness_member(&format!("={}", hex_key(1, 32))),
            Err(WitnessSetError::InvalidMemberSpec { .. })
        ));
    }

    #[test]
    fn unknown_curve_tag_is_refused_not_defaulted() {
        assert!(matches!(
            parse_witness_member(&format!("w1=ed448:{}", hex_key(1, 57))),
            Err(WitnessSetError::InvalidMemberSpec { .. })
        ));
    }

    #[test]
    fn computed_said_is_stable_across_member_order() {
        let a = build_witness_set(
            &[
                format!("w1={}", hex_key(1, 32)),
                format!("w2={}", hex_key(2, 32)),
            ],
            2,
        )
        .unwrap();
        let b = build_witness_set(
            &[
                format!("w2={}", hex_key(2, 32)),
                format!("w1={}", hex_key(1, 32)),
            ],
            2,
        )
        .unwrap();
        assert_eq!(a.said, b.said);
        assert!(a.said.starts_with('E'));
    }

    #[test]
    fn different_content_yields_a_different_said() {
        let a = build_witness_set(&[format!("w1={}", hex_key(1, 32))], 1).unwrap();
        let b = build_witness_set(&[format!("w1={}", hex_key(9, 32))], 1).unwrap();
        let c = build_witness_set(
            &[
                format!("w1={}", hex_key(1, 32)),
                format!("w2={}", hex_key(2, 32)),
            ],
            1,
        )
        .unwrap();
        assert_ne!(a.said, b.said);
        assert_ne!(a.said, c.said);
    }

    #[test]
    fn structural_violations_are_refused() {
        let dup = build_witness_set(
            &[
                format!("w1={}", hex_key(1, 32)),
                format!("w1={}", hex_key(2, 32)),
            ],
            1,
        );
        assert!(matches!(dup, Err(WitnessSetError::Set(_))));
        let over = build_witness_set(&[format!("w1={}", hex_key(1, 32))], 2);
        assert!(matches!(over, Err(WitnessSetError::Set(_))));
    }
}
