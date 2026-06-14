//! `did:webs` DID-document projection of a resolved KERI key-state.
//!
//! `did:webs` anchors a KERI AID into a **web-resolvable** DID document so a
//! standard DID resolver can verify the identifier without speaking KERI itself.
//! The document is *derived*, not authored: every field comes from replaying the
//! KEL into a [`KeyState`], so the verification material is exactly the AID's
//! current signing keys. The KEL remains the source of truth; this is its
//! projection into the DID-core data model.
//!
//! Wire shape (the resolved `didDocument`, ToIP did:webs method):
//! `{id, verificationMethod, service, alsoKnownAs}` — field order and labels
//! match the reference resolver (`did-webs-resolver`'s `gen_did_document`), so a
//! document auths emits reads in a stock did:webs/DID-core resolver.
//!
//! - `id` is `did:webs:<domain>:<aid>` (the AID is the resolved prefix).
//! - each current signing key becomes one `JsonWebKey` verification method whose
//!   fragment is the key's own CESR value (`#DAAB…`), controller is the document
//!   `id`, and `publicKeyJwk` carries the curve-correct JWK (`OKP`/`Ed25519` for
//!   Ed25519, `EC`/`P-256` for P-256) — the byte-exact form the reference emits.
//! - `alsoKnownAs` carries the `did:keri:<aid>` equivalent, the cross-method link
//!   that lets a resolver fall back to native KERI resolution.
//!
//! It is a *parsed* type: building one from a [`KeyState`] cannot fail to be
//! well-formed (a resolved key-state already names valid current keys), and a
//! verification method is constructed only from a decoded [`KeriPublicKey`], so a
//! malformed key is rejected at the boundary rather than serialized into a
//! document.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::keys::{KeriDecodeError, KeriPublicKey};
use crate::state::KeyState;
use crate::types::CesrKey;

/// A public key projected into the JOSE JWK shape a DID-core `publicKeyJwk`
/// carries. Curve-tagged so a resolver picks the right verification algorithm:
/// Ed25519 is an `OKP` key (`x` only), P-256 is an `EC` key (`x` and `y`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum PublicKeyJwk {
    /// Edwards-curve octet key pair (Ed25519): `{kty:"OKP", crv:"Ed25519", x}`.
    #[serde(rename = "OKP")]
    Okp {
        /// JWK key id — the key's CESR-qualified value (`kid`).
        kid: String,
        /// Curve name — always `"Ed25519"` for this variant.
        crv: String,
        /// base64url(no-pad) of the 32 raw public-key bytes.
        x: String,
    },
    /// Elliptic-curve key (P-256): `{kty:"EC", crv:"P-256", x, y}`.
    #[serde(rename = "EC")]
    Ec {
        /// JWK key id — the key's CESR-qualified value (`kid`).
        kid: String,
        /// Curve name — always `"P-256"` for this variant.
        crv: String,
        /// base64url(no-pad) of the 32-byte affine x-coordinate.
        x: String,
        /// base64url(no-pad) of the 32-byte affine y-coordinate.
        y: String,
    },
}

impl PublicKeyJwk {
    /// Project a decoded KERI public key into its JWK, tagged `kid` with the
    /// key's own CESR value.
    ///
    /// Ed25519 maps to an `OKP` key over the 32 raw bytes; P-256 maps to an `EC`
    /// key whose `x`/`y` are the affine coordinates recovered by decompressing the
    /// SEC1 point. Returns [`KeriDecodeError::DecodeError`] only if a P-256 point
    /// fails to decompress (not a valid curve point) — Ed25519 is infallible.
    pub fn from_key(key: &KeriPublicKey, kid: &str) -> Result<Self, KeriDecodeError> {
        match key {
            KeriPublicKey::Ed25519 { key: raw, .. } => Ok(Self::Okp {
                kid: kid.to_string(),
                crv: "Ed25519".to_string(),
                x: URL_SAFE_NO_PAD.encode(raw),
            }),
            KeriPublicKey::P256 {
                key: compressed, ..
            } => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                // Decompress the SEC1 point and re-encode uncompressed to read
                // both affine coordinates the EC JWK needs.
                let pk = p256::PublicKey::from_sec1_bytes(compressed).map_err(|e| {
                    KeriDecodeError::DecodeError(format!("P-256 point decode failed: {e}"))
                })?;
                let uncompressed = pk.to_encoded_point(false);
                let x = uncompressed.x().ok_or_else(|| {
                    KeriDecodeError::DecodeError("P-256 point has no x-coordinate".to_string())
                })?;
                let y = uncompressed.y().ok_or_else(|| {
                    KeriDecodeError::DecodeError("P-256 point has no y-coordinate".to_string())
                })?;
                Ok(Self::Ec {
                    kid: kid.to_string(),
                    crv: "P-256".to_string(),
                    x: URL_SAFE_NO_PAD.encode(x),
                    y: URL_SAFE_NO_PAD.encode(y),
                })
            }
        }
    }
}

/// A single DID-core verification method projecting one current signing key.
///
/// The fragment (`id`) is the key's own CESR value, so the verification method is
/// self-identifying across a rotation: a resolver references the exact key that
/// signed, not a positional `#key-0` that shifts when keys rotate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID-relative fragment `#<key-cesr>` (the key's own CESR value).
    pub id: String,
    /// Verification-method type — `"JsonWebKey"` (the curve lives in `publicKeyJwk`).
    #[serde(rename = "type")]
    pub type_: String,
    /// The controlling DID (the document `id`).
    pub controller: String,
    /// The public key in JWK form.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicKeyJwk,
}

/// The resolved `did:webs` DID document for a KERI AID.
///
/// Field order and labels match the ToIP did:webs reference resolver's
/// `gen_did_document` (`{id, verificationMethod, service, alsoKnownAs}`), so the
/// emitted JSON reads byte-compatibly in a stock did:webs/DID-core resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebsDocument {
    /// The DID this document describes: `did:webs:<domain>:<aid>`.
    pub id: String,
    /// One verification method per current signing key.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Service endpoints (KERI agent/witness URLs). Empty for a KEL-only
    /// projection that has no live endpoint advertisement.
    pub service: Vec<serde_json::Value>,
    /// Designated equivalent identifiers — carries the `did:keri:<aid>` link so a
    /// resolver can fall back to native KERI resolution of the same AID.
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
}

impl DidWebsDocument {
    /// Build a `did:webs` DID document by projecting a resolved key-state onto the
    /// given web `domain`.
    ///
    /// `domain` is the host (and optional `:port`/path) the document will be
    /// served under; the AID is `state.prefix`. Every current signing key in
    /// `state` becomes one verification method. Returns
    /// [`KeriDecodeError`] only if a current key is undecodable or (for P-256) not
    /// a valid curve point — invalidity caught at the boundary, never serialized.
    ///
    /// Args:
    /// * `state`: The resolved current [`KeyState`] (from KEL replay).
    /// * `domain`: The web domain/host the `did:webs` is anchored at.
    pub fn from_key_state(state: &KeyState, domain: &str) -> Result<Self, KeriDecodeError> {
        let aid = state.prefix.as_str();
        let id = format!("did:webs:{domain}:{aid}");

        let mut verification_method = Vec::with_capacity(state.current_keys.len());
        for cesr_key in &state.current_keys {
            verification_method.push(verification_method_for(cesr_key, &id)?);
        }

        Ok(Self {
            id,
            verification_method,
            service: Vec::new(),
            also_known_as: vec![format!("did:keri:{aid}")],
        })
    }
}

/// Build one verification method from a current key's CESR string, controlled by
/// `did`. The key is decoded first (parse, don't validate), so the JWK is built
/// only from a known curve and valid bytes.
fn verification_method_for(
    cesr_key: &CesrKey,
    did: &str,
) -> Result<VerificationMethod, KeriDecodeError> {
    let kid = cesr_key.as_str();
    let key = KeriPublicKey::parse(kid)?;
    Ok(VerificationMethod {
        id: format!("#{kid}"),
        type_: "JsonWebKey".to_string(),
        controller: did.to_string(),
        public_key_jwk: PublicKeyJwk::from_key(&key, kid)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{Prefix, Said, Threshold};

    /// A single-key Ed25519 key-state at the given AID/key.
    fn ed25519_state(aid: &str, key_cesr: &str) -> KeyState {
        KeyState::from_inception(
            Prefix::new_unchecked(aid.to_string()),
            vec![CesrKey::new_unchecked(key_cesr.to_string())],
            vec![Said::new_unchecked("ENext0".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked(aid.to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        )
    }

    /// The CESR-qualified Ed25519 verkey over `raw`.
    fn ed25519_cesr(raw: &[u8; 32]) -> String {
        KeriPublicKey::ed25519(raw).unwrap().to_qb64().unwrap()
    }

    /// The CESR-qualified P-256 verkey over a real keypair's compressed point.
    fn p256_cesr() -> (String, [u8; 33]) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        // Deterministic non-identity scalar → a valid curve point.
        let sk = p256::SecretKey::from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
        .unwrap();
        let pt = sk.public_key().to_encoded_point(true);
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(pt.as_bytes());
        let cesr = KeriPublicKey::P256 {
            key: compressed,
            transferable: true,
        }
        .to_qb64()
        .unwrap();
        (cesr, compressed)
    }

    #[test]
    fn document_has_canonical_field_order() {
        let key = ed25519_cesr(&[3u8; 32]);
        let state = ed25519_state("EAid000000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();

        let json = serde_json::to_value(&doc).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // Reference resolver `gen_did_document` order: id, verificationMethod, service, alsoKnownAs.
        assert_eq!(
            keys,
            vec!["id", "verificationMethod", "service", "alsoKnownAs"]
        );
    }

    #[test]
    fn ed25519_verification_method_matches_reference_shape() {
        let key = ed25519_cesr(&[7u8; 32]);
        let state = ed25519_state("EAid000000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();

        assert_eq!(
            doc.id,
            "did:webs:example.com:EAid000000000000000000000000000000000000000"
        );
        assert_eq!(
            doc.also_known_as,
            vec!["did:keri:EAid000000000000000000000000000000000000000"]
        );
        assert!(doc.service.is_empty());

        let vm = &doc.verification_method[0];
        // Fragment is the key's OWN cesr value, not a positional #key-0.
        assert_eq!(vm.id, format!("#{key}"));
        assert_eq!(vm.type_, "JsonWebKey");
        assert_eq!(vm.controller, doc.id);
        match &vm.public_key_jwk {
            PublicKeyJwk::Okp { kid, crv, x } => {
                assert_eq!(kid, &key);
                assert_eq!(crv, "Ed25519");
                // x is base64url(no-pad) of the 32 raw bytes.
                assert_eq!(x, &URL_SAFE_NO_PAD.encode([7u8; 32]));
            }
            other => panic!("expected OKP JWK, got {other:?}"),
        }
    }

    #[test]
    fn ed25519_jwk_serializes_kty_first() {
        // `#[serde(tag = "kty")]` puts kty at the front, then the variant fields —
        // {kty, kid, crv, x}, the reference publicKeyJwk shape.
        let key = ed25519_cesr(&[1u8; 32]);
        let state = ed25519_state("EAid000000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();
        let jwk = serde_json::to_value(&doc.verification_method[0].public_key_jwk).unwrap();
        let labels: Vec<&str> = jwk
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(labels, vec!["kty", "kid", "crv", "x"]);
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
    }

    #[test]
    fn p256_verification_method_emits_ec_jwk_with_x_and_y() {
        let (key, compressed) = p256_cesr();
        let state = ed25519_state("EAidP256000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();

        let vm = &doc.verification_method[0];
        assert_eq!(vm.id, format!("#{key}"));
        match &vm.public_key_jwk {
            PublicKeyJwk::Ec { kid, crv, x, y } => {
                assert_eq!(kid, &key);
                assert_eq!(crv, "P-256");
                // x is the 32-byte affine x; for a compressed point that is bytes 1..33.
                assert_eq!(x, &URL_SAFE_NO_PAD.encode(&compressed[1..33]));
                // y is recovered by decompression — 32 bytes, present and non-empty.
                assert_eq!(URL_SAFE_NO_PAD.decode(y).unwrap().len(), 32);
            }
            other => panic!("expected EC JWK, got {other:?}"),
        }
    }

    #[test]
    fn multisig_emits_one_method_per_key() {
        let k1 = ed25519_cesr(&[1u8; 32]);
        let k2 = ed25519_cesr(&[2u8; 32]);
        let mut state = ed25519_state("EAid000000000000000000000000000000000000000", &k1);
        state.current_keys.push(CesrKey::new_unchecked(k2.clone()));
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.verification_method[0].id, format!("#{k1}"));
        assert_eq!(doc.verification_method[1].id, format!("#{k2}"));
    }

    #[test]
    fn domain_with_port_and_path_is_preserved() {
        // did:webs allows host%3Aport and path segments before the AID.
        let key = ed25519_cesr(&[5u8; 32]);
        let state = ed25519_state("EAid000000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com%3A3901:dids").unwrap();
        assert_eq!(
            doc.id,
            "did:webs:example.com%3A3901:dids:EAid000000000000000000000000000000000000000"
        );
        assert_eq!(doc.verification_method[0].controller, doc.id);
    }

    #[test]
    fn undecodable_key_is_rejected_at_the_boundary() {
        let mut state = ed25519_state("EAid000000000000000000000000000000000000000", "Dvalid");
        state.current_keys = vec![CesrKey::new_unchecked("Xnot-a-verkey".to_string())];
        assert!(DidWebsDocument::from_key_state(&state, "example.com").is_err());
    }

    #[test]
    fn document_round_trips_through_json() {
        let key = ed25519_cesr(&[9u8; 32]);
        let state = ed25519_state("EAid000000000000000000000000000000000000000", &key);
        let doc = DidWebsDocument::from_key_state(&state, "example.com").unwrap();
        let wire = serde_json::to_string(&doc).unwrap();
        let parsed: DidWebsDocument = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, doc);
    }
}
