//! Deterministic fixtures for the integration battery.
//!
//! Fixed-seed keys only (no RNG) so every vector is reproducible. Signing comes
//! from the primary `ed25519-dalek`/`p256` deps; cosignature/key fixture types
//! from the `auths-verifier` dev-dep.

use auths_anchor::{
    Anchor, ControllerKeys, CurrentKey, FinalizedAnchor, Head, OperatorInfo, PartySignature,
    SeedId, WitnessRef, WitnessSet, WitnessSetRef,
};
use auths_crypto::CurveType;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};

fn party_sk() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn witness_sk(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[100u8.wrapping_add(i); 32])
}

fn ts(index: u64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + index as i64, 0).unwrap()
}

/// An Ed25519-signed anchor at `index` with the given head, threshold `t`, and
/// witness-set SAID.
pub fn signed_anchor(index: u64, head: [u8; 32], threshold: u32, said: &str) -> Anchor {
    let sk = party_sk();
    let vk = sk.verifying_key();
    let mut anchor = Anchor {
        seed_id: SeedId::derive("did:keri:root", "did:keri:agent", "ESeal"),
        index,
        head: Head::from_bytes(head),
        cumulative: index as u128 * 100,
        timestamp: ts(index),
        witness_set: WitnessSetRef {
            said: said.to_string(),
            threshold,
        },
        sig_party: PartySignature {
            curve: CurveType::Ed25519,
            public_key: vk.as_bytes().to_vec(),
            signature: Vec::new(),
        },
    };
    let message = anchor.party_signing_bytes().unwrap();
    anchor.sig_party.signature = sk.sign(&message).to_bytes().to_vec();
    anchor
}

/// A P-256-signed anchor at `index` (the other curve path).
pub fn signed_anchor_p256(index: u64) -> Anchor {
    use p256::ecdsa::{Signature, SigningKey as P256Signing, signature::Signer as _};
    let sk = P256Signing::from_bytes((&[7u8; 32]).into()).unwrap();
    let public_key = sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let mut anchor = signed_anchor(index, [1u8; 32], 2, "EWitSet");
    anchor.sig_party = PartySignature {
        curve: CurveType::P256,
        public_key,
        signature: Vec::new(),
    };
    let message = anchor.party_signing_bytes().unwrap();
    let sig: Signature = sk.sign(&message);
    anchor.sig_party.signature = sig.to_bytes().to_vec();
    anchor
}

/// The controller keys that authorize `anchor`.
pub fn controller_keys_for(anchor: &Anchor) -> ControllerKeys {
    ControllerKeys {
        current: vec![CurrentKey {
            curve: anchor.sig_party.curve,
            public_key: anchor.sig_party.public_key.clone(),
        }],
    }
}

/// A finalized anchor over `n` witnesses with threshold `t`.
///
/// The declared set is genuinely self-addressing (SAID computed from content,
/// committed into the party-signed anchor), and each cosigner carries a
/// member-signed checkpoint rooting its inclusion proof — the material a real
/// node must produce.
pub fn finalized(n: u8, threshold: u32) -> FinalizedAnchor {
    let members: Vec<WitnessRef> = (0..n)
        .map(|i| WitnessRef {
            name: format!("witness-{i}"),
            public_key: witness_sk(i).verifying_key().as_bytes().to_vec(),
            operator: Some(OperatorInfo {
                operator: format!("op-{i}"),
                organization: format!("org-{i}"),
                jurisdiction: "US".into(),
                infrastructure: format!("aws/zone-{i}"),
            }),
        })
        .collect();
    let mut witness_set = WitnessSet {
        said: String::new(),
        threshold,
        members,
    };
    witness_set.said = witness_set.computed_said().unwrap();

    let anchor = signed_anchor(1, [1u8; 32], threshold, &witness_set.said);

    let cosign_message = anchor.cosign_bytes().unwrap();
    let leaf = auths_transparency::hash_leaf(&cosign_message);
    let mut cosignatures = Vec::new();
    let mut inclusion = Vec::new();
    for i in 0..n {
        let sk = witness_sk(i);
        let sig = sk.sign(&cosign_message);
        cosignatures.push(auths_anchor::WitnessCosignature {
            witness_name: format!("witness-{i}"),
            witness_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                sk.verifying_key().to_bytes(),
            ),
            signature: auths_verifier::Ed25519Signature::from_bytes(sig.to_bytes()),
            timestamp: ts(1),
        });
        inclusion.push(logged_inclusion(&format!("witness-{i}"), &sk, leaf));
    }

    FinalizedAnchor {
        anchor,
        witness_set,
        cosignatures,
        inclusion,
    }
}

/// A member-signed checkpoint over a one-leaf log containing `leaf`, plus the
/// inclusion proof rooted in it.
pub fn logged_inclusion(
    name: &str,
    witness_key: &SigningKey,
    leaf: auths_transparency::MerkleHash,
) -> auths_anchor::LoggedInclusion {
    let hashes = auths_transparency::prove_inclusion(&[leaf], 0).unwrap();
    let root = auths_transparency::compute_root(&[leaf]);
    let checkpoint = auths_transparency::Checkpoint {
        origin: auths_transparency::LogOrigin::new(&format!("awn/{name}")).unwrap(),
        size: 1,
        root,
        timestamp: ts(1),
    };
    let log_signature = witness_key.sign(checkpoint.to_note_body().as_bytes());
    auths_anchor::LoggedInclusion {
        witness_name: name.to_string(),
        checkpoint: auths_transparency::SignedCheckpoint {
            checkpoint,
            log_signature: auths_verifier::Ed25519Signature::from_bytes(log_signature.to_bytes()),
            log_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                witness_key.verifying_key().to_bytes(),
            ),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        },
        proof: auths_anchor::InclusionProof {
            index: 0,
            size: 1,
            root,
            hashes,
        },
    }
}
