//! Witness conformance harness (E3).
//!
//! A black-box conformance suite for any AWN witness's *accept* surface. It
//! builds a canonical set of vectors — monotone accept, a duplicity fork, a
//! non-monotone rejection, and the freshness ladder — and checks the shipped
//! protocol core satisfies every one. The vectors can be emitted as JSON so a
//! third-party witness (a regulator's non-Auths node) can drive its own
//! `POST /v1/anchor` endpoint through the identical suite and claim conformance
//! — answering "who may join a witness set" with a test, not a document.
//!
//! Threshold-finalization and inclusion-proof conformance are the *verifier*
//! contract, exercised by the `auths-anchor` invariant battery
//! (`i_final_1_threshold_enforced`, `i_final_2_cosigner_must_be_in_declared_set`).

use std::path::Path;

use anyhow::{bail, Context, Result};
use auths_anchor::{
    accept_anchor, freshness, Acceptance, Anchor, ControllerKeys, CurrentKey, CurveType, Head,
    PartySignature, SeedId, WitnessSetRef,
};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000, 0).single().unwrap()
}

fn party_sk() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn signed_anchor(index: u64, head: [u8; 32]) -> Anchor {
    let sk = party_sk();
    let mut anchor = Anchor {
        seed_id: SeedId::derive("did:keri:root", "did:keri:agent", "ESeal"),
        index,
        head: Head::from_bytes(head),
        cumulative: index as u128 * 100,
        timestamp: Utc
            .timestamp_opt(1_700_000_000 + index as i64, 0)
            .single()
            .unwrap(),
        witness_set: WitnessSetRef {
            said: "EWitSet".into(),
            threshold: 2,
        },
        sig_party: PartySignature {
            curve: CurveType::Ed25519,
            public_key: sk.verifying_key().as_bytes().to_vec(),
            signature: Vec::new(),
        },
    };
    let message = anchor.party_signing_bytes().expect("party signing bytes");
    anchor.sig_party.signature = sk.sign(&message).to_bytes().to_vec();
    anchor
}

fn keys() -> ControllerKeys {
    // Build the key outside `vec![]`: the curve-agnostic AST lint can't see a
    // scoped `CurveType::` path inside a macro token tree.
    let current_key = CurrentKey {
        curve: CurveType::Ed25519,
        public_key: party_sk().verifying_key().as_bytes().to_vec(),
    };
    ControllerKeys {
        current: vec![current_key],
    }
}

/// Run the conformance suite against the shipped protocol core, optionally
/// writing the vectors to `emit_dir` for third-party witnesses to reuse.
///
/// Args:
/// * `emit_dir`: when `Some`, a directory to write `conformance-vectors.json` to.
pub fn run(emit_dir: Option<&Path>) -> Result<()> {
    let prior = signed_anchor(1, [1u8; 32]);
    let next = signed_anchor(2, [2u8; 32]);
    let fork = signed_anchor(1, [9u8; 32]);
    let mut passed = 0u32;

    // Monotone accept: a well-ordered successor is co-signed.
    match accept_anchor(&next, &keys(), Some(&prior), now())? {
        Acceptance::CoSign(_) => passed += 1,
        Acceptance::Duplicity(_) => bail!("monotone accept: expected co-sign, got duplicity"),
    }

    // Duplicity: same index, different head is refused with a verifiable proof.
    match accept_anchor(&fork, &keys(), Some(&prior), now())? {
        Acceptance::Duplicity(proof) => {
            proof
                .verify()
                .context("duplicity: emitted proof must verify offline")?;
            passed += 1;
        }
        Acceptance::CoSign(_) => bail!("duplicity: expected refusal, got co-sign"),
    }

    // Non-monotone index is rejected outright.
    if accept_anchor(&signed_anchor(1, [1u8; 32]), &keys(), Some(&next), now()).is_err() {
        passed += 1;
    } else {
        bail!("regression: expected rejection of a non-monotone index");
    }

    // Freshness ladder.
    for (result, expected) in [
        (freshness(Some(9), Some(7)), "fresh"),
        (freshness(Some(5), Some(7)), "stale"),
        (freshness(Some(5), None), "unanchored"),
    ] {
        if result.status() != expected {
            bail!("freshness: expected {expected}, got {}", result.status());
        }
    }
    passed += 1;

    if let Some(dir) = emit_dir {
        let path = dir.join("conformance-vectors.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&vector_document(&prior, &next, &fork))?,
        )
        .with_context(|| format!("writing {}", path.display()))?;
        println!("witness-conformance: wrote vectors to {}", path.display());
    }

    println!("witness-conformance: {passed}/4 vector groups passed");
    Ok(())
}

/// A machine-readable vector document a third-party witness can be driven with.
fn vector_document(prior: &Anchor, next: &Anchor, fork: &Anchor) -> serde_json::Value {
    serde_json::json!({
        "version": "witness-conformance/v1",
        "monotone_accept": { "prior": prior, "request": next, "expect": "cosign" },
        "duplicity": { "prior": prior, "request": fork, "expect": "duplicity" },
        "freshness_ladder": [
            { "bundle_index": 9, "anchor_index": 7, "expect": "fresh" },
            { "bundle_index": 5, "anchor_index": 7, "expect": "stale" },
            { "bundle_index": 5, "anchor_index": null, "expect": "unanchored" }
        ]
    })
}
