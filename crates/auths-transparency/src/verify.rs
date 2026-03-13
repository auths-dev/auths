//! Offline bundle verification logic.
//!
//! Provides [`verify_bundle`] — a synchronous, I/O-free function that verifies
//! an [`OfflineBundle`] against a [`TrustRoot`].

use chrono::{DateTime, Duration, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::bundle::{
    BundleVerificationReport, CheckpointStatus, DelegationStatus, InclusionStatus, NamespaceStatus,
    SignatureStatus, WitnessStatus,
};
use crate::checkpoint::SignedCheckpoint;
use crate::entry::{EntryBody, EntryType};
use crate::merkle::hash_leaf;
use crate::{OfflineBundle, TrustRoot};
use auths_verifier::IdentityDID;

const STALE_BUNDLE_DAYS: i64 = 90;

/// Verifies an offline transparency bundle against a trust root.
///
/// Each verification dimension (signature, inclusion, checkpoint, witnesses,
/// namespace, delegation) is evaluated independently so callers can make
/// nuanced trust decisions.
///
/// Args:
/// * `bundle` — The offline bundle to verify.
/// * `trust_root` — Trusted log public key and witness set.
/// * `now` — Current wall-clock time (injected, never read from system clock).
///
/// Usage:
/// ```ignore
/// let report = verify_bundle(&bundle, &trust_root, now);
/// if report.is_valid() {
///     // bundle is trustworthy
/// }
/// ```
pub fn verify_bundle(
    bundle: &OfflineBundle,
    trust_root: &TrustRoot,
    now: DateTime<Utc>,
) -> BundleVerificationReport {
    let signature = verify_signature(bundle);
    let inclusion = verify_inclusion_proof(bundle);
    let checkpoint = verify_checkpoint(&bundle.signed_checkpoint, trust_root);
    let witnesses = verify_witnesses(&bundle.signed_checkpoint, trust_root);
    let delegation = verify_delegation_chain(bundle);
    let namespace = derive_namespace_status(&delegation, bundle);

    let mut warnings = Vec::new();
    check_staleness(&bundle.signed_checkpoint, now, &mut warnings);

    BundleVerificationReport {
        signature,
        inclusion,
        checkpoint,
        witnesses,
        namespace,
        delegation,
        warnings,
    }
}

fn resolve_actor_public_key(bundle: &OfflineBundle) -> Option<[u8; 32]> {
    let actor_did = bundle.entry.content.actor_did.as_str();

    if actor_did.starts_with("did:key:z") {
        return auths_crypto::did_key_to_ed25519(actor_did).ok();
    }

    if actor_did.starts_with("did:keri:") {
        for link in &bundle.delegation_chain {
            if link.link_type == EntryType::DeviceBind
                && let EntryBody::DeviceBind {
                    ref device_did,
                    ref public_key,
                } = link.entry.content.body
                && device_did.as_str() == actor_did
            {
                return Some(*public_key.as_bytes());
            }
        }
    }

    None
}

fn verify_signature(bundle: &OfflineBundle) -> SignatureStatus {
    let public_key_bytes = match resolve_actor_public_key(bundle) {
        Some(pk) => pk,
        None => {
            return SignatureStatus::Failed {
                reason: format!(
                    "could not resolve public key for actor DID: {}",
                    bundle.entry.content.actor_did
                ),
            };
        }
    };

    let canonical = match bundle.entry.content.canonicalize() {
        Ok(c) => c,
        Err(e) => {
            return SignatureStatus::Failed {
                reason: format!("canonicalization failed: {e}"),
            };
        }
    };

    let peer_key = UnparsedPublicKey::new(&ED25519, &public_key_bytes);
    match peer_key.verify(&canonical, bundle.entry.actor_sig.as_bytes()) {
        Ok(()) => SignatureStatus::Verified,
        Err(_) => SignatureStatus::Failed {
            reason: "Ed25519 signature verification failed".into(),
        },
    }
}

fn verify_inclusion_proof(bundle: &OfflineBundle) -> InclusionStatus {
    let leaf_data = match bundle.entry.leaf_data() {
        Ok(d) => d,
        Err(e) => {
            return InclusionStatus::Failed {
                reason: format!("leaf data serialization failed: {e}"),
            };
        }
    };
    let leaf_hash = hash_leaf(&leaf_data);

    let proof = &bundle.inclusion_proof;
    if let Err(e) = crate::merkle::verify_inclusion(
        &leaf_hash,
        proof.index,
        proof.size,
        &proof.hashes,
        &proof.root,
    ) {
        return InclusionStatus::Failed {
            reason: format!("Merkle inclusion failed: {e}"),
        };
    }

    if proof.root != bundle.signed_checkpoint.checkpoint.root {
        return InclusionStatus::Failed {
            reason: "inclusion proof root does not match checkpoint root".into(),
        };
    }

    InclusionStatus::Verified
}

fn verify_checkpoint(signed: &SignedCheckpoint, trust_root: &TrustRoot) -> CheckpointStatus {
    if signed.checkpoint.origin != trust_root.log_origin {
        return CheckpointStatus::InvalidSignature;
    }

    let note_body = signed.checkpoint.to_note_body();

    let peer_key = UnparsedPublicKey::new(&ED25519, trust_root.log_public_key.as_bytes());
    match peer_key.verify(note_body.as_bytes(), signed.log_signature.as_bytes()) {
        Ok(()) => CheckpointStatus::Verified,
        Err(_) => CheckpointStatus::InvalidSignature,
    }
}

fn verify_witnesses(signed: &SignedCheckpoint, trust_root: &TrustRoot) -> WitnessStatus {
    if trust_root.witnesses.is_empty() {
        return WitnessStatus::NotProvided;
    }

    let note_body = signed.checkpoint.to_note_body();
    let required = trust_root.witnesses.len() / 2 + 1;
    let mut verified = 0usize;

    for cosig in &signed.witnesses {
        let trusted = trust_root
            .witnesses
            .iter()
            .find(|w| w.public_key.as_bytes() == cosig.witness_public_key.as_bytes());

        if let Some(_witness) = trusted {
            let peer_key = UnparsedPublicKey::new(&ED25519, cosig.witness_public_key.as_bytes());
            if peer_key
                .verify(note_body.as_bytes(), cosig.signature.as_bytes())
                .is_ok()
            {
                verified += 1;
            }
        }
    }

    if verified >= required {
        WitnessStatus::Quorum { verified, required }
    } else {
        WitnessStatus::Insufficient { verified, required }
    }
}

fn check_staleness(signed: &SignedCheckpoint, now: DateTime<Utc>, warnings: &mut Vec<String>) {
    #[allow(clippy::expect_used)] // INVARIANT: 90 days always fits in Duration
    let stale_threshold =
        Duration::try_days(STALE_BUNDLE_DAYS).expect("STALE_BUNDLE_DAYS is a small constant");
    if now - signed.checkpoint.timestamp > stale_threshold {
        warnings.push(format!(
            "bundle checkpoint is older than {} days",
            STALE_BUNDLE_DAYS
        ));
    }
}

fn verify_delegation_chain(bundle: &OfflineBundle) -> DelegationStatus {
    if bundle.delegation_chain.is_empty() {
        return DelegationStatus::NoDelegationData;
    }

    let chain = &bundle.delegation_chain;

    // Epic 1 scope: only the standard 3-link delegation chain is supported:
    // [DeviceBind, OrgAddMember, NamespaceClaim]. Epic 3 (fn-74) will extend
    // this to support direct namespace ownership (no org), NamespaceDelegate
    // chains (4+ links), and variable chain lengths.
    if chain.len() != 3 {
        return DelegationStatus::ChainBroken {
            reason: format!("expected 3 delegation links, got {}", chain.len()),
        };
    }

    let expected_types = [
        EntryType::DeviceBind,
        EntryType::OrgAddMember,
        EntryType::NamespaceClaim,
    ];
    for (i, expected) in expected_types.iter().enumerate() {
        if &chain[i].link_type != expected {
            return DelegationStatus::ChainBroken {
                reason: format!(
                    "link[{i}] expected type {:?}, got {:?}",
                    expected, chain[i].link_type
                ),
            };
        }
    }

    // Check for duplicate sequence numbers
    let mut sequences: Vec<u64> = chain.iter().map(|l| l.entry.sequence).collect();
    sequences.sort_unstable();
    sequences.dedup();
    if sequences.len() != chain.len() {
        return DelegationStatus::ChainBroken {
            reason: "duplicate sequence numbers in delegation chain".into(),
        };
    }

    // Verify each link's inclusion proof against the checkpoint root
    let checkpoint_root = &bundle.signed_checkpoint.checkpoint.root;
    for (i, link) in chain.iter().enumerate() {
        let leaf_data = match link.entry.leaf_data() {
            Ok(d) => d,
            Err(e) => {
                return DelegationStatus::ChainBroken {
                    reason: format!("link[{i}] leaf data failed: {e}"),
                };
            }
        };
        let leaf_hash = hash_leaf(&leaf_data);
        let proof = &link.inclusion_proof;
        if let Err(e) = crate::merkle::verify_inclusion(
            &leaf_hash,
            proof.index,
            proof.size,
            &proof.hashes,
            &proof.root,
        ) {
            return DelegationStatus::ChainBroken {
                reason: format!("link[{i}] inclusion proof failed: {e}"),
            };
        }
        if &proof.root != checkpoint_root {
            return DelegationStatus::ChainBroken {
                reason: format!("link[{i}] proof root does not match checkpoint"),
            };
        }
    }

    // Extract DID connectivity
    let device_did = match &chain[0].entry.content.body {
        EntryBody::DeviceBind { device_did, .. } => device_did.clone(),
        _ => {
            return DelegationStatus::ChainBroken {
                reason: "link[0] body is not DeviceBind".into(),
            };
        }
    };

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: actor_did from a parsed Entry is already valid
    let identity_did = IdentityDID::new_unchecked(chain[0].entry.content.actor_did.as_str());

    let (member_did, member_role, org_did) = match &chain[1].entry.content.body {
        EntryBody::OrgAddMember {
            member_did, role, ..
        } => {
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: actor_did from a parsed Entry is already valid
            let org = IdentityDID::new_unchecked(chain[1].entry.content.actor_did.as_str());
            (member_did.clone(), *role, org)
        }
        _ => {
            return DelegationStatus::ChainBroken {
                reason: "link[1] body is not OrgAddMember".into(),
            };
        }
    };

    // Verify DID connectivity: the member added in OrgAddMember should match the identity that bound the device
    if member_did.as_str() != identity_did.as_str() {
        return DelegationStatus::ChainBroken {
            reason: format!(
                "DID connectivity broken: OrgAddMember member_did ({}) != DeviceBind actor_did ({})",
                member_did, identity_did
            ),
        };
    }

    DelegationStatus::ChainVerified {
        org_did,
        member_did,
        member_role,
        device_did,
    }
}

fn derive_namespace_status(
    delegation: &DelegationStatus,
    bundle: &OfflineBundle,
) -> NamespaceStatus {
    match delegation {
        DelegationStatus::ChainVerified { .. } => {
            let has_namespace_claim = bundle
                .delegation_chain
                .iter()
                .any(|link| link.link_type == EntryType::NamespaceClaim);
            if has_namespace_claim {
                NamespaceStatus::Authorized
            } else {
                NamespaceStatus::Owned
            }
        }
        DelegationStatus::Direct => NamespaceStatus::Owned,
        // No delegation data: assume direct ownership (weaker trust signal)
        DelegationStatus::NoDelegationData => NamespaceStatus::Owned,
        DelegationStatus::ChainBroken { .. } => NamespaceStatus::Unauthorized,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::TrustRootWitness;
    use crate::bundle::DelegationChainLink;
    use crate::checkpoint::{Checkpoint, WitnessCosignature};
    use crate::entry::{Entry, EntryContent};
    use crate::merkle::compute_root;
    use crate::proof::InclusionProof;
    use crate::types::LogOrigin;
    use auths_verifier::{CanonicalDid, DeviceDID, Ed25519PublicKey, Ed25519Signature};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn fixed_now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn fixed_ts() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2025-06-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    struct TestFixture {
        log_keypair: Ed25519KeyPair,
        log_public_key: [u8; 32],
        actor_keypair: Ed25519KeyPair,
        actor_public_key: [u8; 32],
        actor_did: String,
        trust_root: TrustRoot,
    }

    fn setup() -> TestFixture {
        let log_keypair = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
        let log_public_key: [u8; 32] = log_keypair.public_key().as_ref().try_into().unwrap();

        let actor_keypair = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
        let actor_public_key: [u8; 32] = actor_keypair.public_key().as_ref().try_into().unwrap();
        let actor_did = auths_crypto::ed25519_pubkey_to_did_key(&actor_public_key);

        let trust_root = TrustRoot {
            log_public_key: Ed25519PublicKey::from_bytes(log_public_key),
            log_origin: LogOrigin::new("test.dev/log").unwrap(),
            witnesses: vec![],
        };

        TestFixture {
            log_keypair,
            log_public_key,
            actor_keypair,
            actor_public_key,
            actor_did,
            trust_root,
        }
    }

    fn make_entry(fixture: &TestFixture) -> Entry {
        let content = EntryContent {
            entry_type: EntryType::DeviceBind,
            body: EntryBody::DeviceBind {
                device_did: DeviceDID::new_unchecked(&fixture.actor_did),
                public_key: Ed25519PublicKey::from_bytes(fixture.actor_public_key),
            },
            actor_did: CanonicalDid::new_unchecked(&fixture.actor_did),
        };
        let canonical = content.canonicalize().unwrap();
        let sig_bytes = fixture.actor_keypair.sign(&canonical);
        let actor_sig = Ed25519Signature::try_from_slice(sig_bytes.as_ref()).unwrap();

        Entry {
            sequence: 0,
            timestamp: fixed_ts(),
            content,
            actor_sig,
        }
    }

    fn make_signed_checkpoint(
        entry: &Entry,
        fixture: &TestFixture,
    ) -> (SignedCheckpoint, InclusionProof) {
        let leaf_data = entry.leaf_data().unwrap();
        let leaf_hash = hash_leaf(&leaf_data);
        let root = compute_root(&[leaf_hash]);

        let checkpoint = Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size: 1,
            root,
            timestamp: fixed_ts(),
        };

        let note_body = checkpoint.to_note_body();
        let log_sig_bytes = fixture.log_keypair.sign(note_body.as_bytes());
        let log_signature = Ed25519Signature::try_from_slice(log_sig_bytes.as_ref()).unwrap();

        let signed = SignedCheckpoint {
            checkpoint,
            log_signature,
            log_public_key: Ed25519PublicKey::from_bytes(fixture.log_public_key),
            witnesses: vec![],
        };

        let proof = InclusionProof {
            index: 0,
            size: 1,
            root,
            hashes: vec![],
        };

        (signed, proof)
    }

    fn make_valid_bundle(fixture: &TestFixture) -> OfflineBundle {
        let entry = make_entry(fixture);
        let (signed_checkpoint, inclusion_proof) = make_signed_checkpoint(&entry, fixture);

        OfflineBundle {
            entry,
            inclusion_proof,
            signed_checkpoint,
            delegation_chain: vec![],
        }
    }

    #[test]
    fn valid_bundle_all_verified() {
        let fixture = setup();
        let bundle = make_valid_bundle(&fixture);
        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());

        assert_eq!(report.signature, SignatureStatus::Verified);
        assert_eq!(report.inclusion, InclusionStatus::Verified);
        assert_eq!(report.checkpoint, CheckpointStatus::Verified);
        assert_eq!(report.witnesses, WitnessStatus::NotProvided);
        assert!(report.is_valid());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn bad_signature_fails() {
        let fixture = setup();
        let mut bundle = make_valid_bundle(&fixture);
        bundle.entry.actor_sig = Ed25519Signature::from_bytes([0xaa; 64]);

        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());

        assert!(matches!(report.signature, SignatureStatus::Failed { .. }));
        assert!(!report.is_valid());
    }

    #[test]
    fn bad_inclusion_proof_fails() {
        let fixture = setup();
        let mut bundle = make_valid_bundle(&fixture);
        bundle
            .inclusion_proof
            .hashes
            .push(crate::types::MerkleHash::from_bytes([0xff; 32]));

        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());

        assert!(matches!(report.inclusion, InclusionStatus::Failed { .. }));
    }

    #[test]
    fn stale_checkpoint_produces_warning() {
        let fixture = setup();
        let mut bundle = make_valid_bundle(&fixture);

        let old_ts = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        bundle.signed_checkpoint.checkpoint.timestamp = old_ts;

        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());

        assert!(!report.warnings.is_empty());
        assert!(report.warnings[0].contains("older than 90 days"));
    }

    #[test]
    fn witness_quorum_met() {
        let w1_keypair = Ed25519KeyPair::from_seed_unchecked(&[10u8; 32]).unwrap();
        let w1_pk: [u8; 32] = w1_keypair.public_key().as_ref().try_into().unwrap();
        let w2_keypair = Ed25519KeyPair::from_seed_unchecked(&[11u8; 32]).unwrap();
        let w2_pk: [u8; 32] = w2_keypair.public_key().as_ref().try_into().unwrap();

        let fixture = setup();
        let bundle = make_valid_bundle(&fixture);

        let note_body = bundle.signed_checkpoint.checkpoint.to_note_body();
        let w1_sig = w1_keypair.sign(note_body.as_bytes());
        let w2_sig = w2_keypair.sign(note_body.as_bytes());

        let mut bundle = bundle;
        bundle.signed_checkpoint.witnesses = vec![
            WitnessCosignature {
                witness_name: "w1".into(),
                witness_public_key: Ed25519PublicKey::from_bytes(w1_pk),
                signature: Ed25519Signature::try_from_slice(w1_sig.as_ref()).unwrap(),
                timestamp: fixed_ts(),
            },
            WitnessCosignature {
                witness_name: "w2".into(),
                witness_public_key: Ed25519PublicKey::from_bytes(w2_pk),
                signature: Ed25519Signature::try_from_slice(w2_sig.as_ref()).unwrap(),
                timestamp: fixed_ts(),
            },
        ];

        let trust_root = TrustRoot {
            log_public_key: Ed25519PublicKey::from_bytes(fixture.log_public_key),
            log_origin: LogOrigin::new("test.dev/log").unwrap(),
            witnesses: vec![
                TrustRootWitness {
                    witness_did: DeviceDID::new_unchecked(auths_crypto::ed25519_pubkey_to_did_key(
                        &w1_pk,
                    )),
                    name: "w1".into(),
                    public_key: Ed25519PublicKey::from_bytes(w1_pk),
                },
                TrustRootWitness {
                    witness_did: DeviceDID::new_unchecked(auths_crypto::ed25519_pubkey_to_did_key(
                        &w2_pk,
                    )),
                    name: "w2".into(),
                    public_key: Ed25519PublicKey::from_bytes(w2_pk),
                },
            ],
        };

        let report = verify_bundle(&bundle, &trust_root, fixed_now());
        assert!(matches!(
            report.witnesses,
            WitnessStatus::Quorum {
                verified: 2,
                required: 2,
            }
        ));
    }

    #[test]
    fn empty_delegation_yields_no_delegation_data() {
        let fixture = setup();
        let bundle = make_valid_bundle(&fixture);
        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());
        assert_eq!(report.delegation, DelegationStatus::NoDelegationData);
    }

    #[test]
    fn delegation_chain_wrong_length_is_broken() {
        let fixture = setup();
        let mut bundle = make_valid_bundle(&fixture);

        let entry = make_entry(&fixture);
        let root = bundle.signed_checkpoint.checkpoint.root;

        bundle.delegation_chain = vec![DelegationChainLink {
            link_type: EntryType::DeviceBind,
            entry,
            inclusion_proof: InclusionProof {
                index: 0,
                size: 1,
                root,
                hashes: vec![],
            },
        }];

        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());
        assert!(matches!(
            report.delegation,
            DelegationStatus::ChainBroken { .. }
        ));
    }

    #[test]
    fn checkpoint_origin_mismatch_fails() {
        let fixture = setup();
        let mut bundle = make_valid_bundle(&fixture);
        bundle.signed_checkpoint.checkpoint.origin = LogOrigin::new("other.dev/log").unwrap();

        let report = verify_bundle(&bundle, &fixture.trust_root, fixed_now());
        assert_eq!(report.checkpoint, CheckpointStatus::InvalidSignature);
    }
}
