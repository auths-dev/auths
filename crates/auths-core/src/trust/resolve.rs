//! Trust resolution logic for verifying identity root keys.
//!
//! This module provides the core trust decision engine that determines
//! whether to trust a presented identity based on the configured policy.

use super::continuity::{KelContinuityChecker, RotationProof};
use super::pinned::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
use super::policy::TrustPolicy;
use crate::error::TrustError;
use chrono::{DateTime, Utc};

/// What the trust engine decided.
#[derive(Debug)]
pub enum TrustDecision {
    /// Key matches existing pin. Proceed.
    Trusted {
        /// The pinned identity.
        pin: PinnedIdentity,
    },

    /// No pin exists. Caller must decide based on policy.
    FirstUse {
        /// The DID encountered for the first time.
        did: String,
        /// The presented public key.
        presented_pk: Vec<u8>,
    },

    /// Key differs from pin, but a valid forward-chain rotation connects them.
    ///
    /// The continuity checker has verified unbroken hash linkage from
    /// pinned tip to current tip, and the resulting key matches presented_pk.
    RotationVerified {
        /// The previous pinned identity.
        old_pin: PinnedIdentity,
        /// Proof of key rotation.
        proof: RotationProof,
    },

    /// Key differs from pin with no valid rotation chain.
    ///
    /// Either no KEL was available, the pinned tip is not an ancestor of the
    /// current tip, or the chain leads to a different key.
    Conflict {
        /// The new pinned identity.
        pin: PinnedIdentity,
        /// The presented public key.
        presented_pk: Vec<u8>,
    },
}

/// Check trust for a presented identity.
///
/// The `continuity_checker` parameter is optional. If `None`, any key mismatch
/// against an existing pin is treated as a hard conflict (no rotation can be
/// verified without KEL access). Pass `Some(&checker)` when the caller has
/// repository access and can verify rotation chains.
///
/// # Arguments
///
/// * `store` - The pin store to look up existing pins
/// * `did` - The DID of the identity being verified
/// * `presented_pk` - The raw public key bytes presented for verification
/// * `continuity_checker` - Optional KEL continuity checker for rotation verification
///
/// # Returns
///
/// A [`TrustDecision`] indicating what action to take.
pub fn check_trust(
    store: &PinnedIdentityStore,
    did: &str,
    presented_pk: &[u8],
    continuity_checker: Option<&dyn KelContinuityChecker>,
) -> Result<TrustDecision, TrustError> {
    let pin = store.lookup(did)?;

    let Some(pin) = pin else {
        return Ok(TrustDecision::FirstUse {
            did: did.to_string(),
            presented_pk: presented_pk.to_vec(),
        });
    };

    // Compare on decoded bytes, not hex strings
    if pin.key_matches(presented_pk)? {
        return Ok(TrustDecision::Trusted { pin });
    }

    // Key differs — attempt rotation continuity check if we have a checker and a tip
    if let (Some(checker), Some(pinned_tip)) = (continuity_checker, &pin.kel_tip_said) {
        match checker.verify_rotation_continuity(did, pinned_tip, presented_pk)? {
            Some(proof) => {
                return Ok(TrustDecision::RotationVerified {
                    old_pin: pin,
                    proof,
                });
            }
            None => {
                // Checker ran but couldn't prove continuity — fall through to conflict
            }
        }
    }

    Ok(TrustDecision::Conflict {
        pin,
        presented_pk: presented_pk.to_vec(),
    })
}

/// Apply the trust policy to a [`TrustDecision`] to get a final resolved key.
///
/// Resolution order for `Explicit` policy:
/// 1. Pinned identity store (only existing pins)
/// 2. Reject unknown identities
///
/// Resolution order for `Tofu` policy:
/// 1. Pinned identity store
/// 2. Interactive prompt → pin on accept
///
/// # Arguments
///
/// * `decision` - The trust decision from [`check_trust`]
/// * `policy` - The trust policy to apply
/// * `store` - The pin store for saving new pins
/// * `interactive_prompt` - Optional function to prompt user for TOFU acceptance
///
/// # Returns
///
/// `Ok(public_key_bytes)` if trusted, `Err` if rejected.
pub fn resolve_trust(
    now: DateTime<Utc>,
    decision: TrustDecision,
    policy: &TrustPolicy,
    store: &PinnedIdentityStore,
    interactive_prompt: Option<&dyn Fn(&str) -> bool>,
) -> Result<Vec<u8>, TrustError> {
    match decision {
        TrustDecision::Trusted { pin } => pin.public_key_bytes(),

        TrustDecision::FirstUse { did, presented_pk } => match policy {
            TrustPolicy::Tofu => {
                let prompt = interactive_prompt.ok_or_else(|| {
                    TrustError::PolicyRejected(
                        "TOFU requires interactive prompt but none available. \
                         Use --trust explicit with a roots file for non-interactive use."
                            .into(),
                    )
                })?;
                let pk_hex = hex::encode(&presented_pk);
                let msg = format!(
                    "Unknown identity: {}\n  Key: {}...\n  Trust this identity?",
                    did,
                    &pk_hex[..16.min(pk_hex.len())]
                );
                if prompt(&msg) {
                    let pin = PinnedIdentity {
                        did,
                        public_key_hex: pk_hex,
                        kel_tip_said: None,
                        kel_sequence: None,
                        first_seen: now,
                        origin: "tofu".into(),
                        trust_level: TrustLevel::Tofu,
                    };
                    store.pin(pin)?;
                    Ok(presented_pk)
                } else {
                    Err(TrustError::PolicyRejected("Identity rejected by user.".into()))
                }
            }
            TrustPolicy::Explicit => {
                let pk_hex = hex::encode(&presented_pk);
                Err(TrustError::PolicyRejected(format!(
                    "Unknown identity '{}' and trust policy is 'explicit'.\n\
                     Options:\n  \
                     1. Add to .auths/roots.json in the repository\n  \
                     2. Pin manually: auths trust pin {} --key {}\n  \
                     3. Provide --issuer-pk {} to bypass trust resolution",
                    did, did, pk_hex, pk_hex
                )))
            }
        },

        TrustDecision::RotationVerified { old_pin, proof } => {
            let updated = PinnedIdentity {
                did: old_pin.did,
                public_key_hex: hex::encode(&proof.new_public_key),
                kel_tip_said: Some(proof.new_kel_tip),
                kel_sequence: Some(proof.new_sequence),
                first_seen: old_pin.first_seen,
                origin: old_pin.origin,
                trust_level: old_pin.trust_level,
            };
            store.update(updated)?;
            Ok(proof.new_public_key)
        }

        TrustDecision::Conflict { pin, presented_pk } => {
            let pinned_hex = &pin.public_key_hex;
            let presented_hex = hex::encode(&presented_pk);
            Err(TrustError::PolicyRejected(format!(
                "TRUST CONFLICT for {}\n  \
                 Pinned key:    {}...\n  \
                 Presented key: {}...\n  \
                 No valid rotation chain connects these keys.\n  \
                 This could indicate an attack or a KEL that was not available.\n\n  \
                 If you trust this new key, remove the old pin first:\n    \
                 auths trust remove {}",
                pin.did,
                &pinned_hex[..16.min(pinned_hex.len())],
                &presented_hex[..16.min(presented_hex.len())],
                pin.did
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pin() -> PinnedIdentity {
        PinnedIdentity {
            did: "did:keri:ETest123".to_string(),
            public_key_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
            kel_tip_said: Some("ETip".to_string()),
            kel_sequence: Some(0),
            first_seen: Utc::now(),
            origin: "test".to_string(),
            trust_level: TrustLevel::Tofu,
        }
    }

    fn temp_store() -> (tempfile::TempDir, PinnedIdentityStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_identities.json");
        let store = PinnedIdentityStore::new(path);
        (dir, store)
    }

    #[test]
    fn test_check_trust_first_use() {
        let (_dir, store) = temp_store();
        let pk: Vec<u8> = (1..=32).collect();

        let decision = check_trust(&store, "did:keri:ENew", &pk, None).unwrap();
        assert!(matches!(decision, TrustDecision::FirstUse { .. }));
    }

    #[test]
    fn test_check_trust_trusted() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();
        store.pin(pin.clone()).unwrap();

        let pk: Vec<u8> = (1..=32).collect();
        let decision = check_trust(&store, &pin.did, &pk, None).unwrap();
        assert!(matches!(decision, TrustDecision::Trusted { .. }));
    }

    #[test]
    fn test_check_trust_conflict() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();
        store.pin(pin.clone()).unwrap();

        let wrong_pk: Vec<u8> = vec![0xFF; 32];
        let decision = check_trust(&store, &pin.did, &wrong_pk, None).unwrap();
        assert!(matches!(decision, TrustDecision::Conflict { .. }));
    }

    #[test]
    fn test_resolve_trust_trusted() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();
        store.pin(pin.clone()).unwrap();

        let decision = TrustDecision::Trusted { pin };
        let result = resolve_trust(Utc::now(), decision, &TrustPolicy::Tofu, &store, None).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_resolve_trust_first_use_tofu_accepted() {
        let (_dir, store) = temp_store();
        let pk: Vec<u8> = (1..=32).collect();

        let decision = TrustDecision::FirstUse {
            did: "did:keri:ENew".to_string(),
            presented_pk: pk.clone(),
        };

        let accept_all = |_: &str| true;
        let result = resolve_trust(
            Utc::now(),
            decision,
            &TrustPolicy::Tofu,
            &store,
            Some(&accept_all),
        )
        .unwrap();

        assert_eq!(result, pk);
        // Should be pinned now
        assert!(store.lookup("did:keri:ENew").unwrap().is_some());
    }

    #[test]
    fn test_resolve_trust_first_use_tofu_rejected() {
        let (_dir, store) = temp_store();
        let pk: Vec<u8> = (1..=32).collect();

        let decision = TrustDecision::FirstUse {
            did: "did:keri:ENew".to_string(),
            presented_pk: pk,
        };

        let reject_all = |_: &str| false;
        let result = resolve_trust(
            Utc::now(),
            decision,
            &TrustPolicy::Tofu,
            &store,
            Some(&reject_all),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }

    #[test]
    fn test_resolve_trust_first_use_explicit_fails() {
        let (_dir, store) = temp_store();
        let pk: Vec<u8> = (1..=32).collect();

        let decision = TrustDecision::FirstUse {
            did: "did:keri:ENew".to_string(),
            presented_pk: pk,
        };

        let result = resolve_trust(Utc::now(), decision, &TrustPolicy::Explicit, &store, None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("explicit"));
        assert!(err.contains("roots.json"));
    }

    #[test]
    fn test_resolve_trust_conflict_fails() {
        let (_dir, store) = temp_store();
        let pin = make_test_pin();
        let wrong_pk: Vec<u8> = vec![0xFF; 32];

        let decision = TrustDecision::Conflict {
            pin,
            presented_pk: wrong_pk,
        };

        let result = resolve_trust(Utc::now(), decision, &TrustPolicy::Tofu, &store, None);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TRUST CONFLICT"));
    }

    #[test]
    fn test_resolve_trust_rotation_verified() {
        let (_dir, store) = temp_store();
        let mut pin = make_test_pin();
        pin.kel_sequence = Some(0);
        store.pin(pin.clone()).unwrap();

        let new_pk: Vec<u8> = vec![0xAA; 32];
        let proof = RotationProof {
            new_public_key: new_pk.clone(),
            new_kel_tip: "ENewTip".to_string(),
            new_sequence: 1,
        };

        let decision = TrustDecision::RotationVerified {
            old_pin: pin.clone(),
            proof,
        };

        let result = resolve_trust(Utc::now(), decision, &TrustPolicy::Tofu, &store, None).unwrap();
        assert_eq!(result, new_pk);

        // Pin should be updated
        let updated = store.lookup(&pin.did).unwrap().unwrap();
        assert_eq!(updated.kel_sequence, Some(1));
        assert_eq!(updated.kel_tip_said, Some("ENewTip".to_string()));
    }
}
