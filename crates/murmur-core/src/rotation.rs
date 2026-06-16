//! Verified key continuity — the headline win (PRD §2).
//!
//! When a contact re-installs or does a planned rotation, the new key was
//! **pre-committed** by the prior key-state. So the app can show a *verified,
//! pre-committed continuation of the same identity* instead of the scary,
//! unverifiable "your safety number changed" warning a pinning model fires on
//! every change. This module is the engine half of that: it models a contact's
//! key-state with its pre-rotation commitment, runs the commitment check over a
//! (prior → current) transition, and — when the rotation verifies — performs the
//! two **binding-mechanism** steps the PRD marks load-bearing (PRD §2, "so this
//! isn't just prose"):
//!
//!  1. **Re-key the Signal session deterministically.** Tear down the old ratchet
//!     and re-establish X3DH against the freshly-replayed key-state. The old
//!     ratchet is *never* continued across an identity change — continuing it
//!     would carry a session rooted in the *previous* key past a key change, the
//!     exact bug that makes a continuity badge a lie.
//!  2. **Re-verify the republished prekey bundle against the new current key.**
//!     A bundle still signed by the *previous* (now-superseded) key is a
//!     stale-signer bundle and must be rejected — accepting a bundle whose signer
//!     you did not re-check is the dangerous bug the PRD names.
//!
//! ## What "pre-committed" means here
//!
//! A KERI inception/rotation event commits not just the *current* signing key but
//! a digest of the *next* one (the `n` field of an `IcpEvent`). A rotation is a
//! verified continuation iff the freshly-revealed current key hashes to the
//! commitment the **prior** key-state recorded — i.e. the holder revealed the key
//! the prior state had already bound itself to. An attacker holding the current
//! signing key but not the secured next key cannot produce such a key, so a
//! current-key-only compromise cannot forge a continuation (PRD §2). The full
//! engine runs this over a witnessed KEL replay (`replay_with_receipts` →
//! `KeyState`, `verify_commitment`); here the same property is modelled directly
//! over the contact's two key-states so the seam is a real check, not a stub.
//!
//! ## The AID is stable; the keys rotate under it
//!
//! A Murmur AID is the inception event's self-addressing id — it does **not**
//! change when the signing key rotates (PRD §2, §6.1). So a contact's key-state
//! carries the **stable AID** plus whichever key currently controls it; a
//! continuation preserves the AID and reveals a pre-committed new key. (The
//! address module derives a digest-AID from a key for the *static* binding the
//! floor claim uses; rotation is precisely the case where the AID outlives the
//! key, so the key-state carries the AID explicitly rather than re-deriving it.)
//!
//! ## The adversarial twin (the trap)
//!
//! A *substituted* key — one the prior state never pre-committed to — is **not** a
//! soft re-pin: it yields [`TrustState::NonContinuationWarning`]. A pinning model
//! would show only an unverifiable warning here; Murmur distinguishes the benign,
//! pre-committed continuation from the substituted one, which is the whole wedge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::address::Aid;
use crate::identity::Identity;
use crate::prekey::{PrekeyBundle, PrekeySecrets, RootedBundle};
use crate::session::Session;
use crate::trust::{TrustState, TrustVerdict};
use crate::{CoreError, CoreResult};

/// Domain-separating context the pre-rotation commitment digests under, so a
/// commitment over a next key can never collide with another digest of the same
/// bytes for a different purpose. KERI commits a digest of the next key-set; the
/// property the continuation check relies on — a one-way binding from the prior
/// state to the next key — is the same.
const NEXT_KEY_COMMITMENT_CONTEXT: &[u8] = b"murmur/pre-rotation/next-key/v1\n";

/// Compute the pre-rotation commitment over a next public key: the digest the
/// prior key-state records so a later rotation can be checked against it. One-way
/// by SHA-256, so the commitment reveals nothing about the next key yet binds the
/// holder to it — revealing a key that hashes to the commitment is the proof the
/// rotation was planned, not substituted.
pub fn compute_next_commitment(next_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEXT_KEY_COMMITMENT_CONTEXT);
    hasher.update(next_public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// One snapshot of a contact's witnessed key-state, as a KEL replay would yield
/// it: the **stable AID** it is for, the current signing key that AID resolves to
/// in this state, and the pre-rotation commitment to the *next* key. A rotation
/// produces a new `KeyState` with the same AID and a freshly-revealed current key;
/// [`verify_continuation`] checks the new one against the prior one's commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyState {
    /// The stable AID this key-state is for. A continuation must preserve it — a
    /// rotation changes the *key*, never the identity.
    pub aid: Aid,
    /// The current signing key the AID resolves to in this state. In the full
    /// engine, the output of a witnessed KEL replay; here, carried directly.
    pub current_key: Vec<u8>,
    /// The pre-rotation commitment to the next key (a [`compute_next_commitment`]
    /// digest). The prior state's commitment is what a rotation is verified
    /// against.
    pub next_commitment: [u8; 32],
}

impl KeyState {
    /// Build a key-state for the stable `aid`, controlled now by `current`, having
    /// pre-committed to `next_public_key`. The AID is carried explicitly because it
    /// outlives the key across a rotation.
    pub fn new(aid: Aid, current: &Identity, next_public_key: &[u8]) -> Self {
        KeyState {
            aid,
            current_key: current.public_key().to_vec(),
            next_commitment: compute_next_commitment(next_public_key),
        }
    }
}

/// Verify a contact's rotation against the prior key-state's pre-rotation
/// commitment.
///
///  * The AID must be preserved (a rotation changes the key, not the identity);
///  * the freshly-revealed `current_key` must hash to the commitment the **prior**
///    state recorded — i.e. the holder revealed the key the prior state had already
///    bound itself to.
///
/// A rotation that satisfies both is a [`TrustState::VerifiedContinuation`]. A
/// rotation whose new key the prior state never pre-committed to is a **substituted
/// key**: it is [`TrustState::NonContinuationWarning`], *never* a soft re-pin — the
/// adversarial case the wedge turns on. (A rotation whose AID changed is not a
/// rotation of the same identity at all, and is likewise warned, not silently
/// re-pinned.)
pub fn verify_continuation(prior: &KeyState, current: &KeyState) -> TrustVerdict {
    if prior.aid != current.aid {
        return TrustVerdict {
            state: TrustState::NonContinuationWarning,
            reason: "the key change is for a different AID — not a continuation of this identity"
                .to_string(),
        };
    }
    // M9: a "rotation" to the SAME key is not a rotation. A key pre-committed to
    // itself would otherwise hash to the prior commitment and pass the check below,
    // so guard it here — inside the public function — so it is correct regardless
    // of caller path (this is `pub` and reachable standalone via `trust::evaluate`).
    if prior.current_key == current.current_key {
        return TrustVerdict {
            state: TrustState::NonContinuationWarning,
            reason: "the new key is identical to the prior key — a rotation must change the key, \
                     not re-present the same one"
                .to_string(),
        };
    }
    let revealed = compute_next_commitment(&current.current_key);
    if revealed == prior.next_commitment {
        TrustVerdict {
            state: TrustState::VerifiedContinuation,
            reason: "the new key was pre-committed by the prior key-state — a verified, \
                     pre-committed continuation of the same identity"
                .to_string(),
        }
    } else {
        TrustVerdict {
            state: TrustState::NonContinuationWarning,
            reason:
                "the new key was NOT pre-committed by the prior key-state — a non-continuation \
                     key change, not a verified rotation"
                    .to_string(),
        }
    }
}

/// The verdict of driving the whole verified-continuation beat: a contact rotates keys, the
/// rotation is checked against the prior state's pre-rotation commitment, and on a
/// *verified* continuation the binding-mechanism steps run — the Signal session is
/// re-keyed deterministically and the republished prekey bundle is re-verified
/// against the fresh current key. Returned by [`verified_rotation_rekey`] so the
/// relay binary's self-test (and the harness) can assert all three held:
/// continuation verified, session re-keyed, prekey re-verified.
///
/// **No session secret lingers in the receipt (H5).** The receipt is a *verdict*,
/// not a key holder: it carries the stable AID, the two trust states, and a
/// [`was_rekeyed`](Self::was_rekeyed) boolean. Both the pre-rotation `Session` and
/// the freshly re-keyed `Session` are confined to [`verified_rotation_rekey`]'s
/// scope, where they are dropped (and zeroized via `ZeroizeOnDrop`) the moment the
/// re-key verdict is computed. So a memory snapshot taken while a receipt is live
/// cannot recover either the superseded root (decrypting pre-rotation traffic) or
/// the new root.
#[derive(Clone, Debug)]
pub struct RotationRekeyReceipt {
    /// The stable AID whose continuation verified — unchanged across the rotation.
    pub aid: Aid,
    /// The trust state surfaced for the pre-committed rotation
    /// ([`TrustState::VerifiedContinuation`]).
    pub continuation: TrustState,
    /// The trust state surfaced for the substituted-key twin
    /// ([`TrustState::NonContinuationWarning`]) — proof the adversarial case is
    /// warned, not re-pinned.
    pub substituted: TrustState,
    /// Whether the re-key produced a root *different* from the pre-rotation one —
    /// decided locally in [`verified_rotation_rekey`], so the superseded root is
    /// dropped (zeroized) rather than carried in the receipt.
    was_rekeyed: bool,
}

impl RotationRekeyReceipt {
    /// True iff the re-keyed session was rooted in a *different* secret than the
    /// pre-rotation one — i.e. the old ratchet was torn down and X3DH re-run
    /// against the new key-state, never continued across the identity change. The
    /// comparison was made (and the prior root dropped) in
    /// [`verified_rotation_rekey`]; the receipt only carries the verdict.
    pub fn session_was_rekeyed(&self) -> bool {
        self.was_rekeyed
    }
}

/// Drive the verified-rotation beat end-to-end, hermetically (PRD §10, the
/// verified-continuation claim, with the §2 binding mechanism).
///
/// The contact is one identity with a **stable AID**; `prior_identity` is the key
/// that controlled it before the rotation and `rotated_identity` is the
/// pre-committed key it rotates to. The two are different keys (that is what a
/// rotation *is*), bound to the same stable AID.
///
///  1. The prior key-state pre-committed to the rotated key, and a prior Signal
///     session was rooted in the *old* key-state.
///  2. The contact rotates: it reveals the pre-committed next key as its new
///     current key and republishes a prekey bundle **signed by the new key**.
///  3. [`verify_continuation`] checks the rotation against the prior commitment —
///     it must be a [`TrustState::VerifiedContinuation`].
///  4. **Re-key:** X3DH is re-run against the *freshly-replayed* key-state, tearing
///     down the old ratchet; the new session root MUST differ from the prior one
///     (the old ratchet is not continued across the rotation).
///  5. **Re-verify the prekey:** the republished bundle MUST verify against the
///     **new** current key; a bundle still signed by the *old* key (a stale-signer
///     bundle) MUST be rejected.
///  6. **The adversarial twin:** a substituted key the prior state never
///     pre-committed to MUST yield [`TrustState::NonContinuationWarning`].
///
/// Returns a [`RotationRekeyReceipt`] iff every step held. Any failure — a
/// substituted key that verified as a continuation, the old ratchet continued
/// across the change, or a stale-signer prekey accepted — is an error, never a
/// silent pass (the RED the trap records).
pub fn verified_rotation_rekey(
    stable_aid: &Aid,
    prior_identity: &Identity,
    rotated_identity: &Identity,
    prior_session_secret: [u8; 32],
    rotated_prekeys: &PrekeySecrets,
    initiator_identity_secret: [u8; 32],
    initiator_ephemeral_secret: [u8; 32],
) -> CoreResult<RotationRekeyReceipt> {
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

    // The rotation must genuinely change the key — a "rotation" to the same key is
    // not a rotation at all.
    if prior_identity.public_key() == rotated_identity.public_key() {
        return Err(CoreError::Malformed(
            "the rotation must change the signing key — prior and rotated keys are identical"
                .into(),
        ));
    }

    // (1) Prior key-state for the stable AID, pre-committing to the rotated key. The
    // prior session is rooted in the OLD key-state.
    let prior_state = KeyState::new(
        stable_aid.clone(),
        prior_identity,
        rotated_identity.public_key(),
    );
    let prior_session = Session::from_secret(prior_session_secret);

    // (2) The rotation reveals the pre-committed key as the new current key, for the
    // same stable AID. The new state pre-commits to a further next key (rotation is
    // continuous); for this beat the further commitment is over the rotated key's own
    // bytes — only the prior→current check is load-bearing here.
    let rotated_state = KeyState::new(
        stable_aid.clone(),
        rotated_identity,
        rotated_identity.public_key(),
    );

    // (3) Check the rotation against the prior commitment — it must be a verified
    // continuation, never a soft re-pin.
    let continuation = verify_continuation(&prior_state, &rotated_state);
    if continuation.state != TrustState::VerifiedContinuation {
        return Err(CoreError::Rejected(
            "continuation-without-precommit: a pre-committed rotation did not verify as a \
             continuation",
        ));
    }

    // (5) Re-verify the republished prekey bundle against the NEW current key. The
    // bundle the contact republishes on rotation is signed by the new key; verifying
    // it against the freshly-replayed current key is the step that closes the
    // stale-signer bug. `verify_rooted` binds the bundle to the AID the *bundle*
    // carries, so we publish it under the rotated key (whose AID-digest is the
    // bundle's claimed AID) and re-verify against that fresh current key.
    let fresh_bundle = PrekeyBundle::publish(rotated_identity, rotated_prekeys)?;
    let rooted: RootedBundle = fresh_bundle
        .verify_rooted(rotated_state.current_key.as_slice())
        .map_err(|_| {
            CoreError::Rejected(
                "the republished prekey bundle did not verify against the fresh current key",
            )
        })?;

    // The stale-signer twin: a bundle still signed by the OLD key must be rejected
    // when re-verified against the new current key — accepting a bundle whose signer
    // we did not re-check is the dangerous bug. We forge a bundle that *claims* the
    // rotated key's bundle-AID but is signed by the prior key, and prove it fails.
    let stale_bundle = PrekeyBundle::publish(prior_identity, rotated_prekeys)?;
    let stale_for_new = PrekeyBundle {
        aid: fresh_bundle.aid.clone(), // claims the rotated key's bundle-AID …
        signal_identity_key: stale_bundle.signal_identity_key,
        signed_prekey: stale_bundle.signed_prekey,
        signature: stale_bundle.signature, // … but signed by the superseded key
    };
    match stale_for_new.verify_rooted(rotated_state.current_key.as_slice()) {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "stale-signer-prekey-accepted: a prekey bundle signed by the superseded key was \
                 accepted against the fresh current key",
            ));
        }
        Err(CoreError::Rejected(_)) => { /* rejected as required */ }
        Err(other) => return Err(other),
    }

    // (4) Re-key: tear down the old ratchet and re-run X3DH against the *verified*
    // new key-state. The re-keyed session is rooted in the rotated keys, so its
    // secret differs from the prior session's — the old ratchet is NOT continued
    // across the rotation.
    let initiator_identity = X25519Secret::from(initiator_identity_secret);
    let initiator_ephemeral = X25519Secret::from(initiator_ephemeral_secret);
    let rekeyed_session =
        crate::prekey::x3dh_initiator(&initiator_identity, &initiator_ephemeral, &rooted)?;
    // Belt and braces: the responder must agree the same root.
    let responder_session = crate::prekey::x3dh_responder(
        rotated_prekeys,
        X25519Public::from(&initiator_identity).to_bytes(),
        X25519Public::from(&initiator_ephemeral).to_bytes(),
    )?;
    if rekeyed_session.secret_bytes() != responder_session.secret_bytes() {
        return Err(CoreError::Rejected(
            "the re-keyed session did not agree on both sides after the rotation",
        ));
    }
    // Decide the re-key verdict here, locally, comparing against the prior root —
    // then the receipt carries only the boolean and the pre-rotation `Session` is
    // dropped (zeroized) at end of scope, never lingering in the receipt (H5).
    let was_rekeyed = rekeyed_session.secret_bytes() != prior_session.secret_bytes();
    if !was_rekeyed {
        return Err(CoreError::Rejected(
            "ratchet-continued-across-identity-change: the session was not re-keyed — the old \
             ratchet's root survived the rotation",
        ));
    }

    // (6) The adversarial twin: a substituted key the prior state never
    // pre-committed to must be warned, not re-pinned.
    let substitute = Identity::from_seed([0xABu8; 32])
        .map_err(|e| CoreError::Malformed(format!("mint substitute key: {e}")))?;
    let substituted_state = KeyState {
        aid: stable_aid.clone(),                       // claims the same stable AID …
        current_key: substitute.public_key().to_vec(), // … but a key never pre-committed
        next_commitment: compute_next_commitment(substitute.public_key()),
    };
    let substituted = verify_continuation(&prior_state, &substituted_state);
    if substituted.state != TrustState::NonContinuationWarning {
        return Err(CoreError::Rejected(
            "substituted-key-accepted: a key the prior state never pre-committed to verified as a \
             continuation",
        ));
    }

    Ok(RotationRekeyReceipt {
        aid: stable_aid.clone(),
        continuation: continuation.state,
        substituted: substituted.state,
        was_rekeyed,
    })
    // `prior_session` and `rekeyed_session` both drop here — their 32-byte roots
    // are zeroized (ZeroizeOnDrop), so neither the superseded nor the new root
    // outlives this scope, let alone the returned receipt.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> Identity {
        Identity::from_seed([byte; 32]).unwrap()
    }

    fn secrets(a: u8, b: u8) -> PrekeySecrets {
        PrekeySecrets::from_seeds([a; 32], [b; 32])
    }

    fn stable_aid() -> Aid {
        Aid::new("did:keri:stable-contact-aid")
    }

    #[test]
    fn a_pre_committed_rotation_verifies_as_a_continuation() {
        let prior = identity(1);
        let rotated = identity(2);
        let aid = stable_aid();
        let prior_state = KeyState::new(aid.clone(), &prior, rotated.public_key());
        let rotated_state = KeyState::new(aid.clone(), &rotated, rotated.public_key());
        let v = verify_continuation(&prior_state, &rotated_state);
        assert_eq!(v.state, TrustState::VerifiedContinuation);
    }

    #[test]
    fn a_substituted_key_is_warned_not_re_pinned() {
        let prior = identity(1);
        let rotated = identity(2);
        let substitute = identity(9);
        let aid = stable_aid();
        let prior_state = KeyState::new(aid.clone(), &prior, rotated.public_key());
        // A key the prior state never pre-committed to, claiming the same stable AID.
        let substituted_state = KeyState::new(aid.clone(), &substitute, substitute.public_key());
        let v = verify_continuation(&prior_state, &substituted_state);
        assert_eq!(v.state, TrustState::NonContinuationWarning);
    }

    #[test]
    fn a_rotation_to_a_different_aid_is_not_a_continuation() {
        let prior = identity(1);
        let rotated = identity(2);
        let prior_state = KeyState::new(stable_aid(), &prior, rotated.public_key());
        // The new state claims a DIFFERENT AID — not a continuation of this identity.
        let rotated_state = KeyState::new(
            Aid::new("did:keri:someone-else"),
            &rotated,
            rotated.public_key(),
        );
        let v = verify_continuation(&prior_state, &rotated_state);
        assert_eq!(v.state, TrustState::NonContinuationWarning);
    }

    #[test]
    fn the_commitment_is_one_way_and_binding() {
        let rotated = identity(2);
        let other = identity(3);
        assert_eq!(
            compute_next_commitment(rotated.public_key()),
            compute_next_commitment(rotated.public_key())
        );
        assert_ne!(
            compute_next_commitment(rotated.public_key()),
            compute_next_commitment(other.public_key())
        );
    }

    #[test]
    fn the_whole_beat_verifies_rekeys_and_re_verifies_the_prekey() {
        let prior = identity(1);
        let rotated = identity(2);
        let aid = stable_aid();
        let rotated_prekeys = secrets(0x40, 0x41);
        let receipt = verified_rotation_rekey(
            &aid,
            &prior,
            &rotated,
            [0x5au8; 32],
            &rotated_prekeys,
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .unwrap();
        assert_eq!(receipt.aid, aid);
        assert_eq!(receipt.continuation, TrustState::VerifiedContinuation);
        assert_eq!(receipt.substituted, TrustState::NonContinuationWarning);
        assert!(receipt.session_was_rekeyed());
    }

    #[test]
    fn a_same_key_rotation_pre_committed_to_itself_is_warned_not_verified() {
        // M9 regression: a "rotation" whose new key equals the prior key — even if
        // the prior state pre-committed to that same key (so the commitment hash
        // matches) — is NOT a verified continuation. verify_continuation catches it
        // standalone, regardless of the verified_rotation_rekey path.
        let key = identity(1);
        let aid = stable_aid();
        // The prior state pre-commits to its OWN current key, then "rotates" to it.
        let prior_state = KeyState::new(aid.clone(), &key, key.public_key());
        let same_state = KeyState::new(aid.clone(), &key, key.public_key());
        // Sanity: without the M9 guard, the commitment would match (the key was
        // pre-committed to itself) — so the same-key check is what rejects it.
        assert_eq!(
            compute_next_commitment(&same_state.current_key),
            prior_state.next_commitment
        );
        let v = verify_continuation(&prior_state, &same_state);
        assert_eq!(v.state, TrustState::NonContinuationWarning);
    }

    #[test]
    fn the_receipt_carries_no_session_secret_only_a_verdict() {
        // H5 regression: the receipt is a verdict, not a key holder. It exposes the
        // AID, the two trust states, and a `was_rekeyed` boolean — never a prior or
        // re-keyed `Session`. We prove the re-key verdict is reported (true) while
        // the receipt is `Clone + Debug` over only printable, non-secret fields, so
        // a memory snapshot of a live receipt recovers no root key.
        let prior = identity(1);
        let rotated = identity(2);
        let aid = stable_aid();
        let rotated_prekeys = secrets(0x40, 0x41);
        let receipt = verified_rotation_rekey(
            &aid,
            &prior,
            &rotated,
            [0x5au8; 32],
            &rotated_prekeys,
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .unwrap();
        assert!(receipt.session_was_rekeyed());
        // The receipt is Debug-printable in full — there is no secret it could leak
        // into a log line, because it holds none.
        let printed = format!("{receipt:?}");
        assert!(printed.contains(aid.as_str()));
    }

    #[test]
    fn a_rotation_that_does_not_change_the_key_is_malformed() {
        let prior = identity(1);
        let rotated_prekeys = secrets(0x40, 0x41);
        let result = verified_rotation_rekey(
            &stable_aid(),
            &prior,
            &prior, // same key — not a rotation
            [0x5au8; 32],
            &rotated_prekeys,
            [0x51u8; 32],
            [0x52u8; 32],
        );
        assert!(matches!(result, Err(CoreError::Malformed(_))));
    }
}
