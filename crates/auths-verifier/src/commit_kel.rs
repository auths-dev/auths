//! KEL-native commit verdict — the heart of Epic B.
//!
//! Given a commit, the signer's device KEL, the root KEL, and the pinned trusted
//! roots, decide whether the commit is authorized **purely by replaying the log**:
//! the device is a delegated identifier the root anchored and has not revoked, and
//! the commit's SSH signature was made by the device's current key — all verified
//! in-process (no `ssh-keygen`, no `allowed_signers`). Every failure is a
//! distinguishable [`CommitVerdict`], never a bare "invalid signature".

use auths_crypto::CryptoProvider;
use auths_keri::witness::{NoWitnessReceipts, WitnessReceiptLookup};
use auths_keri::{
    CesrKey, DelegatorKelLookup, Event, KeriPublicKey, KeriSequence, Prefix, Said, Seal,
    WitnessedReplay, validate_delegation, validate_kel_with_lookup, validate_kel_with_receipts,
};

use crate::commit::{extract_ssh_signature, verify_commit_signature};
use crate::commit_error::CommitVerificationError;
use crate::core::DevicePublicKey;
use crate::duplicity::{KelEventRef, detect_duplicity};
use crate::ssh_sig::parse_sshsig_pem;

/// The outcome of KEL-native commit verification. Distinguishable so the CLI/UX can
/// explain *why* a commit failed (never a generic `InvalidSignature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitVerdict {
    /// Authorized: the signer is a non-revoked delegate of a pinned root (or the
    /// pinned root itself) and the SSH signature matches its current key.
    Valid {
        /// The verified signer `did:keri:`.
        signer_did: String,
        /// The root `did:keri:` it chains to.
        root_did: String,
        /// True if the root KEL shows a fork (non-fatal warning — trust-on-first-sight).
        duplicitous_root: bool,
    },
    /// The commit carries no SSH signature.
    Unsigned,
    /// The SSH signature did not validate (tampered commit, wrong namespace, or bad sig).
    SshSignatureInvalid,
    /// A PGP-signed commit (out of scope).
    GpgUnsupported,
    /// The signer's device KEL failed to replay/validate.
    DeviceKelInvalid(String),
    /// The root KEL failed to replay/validate.
    RootKelInvalid(String),
    /// The root identity is not in the pinned trusted-root set (`.auths/roots`).
    RootNotPinned(String),
    /// The root identity's KEL is abandoned.
    RootAbandoned,
    /// The device is not delegated by the claimed/pinned root.
    NotDelegatedByClaimedRoot {
        /// The device's `did:keri:`.
        device_did: String,
        /// The root we verified against.
        root_did: String,
    },
    /// The root never anchored the device's delegated inception.
    DelegationSealNotFound,
    /// The root has revoked this device's delegation.
    DeviceRevoked,
    /// The SSH signer key is not the device's current key (and not a known prior key).
    SignerKeyMismatch,
    /// The SSH signer key is a *superseded* device key (the device rotated since signing).
    SignedBySupersededKey,
    /// Under `--require-witnesses`, the signer's root KEL did not reach M-of-N
    /// witness quorum for an establishment event (fail-closed).
    WitnessQuorumNotMet {
        /// The root `did:keri:` whose KEL is under-quorum.
        root_did: String,
        /// Distinct valid witness receipts collected.
        collected: usize,
        /// Receipts required by the in-force backer threshold.
        required: usize,
    },
}

/// Verifier-side witness policy — independent of the signer's own `WitnessPolicy`.
///
/// A verifier cannot trust the signer's self-declared policy (it lives in the
/// signer's config), so it sets its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifierWitnessPolicy {
    /// Under-quorum signer key-state is a non-fatal warning (preserves the
    /// Stage-1 trust-on-first-sight caveat during rollout). The default.
    #[default]
    Warn,
    /// Under-quorum signer key-state fails verification (fail-closed).
    RequireWitnesses,
}

/// Witness-quorum status of a verified signer KEL, surfaced for CLI display (D.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessGateStatus {
    /// The signer KEL designates no witnesses (`bt=0`); none required.
    NotRequired,
    /// Witness quorum was met.
    Met,
    /// Quorum was not met but accepted anyway under [`VerifierWitnessPolicy::Warn`].
    UnderQuorum {
        /// Distinct valid receipts collected.
        collected: usize,
        /// Receipts required by the in-force backer threshold.
        required: usize,
    },
}

/// A commit verdict paired with the signer KEL's witness-quorum status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedVerdict {
    /// The commit authorization verdict.
    pub verdict: CommitVerdict,
    /// Witness-quorum status of the signer's (root) KEL.
    pub witness: WitnessGateStatus,
}

impl CommitVerdict {
    /// Whether the commit is authorized (a `Valid` verdict, regardless of the
    /// non-fatal duplicity warning).
    pub fn is_valid(&self) -> bool {
        matches!(self, CommitVerdict::Valid { .. })
    }
}

/// `DelegatorKelLookup` over an in-memory root KEL slice — answers "did the root
/// anchor a seal for this delegated event?" by scanning the root KEL's seals.
struct RootKelLookup<'a> {
    root_kel: &'a [Event],
}

impl DelegatorKelLookup for RootKelLookup<'_> {
    fn find_seal(&self, _delegator_aid: &Prefix, seal_said: &Said) -> Option<KeriSequence> {
        for event in self.root_kel {
            for seal in event.anchors() {
                if let Seal::KeyEvent { d, .. } = seal
                    && d == seal_said
                {
                    return Some(event.sequence());
                }
            }
        }
        None
    }
}

/// Whether the root KEL has anchored a revocation (`Seal::Digest{d == device_prefix}`)
/// for the device. Stateless twin of the backend-bound `delegation_status`.
fn revocation_status(root_kel: &[Event], device_prefix: &Prefix) -> bool {
    root_kel.iter().any(|event| {
        event
            .anchors()
            .iter()
            .any(|seal| matches!(seal, Seal::Digest { d } if d.as_str() == device_prefix.as_str()))
    })
}

/// The establishment keys (`k[]`) across a device KEL, parsed to device pubkeys —
/// used to tell a *superseded* signer (rotated away) from an *unrelated* one.
fn establishment_keys(device_kel: &[Event]) -> Vec<DevicePublicKey> {
    device_kel
        .iter()
        .filter_map(|event| match event {
            Event::Icp(e) => Some(&e.k),
            Event::Dip(e) => Some(&e.k),
            Event::Rot(e) => Some(&e.k),
            Event::Drt(e) => Some(&e.k),
            _ => None,
        })
        .flatten()
        .filter_map(cesr_to_device_pk)
        .collect()
}

/// Decode a CESR-encoded verkey into a curve-tagged device public key.
fn cesr_to_device_pk(cesr: &CesrKey) -> Option<DevicePublicKey> {
    let keri = KeriPublicKey::parse(cesr.as_str()).ok()?;
    let curve = keri.curve();
    let bytes = keri.into_bytes().to_vec();
    DevicePublicKey::try_new(curve, &bytes).ok()
}

/// Verify a commit purely by KEL replay + delegation + in-process SSH-signature check.
///
/// Args:
/// * `commit_bytes`: The raw git commit object (with the `gpgsig` SSH signature).
/// * `device_kel`: The signer device's KEL events (a `dip`, or the root's `icp` when
///   the root signs directly).
/// * `root_kel`: The root identity's KEL events (the delegator).
/// * `pinned_roots`: Trusted root `did:keri:` strings (from `.auths/roots`).
/// * `provider`: Crypto provider for in-process signature verification.
///
/// Usage:
/// ```ignore
/// let verdict = verify_commit_against_kel(commit, &device_kel, &root_kel, &pinned, &provider).await;
/// assert!(verdict.is_valid());
/// ```
pub async fn verify_commit_against_kel(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
) -> CommitVerdict {
    verify_commit_against_kel_witnessed(
        commit_bytes,
        device_kel,
        root_kel,
        pinned_roots,
        provider,
        &NoWitnessReceipts,
        VerifierWitnessPolicy::Warn,
    )
    .await
    .verdict
}

/// Verify a commit and gate the signer's root KEL on M-of-N witness receipts.
///
/// Like [`verify_commit_against_kel`] but resolves the root KEL's witness
/// receipts through `receipt_lookup` and applies a verifier-side `policy`:
/// under [`VerifierWitnessPolicy::Warn`] an under-quorum root is a non-fatal
/// [`WitnessGateStatus::UnderQuorum`]; under
/// [`VerifierWitnessPolicy::RequireWitnesses`] it is a fatal
/// [`CommitVerdict::WitnessQuorumNotMet`]. A `bt=0` root verifies unchanged.
///
/// Args:
/// * `commit_bytes`: The raw git commit object.
/// * `device_kel`: The signer device's KEL events.
/// * `root_kel`: The root (delegator) KEL events.
/// * `pinned_roots`: Trusted root `did:keri:` strings.
/// * `provider`: Crypto provider for signature verification.
/// * `receipt_lookup`: Source of the root KEL's witness receipts.
/// * `policy`: The verifier's witness policy (independent of the signer's).
///
/// Usage:
/// ```ignore
/// let wv = verify_commit_against_kel_witnessed(c, &dk, &rk, &pinned, &p, &lookup, policy).await;
/// assert!(wv.verdict.is_valid());
/// ```
pub async fn verify_commit_against_kel_witnessed(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    receipt_lookup: &dyn WitnessReceiptLookup,
    policy: VerifierWitnessPolicy,
) -> WitnessedVerdict {
    // 1. Replay + witness-gate the root KEL (validates SAIDs incl. the
    //    self-addressing icp prefix, then checks M-of-N witness agreement).
    let replay = match validate_kel_with_receipts(root_kel, None, receipt_lookup) {
        Ok(r) => r,
        Err(e) => {
            return WitnessedVerdict {
                verdict: CommitVerdict::RootKelInvalid(e.to_string()),
                witness: WitnessGateStatus::NotRequired,
            };
        }
    };
    let root_state = replay.state().clone();
    let root_did = format!("did:keri:{}", root_state.prefix);

    let witness = match &replay {
        WitnessedReplay::Accepted(s) => {
            if s.backers.is_empty() {
                WitnessGateStatus::NotRequired
            } else {
                WitnessGateStatus::Met
            }
        }
        WitnessedReplay::Pending {
            collected,
            required,
            state,
            ..
        } => {
            let required = required
                .simple_value()
                .map(|v| v as usize)
                .unwrap_or(state.backers.len());
            let status = WitnessGateStatus::UnderQuorum {
                collected: *collected,
                required,
            };
            // The verifier's own policy decides fail-open vs fail-closed —
            // never the signer's self-declared WitnessPolicy.
            if matches!(policy, VerifierWitnessPolicy::RequireWitnesses) {
                return WitnessedVerdict {
                    verdict: CommitVerdict::WitnessQuorumNotMet {
                        root_did,
                        collected: *collected,
                        required,
                    },
                    witness: status,
                };
            }
            status
        }
    };

    let verdict = authorize_commit(
        commit_bytes,
        device_kel,
        root_kel,
        pinned_roots,
        provider,
        root_state,
    )
    .await;
    WitnessedVerdict { verdict, witness }
}

/// Steps 2–6 of commit authorization, given an already replayed `root_state`:
/// pinned-root + abandonment checks, device-KEL replay, delegation/revocation,
/// duplicity warning, and the in-process SSH-signature binding.
async fn authorize_commit(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    root_state: auths_keri::KeyState,
) -> CommitVerdict {
    let root_prefix = root_state.prefix.clone();
    let root_did = format!("did:keri:{root_prefix}");

    // 2. The root must be pinned (the trailer-claimed root may only SELECT a pinned root).
    if !pinned_roots.contains(&root_did) {
        return CommitVerdict::RootNotPinned(root_did);
    }
    if root_state.is_abandoned {
        return CommitVerdict::RootAbandoned;
    }

    // 3. Replay the device KEL (a dip needs the delegator lookup against the root).
    let lookup = RootKelLookup { root_kel };
    let device_state = match validate_kel_with_lookup(device_kel, Some(&lookup)) {
        Ok(s) => s,
        Err(e) => {
            // A device dip the root never anchored fails replay here (the lookup
            // can't resolve its delegation seal) — surface that distinctly from a
            // structurally-broken device KEL.
            if let Some(first @ Event::Dip(_)) = device_kel.first()
                && validate_delegation(first, root_kel).is_err()
            {
                return CommitVerdict::DelegationSealNotFound;
            }
            return CommitVerdict::DeviceKelInvalid(e.to_string());
        }
    };
    let device_prefix = device_state.prefix.clone();
    let device_did = format!("did:keri:{device_prefix}");

    // 4. Authorization: the pinned root signing directly, or a non-revoked delegate.
    // Replay already confirmed the dip is anchored by *a* delegator (via the lookup);
    // here we confirm that delegator is THIS root and the delegation is still live.
    let root_signs_directly = device_prefix == root_prefix && device_state.delegator.is_none();
    if !root_signs_directly {
        match &device_state.delegator {
            Some(delegator) if *delegator == root_prefix => {}
            _ => {
                return CommitVerdict::NotDelegatedByClaimedRoot {
                    device_did,
                    root_did,
                };
            }
        }
        if revocation_status(root_kel, &device_prefix) {
            return CommitVerdict::DeviceRevoked;
        }
    }

    // 5. Non-fatal duplicity warning on the root KEL (trust-on-first-sight, fail-open).
    let refs: Vec<KelEventRef> = root_kel
        .iter()
        .map(|e| KelEventRef {
            prefix: root_prefix.as_str(),
            seq: e.sequence().value() as u64,
            said: e.said().as_str(),
        })
        .collect();
    let duplicitous_root = !matches!(
        detect_duplicity(&refs),
        crate::duplicity::DuplicityReport::Clean
    );

    // 6. Binding + in-process SSH-signature verification against the device's CURRENT key.
    let Some(current_cesr) = device_state.current_keys.first() else {
        return CommitVerdict::DeviceKelInvalid("device KEL has no current key".to_string());
    };
    let Some(current_pk) = cesr_to_device_pk(current_cesr) else {
        return CommitVerdict::DeviceKelInvalid("device current key is undecodable".to_string());
    };

    match verify_commit_signature(
        commit_bytes,
        std::slice::from_ref(&current_pk),
        provider,
        None,
    )
    .await
    {
        Ok(_) => CommitVerdict::Valid {
            signer_did: device_did,
            root_did,
            duplicitous_root,
        },
        Err(CommitVerificationError::UnsignedCommit) => CommitVerdict::Unsigned,
        Err(CommitVerificationError::GpgNotSupported) => CommitVerdict::GpgUnsupported,
        Err(CommitVerificationError::SignatureInvalid) => CommitVerdict::SshSignatureInvalid,
        Err(CommitVerificationError::NamespaceMismatch { .. }) => {
            CommitVerdict::SshSignatureInvalid
        }
        Err(CommitVerificationError::UnknownSigner) => {
            classify_unknown_signer(commit_bytes, device_kel, &current_pk)
        }
        Err(_) => CommitVerdict::SshSignatureInvalid,
    }
}

/// The SSH signer key isn't the current key — distinguish a *superseded* device key
/// (rotated away) from an unrelated one for a clearer verdict.
fn classify_unknown_signer(
    commit_bytes: &[u8],
    device_kel: &[Event],
    current_pk: &DevicePublicKey,
) -> CommitVerdict {
    let Ok(content) = std::str::from_utf8(commit_bytes) else {
        return CommitVerdict::SignerKeyMismatch;
    };
    let Ok(extracted) = extract_ssh_signature(content) else {
        return CommitVerdict::SignerKeyMismatch;
    };
    let Ok(envelope) = parse_sshsig_pem(&extracted.signature_pem) else {
        return CommitVerdict::SignerKeyMismatch;
    };
    if envelope.public_key != *current_pk
        && establishment_keys(device_kel).contains(&envelope.public_key)
    {
        return CommitVerdict::SignedBySupersededKey;
    }
    CommitVerdict::SignerKeyMismatch
}
