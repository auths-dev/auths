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
    CesrKey, Event, KelSealIndex, KeriPublicKey, Prefix, Seal, TrustedKel, WitnessedReplay,
    validate_delegation,
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
    /// The root has revoked this device/agent's delegation and the commit carries
    /// no in-band signing position, so it cannot be ordered against the revocation
    /// (conservative flat rejection — preserves the no-position default).
    DeviceRevoked,
    /// The commit was signed **at or after** the delegator anchored the revocation
    /// (its in-band `Auths-Anchor-Seq` is ≥ the revocation's KEL position). Distinct
    /// from [`CommitVerdict::DeviceRevoked`]: a commit signed *before* the revocation
    /// stays [`CommitVerdict::Valid`] — revocation is ordered by KEL position, never
    /// wall-clock, so legitimate prior history is not retroactively invalidated.
    SignedAfterRevocation {
        /// The signer's `did:keri:`.
        signer_did: String,
        /// The signing position claimed in-band (`Auths-Anchor-Seq`).
        signed_at: u128,
        /// The KEL position at which the delegator anchored the revocation.
        revoked_at: u128,
    },
    /// The agent signed exercising a capability outside its delegator-anchored
    /// scope (the delegator never granted it). Scope is advisory authorization
    /// anchored by the delegator (the ACDC upgrade is Epic F).
    OutsideAgentScope {
        /// The signer's `did:keri:`.
        signer_did: String,
        /// The capability the commit claimed that the scope does not grant.
        capability: String,
    },
    /// The agent signed at/after its delegator-anchored expiry. Checked against the
    /// signing time via an injected `now` (no wall-clock in the verifier).
    AgentExpired {
        /// The signer's `did:keri:`.
        signer_did: String,
        /// The expiry instant (Unix epoch seconds) the delegator anchored.
        expired_at: i64,
        /// The signing time the commit was checked against (injected `now`).
        signed_at: i64,
    },
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

    /// A stable, machine-readable code for this verdict, suitable for the `status`
    /// field of structured output. Lets a consumer attribute a rejection to its
    /// specific cause (e.g. `outside-agent-scope`) without parsing the human
    /// `error` string. These codes are part of the CLI's machine contract — keep
    /// them stable.
    pub fn code(&self) -> &'static str {
        match self {
            CommitVerdict::Valid { .. } => "valid",
            CommitVerdict::Unsigned => "unsigned",
            CommitVerdict::SshSignatureInvalid => "ssh-signature-invalid",
            CommitVerdict::GpgUnsupported => "gpg-unsupported",
            CommitVerdict::DeviceKelInvalid(_) => "device-kel-invalid",
            CommitVerdict::RootKelInvalid(_) => "root-kel-invalid",
            CommitVerdict::RootNotPinned(_) => "root-not-pinned",
            CommitVerdict::RootAbandoned => "root-abandoned",
            CommitVerdict::NotDelegatedByClaimedRoot { .. } => "not-delegated-by-claimed-root",
            CommitVerdict::DelegationSealNotFound => "delegation-seal-not-found",
            CommitVerdict::DeviceRevoked => "device-revoked",
            CommitVerdict::SignedAfterRevocation { .. } => "signed-after-revocation",
            CommitVerdict::OutsideAgentScope { .. } => "outside-agent-scope",
            CommitVerdict::AgentExpired { .. } => "agent-expired",
            CommitVerdict::SignerKeyMismatch => "signer-key-mismatch",
            CommitVerdict::SignedBySupersededKey => "signed-by-superseded-key",
            CommitVerdict::WitnessQuorumNotMet { .. } => "witness-quorum-not-met",
        }
    }
}

/// The KEL position (root sequence) at which the delegator anchored a revocation
/// (`Seal::Digest{d == device_prefix}`) for the device/agent, or `None` if not
/// revoked. KERI carries no wall-clock, so revocation is ordered by this position.
///
/// Args:
/// * `root_kel`: The delegator's KEL.
/// * `device_prefix`: The delegated identifier's prefix.
fn revocation_position(root_kel: &[Event], device_prefix: &Prefix) -> Option<u128> {
    root_kel.iter().find_map(|event| {
        let revokes = event
            .anchors()
            .iter()
            .any(|seal| matches!(seal, Seal::Digest { d } if d.as_str() == device_prefix.as_str()));
        revokes.then(|| event.sequence().value())
    })
}

/// The CESR commit trailer key carrying the signer's in-band KEL position — the
/// delegator-anchoring sequence in force when the commit was signed. Lets the
/// verifier order a commit against a later revocation by KEL position.
pub const ANCHOR_SEQ_TRAILER: &str = "Auths-Anchor-Seq";

/// Format the signing-position commit trailer (`Auths-Anchor-Seq: <seq>`).
///
/// Args:
/// * `seq`: The delegator-anchoring sequence in force at signing.
///
/// Usage:
/// ```
/// use auths_verifier::anchor_seq_trailer;
/// assert_eq!(anchor_seq_trailer(7), "Auths-Anchor-Seq: 7");
/// ```
pub fn anchor_seq_trailer(seq: u128) -> String {
    format!("{ANCHOR_SEQ_TRAILER}: {seq}")
}

/// Parse the signer's in-band KEL position from a commit's `Auths-Anchor-Seq`
/// trailer, or `None` if absent/unparseable.
///
/// Args:
/// * `commit_bytes`: The raw signed commit content.
fn parse_anchor_seq(commit_bytes: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(commit_bytes).ok()?;
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(ANCHOR_SEQ_TRAILER)?;
        rest.trim_start()
            .strip_prefix(':')?
            .trim()
            .parse::<u128>()
            .ok()
    })
}

/// The commit trailer key naming the root identity (`Auths-Id: did:keri:…`).
pub const ID_TRAILER: &str = "Auths-Id";

/// The commit trailer key naming the signing device/agent (`Auths-Device: …`).
pub const DEVICE_TRAILER: &str = "Auths-Device";

/// Extract `(root_did, device_did)` from a commit's `Auths-Id` / `Auths-Device`
/// trailers. Returns `None` when either trailer is absent (a commit not signed
/// by `auths`). Keys match case-insensitively; the last occurrence wins (git
/// trailer semantics). These are in-band *claims* that select which KELs to
/// replay — the proof is always the signature + the pinned-root check.
///
/// Args:
/// * `raw_commit`: The raw git commit object (headers + message).
///
/// Usage:
/// ```
/// use auths_verifier::commit_signer_trailers;
/// let commit = "tree abc\n\nfix\n\nAuths-Id: did:keri:Er\nAuths-Device: did:keri:Ed\n";
/// assert_eq!(
///     commit_signer_trailers(commit),
///     Some(("did:keri:Er".into(), "did:keri:Ed".into()))
/// );
/// ```
pub fn commit_signer_trailers(raw_commit: &str) -> Option<(String, String)> {
    let message = raw_commit
        .split_once("\n\n")
        .map(|(_, m)| m)
        .unwrap_or(raw_commit);
    let find = |key: &str| {
        message.lines().rev().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(key)
                .then(|| v.trim().to_string())
        })
    };
    Some((find(ID_TRAILER)?, find(DEVICE_TRAILER)?))
}

/// The CESR commit trailer key carrying the capability the commit exercises, checked
/// against the agent's delegator-anchored scope.
pub const SCOPE_TRAILER: &str = "Auths-Scope";

/// Format a scope-claim commit trailer (`Auths-Scope: <cap>[,<cap>…]`).
///
/// Args:
/// * `capabilities`: The capabilities the commit exercises.
///
/// Usage:
/// ```
/// use auths_verifier::scope_trailer;
/// assert_eq!(scope_trailer(&["sign_commit".into()]), "Auths-Scope: sign_commit");
/// ```
pub fn scope_trailer(capabilities: &[String]) -> String {
    format!("{SCOPE_TRAILER}: {}", capabilities.join(","))
}

/// Parse the capabilities a commit claims from its `Auths-Scope` trailer.
fn parse_scope_claim(commit_bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(commit_bytes) else {
        return Vec::new();
    };
    text.lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(SCOPE_TRAILER)?
                .trim_start()
                .strip_prefix(':')
                .map(|rest| {
                    rest.trim()
                        .split(',')
                        .filter(|c| !c.is_empty())
                        .map(|c| c.trim().to_string())
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_default()
}

/// The agent's latest delegator-anchored scope in `root_kel`, or `None`.
fn read_agent_scope_from_kel(
    root_kel: &[Event],
    agent_prefix: &Prefix,
) -> Option<auths_keri::AgentScope> {
    let mut found = None;
    for event in root_kel {
        for seal in event.anchors() {
            if let Seal::Digest { d } = seal
                && let Some((prefix, scope)) = auths_keri::decode_agent_scope(d.as_str())
                && prefix == agent_prefix.as_str()
            {
                found = Some(scope);
            }
        }
    }
    found
}

/// How a commit's signing position orders against a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocationOrdering {
    /// The delegation was never revoked.
    NotRevoked,
    /// The commit was signed strictly before the revocation's KEL position — valid.
    SignedBefore,
    /// The commit was signed at/after the revocation's KEL position — rejected.
    SignedAfter {
        /// The signing position claimed in-band.
        signed_at: u128,
        /// The revocation's KEL position.
        revoked_at: u128,
    },
    /// Revoked, but the commit carries no in-band position — cannot be ordered.
    RevokedUnknownPosition,
}

/// Order a commit's in-band signing position against the revocation position.
///
/// NOTE (RT-003): the in-band position is a signer-chosen trailer, so the *caller*
/// no longer treats [`RevocationOrdering::SignedBefore`] as acceptance — a
/// currently-revoked delegate fails closed regardless of the claimed position
/// until an independent ordering source (witness receipt / transparency log /
/// signed git-history reachability) exists. This function still computes the
/// ordering so that stronger fix can later accept a `SignedBefore` commit when it
/// is independently corroborated.
fn classify_revocation(
    signing_anchor: Option<u128>,
    revocation: Option<u128>,
) -> RevocationOrdering {
    match (revocation, signing_anchor) {
        (None, _) => RevocationOrdering::NotRevoked,
        (Some(_), None) => RevocationOrdering::RevokedUnknownPosition,
        (Some(rev), Some(sign)) if sign < rev => RevocationOrdering::SignedBefore,
        (Some(rev), Some(sign)) => RevocationOrdering::SignedAfter {
            signed_at: sign,
            revoked_at: rev,
        },
    }
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
    verify_commit_against_kel_witnessed_at(
        commit_bytes,
        device_kel,
        root_kel,
        pinned_roots,
        provider,
        receipt_lookup,
        policy,
        None,
    )
    .await
}

/// Verify a commit with the witness gate AND the delegator-anchored scope/expiry
/// gate, evaluated against the injected signing time `now` (Unix epoch seconds).
///
/// Identical to [`verify_commit_against_kel_witnessed`] plus: when the signer is a
/// delegate whose delegator anchored a scope seal, a commit exercising a capability
/// outside that scope is rejected with [`CommitVerdict::OutsideAgentScope`], and a
/// commit signed at/after the anchored expiry is rejected with
/// [`CommitVerdict::AgentExpired`]. Scope is always read from the delegator's
/// (`root_kel`'s) anchored seals, never agent-self-asserted — a delegate cannot
/// widen its own grant.
///
/// Args:
/// * `commit_bytes`: The raw git commit object.
/// * `device_kel`: The signer's KEL (a delegate `dip`, or a root `icp`).
/// * `root_kel`: The delegator's KEL (carries the scope seal).
/// * `pinned_roots`: Trusted root `did:keri:` strings.
/// * `provider`: Crypto provider for signature verification.
/// * `receipt_lookup`: Source of the root KEL's witness receipts.
/// * `policy`: The verifier's witness policy (independent of the signer's).
/// * `now`: The signing time to check scope/expiry against (injected at the boundary).
///
/// Usage:
/// ```ignore
/// let wv = verify_commit_against_kel_witnessed_scoped(c, &dk, &rk, &pinned, &p, &lk, policy, now).await;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn verify_commit_against_kel_witnessed_scoped(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    receipt_lookup: &dyn WitnessReceiptLookup,
    policy: VerifierWitnessPolicy,
    now: i64,
) -> WitnessedVerdict {
    verify_commit_against_kel_witnessed_at(
        commit_bytes,
        device_kel,
        root_kel,
        pinned_roots,
        provider,
        receipt_lookup,
        policy,
        Some(now),
    )
    .await
}

/// Shared body of the witnessed commit-verify path: replay + witness-gate the root
/// KEL, then authorize the commit. `now` is `None` for the unscoped entrypoint and
/// `Some(epoch_secs)` when the delegator-anchored scope/expiry gate must evaluate.
#[allow(clippy::too_many_arguments)]
async fn verify_commit_against_kel_witnessed_at(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    receipt_lookup: &dyn WitnessReceiptLookup,
    policy: VerifierWitnessPolicy,
    now: Option<i64>,
) -> WitnessedVerdict {
    // 1. Replay + witness-gate the root KEL (validates SAIDs incl. the
    //    self-addressing icp prefix, then checks M-of-N witness agreement).
    // rt-002-allow: root_kel is authenticated at the ingestion boundary before it reaches here (CI --identity-bundle → validate_signed_kel in load_bundle_trust; local registry = trusted self-owned store), and this replay additionally enforces the M-of-N witness gate. Residual: the opt-in --remote/--oobi stranger feed, whose signature-carrying transport is tracked (RT-002 follow-up).
    let replay = match TrustedKel::from_trusted_source(root_kel)
        .replay_with_receipts(None, receipt_lookup)
    {
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
        now,
    )
    .await;
    WitnessedVerdict { verdict, witness }
}

/// Verify a commit and additionally enforce the agent's delegator-anchored
/// scope/expiry against an injected signing time `now` (Unix epoch seconds).
///
/// Identical to [`verify_commit_against_kel`] plus: a delegated signer whose
/// delegator anchored a scope seal is rejected when the commit exercises a capability
/// outside that scope ([`CommitVerdict::OutsideAgentScope`]) or signs at/after the
/// anchored expiry ([`CommitVerdict::AgentExpired`], checked against `now`).
///
/// Args:
/// * `commit_bytes`: The signed commit.
/// * `device_kel`: The signer's KEL.
/// * `root_kel`: The delegator's KEL (carries the scope seal).
/// * `pinned_roots`: Trusted root DIDs.
/// * `provider`: Crypto provider for signature verification.
/// * `now`: The signing time to check expiry against (injected at the boundary).
///
/// Usage:
/// ```ignore
/// let verdict = verify_commit_against_kel_scoped(commit, &device_kel, &root_kel, &pinned, &provider, now).await;
/// ```
pub async fn verify_commit_against_kel_scoped(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    now: i64,
) -> CommitVerdict {
    // rt-002-allow: root_kel is authenticated at the ingestion boundary (CI --identity-bundle → validate_signed_kel in load_bundle_trust; local registry = trusted self-owned store). Residual: opt-in --remote/--oobi stranger feed — signature-carrying transport tracked (RT-002 follow-up).
    let root_state = match TrustedKel::from_trusted_source(root_kel).replay() {
        Ok(state) => state,
        Err(e) => return CommitVerdict::RootKelInvalid(e.to_string()),
    };
    authorize_commit(
        commit_bytes,
        device_kel,
        root_kel,
        pinned_roots,
        provider,
        root_state,
        Some(now),
    )
    .await
}

/// Steps 2–6 of commit authorization, given an already replayed `root_state`:
/// pinned-root + abandonment checks, device-KEL replay, delegation/revocation,
/// duplicity warning, and the in-process SSH-signature binding.
#[allow(clippy::too_many_arguments)]
async fn authorize_commit(
    commit_bytes: &[u8],
    device_kel: &[Event],
    root_kel: &[Event],
    pinned_roots: &[String],
    provider: &dyn CryptoProvider,
    root_state: auths_keri::KeyState,
    now: Option<i64>,
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
    let lookup = KelSealIndex::from_events(root_kel);
    // rt-002-allow: device_kel is authenticated at the ingestion boundary (CI --identity-bundle → validate_signed_kel in load_bundle_trust; local registry = trusted self-owned store); the dip's delegation is additionally bound to the already-replayed root via the root KelSealIndex. Residual: opt-in --remote/--oobi stranger feed — tracked (RT-002 follow-up).
    let device_state =
        match TrustedKel::from_trusted_source(device_kel).replay_with_lookup(Some(&lookup)) {
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

    // 4. Authorization: the pinned root signing directly, or a non-revoked, in-scope
    // delegate. Replay already confirmed the dip is anchored by *a* delegator (via the
    // lookup); this confirms that delegator is THIS root and the delegation is live.
    if let Some(verdict) = reject_unauthorized_delegate(
        commit_bytes,
        root_kel,
        &root_prefix,
        &device_state,
        &device_did,
        &root_did,
        now,
    ) {
        return verdict;
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

/// Step 4 of [`authorize_commit`]: reject a delegate that is not authorized by this
/// root. Returns `Some(verdict)` to reject, `None` when the signer is the pinned root
/// signing directly or a live, in-scope delegate.
///
/// Checks (in order): the delegation names THIS root; the delegate is not revoked
/// (ordered by KEL position, KERI carries no wall-clock — signed-before stays valid,
/// signed-at/after fails, unknown position is the conservative flat rejection); and
/// the commit stays within the delegator-anchored scope (enforced whenever the
/// delegator anchored a scope seal — never agent-self-asserted) and, when a signing
/// time is injected, before any anchored expiry.
fn reject_unauthorized_delegate(
    commit_bytes: &[u8],
    root_kel: &[Event],
    root_prefix: &Prefix,
    device_state: &auths_keri::KeyState,
    device_did: &str,
    root_did: &str,
    now: Option<i64>,
) -> Option<CommitVerdict> {
    let device_prefix = device_state.prefix.clone();
    let root_signs_directly = device_prefix == *root_prefix && device_state.delegator.is_none();
    if root_signs_directly {
        return None;
    }

    match &device_state.delegator {
        Some(delegator) if *delegator == *root_prefix => {}
        _ => {
            return Some(CommitVerdict::NotDelegatedByClaimedRoot {
                device_did: device_did.to_string(),
                root_did: root_did.to_string(),
            });
        }
    }

    let revocation = revocation_position(root_kel, &device_prefix);
    match classify_revocation(parse_anchor_seq(commit_bytes), revocation) {
        RevocationOrdering::NotRevoked => {}
        // RT-003: revocation is terminal for NEW signatures. The in-band
        // `Auths-Anchor-Seq` is signer-chosen, so a "signed before revocation"
        // claim is not a trustworthy ordering source — a revoked-but-unrotated
        // key would simply claim position 0. Until an INDEPENDENT signal exists
        // (witness-receipted KSN / transparency log / signed git-history
        // reachability), a currently-revoked delegate fails closed regardless of
        // the self-reported position. This over-rejects genuinely-prior commits
        // in the stateless verifier — the accepted interim cost (open question 2).
        // `SignedBefore` is still computed so the witness-ordered fix can later
        // accept it when independently corroborated.
        RevocationOrdering::SignedBefore | RevocationOrdering::RevokedUnknownPosition => {
            return Some(CommitVerdict::DeviceRevoked);
        }
        RevocationOrdering::SignedAfter {
            signed_at,
            revoked_at,
        } => {
            return Some(CommitVerdict::SignedAfterRevocation {
                signer_did: device_did.to_string(),
                signed_at,
                revoked_at,
            });
        }
    }

    if let Some(scope) = read_agent_scope_from_kel(root_kel, &device_prefix) {
        // Expiry is time-dependent: only enforceable when a signing time is injected.
        if let Some(now) = now
            && let Some(expires_at) = scope.expires_at
            && now >= expires_at
        {
            return Some(CommitVerdict::AgentExpired {
                signer_did: device_did.to_string(),
                expired_at: expires_at,
                signed_at: now,
            });
        }
        // Capability attenuation is time-independent: a delegate may never exceed the
        // delegator-anchored scope, so it is enforced whether or not a time is given.
        if !scope.capabilities.is_empty() {
            for claimed in parse_scope_claim(commit_bytes) {
                if !scope.capabilities.iter().any(|c| c.as_str() == claimed) {
                    return Some(CommitVerdict::OutsideAgentScope {
                        signer_did: device_did.to_string(),
                        capability: claimed,
                    });
                }
            }
        }
    }

    None
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn trailer_round_trips_signing_sequence() {
        assert_eq!(anchor_seq_trailer(7), "Auths-Anchor-Seq: 7");
        // Parses out of a realistic multi-line commit body.
        let commit =
            "fix: a thing\n\nbody line\n\nAuths-Id: did:keri:Eroot\nAuths-Anchor-Seq: 42\n";
        assert_eq!(parse_anchor_seq(commit.as_bytes()), Some(42));
        assert_eq!(parse_anchor_seq(b"no trailer here"), None);
    }

    #[test]
    fn commit_before_revocation_still_valid() {
        // Signed at KEL position 1, revoked at 2 → before → not rejected.
        assert_eq!(
            classify_revocation(Some(1), Some(2)),
            RevocationOrdering::SignedBefore
        );
    }

    #[test]
    fn commit_after_revocation_rejected_by_position() {
        // Signed at position 3, revoked at 2 → at/after → rejected with both positions.
        assert_eq!(
            classify_revocation(Some(3), Some(2)),
            RevocationOrdering::SignedAfter {
                signed_at: 3,
                revoked_at: 2
            }
        );
        // Signed exactly at the revocation position is also rejected.
        assert!(matches!(
            classify_revocation(Some(2), Some(2)),
            RevocationOrdering::SignedAfter { .. }
        ));
    }

    #[test]
    fn revocation_ordering_is_kel_position_not_wallclock() {
        // Ordering depends only on KEL positions — no clock is consulted.
        // Not revoked → always valid regardless of any position.
        assert_eq!(
            classify_revocation(Some(99), None),
            RevocationOrdering::NotRevoked
        );
        // Revoked but the commit carries no position → conservative (cannot order).
        assert_eq!(
            classify_revocation(None, Some(5)),
            RevocationOrdering::RevokedUnknownPosition
        );
        // The same revocation position yields opposite verdicts purely by the
        // signing position — proving it is positional, not temporal.
        assert_eq!(
            classify_revocation(Some(4), Some(5)),
            RevocationOrdering::SignedBefore
        );
        assert!(matches!(
            classify_revocation(Some(6), Some(5)),
            RevocationOrdering::SignedAfter { .. }
        ));
    }
}
