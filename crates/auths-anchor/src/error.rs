//! Typed errors for the AWN protocol core.
//!
//! Every failure mode is a closed, named variant — no `anyhow`, no
//! `Box<dyn Error>` (CLAUDE.md domain-error rule). A relying party maps these
//! to its own coarse client/server responses; the variants exist so the node,
//! the watcher, and the tests can branch on exactly what failed.

/// A failure while deciding, finalizing, or verifying a spend anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The party signature did not verify under any current key of the seed's
    /// controller (I-DUP-3: an anchor is only authorized under current keys).
    #[error("party signature does not verify under the controller's current keys")]
    PartySignatureInvalid,

    /// The party's public key is not among the controller's current KEL keys.
    #[error("party key is not a current key of the controller")]
    PartyKeyNotCurrent,

    /// A new anchor's index regressed below the prior anchor — a rollback
    /// attempt. An exact-index, exact-head resubmission is a benign no-op and is
    /// reported separately, so only a true rewind reaches this variant.
    #[error("index {got} regresses below prior {prior} — fetch the latest anchor and extend it")]
    IndexRollback {
        /// The submitted index.
        got: u64,
        /// This witness's last co-signed index for the seed.
        prior: u64,
    },

    /// A new anchor's cumulative total regressed below the prior anchor.
    #[error("cumulative regression: {got} is below prior {prior}")]
    CumulativeRegression {
        /// The submitted cumulative total (cents).
        got: u128,
        /// The prior co-signed cumulative total.
        prior: u128,
    },

    /// A new anchor's timestamp moved backwards relative to the prior anchor.
    #[error("timestamp regression: anchor time precedes the prior anchor")]
    TimestampRegression,

    /// A curve tag names a byte layout that does not match its payload.
    #[error("malformed key or signature material: {0}")]
    MalformedMaterial(String),

    /// A finalized anchor carried fewer distinct cosignatures than its
    /// witness-set threshold requires (I-FINAL-1).
    #[error("insufficient cosignatures: {got} distinct, threshold is {threshold}")]
    ThresholdNotMet {
        /// Distinct, in-set cosignatures counted.
        got: u32,
        /// The declared `t` of the `t`-of-`N` witness set.
        threshold: u32,
    },

    /// A cosignature was attributed to a key outside the anchor's declared
    /// witness set (I-FINAL-2: all cosigners must be inside `𝒲`).
    #[error("cosignature from a witness outside the declared set: {name}")]
    CosignerOutsideSet {
        /// The offending witness name.
        name: String,
    },

    /// The resolved witness set does not match the SAID the anchor commits to
    /// (I-TRUST-3: the anchor points at a KEL-anchored set).
    #[error("witness-set SAID mismatch: anchor commits to {committed}, resolved {resolved}")]
    WitnessSetMismatch {
        /// The SAID the anchor's `witness_set` reference commits to.
        committed: String,
        /// The SAID of the resolved set supplied for verification.
        resolved: String,
    },

    /// A cosignature signature did not verify over the anchor's cosign message.
    #[error("cosignature does not verify for witness {name}")]
    CosignatureInvalid {
        /// The witness whose cosignature failed.
        name: String,
    },

    /// A log inclusion proof did not verify against its stated root.
    #[error("inclusion proof failed: {0}")]
    InclusionInvalid(String),

    /// A duplicity proof was structurally invalid or self-inconsistent.
    #[error("invalid duplicity proof: {0}")]
    InvalidDuplicityProof(String),

    /// An anchor's timestamp is beyond the witness's acceptable future skew —
    /// a post-dated τ would make every later withholding gap (`now − τ_latest`)
    /// read as fresh, so it is refused at the door.
    #[error("anchor timestamp is {ahead_secs}s in the future (max skew {max_secs}s)")]
    TimestampInFuture {
        /// How far ahead of the witness clock the timestamp is.
        ahead_secs: i64,
        /// The maximum tolerated forward skew.
        max_secs: i64,
    },

    /// An anchor timestamp carries sub-second precision. Signing bytes commit
    /// to whole seconds, so sub-second wire values would be malleable without
    /// invalidating the signature — refused instead of silently truncated.
    #[error("anchor timestamp carries sub-second precision")]
    SubSecondTimestamp,

    /// The resolved witness set is structurally invalid (duplicate member
    /// names/keys, zero threshold, or a threshold above the member count).
    #[error("invalid witness set: {0}")]
    SetInvalid(String),

    /// The resolved set's content does not hash to the SAID it claims — the
    /// set is not self-addressing, so nothing it declares can be trusted.
    #[error("witness-set content does not match its SAID: claimed {claimed}, computed {computed}")]
    SetSaidMismatch {
        /// The SAID the resolved set claims for itself.
        claimed: String,
        /// The SAID recomputed from the set's canonical content.
        computed: String,
    },

    /// A cosigner's log checkpoint did not verify under the declared member key.
    #[error("log checkpoint unverifiable for witness {name}: {detail}")]
    CheckpointUnverifiable {
        /// The witness whose checkpoint failed.
        name: String,
        /// What failed.
        detail: String,
    },

    /// A counted cosigner supplied no valid log inclusion for the anchor —
    /// a co-signature without a logged anchor is not finalization-grade.
    #[error("no valid log inclusion for cosigner {name}")]
    InclusionMissing {
        /// The cosigner lacking a logged inclusion.
        name: String,
    },

    /// A byte string that must be exactly 32 bytes (a head or a seed id) was
    /// the wrong length.
    #[error("expected 32 bytes, got {got}")]
    BadLength {
        /// The actual decoded length.
        got: usize,
    },

    /// A hex- or base64-encoded field failed to decode.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Canonicalization of an anchor for signing/verification failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// A failure inside an [`crate::store::AnchorStore`] adapter.
///
/// The store's contract is a compare-and-set (D7); adapters surface their
/// backend faults as this closed set so the accept path can distinguish a lost
/// race (not an error) from an actual storage fault.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The backend rejected or failed the operation.
    #[error("anchor store backend error: {0}")]
    Backend(String),

    /// The stored state for a seed was corrupt or undecodable.
    #[error("corrupt anchor record for seed: {0}")]
    Corrupt(String),
}
