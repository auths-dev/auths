//! Per-prefix KEL store — one Git ref per member KEL.
//!
//! The witness write path stores each member's KEL under its **own** ref,
//! `refs/auths/kel/<s1>/<prefix>` (`s1` = the first two prefix characters, the
//! same shard the packed tree uses), with the identity's familiar tree layout
//! (`events/<seq>.json`, `events/<seq>.attachments.cesr`, `tip.json`,
//! `state.json`) rooted directly at the ref's tree.
//!
//! This is the storage shape the bulk-onboarding bench (`tests/scale/REPORT.md`)
//! and the payment-path study argue for: short, independent KELs that replay in
//! milliseconds, and **no global lock** — concurrent appends to *distinct*
//! prefixes touch distinct refs and distinct advisory locks, so onboarding N
//! identities never serializes on a shared ref the way the packed
//! `refs/auths/registry` backend does. Same-prefix appends serialize on a
//! per-prefix lock, which is exactly the first-seen ordering a witness wants.
//!
//! Git is the source of truth. Everything else (the witness's SQLite
//! `first_seen`/`receipts` tables, roster indexes) is a derived read index.

use std::fs::File;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt;
use git2::{Commit, Repository, Tree};

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::ports::registry::RegistryError;
use auths_id::storage::registry::schemas::{CachedStateJson, TipInfo};
use auths_id::storage::registry::shard::shard_prefix;
use auths_keri::{Prefix, SignedEvent, state_after_event, validate_signed_event};
use auths_keri::{validate_for_append, verify_event_crypto, verify_event_said};
use auths_verifier::clock::{ClockProvider, SystemClock};

use super::tree_ops::{TreeMutator, TreeNavigator};

/// Root of the per-prefix KEL ref namespace.
///
/// Everything under it is fetched by the witness replication refspec
/// (`+refs/auths/*:refs/auths/*`) and served read-only over git smart-HTTP.
pub const KEL_REF_ROOT: &str = "refs/auths/kel";

/// Directory (inside the repo dir, outside the object store) holding the
/// per-prefix advisory lock files.
const KEL_LOCK_DIR: &str = ".auths-kel-locks";

/// Outcome of an idempotent signed append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelAppendOutcome {
    /// The event extended the KEL — a new commit was created.
    Appended,
    /// The identical event (same sequence, same SAID) was already stored;
    /// nothing was written. Re-submission is a no-op, never a fork.
    AlreadyStored,
}

/// The Git ref a prefix's KEL lives under.
///
/// Args:
/// * `prefix`: The member's KERI prefix.
///
/// Usage:
/// ```ignore
/// let ref_name = kel_ref(&prefix)?; // refs/auths/kel/EO/EO3x…
/// ```
pub fn kel_ref(prefix: &Prefix) -> Result<String, RegistryError> {
    let (s1, _) = shard_prefix(prefix)?;
    Ok(format!("{KEL_REF_ROOT}/{s1}/{}", prefix.as_str()))
}

/// Per-prefix KEL store over a Git repository.
///
/// Each member's KEL is an independent chain of commits on its own ref; every
/// append validates the full KERI ruleset (SAID, sequence, prior-digest chain,
/// pre-rotation commitment, and — when signatures are attached — the
/// controller signatures themselves) before anything is written.
#[derive(Clone)]
pub struct PerPrefixKelStore {
    repo_path: PathBuf,
    clock: Arc<dyn ClockProvider>,
}

impl PerPrefixKelStore {
    /// Open a store over an existing Git repository (bare or with worktree).
    ///
    /// Args:
    /// * `repo_path`: Path to the repository (the witness's `--registry` dir).
    ///
    /// Usage:
    /// ```ignore
    /// let store = PerPrefixKelStore::open("/data/registry");
    /// ```
    pub fn open(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
            clock: Arc::new(SystemClock),
        }
    }

    /// Open a store with an injected clock (tests, deterministic commits).
    ///
    /// Args:
    /// * `repo_path`: Path to the repository.
    /// * `clock`: Clock used for commit timestamps.
    pub fn with_clock(repo_path: impl Into<PathBuf>, clock: Arc<dyn ClockProvider>) -> Self {
        Self {
            repo_path: repo_path.into(),
            clock,
        }
    }

    /// The repository path this store operates on.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    fn open_repo(&self) -> Result<Repository, RegistryError> {
        Repository::open(&self.repo_path).map_err(|e| RegistryError::NotFound {
            entity_type: "repository".into(),
            id: format!("{}: {}", self.repo_path.display(), e.message()),
        })
    }

    /// Current tip commit + tree of a prefix's KEL ref, or `None` before inception.
    fn tip_commit_and_tree<'r>(
        &self,
        repo: &'r Repository,
        prefix: &Prefix,
    ) -> Result<Option<(Commit<'r>, Tree<'r>)>, RegistryError> {
        let ref_name = kel_ref(prefix)?;
        match repo.find_reference(&ref_name) {
            Ok(reference) => {
                let commit = reference
                    .peel_to_commit()
                    .map_err(|e| RegistryError::Internal(format!("broken KEL ref: {e}")))?;
                let tree = commit
                    .tree()
                    .map_err(|e| RegistryError::Internal(format!("broken KEL tree: {e}")))?;
                Ok(Some((commit, tree)))
            }
            Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(RegistryError::storage(e)),
        }
    }

    /// Append a signed event to a prefix's KEL, validating the full ruleset.
    ///
    /// Idempotent: re-submitting an event already at its sequence with the
    /// same SAID returns [`KelAppendOutcome::AlreadyStored`]; a *different*
    /// event at an occupied sequence is refused with
    /// [`RegistryError::EventExists`] — append-only, never a fork.
    ///
    /// When `attachment` carries CESR indexed signatures they are verified
    /// against the event's key list (and, for rotations, the prior
    /// pre-rotation commitments) via `validate_signed_event`. An empty
    /// attachment skips signature verification — callers that require signed
    /// ingest (the witness sink) must enforce non-empty attachments.
    ///
    /// Args:
    /// * `prefix`: The member prefix the event belongs to.
    /// * `event`: The finalized event.
    /// * `attachment`: CESR attachment bytes (`-A…` sigs, optional `-G…` seal).
    ///
    /// Usage:
    /// ```ignore
    /// let outcome = store.append_signed_event(&prefix, &event, &attachment)?;
    /// ```
    pub fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
    ) -> Result<KelAppendOutcome, RegistryError> {
        let _lock = PrefixLock::acquire(&self.repo_path, prefix)?;
        let repo = self.open_repo()?;
        let current = self.tip_commit_and_tree(&repo, prefix)?;

        let seq = event.sequence().value();
        let tip = self.read_tip(&repo, current.as_ref().map(|(_, t)| t))?;

        if let Some(outcome) = self.check_idempotent_resubmission(&repo, prefix, &tip, event)? {
            return Ok(outcome);
        }
        validate_append_position(prefix, event, seq, tip.as_ref())?;

        let state = self.read_cached_state(&repo, current.as_ref().map(|(_, t)| t));
        verify_event_said(event).map_err(said_error)?;
        verify_event_crypto(event, state.as_ref()).map_err(crypto_error)?;
        verify_attachment_signatures(event, state.as_ref(), attachment)?;

        let new_state = state_after_event(state.as_ref(), event)
            .map_err(|e| RegistryError::Internal(e.to_string()))?;
        self.commit_event(&repo, prefix, event, attachment, &new_state, current)?;
        Ok(KelAppendOutcome::Appended)
    }

    /// Idempotency check: same-(seq, SAID) resubmission is a stored no-op; a
    /// conflicting SAID at an occupied sequence is a refused fork.
    fn check_idempotent_resubmission(
        &self,
        repo: &Repository,
        prefix: &Prefix,
        tip: &Option<TipInfo>,
        event: &Event,
    ) -> Result<Option<KelAppendOutcome>, RegistryError> {
        let seq = event.sequence().value();
        let Some(tip) = tip else {
            return Ok(None);
        };
        if seq > tip.sequence {
            return Ok(None);
        }
        let stored = self.get_event_in_repo(repo, prefix, seq)?;
        if stored.said() == event.said() {
            return Ok(Some(KelAppendOutcome::AlreadyStored));
        }
        Err(RegistryError::EventExists {
            prefix: prefix.to_string(),
            seq,
        })
    }

    fn read_tip(
        &self,
        repo: &Repository,
        tree: Option<&Tree<'_>>,
    ) -> Result<Option<TipInfo>, RegistryError> {
        let Some(tree) = tree else {
            return Ok(None);
        };
        let navigator = TreeNavigator::new(repo, tree.clone());
        match navigator.read_blob_path(TIP_FILE) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(_) => Ok(None),
        }
    }

    fn read_cached_state(&self, repo: &Repository, tree: Option<&Tree<'_>>) -> Option<KeyState> {
        let tree = tree?;
        let navigator = TreeNavigator::new(repo, tree.clone());
        let bytes = navigator.read_blob_path(STATE_FILE).ok()?;
        let cached: CachedStateJson = serde_json::from_slice(&bytes).ok()?;
        Some(cached.state)
    }

    /// Write event + tip + state (+ attachment) as one commit and advance the ref.
    fn commit_event(
        &self,
        repo: &Repository,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
        new_state: &KeyState,
        current: Option<(Commit<'_>, Tree<'_>)>,
    ) -> Result<(), RegistryError> {
        let seq = event.sequence().value();
        let mut mutator = TreeMutator::new();
        mutator.write_blob(&event_file(seq), serde_json::to_vec_pretty(event)?);
        let tip = TipInfo::new(seq, event.said().clone());
        mutator.write_blob(TIP_FILE, serde_json::to_vec_pretty(&tip)?);
        let cached = CachedStateJson::new(new_state.clone(), event.said().clone());
        mutator.write_blob(STATE_FILE, serde_json::to_vec_pretty(&cached)?);
        if !attachment.is_empty() {
            mutator.write_blob(&attachment_file(seq), attachment.to_vec());
        }

        let (parent, base_tree) = match &current {
            Some((commit, tree)) => (Some(commit), Some(tree)),
            None => (None, None),
        };
        let tree_oid = mutator.build_tree(repo, base_tree)?;
        let tree = repo.find_tree(tree_oid).map_err(RegistryError::storage)?;
        let signature = self.commit_signature(repo)?;
        let parents: Vec<&Commit> = parent.into_iter().collect();
        let message = format!("Append event {} seq {}", prefix, seq);
        let commit_oid = repo
            .commit(None, &signature, &signature, &message, &tree, &parents)
            .map_err(RegistryError::storage)?;

        let ref_name = kel_ref(prefix)?;
        repo.reference(&ref_name, commit_oid, true, &message)
            .map_err(RegistryError::storage)?;
        Ok(())
    }

    fn commit_signature(
        &self,
        repo: &Repository,
    ) -> Result<git2::Signature<'static>, RegistryError> {
        let now = self.clock.now();
        repo.signature()
            .or_else(|_| {
                git2::Signature::new(
                    "auths-witness",
                    "witness@auths.local",
                    &git2::Time::new(now.timestamp(), 0),
                )
            })
            .map_err(RegistryError::storage)
    }

    /// The tip (latest sequence + SAID) of a prefix's KEL.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    pub fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        let repo = self.open_repo()?;
        let current = self.tip_commit_and_tree(&repo, prefix)?;
        self.read_tip(&repo, current.as_ref().map(|(_, t)| t))?
            .ok_or_else(|| RegistryError::identity_not_found(prefix))
    }

    /// A stored event by sequence number.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    /// * `seq`: The event's sequence number.
    pub fn get_event(&self, prefix: &Prefix, seq: u128) -> Result<Event, RegistryError> {
        let repo = self.open_repo()?;
        self.get_event_in_repo(&repo, prefix, seq)
    }

    fn get_event_in_repo(
        &self,
        repo: &Repository,
        prefix: &Prefix,
        seq: u128,
    ) -> Result<Event, RegistryError> {
        let Some((_, tree)) = self.tip_commit_and_tree(repo, prefix)? else {
            return Err(RegistryError::identity_not_found(prefix));
        };
        let navigator = TreeNavigator::new(repo, tree);
        let bytes = navigator
            .read_blob_path(&event_file(seq))
            .map_err(|_| RegistryError::event_not_found(prefix, seq))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// A stored event's CESR attachment, if one was written.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    /// * `seq`: The event's sequence number.
    pub fn get_attachment(
        &self,
        prefix: &Prefix,
        seq: u128,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        let repo = self.open_repo()?;
        let Some((_, tree)) = self.tip_commit_and_tree(&repo, prefix)? else {
            return Ok(None);
        };
        let navigator = TreeNavigator::new(&repo, tree);
        Ok(navigator.read_blob_path(&attachment_file(seq)).ok())
    }

    /// Visit a prefix's events in sequence order, starting at `from_seq`.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    /// * `from_seq`: First sequence to visit.
    /// * `visitor`: Callback; return `ControlFlow::Break(())` to stop early.
    pub fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u128,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let repo = self.open_repo()?;
        let Some((_, tree)) = self.tip_commit_and_tree(&repo, prefix)? else {
            return Err(RegistryError::identity_not_found(prefix));
        };
        let navigator = TreeNavigator::new(&repo, tree.clone());
        let tip = self
            .read_tip(&repo, Some(&tree))?
            .ok_or_else(|| RegistryError::identity_not_found(prefix))?;
        for seq in from_seq..=tip.sequence {
            let bytes = navigator
                .read_blob_path(&event_file(seq))
                .map_err(|_| RegistryError::event_not_found(prefix, seq))?;
            let event: Event = serde_json::from_slice(&bytes)?;
            if visitor(&event).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// The validated key state of a prefix.
    ///
    /// Serves the cached `state.json` when it matches the tip; otherwise
    /// replays the KEL with full validation (SAID, chain linkage, sequence
    /// continuity, crypto commitments), so tampered refs cannot smuggle a
    /// forged state past a reader.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    pub fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        let repo = self.open_repo()?;
        let Some((_, tree)) = self.tip_commit_and_tree(&repo, prefix)? else {
            return Err(RegistryError::identity_not_found(prefix));
        };
        let navigator = TreeNavigator::new(&repo, tree.clone());
        if let Ok(state_bytes) = navigator.read_blob_path(STATE_FILE)
            && let Ok(cached) = serde_json::from_slice::<CachedStateJson>(&state_bytes)
            && let Ok(tip_bytes) = navigator.read_blob_path(TIP_FILE)
            && let Ok(tip) = serde_json::from_slice::<TipInfo>(&tip_bytes)
            && cached.is_valid_for(&tip.said)
        {
            return Ok(cached.state);
        }
        self.replay_and_validate(prefix)
    }

    /// Replay a prefix's KEL from inception with full validation.
    fn replay_and_validate(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        let mut state: Option<KeyState> = None;
        let mut replay_error: Option<RegistryError> = None;
        self.visit_events(prefix, 0, &mut |event| {
            let seq = event.sequence().value();
            let validation = if seq == 0 {
                verify_event_said(event).and_then(|()| verify_event_crypto(event, None))
            } else {
                match &state {
                    Some(s) => validate_for_append(event, s),
                    None => {
                        replay_error = Some(RegistryError::Internal(format!(
                            "KEL replay: event at seq {seq} but no prior state"
                        )));
                        return ControlFlow::Break(());
                    }
                }
            };
            if let Err(e) = validation {
                replay_error = Some(RegistryError::Internal(format!(
                    "KEL validation failed at seq {seq}: {e}"
                )));
                return ControlFlow::Break(());
            }
            match state_after_event(state.as_ref(), event) {
                Ok(next) => {
                    state = Some(next);
                    ControlFlow::Continue(())
                }
                Err(e) => {
                    replay_error = Some(RegistryError::Internal(format!(
                        "KEL replay failed at seq {seq}: {e}"
                    )));
                    ControlFlow::Break(())
                }
            }
        })?;
        if let Some(err) = replay_error {
            return Err(err);
        }
        state.ok_or_else(|| RegistryError::identity_not_found(prefix))
    }

    /// All prefixes this store holds, enumerated from the ref namespace.
    ///
    /// This is a ref listing — O(#identities) with no KEL walks — so a roster
    /// never replays anything. (Packed-refs keep it one file read.)
    pub fn list_prefixes(&self) -> Result<Vec<Prefix>, RegistryError> {
        let repo = self.open_repo()?;
        let glob = format!("{KEL_REF_ROOT}/*");
        let refs = repo
            .references_glob(&glob)
            .map_err(RegistryError::storage)?;
        let mut prefixes = Vec::new();
        for reference in refs.flatten() {
            if let Ok(name) = reference.name()
                && let Some(tail) = name.rsplit('/').next()
                && let Ok(prefix) = Prefix::new(tail.to_string())
            {
                prefixes.push(prefix);
            }
        }
        Ok(prefixes)
    }

    /// Whether this store holds a KEL for `prefix`.
    ///
    /// Args:
    /// * `prefix`: The member prefix.
    pub fn holds(&self, prefix: &Prefix) -> Result<bool, RegistryError> {
        let repo = self.open_repo()?;
        Ok(self.tip_commit_and_tree(&repo, prefix)?.is_some())
    }
}

const TIP_FILE: &str = "tip.json";
const STATE_FILE: &str = "state.json";

fn event_file(seq: u128) -> String {
    format!("events/{seq:08}.json")
}

fn attachment_file(seq: u128) -> String {
    format!("events/{seq:08}.attachments.cesr")
}

/// Positional constraints: prefix match, monotonic sequence, inception-first,
/// prior-SAID chain. Mirrors the packed backend's append constraints.
fn validate_append_position(
    prefix: &Prefix,
    event: &Event,
    seq: u128,
    tip: Option<&TipInfo>,
) -> Result<(), RegistryError> {
    if event.prefix() != prefix {
        return Err(RegistryError::InvalidPrefix {
            prefix: prefix.to_string(),
            reason: format!(
                "event prefix '{}' does not match expected '{}'",
                event.prefix(),
                prefix
            ),
        });
    }
    let expected_seq = tip.map(|t| t.sequence + 1).unwrap_or(0);
    if seq != expected_seq {
        return Err(RegistryError::SequenceGap {
            prefix: prefix.to_string(),
            expected: expected_seq,
            got: seq,
        });
    }
    if seq == 0 && !event.is_inception() {
        return Err(RegistryError::InvalidEvent {
            reason: "first event (seq 0) must be inception".into(),
        });
    }
    if seq > 0 {
        let prev = event
            .previous()
            .ok_or_else(|| RegistryError::InvalidEvent {
                reason: format!("event at seq {seq} must reference a prior SAID"),
            })?;
        let expected_prev = tip
            .map(|t| t.said.as_str())
            .ok_or_else(|| RegistryError::Internal("no tip for non-zero sequence".into()))?;
        if prev.as_str() != expected_prev {
            return Err(RegistryError::SaidMismatch {
                expected: expected_prev.to_string(),
                actual: prev.to_string(),
            });
        }
    }
    Ok(())
}

/// Verify CESR attachment signatures against the event's key list when present.
///
/// A delegated attachment (`-A…-G…`) contributes its signature group; the
/// source-seal couple is stored verbatim but not interpreted here (bilateral
/// delegation binding is a verifier/replay concern).
fn verify_attachment_signatures(
    event: &Event,
    state: Option<&KeyState>,
    attachment: &[u8],
) -> Result<(), RegistryError> {
    if attachment.is_empty() {
        return Ok(());
    }
    let (signatures, _seals) = auths_keri::parse_delegated_attachment(attachment).map_err(|e| {
        RegistryError::InvalidEvent {
            reason: format!("unparseable CESR attachment: {e}"),
        }
    })?;
    if signatures.is_empty() {
        return Ok(());
    }
    let signed = SignedEvent::new(event.clone(), signatures);
    validate_signed_event(&signed, state).map_err(|e| RegistryError::InvalidEvent {
        reason: format!("attachment signature verification failed: {e}"),
    })
}

fn said_error(e: auths_keri::ValidationError) -> RegistryError {
    match e {
        auths_keri::ValidationError::InvalidSaid { expected, actual } => {
            RegistryError::SaidMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            }
        }
        other => RegistryError::InvalidEvent {
            reason: other.to_string(),
        },
    }
}

fn crypto_error(e: auths_keri::ValidationError) -> RegistryError {
    match e {
        auths_keri::ValidationError::SignatureFailed { sequence } => RegistryError::InvalidEvent {
            reason: format!("signature verification failed at sequence {sequence}"),
        },
        auths_keri::ValidationError::CommitmentMismatch { sequence } => {
            RegistryError::InvalidEvent {
                reason: format!("pre-rotation commitment mismatch at sequence {sequence}"),
            }
        }
        other => RegistryError::InvalidEvent {
            reason: other.to_string(),
        },
    }
}

/// Advisory lock scoped to one prefix — concurrent appends to distinct
/// prefixes never contend.
struct PrefixLock {
    file: File,
}

impl PrefixLock {
    fn acquire(repo_path: &Path, prefix: &Prefix) -> Result<Self, RegistryError> {
        let dir = repo_path.join(KEL_LOCK_DIR);
        std::fs::create_dir_all(&dir)?;
        let (s1, _) = shard_prefix(prefix)?;
        let file = File::create(dir.join(format!("{s1}-{}.lock", prefix.as_str())))?;
        file.lock_exclusive()?;
        Ok(Self { file })
    }
}

impl Drop for PrefixLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
