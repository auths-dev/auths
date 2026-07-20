//! The anchor role — a witness's spend-anchor service.
//!
//! This is the I/O-orchestration half above the pure protocol core: it resolves
//! prior state through the [`AnchorStore`], runs the pure `accept_anchor` rule,
//! and — on acceptance — CAS-stores, cosigns, appends the anchor to the
//! witness's own append-only log, and returns the cosignature together with the
//! member-signed logged inclusion. A cosignature without a logged inclusion is
//! not finalization-grade, so the two are minted together or not at all. The
//! store is the serialization point: a concurrent fork is caught as a lost CAS
//! and re-run against the winner, which yields a duplicity proof if the heads
//! differ. The node never forks the rule; it composes it.
//!
//! The HTTP surface (the `/v1/anchor` submit/read routes and the `/health`
//! probe) is built here too, so the node binary composes one router builder and
//! the integration tests drive the exact same surface over `oneshot`.

// The wall clock is read at this HTTP boundary before it is injected into the
// pure acceptance rule — the same allowance the cosign role and the node binary
// take at their edges.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_anchor::{
    Acceptance, Anchor, AnchorError, AnchorStore, CasOutcome, ControllerKeys, DuplicityProof,
    LoggedInclusion, SeedId, StoreError, WitnessCosignature, accept_anchor,
};
use auths_transparency::{FsTileStore, LogWriter, TileStore, hash_leaf};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::registry::{PartyResolveError, controller_keys_for_party};
use crate::signer::{FileSigner, Signer};
use crate::sqlite_store::SqliteAnchorStore;

/// What the service decided for one submission.
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// The anchor was accepted, stored, cosigned, and logged.
    CoSigned {
        /// The stored anchor.
        anchor: Box<Anchor>,
        /// This witness's cosignature over the anchor's cosign message.
        cosignature: Box<WitnessCosignature>,
        /// The member-signed checkpoint + inclusion proof for the anchor leaf —
        /// what makes the cosignature finalization-grade.
        inclusion: Box<LoggedInclusion>,
    },
    /// The submission exactly matches the last co-signed anchor at this index —
    /// an idempotent replay, accepted as a no-op with nothing re-stored.
    AlreadyAnchored(Box<Anchor>),
    /// The anchor equivocated against the co-signed prior — refused, with the
    /// publishable proof.
    Duplicity(Box<DuplicityProof>),
}

/// A failure serving one submission.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The pure acceptance rule rejected the request (non-monotone, bad sig, …).
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// The anchor store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The witness log faulted while appending or proving.
    #[error("witness log error: {0}")]
    Log(String),
    /// A concurrent writer won the CAS with a non-conflicting anchor; the caller
    /// should retry against fresh prior state.
    #[error("lost a compare-and-set race without a fork — retry")]
    Contended,
}

/// A witness's anchor-acceptance service over a signer, a store, and its own
/// append-only log.
pub struct AnchorService<S, T, L: TileStore> {
    signer: S,
    store: T,
    log: LogWriter<L>,
}

impl<S: Signer, T: AnchorStore, L: TileStore> AnchorService<S, T, L> {
    /// Build a service from a signer, a store, and the witness's log writer.
    ///
    /// The log writer must sign with the SAME Ed25519 identity as `signer` —
    /// verifiers pin one member key for both the cosignature and the logged
    /// inclusion's checkpoint.
    ///
    /// Args:
    /// * `signer`: the witness cosigning identity.
    /// * `store`: the per-seed latest-anchor store.
    /// * `log`: the witness's append-only log, signing as the same identity.
    pub fn new(signer: S, store: T, log: LogWriter<L>) -> Self {
        Self { signer, store, log }
    }

    /// Decide, store, cosign, and log one anchor request.
    ///
    /// Args:
    /// * `req`: the incoming anchor request.
    /// * `keys`: the controller's current keys (resolved from the KEL upstream).
    /// * `now`: injected clock.
    ///
    /// Usage:
    /// ```ignore
    /// match service.submit(&req, &keys, clock.now()).await? {
    ///     SubmitOutcome::CoSigned { cosignature, inclusion, .. } => respond(cosignature, inclusion),
    ///     SubmitOutcome::Duplicity(proof) => refuse_and_publish(proof),
    /// }
    /// ```
    pub async fn submit(
        &self,
        req: &Anchor,
        keys: &ControllerKeys,
        now: DateTime<Utc>,
    ) -> Result<SubmitOutcome, ServiceError> {
        let prior = self.store.latest(&req.seed_id)?;
        match accept_anchor(req, keys, prior.as_ref(), now)? {
            Acceptance::AlreadyAnchored(anchor) => Ok(SubmitOutcome::AlreadyAnchored(anchor)),
            Acceptance::Duplicity(proof) => Ok(SubmitOutcome::Duplicity(proof)),
            Acceptance::CoSign(anchor) => {
                let expected = prior.as_ref().map(|p| p.index);
                match self
                    .store
                    .compare_and_set(&req.seed_id, expected, &anchor)?
                {
                    CasOutcome::Won => {
                        let (cosignature, inclusion) = self.cosign_and_log(&anchor, now).await?;
                        Ok(SubmitOutcome::CoSigned {
                            anchor,
                            cosignature: Box::new(cosignature),
                            inclusion: Box::new(inclusion),
                        })
                    }
                    CasOutcome::Lost(winner) => {
                        match accept_anchor(req, keys, Some(&winner), now)? {
                            Acceptance::AlreadyAnchored(anchor) => {
                                Ok(SubmitOutcome::AlreadyAnchored(anchor))
                            }
                            Acceptance::Duplicity(proof) => Ok(SubmitOutcome::Duplicity(proof)),
                            Acceptance::CoSign(_) => Err(ServiceError::Contended),
                        }
                    }
                }
            }
        }
    }

    /// The latest co-signed anchor for a seed (the public withholding-detection
    /// read).
    ///
    /// Args:
    /// * `seed`: the spend chain to read.
    pub fn latest(&self, seed: &auths_anchor::SeedId) -> Result<Option<Anchor>, ServiceError> {
        Ok(self.store.latest(seed)?)
    }

    /// Cosign an accepted anchor and append it to the witness's own log,
    /// returning the cosignature plus the member-signed logged inclusion.
    async fn cosign_and_log(
        &self,
        anchor: &Anchor,
        now: DateTime<Utc>,
    ) -> Result<(WitnessCosignature, LoggedInclusion), ServiceError> {
        let message = anchor.cosign_bytes().map_err(ServiceError::Anchor)?;
        let cosignature = WitnessCosignature {
            witness_name: self.signer.witness_name().to_string(),
            witness_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                self.signer.public_key(),
            ),
            signature: auths_verifier::Ed25519Signature::from_bytes(self.signer.sign(&message)),
            timestamp: now,
        };

        let leaf = hash_leaf(&message);
        self.log
            .append(leaf, now)
            .await
            .map_err(|e| ServiceError::Log(e.to_string()))?;
        // Proof and checkpoint come from ONE read of the grown log, so the
        // proof is always rooted in exactly the checkpoint beside it.
        let proven = self
            .log
            .prove(&leaf)
            .await
            .map_err(|e| ServiceError::Log(e.to_string()))?;
        let inclusion = LoggedInclusion {
            witness_name: self.signer.witness_name().to_string(),
            checkpoint: proven.signed_checkpoint,
            proof: proven.inclusion_proof,
        };
        Ok((cosignature, inclusion))
    }
}

/// The node's live anchor service, wired to the durable SQLite store and the
/// witness's own append-only log — the concrete type the HTTP surface drives.
pub type NodeAnchorService = AnchorService<FileSigner, SqliteAnchorStore, FsTileStore>;

/// Shared state behind the anchor role's HTTP surface: the acceptance service,
/// the registry the node resolves submitter keys against, and the durable
/// directory where caught equivocation proofs are recorded for later re-serving.
pub struct AppState {
    service: NodeAnchorService,
    registry: PathBuf,
    duplicity_dir: PathBuf,
    witness_name: String,
    roles: Vec<String>,
}

impl AppState {
    /// Assemble the anchor role's shared state.
    ///
    /// Args:
    /// * `service`: the wired anchor-acceptance service.
    /// * `registry`: local copy of the parties' public registry, for key resolution.
    /// * `duplicity_dir`: durable directory where caught equivocation proofs are recorded.
    /// * `witness_name`: this node's public name, echoed at `/health`.
    /// * `roles`: the roles this node serves, echoed at `/health`.
    ///
    /// Usage:
    /// ```ignore
    /// let state = Arc::new(AppState::new(service, registry, data_dir.join("duplicity"), name, roles));
    /// let app = anchor_router(state, true);
    /// ```
    pub fn new(
        service: NodeAnchorService,
        registry: PathBuf,
        duplicity_dir: PathBuf,
        witness_name: String,
        roles: Vec<String>,
    ) -> Self {
        Self {
            service,
            registry,
            duplicity_dir,
            witness_name,
            roles,
        }
    }
}

/// One anchor submission: the anchor plus the party naming the witness resolves
/// keys for. The party fields identify WHO is anchoring; the anchor itself
/// carries no per-record data.
#[derive(Deserialize)]
struct SubmitBody {
    anchor: Anchor,
    party: PartyRef,
}

#[derive(Deserialize)]
struct PartyRef {
    root: String,
    agent: String,
}

fn error_body(status: StatusCode, detail: String) -> Response {
    (status, Json(serde_json::json!({ "error": detail }))).into_response()
}

/// Shape-validate a `{seed}` path segment before decoding, so an RP that passes
/// a `did:` or a head string gets one consistent, product-voiced 400 naming the
/// expected form instead of the internal hex-decoder phrasing. The `Err` is the
/// message; the caller shapes the 400.
fn parse_seed_hex(seed_hex: &str) -> Result<SeedId, String> {
    if seed_hex.len() != 64 || !seed_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "seed must be a 64-character hex seed_id; got '{seed_hex}'"
        ));
    }
    SeedId::from_hex(seed_hex).map_err(|e| e.to_string())
}

/// Durably record a caught equivocation so it outlives the 409 response. A
/// witness that catches a cheat must be able to hand the proof to anyone who
/// asks later, not only the submitter whose fork tripped it.
fn record_duplicity(dir: &Path, proof: &DuplicityProof) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", proof.seed_id.to_hex()));
    let bytes = serde_json::to_vec_pretty(proof).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

/// Read a previously recorded duplicity proof for a seed, if one was caught.
fn read_duplicity(dir: &Path, seed: &SeedId) -> Option<DuplicityProof> {
    let path = dir.join(format!("{}.json", seed.to_hex()));
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn submit_anchor(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SubmitBody>,
) -> Response {
    let keys = match controller_keys_for_party(&state.registry, &body.party.root, &body.party.agent)
    {
        Ok(keys) => keys,
        Err(e @ PartyResolveError::RegistryUnavailable) => {
            return error_body(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
        }
        Err(e) => return error_body(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
    };
    let now = chrono::Utc::now();
    match state.service.submit(&body.anchor, &keys, now).await {
        Ok(SubmitOutcome::CoSigned {
            cosignature,
            inclusion,
            ..
        }) => Json(serde_json::json!({
            "cosignature": *cosignature,
            "inclusion": *inclusion,
        }))
        .into_response(),
        Ok(SubmitOutcome::AlreadyAnchored(anchor)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "already_anchored": true, "index": anchor.index })),
        )
            .into_response(),
        Ok(SubmitOutcome::Duplicity(proof)) => {
            let _ = record_duplicity(&state.duplicity_dir, &proof);
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "duplicity": *proof })),
            )
                .into_response()
        }
        Err(ServiceError::Anchor(e)) => error_body(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        Err(ServiceError::Contended) => {
            error_body(StatusCode::CONFLICT, "contended — retry".to_string())
        }
        Err(e) => error_body(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn latest_anchor(
    State(state): State<Arc<AppState>>,
    AxumPath(seed_hex): AxumPath<String>,
) -> Response {
    let seed = match parse_seed_hex(&seed_hex) {
        Ok(seed) => seed,
        Err(msg) => return error_body(StatusCode::BAD_REQUEST, msg),
    };
    match state.service.latest(&seed) {
        Ok(Some(anchor)) => Json(serde_json::json!({ "anchor": anchor })).into_response(),
        Ok(None) => error_body(StatusCode::NOT_FOUND, "no anchor for this seed".to_string()),
        Err(e) => error_body(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn duplicity_for_seed(
    State(state): State<Arc<AppState>>,
    AxumPath(seed_hex): AxumPath<String>,
) -> Response {
    let seed = match parse_seed_hex(&seed_hex) {
        Ok(seed) => seed,
        Err(msg) => return error_body(StatusCode::BAD_REQUEST, msg),
    };
    match read_duplicity(&state.duplicity_dir, &seed) {
        Some(proof) => Json(serde_json::json!({ "duplicity": proof })).into_response(),
        None => error_body(
            StatusCode::NOT_FOUND,
            "no recorded duplicity for this seed".to_string(),
        ),
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({
        "up": true,
        "roles": state.roles,
        "witness_name": state.witness_name,
    }))
    .into_response()
}

/// Build the anchor role's HTTP surface over shared state.
///
/// The node binary and the integration tests both compose this one builder, so
/// tests drive the exact routes the node serves via `tower::ServiceExt::oneshot`
/// rather than re-deriving them. `serve_health` registers the shared `/health`
/// route; the node omits it here when another role already owns that path.
///
/// Args:
/// * `state`: the anchor role's shared state.
/// * `serve_health`: register the `/health` probe on this router.
///
/// Usage:
/// ```ignore
/// let app = anchor_router(Arc::new(state), true);
/// ```
pub fn anchor_router(state: Arc<AppState>, serve_health: bool) -> Router {
    let mut router = Router::new()
        .route("/v1/anchor", post(submit_anchor))
        .route("/v1/anchor/{seed}", get(latest_anchor))
        .route("/v1/duplicity/{seed}", get(duplicity_for_seed));
    if serve_health {
        router = router.route("/health", get(health));
    }
    router.with_state(state)
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Deterministic fixtures shared by the node's unit tests.

    use auths_anchor::{
        Anchor, ControllerKeys, CurrentKey, CurveType, Head, PartySignature, SeedId, WitnessSetRef,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::{Signer as _, SigningKey};

    pub(crate) fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap()
    }

    pub(crate) fn party_sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    pub(crate) fn signed_anchor(index: u64, head: [u8; 32]) -> Anchor {
        signed_anchor_committing(index, head, "EWit", 1)
    }

    pub(crate) fn signed_anchor_committing(
        index: u64,
        head: [u8; 32],
        said: &str,
        threshold: u32,
    ) -> Anchor {
        let sk = party_sk();
        let mut anchor = Anchor {
            seed_id: SeedId::derive("root", "agent", "seal"),
            index,
            head: Head::from_bytes(head),
            cumulative: index as u128 * 100,
            timestamp: now(),
            witness_set: WitnessSetRef {
                said: said.to_string(),
                threshold,
            },
            sig_party: PartySignature {
                curve: CurveType::Ed25519,
                public_key: sk.verifying_key().as_bytes().to_vec(),
                signature: Vec::new(),
            },
        };
        let msg = anchor.party_signing_bytes().unwrap();
        anchor.sig_party.signature = sk.sign(&msg).to_bytes().to_vec();
        anchor
    }

    pub(crate) fn keys() -> ControllerKeys {
        ControllerKeys {
            current: vec![CurrentKey {
                curve: CurveType::Ed25519,
                public_key: party_sk().verifying_key().as_bytes().to_vec(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{keys, now, signed_anchor};
    use super::*;
    use crate::anchor_store::InMemoryAnchorStore;
    use crate::signer::FileSigner;
    use auths_transparency::{FsTileStore, LogOrigin, LogSigningKey};

    fn service(
        dir: &std::path::Path,
    ) -> AnchorService<FileSigner, InMemoryAnchorStore, FsTileStore> {
        let seed = [1u8; 32];
        let log = LogWriter::new(
            FsTileStore::new(dir.to_path_buf()),
            LogSigningKey::from_seed(seed).unwrap(),
            LogOrigin::new("awn/us-west").unwrap(),
        );
        AnchorService::new(
            FileSigner::from_seed("us-west", seed),
            InMemoryAnchorStore::new(),
            log,
        )
    }

    #[tokio::test]
    async fn cosigns_logs_then_refuses_a_fork() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let first = signed_anchor(1, [1u8; 32]);
        let SubmitOutcome::CoSigned {
            anchor,
            cosignature,
            inclusion,
        } = svc.submit(&first, &keys(), now()).await.unwrap()
        else {
            panic!("expected cosign");
        };

        // The logged inclusion is finalization-grade: checkpoint signed by this
        // witness, proof rooted in it, leaf = this anchor's cosign message.
        let message = anchor.cosign_bytes().unwrap();
        let leaf = hash_leaf(&message);
        inclusion
            .checkpoint
            .verify_log_signature(&cosignature.witness_public_key)
            .unwrap();
        assert_eq!(inclusion.proof.root, inclusion.checkpoint.checkpoint.root);
        inclusion.proof.verify(&leaf).unwrap();

        let fork = signed_anchor(1, [2u8; 32]);
        assert!(matches!(
            svc.submit(&fork, &keys(), now()).await.unwrap(),
            SubmitOutcome::Duplicity(_)
        ));
    }

    #[tokio::test]
    async fn service_output_finalizes_under_the_strict_verifier() {
        use super::tests_support::signed_anchor_committing;
        let dir = tempfile::tempdir().unwrap();
        let seed = [1u8; 32];
        let wsk = ed25519_dalek::SigningKey::from_bytes(&seed);

        let mut set = auths_anchor::WitnessSet {
            said: String::new(),
            threshold: 1,
            members: vec![auths_anchor::WitnessRef {
                name: "us-west".into(),
                curve: auths_anchor::CurveType::Ed25519,
                public_key: wsk.verifying_key().as_bytes().to_vec(),
                operator: None,
            }],
        };
        set.said = set.computed_said().unwrap();

        let req = signed_anchor_committing(1, [7u8; 32], &set.said, 1);
        let svc = service(dir.path());
        let SubmitOutcome::CoSigned {
            anchor,
            cosignature,
            inclusion,
        } = svc.submit(&req, &keys(), now()).await.unwrap()
        else {
            panic!("expected cosign");
        };

        // The whole loop closes: what the node emitted is exactly what the
        // strict offline verifier accepts.
        let finalized = auths_anchor::FinalizedAnchor {
            anchor: *anchor,
            witness_set: set,
            cosignatures: vec![*cosignature],
            inclusion: vec![*inclusion],
        };
        auths_anchor::verify_finalized(&finalized, Some(&finalized.anchor.witness_set.said))
            .unwrap();
    }
}
