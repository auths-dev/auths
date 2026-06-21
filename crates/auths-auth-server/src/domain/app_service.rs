//! Application service that orchestrates auth domain workflows.
//!
//! Keeps all state-machine logic and cryptographic decisions out of HTTP handlers.

use std::sync::Arc;

use auths_telemetry::{build_audit_event, emit_telemetry};
use auths_verifier::clock::ClockProvider;
use uuid::Uuid;

use chrono::{DateTime, Utc};

use crate::domain::{AuthSession, SessionStatus};
use crate::error::{AuthApiError, AuthApiResult};
use crate::ports::{IdentityResolver, SessionStore};

/// Encapsulates auth challenge orchestration, decoupled from HTTP concerns.
///
/// Usage:
/// ```ignore
/// let svc = AuthAppService::new(store.clone(), resolver.clone(), Arc::new(SystemClock));
/// svc.verify_challenge(VerifyCommand { .. }).await?;
/// let status = svc.get_session_status(&id).await?;
/// ```
pub struct AuthAppService {
    store: Arc<dyn SessionStore>,
    resolver: Arc<dyn IdentityResolver>,
    clock: Arc<dyn ClockProvider>,
}

/// Input for the verify-challenge workflow.
pub struct VerifyCommand {
    pub session_id: Uuid,
    pub did: String,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
}

/// Successful verification result, returned to the caller.
pub struct VerifiedSession {
    pub session_id: Uuid,
    pub did: String,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of a status query.
pub struct SessionStatusView {
    pub id: Uuid,
    pub status: String,
    pub did: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl AuthAppService {
    pub fn new(
        store: Arc<dyn SessionStore>,
        resolver: Arc<dyn IdentityResolver>,
        clock: Arc<dyn ClockProvider>,
    ) -> Self {
        Self {
            store,
            resolver,
            clock,
        }
    }

    /// Provides access to the underlying session store for simple CRUD
    /// operations (e.g. creating a new session in the init handler).
    pub fn sessions(&self) -> &dyn SessionStore {
        self.store.as_ref()
    }

    /// Returns the injected clock, allowing route handlers to obtain
    /// the current time from the same source as session expiry checks.
    pub fn clock(&self) -> &dyn ClockProvider {
        self.clock.as_ref()
    }

    /// Verify a signed challenge, transitioning the session Pending → Verified.
    ///
    /// Args:
    /// * `cmd`: All inputs required for verification.
    ///
    /// Usage:
    /// ```ignore
    /// svc.verify_challenge(cmd).await?;
    /// ```
    pub async fn verify_challenge(&self, cmd: VerifyCommand) -> AuthApiResult<VerifiedSession> {
        let session = self.fetch_pending_session(&cmd.session_id).await?;
        let resolved_key = self
            .resolver
            .resolve_current_key(&cmd.did)
            .await
            .map_err(|e| AuthApiError::ResolutionFailed(e.to_string()))?;
        let presented_key = decode_and_match_public_key(&cmd.public_key, &resolved_key)?;
        verify_challenge_signature(&session, &presented_key, &cmd.signature).await?;
        self.commit_verification(&cmd.session_id, &cmd.did, session.challenge.expires_at)
            .await
    }

    /// Return the current status of a session, auto-expiring if needed.
    ///
    /// Args:
    /// * `id`: The session UUID to look up.
    ///
    /// Usage:
    /// ```ignore
    /// let view = svc.get_session_status(&id).await?;
    /// ```
    pub async fn get_session_status(&self, id: &Uuid) -> AuthApiResult<SessionStatusView> {
        let session = self.get_session_or_expire(id).await?;

        let (status, did) = match &session.status {
            SessionStatus::Pending => ("pending".to_string(), None),
            SessionStatus::Verified { did, .. } => ("verified".to_string(), Some(did.clone())),
            SessionStatus::Expired => ("expired".to_string(), None),
        };

        Ok(SessionStatusView {
            id: *id,
            status,
            did,
            expires_at: session.challenge.expires_at,
        })
    }

    /// Fetch a session and assert it is still Pending and not expired.
    async fn fetch_pending_session(&self, session_id: &Uuid) -> AuthApiResult<AuthSession> {
        let session = self.get_session_or_expire(session_id).await?;

        if matches!(session.status, SessionStatus::Verified { .. }) {
            return Err(AuthApiError::SessionAlreadyVerified(session_id.to_string()));
        }

        if matches!(session.status, SessionStatus::Expired) {
            return Err(AuthApiError::SessionExpired(session_id.to_string()));
        }

        Ok(session)
    }

    /// Fetch a session by ID. If it is Pending but past its TTL, atomically
    /// mark it Expired via CAS and return it with the updated status.
    async fn get_session_or_expire(&self, id: &Uuid) -> AuthApiResult<AuthSession> {
        let mut session = self
            .store
            .get(id)
            .await
            .map_err(|e| AuthApiError::Internal(e.to_string()))?
            .ok_or_else(|| AuthApiError::SessionNotFound(id.to_string()))?;

        if matches!(session.status, SessionStatus::Pending)
            && session.challenge.is_expired(self.clock.now())
        {
            let _ = self
                .store
                .update_status(id, SessionStatus::Pending, SessionStatus::Expired)
                .await;
            session.status = SessionStatus::Expired;
        }

        Ok(session)
    }

    /// Atomically transition the session from Pending to Verified (CAS).
    async fn commit_verification(
        &self,
        session_id: &Uuid,
        did: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthApiResult<VerifiedSession> {
        let verified = self
            .store
            .update_status(
                session_id,
                SessionStatus::Pending,
                SessionStatus::Verified {
                    did: did.to_string(),
                    verified_at: self.clock.now(),
                },
            )
            .await
            .map_err(|e| AuthApiError::Internal(e.to_string()))?;

        if !verified {
            let current = self
                .store
                .get(session_id)
                .await
                .map_err(|e| AuthApiError::Internal(e.to_string()))?;

            return match current.as_ref().map(|s| &s.status) {
                Some(SessionStatus::Expired) | None => {
                    let event = build_audit_event(
                        did,
                        "session_verification",
                        "Expired",
                        self.clock.now().timestamp(),
                    );
                    emit_telemetry(&event);
                    Err(AuthApiError::SessionExpired(session_id.to_string()))
                }
                _ => {
                    let event = build_audit_event(
                        did,
                        "session_verification",
                        "Conflict",
                        self.clock.now().timestamp(),
                    );
                    emit_telemetry(&event);
                    Err(AuthApiError::SessionAlreadyVerified(session_id.to_string()))
                }
            };
        }

        let event = build_audit_event(
            did,
            "session_verification",
            "Success",
            self.clock.now().timestamp(),
        );
        emit_telemetry(&event);

        Ok(VerifiedSession {
            session_id: *session_id,
            did: did.to_string(),
            expires_at,
        })
    }
}

/// Decodes the hex-encoded presented key and verifies it matches the resolved key.
fn decode_and_match_public_key(hex_key: &str, resolved_key: &[u8]) -> AuthApiResult<Vec<u8>> {
    let presented_key = hex::decode(hex_key)
        .map_err(|e| AuthApiError::InvalidRequest(format!("invalid public_key hex: {e}")))?;

    if resolved_key != presented_key {
        return Err(AuthApiError::VerificationFailed(
            "presented public key does not match resolved identity key".to_string(),
        ));
    }

    Ok(presented_key)
}

/// Reconstructs the canonical challenge payload and verifies the Ed25519 signature.
async fn verify_challenge_signature(
    session: &AuthSession,
    public_key_bytes: &[u8],
    hex_signature: &str,
) -> AuthApiResult<()> {
    let payload = session
        .challenge
        .canonical_payload()
        .map_err(|e| AuthApiError::Internal(format!("canonical JSON error: {e}")))?;

    let sig_bytes = hex::decode(hex_signature)
        .map_err(|e| AuthApiError::InvalidRequest(format!("invalid signature hex: {e}")))?;

    let key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| AuthApiError::InvalidRequest("device key must be 32 bytes".to_string()))?;
    let device_key = auths_verifier::DevicePublicKey::ed25519(&key_bytes);

    device_key
        .verify(&payload, &sig_bytes, auths_crypto::default_provider())
        .await
        .map_err(|_| AuthApiError::VerificationFailed("signature verification failed".to_string()))
}
