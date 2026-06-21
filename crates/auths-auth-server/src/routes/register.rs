//! POST /connect/register — RFC 7591 dynamic client registration.

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHasher};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::AuthServerState;
use crate::domain::client::{GrantType, RegisteredClient, ResponseType, TokenEndpointAuthMethod};
use crate::domain::registration::{
    KeriCapabilityReceipt, RegistrationRequest, RegistrationResponse, validate_registration_request,
};
use crate::domain::verification::{
    RegistrationVerificationError, VerifiedReceipt, verify_keri_receipt,
};
use crate::error::AuthApiError;

/// Validated grant/response types and auth method from the registration request.
struct ValidatedMetadata {
    grant_types: Vec<GrantType>,
    response_types: Vec<ResponseType>,
    auth_method: TokenEndpointAuthMethod,
}

/// Credentials generated during client registration.
struct ClientCredentials {
    client_id: String,
    client_secret: Option<String>,
    client_secret_hash: Option<String>,
    registration_access_token: String,
    registration_access_token_hash: String,
}

/// Handler for `POST /connect/register`.
pub async fn register_client(
    State(state): State<AuthServerState>,
    Json(request): Json<RegistrationRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let meta = validate_metadata(&request, state.config().allow_http_redirects)?;
    let verified = verify_capabilities(&request.keri_capability_receipt).await?;
    let credentials = generate_credentials(&meta.auth_method).await?;
    let now = state.app_service().clock().now();

    persist_client(&state, &request, verified, &credentials, &meta, now).await?;

    Ok((
        StatusCode::CREATED,
        Json(RegistrationResponse {
            client_id: credentials.client_id,
            client_secret: credentials.client_secret,
            client_name: request.client_name,
            redirect_uris: request.redirect_uris,
            grant_types: meta.grant_types,
            response_types: meta.response_types,
            token_endpoint_auth_method: meta.auth_method,
            registration_access_token: credentials.registration_access_token,
            client_id_issued_at: now.timestamp(),
            client_secret_expires_at: 0,
        }),
    ))
}

fn validate_metadata(
    request: &RegistrationRequest,
    allow_http: bool,
) -> Result<ValidatedMetadata, AuthApiError> {
    let (grant_types, response_types, auth_method) =
        validate_registration_request(request, allow_http)
            .map_err(|e| AuthApiError::InvalidRequest(e.to_string()))?;
    Ok(ValidatedMetadata {
        grant_types,
        response_types,
        auth_method,
    })
}

async fn verify_capabilities(
    receipt: &KeriCapabilityReceipt,
) -> Result<VerifiedReceipt, AuthApiError> {
    verify_keri_receipt(receipt).await.map_err(|e| match &e {
        RegistrationVerificationError::InvalidSignature(_)
        | RegistrationVerificationError::AttestationError(_) => {
            AuthApiError::VerificationFailed(e.to_string())
        }
        RegistrationVerificationError::MissingCapability { .. } => {
            AuthApiError::VerificationFailed(e.to_string())
        }
        _ => AuthApiError::InvalidRequest(e.to_string()),
    })
}

#[allow(clippy::disallowed_methods)]
async fn generate_credentials(
    auth_method: &TokenEndpointAuthMethod,
) -> Result<ClientCredentials, AuthApiError> {
    let client_id = Uuid::new_v4().to_string();
    let (client_secret, client_secret_hash) = if auth_method
        != &TokenEndpointAuthMethod::PrivateKeyJwt
        && auth_method != &TokenEndpointAuthMethod::None
    {
        let secret = generate_random_token()?;
        let hash = hash_secret_blocking(&secret).await?;
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };
    let registration_access_token = generate_random_token()?;
    let registration_access_token_hash = hash_secret_blocking(&registration_access_token).await?;

    Ok(ClientCredentials {
        client_id,
        client_secret,
        client_secret_hash,
        registration_access_token,
        registration_access_token_hash,
    })
}

async fn persist_client(
    state: &AuthServerState,
    request: &RegistrationRequest,
    verified: VerifiedReceipt,
    credentials: &ClientCredentials,
    meta: &ValidatedMetadata,
    now: DateTime<Utc>,
) -> Result<(), AuthApiError> {
    let expires_at = state
        .config()
        .client_ttl_secs
        .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

    state
        .clients()
        .create(RegisteredClient {
            client_id: credentials.client_id.clone(),
            client_name: request.client_name.clone(),
            keri_aid: verified.keri_aid,
            client_secret_hash: credentials.client_secret_hash.clone(),
            redirect_uris: request.redirect_uris.clone(),
            grant_types: meta.grant_types.clone(),
            response_types: meta.response_types.clone(),
            token_endpoint_auth_method: meta.auth_method.clone(),
            registration_access_token_hash: credentials.registration_access_token_hash.clone(),
            jwks: request.jwks.clone(),
            created_at: now,
            expires_at,
            revoked_at: None,
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))
}

/// Generate a 32-byte random token encoded as base64url.
fn generate_random_token() -> Result<String, AuthApiError> {
    let mut bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .map_err(|_| AuthApiError::Internal("failed to generate random token".to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Hash a secret using Argon2id on the blocking thread pool.
///
/// Argon2 is intentionally CPU-bound; running it on the async executor
/// would stall the Tokio reactor and degrade all concurrent requests.
async fn hash_secret_blocking(secret: &str) -> Result<String, AuthApiError> {
    let secret = secret.to_string();
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(secret.as_bytes(), &salt)
            .map_err(|e| AuthApiError::Internal(format!("argon2 hash error: {e}")))?;
        Ok(hash.to_string())
    })
    .await
    .map_err(|e| AuthApiError::Internal(format!("blocking task panicked: {e}")))?
}
