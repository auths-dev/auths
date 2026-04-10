//! Error mapping from Rekor HTTP responses to `LogError`.

use auths_core::ports::transparency_log::LogError;
use reqwest::StatusCode;

/// Map a Rekor HTTP response status to a `LogError`.
///
/// Returns `Ok(())` for success statuses (200, 201).
/// Returns the parsed `LogError` for error statuses.
pub fn map_rekor_status(status: StatusCode, body: &str) -> Result<(), LogError> {
    match status.as_u16() {
        200 | 201 => Ok(()),
        400 => Err(LogError::SubmissionRejected {
            reason: format!("bad request: {}", truncate(body, 200)),
        }),
        // 409 is handled separately in the client (idempotent success)
        413 => Err(LogError::SubmissionRejected {
            reason: "payload too large".into(),
        }),
        422 => Err(LogError::SubmissionRejected {
            reason: format!("unprocessable entity: {}", truncate(body, 200)),
        }),
        429 => {
            // Parse Retry-After header would happen at the call site;
            // here we provide a default
            Err(LogError::RateLimited {
                retry_after_secs: 10,
            })
        }
        500 => Err(LogError::Unavailable("server error".into())),
        503 => Err(LogError::Unavailable("service unavailable".into())),
        _ => Err(LogError::InvalidResponse(format!(
            "unexpected status {}: {}",
            status.as_u16(),
            truncate(body, 200)
        ))),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
