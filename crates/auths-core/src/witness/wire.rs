//! Witness submit-wire envelope.
//!
//! The registry event dialect carries controller signatures in a detached
//! CESR attachment (`-A…` indexed sigs, optional `-G…` source seal) rather
//! than an inline `x` field, so the submit wire needs a place for those bytes
//! that does not perturb the event body (the SAID is computed over the event
//! alone). The envelope is:
//!
//! ```json
//! { "event": { …KERI event… }, "attachment_b64": "<base64url-no-pad CESR>" }
//! ```
//!
//! A bare event body (no `event` key) remains accepted for the legacy inline
//! `x` dialect, so old clients keep working. Both sides of the wire live here
//! — clients build with [`encode_submit_body`], the server splits with
//! [`split_submit_body`] — so the convention exists exactly once.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// The envelope's event field name.
const EVENT_FIELD: &str = "event";
/// The envelope's attachment field name (base64url-no-pad CESR bytes).
const ATTACHMENT_FIELD: &str = "attachment_b64";

/// Build a submit body carrying an event and its CESR attachment.
///
/// With an empty attachment the bare event is returned unchanged, so callers
/// need not special-case unattached events.
///
/// Args:
/// * `event_json`: Canonical bytes of the finalized event.
/// * `attachment`: CESR attachment bytes (may be empty).
///
/// Usage:
/// ```ignore
/// let body = encode_submit_body(&event_bytes, &attachment)?;
/// ```
pub fn encode_submit_body(event_json: &[u8], attachment: &[u8]) -> Result<Vec<u8>, String> {
    if attachment.is_empty() {
        return Ok(event_json.to_vec());
    }
    let event: serde_json::Value =
        serde_json::from_slice(event_json).map_err(|e| format!("event is not JSON: {e}"))?;
    let envelope = serde_json::json!({
        EVENT_FIELD: event,
        ATTACHMENT_FIELD: URL_SAFE_NO_PAD.encode(attachment),
    });
    serde_json::to_vec(&envelope).map_err(|e| format!("envelope serialization: {e}"))
}

/// Split a submit body into the event and its attachment bytes.
///
/// Accepts either the envelope form (`{"event": …, "attachment_b64": …}`) or
/// a bare event (returned with an empty attachment).
///
/// Args:
/// * `body`: The parsed request body.
///
/// Usage:
/// ```ignore
/// let (event, attachment) = split_submit_body(body)?;
/// ```
pub fn split_submit_body(body: serde_json::Value) -> Result<(serde_json::Value, Vec<u8>), String> {
    let Some(obj) = body.as_object() else {
        return Err("request body must be a JSON object".to_string());
    };
    if !obj.contains_key(EVENT_FIELD) {
        return Ok((body, Vec::new()));
    }
    let event = obj
        .get(EVENT_FIELD)
        .cloned()
        .ok_or_else(|| "envelope missing 'event'".to_string())?;
    if !event.is_object() {
        return Err("envelope 'event' must be a JSON object".to_string());
    }
    let attachment = match obj.get(ATTACHMENT_FIELD) {
        None => Vec::new(),
        Some(serde_json::Value::String(b64)) => URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("attachment_b64 is not base64url-no-pad: {e}"))?,
        Some(_) => return Err("'attachment_b64' must be a string".to_string()),
    };
    Ok((event, attachment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_event_passes_through() {
        let body = serde_json::json!({"t": "icp", "d": "E1"});
        let (event, attachment) = split_submit_body(body.clone()).unwrap();
        assert_eq!(event, body);
        assert!(attachment.is_empty());
    }

    #[test]
    fn envelope_roundtrips() {
        let event = serde_json::json!({"t": "rot", "d": "E2"});
        let attachment = b"-AABAAfake".to_vec();
        let body = encode_submit_body(&serde_json::to_vec(&event).unwrap(), &attachment).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let (out_event, out_attachment) = split_submit_body(parsed).unwrap();
        assert_eq!(out_event, event);
        assert_eq!(out_attachment, attachment);
    }

    #[test]
    fn empty_attachment_encodes_bare() {
        let event = serde_json::json!({"t": "icp"});
        let body = encode_submit_body(&serde_json::to_vec(&event).unwrap(), &[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn bad_base64_is_rejected() {
        let body = serde_json::json!({"event": {"t": "icp"}, "attachment_b64": "!!!"});
        assert!(split_submit_body(body).is_err());
    }
}
