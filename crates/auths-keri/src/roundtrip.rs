use auths_verifier::keri::KeriEvent;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cesride::{Indexer, Siger};

use crate::codec::CesrCodec;
use crate::error::KeriTranslationError;
use crate::event::serialize_for_cesr;
use crate::stream::{CesrStream, assemble_cesr_stream};

/// Exports a sequence of Auths internal events as a CESR stream.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `events`: Internal Auths events in sequence order.
///
/// Usage:
/// ```ignore
/// use auths_keri::{CesrV1Codec, export_kel_as_cesr};
///
/// let codec = CesrV1Codec::new();
/// let stream = export_kel_as_cesr(&codec, &events)?;
/// std::fs::write("identity.cesr", &stream.bytes)?;
/// ```
pub fn export_kel_as_cesr(
    codec: &dyn CesrCodec,
    events: &[KeriEvent],
) -> Result<CesrStream, KeriTranslationError> {
    let serialized: Vec<_> = events
        .iter()
        .map(|event| serialize_for_cesr(codec, event))
        .collect::<Result<_, _>>()?;

    assemble_cesr_stream(codec, &serialized)
}

/// Imports a CESR stream and converts it back to Auths internal events.
///
/// Parses the CESR stream, extracts JSON event bodies and attached signatures,
/// and reconstitutes `KeriEvent` types with signatures re-embedded in the `x` field
/// as base64url-no-pad.
///
/// Args:
/// * `_codec`: The CESR codec (reserved for future extensibility).
/// * `cesr_bytes`: Raw bytes of a CESR stream.
pub fn import_cesr_to_events(
    _codec: &dyn CesrCodec,
    cesr_bytes: &[u8],
) -> Result<Vec<KeriEvent>, KeriTranslationError> {
    let mut offset = 0;
    let mut events = Vec::new();

    while offset < cesr_bytes.len() {
        if cesr_bytes[offset] != b'{' {
            offset += 1;
            continue;
        }

        let remaining = &cesr_bytes[offset..];
        let body_len = extract_body_length(remaining)?;
        if body_len > remaining.len() {
            return Err(KeriTranslationError::DecodingFailed(format!(
                "body length {body_len} exceeds remaining bytes {}",
                remaining.len()
            )));
        }
        let body_bytes = &remaining[..body_len];

        let mut value: serde_json::Value = serde_json::from_slice(body_bytes)
            .map_err(KeriTranslationError::SerializationFailed)?;

        let attachment_start = offset + body_len;
        let sig_base64 = extract_attached_signature(&cesr_bytes[attachment_start..])?;
        if let Some(b64) = sig_base64
            && let Some(obj) = value.as_object_mut()
        {
            obj.insert("x".to_string(), serde_json::Value::String(b64));
        }

        let event: KeriEvent =
            serde_json::from_value(value).map_err(KeriTranslationError::SerializationFailed)?;
        events.push(event);

        offset = find_next_event_start(cesr_bytes, attachment_start);
    }

    Ok(events)
}

fn extract_body_length(bytes: &[u8]) -> Result<usize, KeriTranslationError> {
    let scan_len = bytes.len().min(200);
    let header = std::str::from_utf8(&bytes[..scan_len])
        .map_err(|e| KeriTranslationError::DecodingFailed(e.to_string()))?;

    let marker = "KERI10JSON";
    let pos = header
        .find(marker)
        .ok_or(KeriTranslationError::DecodingFailed(
            "no KERI10JSON version string found".into(),
        ))?;

    let hex_start = pos + marker.len();
    if hex_start + 6 > header.len() {
        return Err(KeriTranslationError::DecodingFailed(
            "version string truncated".into(),
        ));
    }
    let hex_str = &header[hex_start..hex_start + 6];
    usize::from_str_radix(hex_str, 16).map_err(|e| {
        KeriTranslationError::DecodingFailed(format!("invalid hex size in version string: {e}"))
    })
}

/// Extracts the first attached indexed signature, returning it as base64url-no-pad.
fn extract_attached_signature(
    attachment_bytes: &[u8],
) -> Result<Option<String>, KeriTranslationError> {
    if attachment_bytes.is_empty() || attachment_bytes[0] == b'{' {
        return Ok(None);
    }

    let available = attachment_bytes.len();
    // Counter code is 4 bytes (`-AAB`), signature is 88 bytes.
    if available < 4 + 88 {
        return Ok(None);
    }

    let counter = std::str::from_utf8(&attachment_bytes[..4])
        .map_err(|e| KeriTranslationError::DecodingFailed(e.to_string()))?;

    if !counter.starts_with("-AA") {
        return Ok(None);
    }

    let sig_qb64 = std::str::from_utf8(&attachment_bytes[4..4 + 88])
        .map_err(|e| KeriTranslationError::DecodingFailed(e.to_string()))?;

    let siger = Siger::new(None, None, None, None, None, None, Some(sig_qb64), None)
        .map_err(|e| KeriTranslationError::DecodingFailed(format!("Siger decode: {e}")))?;

    Ok(Some(URL_SAFE_NO_PAD.encode(siger.raw())))
}

fn find_next_event_start(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|&b| b == b'{')
        .map_or(bytes.len(), |pos| from + pos)
}
