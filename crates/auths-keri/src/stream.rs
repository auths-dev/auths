use crate::codec::{CesrCodec, SigType};
use crate::error::KeriTranslationError;
use crate::event::SerializedEvent;

/// A group of CESR attachments for a single event.
#[derive(Debug, Clone)]
pub struct AttachmentGroup {
    /// Controller indexed signatures (CESR-qualified strings).
    pub controller_signatures: Vec<String>,
}

/// A complete CESR stream of KERI events with attachments.
#[derive(Debug, Clone)]
pub struct CesrStream {
    /// The raw bytes of the complete stream.
    pub bytes: Vec<u8>,

    /// Number of events in the stream.
    pub event_count: usize,
}

/// Assembles a CESR stream from a sequence of serialized events.
///
/// Each event's JSON body is followed by its CESR signature attachments.
/// The result is a concatenation suitable for any spec-compliant KERI parser.
///
/// Args:
/// * `codec`: The CESR codec for signature encoding.
/// * `events`: Serialized events from [`serialize_for_cesr`](crate::serialize_for_cesr).
///
/// Usage:
/// ```ignore
/// let stream = assemble_cesr_stream(&codec, &serialized_events)?;
/// std::fs::write("identity.cesr", &stream.bytes)?;
/// ```
pub fn assemble_cesr_stream(
    codec: &dyn CesrCodec,
    events: &[SerializedEvent],
) -> Result<CesrStream, KeriTranslationError> {
    let mut stream = Vec::new();

    for event in events {
        stream.extend_from_slice(&event.body_bytes);

        if let Some(ref sig_bytes) = event.signature_bytes {
            let cesr_sig = codec.encode_indexed_signature(
                sig_bytes,
                SigType::Ed25519,
                event.signature_key_index,
            )?;

            // Counter code: `-A` (group) + 2-char base64url count.
            // `-AAB` = 1 controller indexed signature.
            let count_code = format!("-AA{}", cesr_count_char(1));
            stream.extend_from_slice(count_code.as_bytes());
            stream.extend_from_slice(cesr_sig.as_bytes());
        }
    }

    Ok(CesrStream {
        event_count: events.len(),
        bytes: stream,
    })
}

/// Encodes a small count (0-63) as a single base64url character.
fn cesr_count_char(count: u8) -> char {
    const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    BASE64URL[count as usize] as char
}
