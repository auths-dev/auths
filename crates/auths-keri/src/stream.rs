use crate::codec::CesrCodec;
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
/// Args:
/// * `codec`: The CESR codec for signature encoding.
/// * `events`: Serialized events from [`serialize_for_cesr`](crate::serialize_for_cesr).
pub fn assemble_cesr_stream(
    _codec: &dyn CesrCodec,
    _events: &[SerializedEvent],
) -> Result<CesrStream, KeriTranslationError> {
    todo!("implemented in fn-14.6")
}
