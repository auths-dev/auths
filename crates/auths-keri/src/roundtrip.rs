use auths_verifier::keri::KeriEvent;

use crate::codec::CesrCodec;
use crate::error::KeriTranslationError;
use crate::stream::CesrStream;

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
    _codec: &dyn CesrCodec,
    _events: &[KeriEvent],
) -> Result<CesrStream, KeriTranslationError> {
    todo!("implemented in fn-14.7")
}

/// Imports a CESR stream and converts it back to Auths internal events.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `cesr_bytes`: Raw bytes of a CESR stream.
pub fn import_cesr_to_events(
    _codec: &dyn CesrCodec,
    _cesr_bytes: &[u8],
) -> Result<Vec<KeriEvent>, KeriTranslationError> {
    todo!("implemented in fn-14.7")
}
