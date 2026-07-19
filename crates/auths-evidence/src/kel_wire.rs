//! KEL wire form for self-contained bundles.
//!
//! A delegated event's source seal (the `-G` couple back-referencing the
//! delegator's anchoring event) travels in the CESR ATTACHMENT, not the event
//! body — so it is `#[serde(skip)]` on the typed event and a naive JSON
//! round-trip drops it, breaking the delegation proof on offline replay. The
//! bundle therefore embeds each event as `{event, sourceSeal}` and reattaches
//! the seal on the way back in.

use auths_id::keri::Event;
use auths_keri::{SourceSeal};
use serde_json::Value;

use crate::error::EvidenceError;

fn seal_of(event: &Event) -> Option<&SourceSeal> {
    match event {
        Event::Dip(e) => e.source_seal.as_ref(),
        Event::Drt(e) => e.source_seal.as_ref(),
        _ => None,
    }
}

fn attach_seal(event: &mut Event, seal: SourceSeal) {
    match event {
        Event::Dip(e) => e.source_seal = Some(seal),
        Event::Drt(e) => e.source_seal = Some(seal),
        _ => {}
    }
}

fn seal_to_value(seal: &SourceSeal) -> Result<Value, EvidenceError> {
    Ok(serde_json::json!({
        "s": serde_json::to_value(&seal.s).map_err(|e| EvidenceError::Canonical(e.to_string()))?,
        "d": serde_json::to_value(&seal.d).map_err(|e| EvidenceError::Canonical(e.to_string()))?,
    }))
}

fn seal_from_value(value: &Value) -> Result<SourceSeal, EvidenceError> {
    Ok(SourceSeal {
        s: serde_json::from_value(value.get("s").cloned().unwrap_or(Value::Null))
            .map_err(|e| EvidenceError::Registry(format!("source seal s: {e}")))?,
        d: serde_json::from_value(value.get("d").cloned().unwrap_or(Value::Null))
            .map_err(|e| EvidenceError::Registry(format!("source seal d: {e}")))?,
    })
}

/// Serialize a resolved KEL for embedding: each item is `{event, sourceSeal}`.
///
/// Args:
/// * `events`: the resolved KEL, in order.
///
/// Usage:
/// ```ignore
/// let wire = kel_to_wire(gate.agent_kel())?;
/// ```
pub fn kel_to_wire(events: &[Event]) -> Result<Vec<Value>, EvidenceError> {
    events
        .iter()
        .map(|event| {
            let body = serde_json::to_value(event)
                .map_err(|e| EvidenceError::Canonical(e.to_string()))?;
            let seal = match seal_of(event) {
                Some(seal) => seal_to_value(seal)?,
                None => Value::Null,
            };
            Ok(serde_json::json!({ "event": body, "sourceSeal": seal }))
        })
        .collect()
}

/// Rebuild a typed KEL from the embedded wire form, reattaching source seals.
///
/// Args:
/// * `items`: the embedded `{event, sourceSeal}` items, in order.
///
/// Usage:
/// ```ignore
/// let kel = kel_from_wire(&bundle.proof.agent_kel)?;
/// ```
pub fn kel_from_wire(items: &[Value]) -> Result<Vec<Event>, EvidenceError> {
    items
        .iter()
        .map(|item| {
            let body = item
                .get("event")
                .ok_or_else(|| EvidenceError::Registry("KEL item missing `event`".to_string()))?;
            let mut event: Event = serde_json::from_value(body.clone())
                .map_err(|e| EvidenceError::Registry(format!("embedded KEL event: {e}")))?;
            if let Some(seal) = item.get("sourceSeal").filter(|v| !v.is_null()) {
                attach_seal(&mut event, seal_from_value(seal)?);
            }
            Ok(event)
        })
        .collect()
}
