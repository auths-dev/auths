//! OOBI-style static KEL export.
//!
//! Writes a `did:keri:` identity's KEL to a flat, host-agnostic file layout that
//! any static web server (GitHub Pages, S3, the git host) can serve — the
//! "no central server" form of KEL distribution. A verifier fetches the file and
//! replays it; trust comes from replay + the prefix-binding guard, never from the
//! host (an OOBI is an untrusted introduction, verified by replay).
//!
//! Layout (auths-only wire format — not yet keripy/keria byte-interop, see Epic
//! 4 / `docs/plans/keri_compliance.md`):
//!
//! ```text
//! <out_root>/.well-known/keri/oobi/<aid>/keri.cesr
//! ```
//!
//! `keri.cesr` is the KEL as a JSON array of event bodies. The CESR-tagged
//! verkeys (`k[]`/`n[]`) are serialized **verbatim**, so curve tags are preserved
//! with zero transformation (unlike the deprecated Ed25519-flattening HTTP
//! resolver). Per-event controller signatures (CESR `-A##` attachments) are not
//! exported: KEL replay derives key-state from the self-addressing SAID chain +
//! pre-rotation commitments — the same basis the C1/C2 verify path relies on —
//! and the prefix-binding guard re-derives the inception SAID on ingest.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use auths_id::ports::registry::{RegistryBackend, RegistryError};
use auths_keri::witness::{encode_nontrans_receipt_couples, parse_nontrans_receipt_couples};
use auths_keri::{Event, Prefix, Said};

/// The file name served at each AID's OOBI path.
pub const OOBI_KEL_FILE: &str = "keri.cesr";

/// Errors exporting (or parsing) an identity's OOBI KEL.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OobiExportError {
    /// No KEL is present for the requested identifier.
    #[error("KEL not found for {0}")]
    NotFound(String),

    /// Reading the KEL from the registry failed.
    #[error("registry read failed: {0}")]
    Backend(#[source] RegistryError),

    /// (De)serializing the KEL failed.
    #[error("serializing KEL failed: {0}")]
    Serialize(#[source] serde_json::Error),

    /// Writing the OOBI files failed.
    #[error("writing OOBI files failed: {0}")]
    Io(#[source] std::io::Error),

    /// Encoding/parsing a CESR receipt couplet group failed.
    #[error("CESR receipt couplet failed: {0}")]
    Cesr(String),
}

/// The relative OOBI path for an AID under a static-hosting root:
/// `.well-known/keri/oobi/<aid>/keri.cesr`.
///
/// Args:
/// * `prefix`: The `did:keri:` prefix (AID). CESR prefixes are base64url, so they
///   are filesystem- and URL-safe path segments.
pub fn oobi_relative_path(prefix: &Prefix) -> PathBuf {
    Path::new(".well-known")
        .join("keri")
        .join("oobi")
        .join(prefix.as_str())
        .join(OOBI_KEL_FILE)
}

/// Export one identity's KEL to the static OOBI layout under `out_root`.
///
/// Reads the prefix's full KEL from `registry` and writes it as
/// `out_root/.well-known/keri/oobi/<aid>/keri.cesr` (a JSON array of events).
/// Returns the path written. Curve tags are preserved verbatim.
///
/// To make a delegated device resolvable end-to-end, export **both** the device
/// AID and the root AID it delegates from: the device's `dip` carries the
/// delegator in `di`, so a client recurses to the root's OOBI.
///
/// Args:
/// * `registry`: The backend holding the identity's KEL.
/// * `prefix`: The `did:keri:` prefix (AID) to export.
/// * `out_root`: The static-hosting root directory.
///
/// Usage:
/// ```ignore
/// let path = export_identity_oobi(&registry, &prefix, Path::new("./public"))?;
/// ```
pub fn export_identity_oobi(
    registry: &dyn RegistryBackend,
    prefix: &Prefix,
    out_root: &Path,
) -> Result<PathBuf, OobiExportError> {
    let events = read_kel(registry, prefix)?;
    let path = out_root.join(oobi_relative_path(prefix));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(OobiExportError::Io)?;
    }
    let body = serde_json::to_vec_pretty(&events).map_err(OobiExportError::Serialize)?;
    std::fs::write(&path, body).map_err(OobiExportError::Io)?;
    Ok(path)
}

/// Parse a `keri.cesr` OOBI body back into KEL events.
///
/// The canonical reader for the OOBI wire format — round-trips with
/// [`export_identity_oobi`]. The HTTP OOBI client resolver and tests use it.
///
/// Args:
/// * `body`: The `keri.cesr` file contents (a JSON array of events).
pub fn parse_oobi_kel(body: &[u8]) -> Result<Vec<Event>, OobiExportError> {
    serde_json::from_slice(body).map_err(OobiExportError::Serialize)
}

/// The file name serving an AID's witness receipts alongside its `keri.cesr` KEL.
pub const OOBI_RECEIPTS_FILE: &str = "receipts.cesr";

/// One witness receipt couplet: `(witness_aid, signature)`.
pub type ReceiptCouple = (Prefix, Vec<u8>);

/// Witness receipts for a single event: its SAID and its couples.
pub type EventReceiptGroup = (Said, Vec<ReceiptCouple>);

/// The relative OOBI receipts path for an AID:
/// `.well-known/keri/oobi/<aid>/receipts.cesr`.
///
/// Args:
/// * `prefix`: The `did:keri:` prefix (AID).
pub fn oobi_receipts_relative_path(prefix: &Prefix) -> PathBuf {
    Path::new(".well-known")
        .join("keri")
        .join("oobi")
        .join(prefix.as_str())
        .join(OOBI_RECEIPTS_FILE)
}

/// Export witness receipts to the OOBI layout as keripy-aligned CESR `-L`
/// NonTransReceiptCouples, keyed by the receipted event SAID.
///
/// Written as a sibling `receipts.cesr` next to `keri.cesr` so the KEL stream
/// (consumed by the OOBI resolver) is unchanged; a client that wants witness
/// proofs fetches this file and feeds the couplets to the receipt-gated replay.
///
/// Args:
/// * `out_root`: The static-hosting root directory.
/// * `prefix`: The AID whose receipts are exported.
/// * `receipts`: `(event_said, [(witness_aid, signature)])` groups.
///
/// Usage:
/// ```ignore
/// let path = export_receipts_oobi(Path::new("./public"), &prefix, &groups)?;
/// ```
pub fn export_receipts_oobi(
    out_root: &Path,
    prefix: &Prefix,
    receipts: &[EventReceiptGroup],
) -> Result<PathBuf, OobiExportError> {
    let mut map = serde_json::Map::new();
    for (said, couples) in receipts {
        let refs: Vec<(&Prefix, &[u8])> = couples.iter().map(|(w, s)| (w, s.as_slice())).collect();
        let group = encode_nontrans_receipt_couples(&refs)
            .map_err(|e| OobiExportError::Cesr(e.to_string()))?;
        map.insert(said.as_str().to_string(), serde_json::Value::String(group));
    }

    let path = out_root.join(oobi_receipts_relative_path(prefix));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(OobiExportError::Io)?;
    }
    let body = serde_json::to_vec_pretty(&serde_json::Value::Object(map))
        .map_err(OobiExportError::Serialize)?;
    std::fs::write(&path, body).map_err(OobiExportError::Io)?;
    Ok(path)
}

/// Parse a `receipts.cesr` OOBI body back into `(event_said, couples)` groups.
///
/// The reader half of [`export_receipts_oobi`]: decodes each event's `-L`
/// NonTransReceiptCouples group into `(witness_aid, signature)` pairs.
///
/// Args:
/// * `body`: The `receipts.cesr` file contents.
pub fn parse_oobi_receipts(body: &[u8]) -> Result<Vec<EventReceiptGroup>, OobiExportError> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(OobiExportError::Serialize)?;
    let mut out = Vec::with_capacity(map.len());
    for (said, group) in map {
        let g = group.as_str().ok_or_else(|| {
            OobiExportError::Cesr(format!("receipt group for {said} is not a string"))
        })?;
        let couples =
            parse_nontrans_receipt_couples(g).map_err(|e| OobiExportError::Cesr(e.to_string()))?;
        out.push((Said::new_unchecked(said), couples));
    }
    Ok(out)
}

/// Read a prefix's full KEL (events from seq 0); empty / not-found → `NotFound`.
fn read_kel(
    registry: &dyn RegistryBackend,
    prefix: &Prefix,
) -> Result<Vec<Event>, OobiExportError> {
    let mut events = Vec::new();
    match registry.visit_events(prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    }) {
        Ok(()) => {}
        Err(RegistryError::NotFound { .. }) => {
            return Err(OobiExportError::NotFound(format!("did:keri:{prefix}")));
        }
        Err(e) => return Err(OobiExportError::Backend(e)),
    }
    if events.is_empty() {
        return Err(OobiExportError::NotFound(format!("did:keri:{prefix}")));
    }
    Ok(events)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::git::{GitRegistryBackend, RegistryConfig};
    use auths_core::crypto::said::{compute_next_commitment, compute_said};
    use auths_keri::{
        CesrKey, IcpEvent, KeriPublicKey, KeriSequence, Said, Threshold, VersionString,
        finalize_icp_event,
    };
    use tempfile::TempDir;

    fn icp_and_prefix() -> (Event, Prefix) {
        let key = KeriPublicKey::ed25519(&[9u8; 32]).unwrap();
        let next = KeriPublicKey::ed25519(&[10u8; 32]).unwrap();
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    fn registry_with_icp() -> (TempDir, GitRegistryBackend, Event, Prefix) {
        let dir = TempDir::new().unwrap();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
        backend.init_if_needed().unwrap();
        let (event, prefix) = icp_and_prefix();
        backend.append_event(&prefix, &event).unwrap();
        (dir, backend, event, prefix)
    }

    #[test]
    fn exports_and_round_trips_verbatim() {
        let (_src, backend, event, prefix) = registry_with_icp();
        let out = TempDir::new().unwrap();

        let path = export_identity_oobi(&backend, &prefix, out.path()).unwrap();
        assert!(path.ends_with(oobi_relative_path(&prefix)));
        assert!(path.exists());

        let body = std::fs::read(&path).unwrap();
        let parsed = parse_oobi_kel(&body).unwrap();
        // Byte-identical round-trip → zero transformation → curve tags preserved.
        assert_eq!(parsed, vec![event]);
    }

    #[test]
    fn exported_inception_prefix_matches_aid() {
        let (_src, backend, _event, prefix) = registry_with_icp();
        let out = TempDir::new().unwrap();
        let path = export_identity_oobi(&backend, &prefix, out.path()).unwrap();

        let parsed = parse_oobi_kel(&std::fs::read(&path).unwrap()).unwrap();
        let value = serde_json::to_value(&parsed[0]).unwrap();
        let derived = compute_said(&value).unwrap();
        // Tamper-evident by construction: the re-derived inception SAID is the AID.
        assert_eq!(derived.as_str(), prefix.as_str());
    }

    #[test]
    fn missing_identity_is_not_found() {
        let (_src, backend, _event, _prefix) = registry_with_icp();
        let out = TempDir::new().unwrap();
        let missing =
            Prefix::new_unchecked("ENotProvisioned00000000000000000000000000000".to_string());
        let err = export_identity_oobi(&backend, &missing, out.path()).unwrap_err();
        assert!(matches!(err, OobiExportError::NotFound(_)));
    }

    #[test]
    fn oobi_keri_cesr_carries_receipts() {
        let out = TempDir::new().unwrap();
        let prefix =
            Prefix::new_unchecked("EAidForReceipts00000000000000000000000000000".to_string());
        let said = Said::new_unchecked("EEventReceipted0000000000000000000000000000".to_string());
        let w1 = Prefix::new_unchecked(
            KeriPublicKey::ed25519(&[0x11u8; 32])
                .unwrap()
                .to_qb64()
                .unwrap(),
        );
        let w2 = Prefix::new_unchecked(
            KeriPublicKey::ed25519(&[0x33u8; 32])
                .unwrap()
                .to_qb64()
                .unwrap(),
        );
        let groups = vec![(
            said.clone(),
            vec![
                (w1.clone(), vec![0x22u8; 64]),
                (w2.clone(), vec![0x44u8; 64]),
            ],
        )];

        let path = export_receipts_oobi(out.path(), &prefix, &groups).unwrap();
        assert!(path.ends_with("receipts.cesr"));

        let body = std::fs::read(&path).unwrap();
        let parsed = parse_oobi_receipts(&body).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, said);
        assert_eq!(parsed[0].1.len(), 2);
        assert_eq!(parsed[0].1[0].0.as_str(), w1.as_str());
        assert_eq!(parsed[0].1[0].1, vec![0x22u8; 64]);
        assert_eq!(parsed[0].1[1].0.as_str(), w2.as_str());
        assert_eq!(parsed[0].1[1].1, vec![0x44u8; 64]);
    }
}
