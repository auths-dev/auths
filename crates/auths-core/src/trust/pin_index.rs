//! Sub-linear lookup index for the pinned-identity store.
//!
//! ## Why this exists
//!
//! [`super::pinned::PinnedIdentityStore`] persists pins as a single JSON array
//! (`known_identities.json`). A by-DID lookup that re-reads and re-parses the
//! whole array is `O(n)`: at fleet scale (≥10^6 pinned identities) a single
//! `auths trust show` re-parses the entire file, so lookup latency grows
//! linearly in registry size and a 10^6-entry lookup costs ~0.9 s.
//!
//! This module adds a persistent sidecar index (`known_identities.idx`) that
//! makes a single-DID lookup `O(log n)` disk reads plus one bounded read of the
//! located entry — independent of how the JSON file is formatted. The index is a
//! pure performance accelerator: it is rebuilt from the store whenever it is
//! stale and is **never** treated as a source of truth.
//!
//! ## Soundness — the index never fabricates trust
//!
//! The index only ever produces a *candidate byte range* into the canonical
//! store. The located bytes are then read **from the store**, parsed, and the
//! parsed entry's `did` is compared to the queried DID before it is returned. If
//! the candidate does not parse, or its DID does not match, the lookup falls
//! back to a full authoritative scan. Consequences:
//!
//! * A DID that is **not** pinned is never reported as found — an absent DID is
//!   absent from the index, and a stale index that points at the wrong entry is
//!   caught by the post-read DID comparison. The lookup fails closed.
//! * A corrupted or attacker-edited index can only ever *fail to find* a pin
//!   (degrading to a full scan) or point at a real entry that is then confirmed
//!   by reading the store — it can never invent a pin the store does not hold.
//!
//! ## Staleness
//!
//! The index header records the store file's length and modification time. That
//! pair is a cheap freshness *hint*, not a trust boundary: when it does not
//! match the store the index is rebuilt; when it does match the index is used to
//! locate a candidate, which is still confirmed against the store. A false
//! freshness match can therefore only ever cause a conservative (fail-closed)
//! not-found, never a fabricated found.

// INVARIANT: the pin index is a file-backed adapter — direct filesystem I/O
// (open/create/seek/read/rename) is its entire purpose, exactly as for the
// PinnedIdentityStore it accelerates.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_types)]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::pinned::PinnedIdentity;
use crate::error::TrustError;

/// Magic prefix so a truncated / foreign file is rejected, not misread.
const MAGIC: &[u8; 8] = b"AUTHSPI1";
/// Width of one index record: blake3(did)[32] + offset u64 + len u64.
const RECORD_LEN: usize = 32 + 8 + 8;
/// Below this store size a full scan is already sub-millisecond, so the sidecar
/// is pure overhead (and an extra file users would see). Stores smaller than
/// this keep using the simple authoritative read path. 64 KiB holds on the order
/// of a few hundred pins; the index only earns its keep at fleet scale.
const MIN_STORE_BYTES_FOR_INDEX: u64 = 64 * 1024;

/// Sidecar index file located next to the JSON store.
///
/// The index records, for each pinned entry, the blake3 hash of its DID and the
/// `[offset, len)` byte span of that entry's JSON object inside the store. The
/// records are sorted by DID hash so a lookup is a binary search by byte-seeking
/// the fixed-width record region — no part of the store is parsed except the one
/// located entry.
pub(crate) struct PinIndex {
    path: PathBuf,
}

/// Outcome of an index lookup.
pub(crate) enum IndexLookup {
    /// The store is small enough that the authoritative full scan should be used
    /// (no sidecar is built for tiny stores).
    NotApplicable,
    /// The index resolved the query: `Some(pin)` if pinned, `None` if absent.
    Resolved(Option<PinnedIdentity>),
}

/// A parsed index header: store freshness fingerprint + record count.
struct Header {
    store_len: u64,
    store_mtime_nanos: u128,
    entry_count: u64,
}

const HEADER_LEN: u64 = 8 /* magic */ + 8 /* store_len */ + 16 /* mtime nanos */ + 8 /* count */;

impl PinIndex {
    /// The index sidecar for a given store path (`<store>.idx`).
    pub(crate) fn for_store(store_path: &Path) -> Self {
        Self {
            path: store_path.with_extension("idx"),
        }
    }

    /// Resolve a DID to its pinned entry using the index, rebuilding the index
    /// from `store_path` first if it is missing or stale.
    ///
    /// Returns:
    /// * `Ok(NotApplicable)` — the store is small enough that a full scan is
    ///   already cheap; the caller should use the authoritative path and no
    ///   sidecar is created.
    /// * `Ok(Resolved(Some(pin)))` — the DID is pinned; `pin` was read and
    ///   confirmed from the store.
    /// * `Ok(Resolved(None))` — the DID is not pinned (fails closed).
    /// * `Err(_)` — an I/O / parse error reading the store (the caller falls
    ///   back to the authoritative scan).
    pub(crate) fn lookup(&self, store_path: &Path, did: &str) -> Result<IndexLookup, TrustError> {
        let fp = store_fingerprint(store_path)?;
        // Small store: a full scan is already sub-millisecond — don't pay for a
        // sidecar (and don't leave an extra file behind).
        if fp.0 < MIN_STORE_BYTES_FOR_INDEX {
            return Ok(IndexLookup::NotApplicable);
        }
        let header = self.read_header().ok().flatten();
        let fresh = matches!(
            &header,
            Some(h) if h.store_len == fp.0 && h.store_mtime_nanos == fp.1
        );
        if !fresh {
            self.rebuild(store_path, fp)?;
        }
        let entry_count = match self.read_header()? {
            Some(h) => h.entry_count,
            None => return Ok(IndexLookup::Resolved(None)),
        };
        let Some((offset, len)) = self.find_span(did, entry_count)? else {
            // Absent from the index ⇒ not pinned (fail closed).
            return Ok(IndexLookup::Resolved(None));
        };
        // Authoritative confirm: read the candidate bytes FROM THE STORE and
        // accept only if it parses to an entry whose DID equals the query.
        match read_entry_at(store_path, offset, len) {
            Ok(Some(pin)) if pin.did == did => Ok(IndexLookup::Resolved(Some(pin))),
            // Stale / colliding / corrupt candidate — not a confirmed match.
            // Fail closed for this fast path; the store-level fallback re-scans.
            Ok(_) => Ok(IndexLookup::Resolved(None)),
            Err(e) => Err(e),
        }
    }

    /// Binary-search the sorted record region for `did`'s span.
    fn find_span(&self, did: &str, entry_count: u64) -> Result<Option<(u64, u64)>, TrustError> {
        if entry_count == 0 {
            return Ok(None);
        }
        let key = did_hash(did);
        let mut file = fs::File::open(&self.path)?;
        let (mut lo, mut hi) = (0u64, entry_count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            file.seek(SeekFrom::Start(HEADER_LEN + mid * RECORD_LEN as u64))?;
            let mut rec_key = [0u8; 32];
            file.read_exact(&mut rec_key)?;
            match rec_key.cmp(&key) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let offset = file.read_u64::<LittleEndian>()?;
                    let len = file.read_u64::<LittleEndian>()?;
                    return Ok(Some((offset, len)));
                }
            }
        }
        Ok(None)
    }

    fn read_header(&self) -> Result<Option<Header>, TrustError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let mut file = fs::File::open(&self.path)?;
        let mut magic = [0u8; 8];
        if file.read_exact(&mut magic).is_err() || &magic != MAGIC {
            return Ok(None);
        }
        let store_len = file.read_u64::<LittleEndian>()?;
        let mut mtime = [0u8; 16];
        file.read_exact(&mut mtime)?;
        let store_mtime_nanos = u128::from_le_bytes(mtime);
        let entry_count = file.read_u64::<LittleEndian>()?;
        Ok(Some(Header {
            store_len,
            store_mtime_nanos,
            entry_count,
        }))
    }

    /// Rebuild the sidecar from the store: record every entry's DID-hash and its
    /// exact byte span, sorted by DID-hash. Written atomically (temp + rename).
    fn rebuild(&self, store_path: &Path, fp: (u64, u128)) -> Result<(), TrustError> {
        let content = fs::read(store_path).unwrap_or_default();
        let mut records = scan_spans(&content)?;
        records.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let tmp = self.path.with_extension("idx.tmp");
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(MAGIC)?;
            file.write_u64::<LittleEndian>(fp.0)?;
            file.write_all(&fp.1.to_le_bytes())?;
            file.write_u64::<LittleEndian>(records.len() as u64)?;
            for (key, offset, len) in &records {
                file.write_all(key)?;
                file.write_u64::<LittleEndian>(*offset)?;
                file.write_u64::<LittleEndian>(*len)?;
            }
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Best-effort removal of the sidecar (after a store mutation), so the next
    /// reader rebuilds rather than trusting a fingerprint race.
    pub(crate) fn invalidate(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// blake3 of the DID string — a fixed 32-byte sortable key.
fn did_hash(did: &str) -> [u8; 32] {
    *blake3::hash(did.as_bytes()).as_bytes()
}

/// Cheap freshness fingerprint: store byte length + modification time in nanos.
fn store_fingerprint(store_path: &Path) -> Result<(u64, u128), TrustError> {
    let meta = fs::metadata(store_path)?;
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok((meta.len(), mtime_nanos))
}

/// Read exactly the `[offset, offset+len)` bytes of the store and parse them as
/// one `PinnedIdentity`. Returns `Ok(None)` if the slice is out of range or does
/// not parse — i.e. a stale/garbage candidate, never a hard error.
fn read_entry_at(
    store_path: &Path,
    offset: u64,
    len: u64,
) -> Result<Option<PinnedIdentity>, TrustError> {
    if len == 0 || len > (1 << 20) {
        return Ok(None);
    }
    let mut file = fs::File::open(store_path)?;
    let file_len = file.metadata()?.len();
    if offset.saturating_add(len) > file_len {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    if file.read_exact(&mut buf).is_err() {
        return Ok(None);
    }
    Ok(serde_json::from_slice::<PinnedIdentity>(&buf).ok())
}

/// Walk the JSON array bytes once and record, for each top-level element, its
/// DID-hash and exact `[offset, len)` object span. This is the single `O(n)`
/// pass that amortises across all subsequent `O(log n)` lookups.
///
/// The scan is a minimal brace/string-aware splitter: it finds each top-level
/// `{ … }` object inside the outer `[ … ]`, slices it, and parses just that
/// object to extract its DID. It does not depend on whitespace or field order,
/// so it works for both the compact and pretty-printed store layouts.
fn scan_spans(content: &[u8]) -> Result<Vec<([u8; 32], u64, u64)>, TrustError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = content.len();
    // Advance to the opening '['.
    while i < n && content[i] != b'[' {
        i += 1;
    }
    if i >= n {
        return Ok(out); // empty / non-array store → no entries
    }
    i += 1;
    while i < n {
        // Skip separators / whitespace between elements.
        match content[i] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => {
                i += 1;
                continue;
            }
            b']' => break,
            b'{' => {}
            _ => {
                // Unexpected token inside the array — bail to a full rebuild by
                // returning what we have; the authoritative scan still backs us.
                break;
            }
        }
        let start = i;
        let mut depth = 0i32;
        let mut in_str = false;
        let mut escaped = false;
        while i < n {
            let c = content[i];
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else {
                match c {
                    b'"' => in_str = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        let end = i; // one past the closing '}'
        let slice = &content[start..end];
        if let Ok(pin) = serde_json::from_slice::<PinnedIdentity>(slice) {
            out.push((did_hash(&pin.did), start as u64, (end - start) as u64));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_verifier::PublicKeyHex;

    fn store_with(dids: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_identities.json");
        let mut arr = String::from("[");
        for (i, did) in dids.iter().enumerate() {
            if i > 0 {
                arr.push(',');
            }
            arr.push_str(&format!(
                r#"{{"did":"{did}","public_key_hex":"{:064x}","curve":"ed25519","first_seen":"2024-01-01T00:00:00Z","origin":"manual","trust_level":"manual"}}"#,
                i + 1
            ));
        }
        arr.push(']');
        fs::write(&path, arr).unwrap();
        (dir, path)
    }

    fn resolved(r: IndexLookup) -> Option<PinnedIdentity> {
        match r {
            IndexLookup::Resolved(p) => p,
            IndexLookup::NotApplicable => {
                panic!("expected the index path to apply for a large store")
            }
        }
    }

    /// Many entries so the store crosses MIN_STORE_BYTES_FOR_INDEX and the index
    /// path actually engages. ~3.6k entries × ~200 bytes ≫ 64 KiB.
    fn big_dids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("did:keri:E{i:043}")).collect()
    }

    #[test]
    fn finds_present_entry_in_large_store() {
        let dids = big_dids(4000);
        let refs: Vec<&str> = dids.iter().map(|s| s.as_str()).collect();
        let (_dir, path) = store_with(&refs);
        let idx = PinIndex::for_store(&path);

        // last entry — worst case for a linear scan
        let target = &dids[3999];
        let pin = resolved(idx.lookup(&path, target).unwrap());
        assert!(pin.is_some(), "indexed lookup must find a present DID");
        assert_eq!(pin.unwrap().did, *target);
        assert!(
            path.with_extension("idx").exists(),
            "sidecar must be written"
        );
    }

    #[test]
    fn absent_did_fails_closed() {
        let dids = big_dids(4000);
        let refs: Vec<&str> = dids.iter().map(|s| s.as_str()).collect();
        let (_dir, path) = store_with(&refs);
        let idx = PinIndex::for_store(&path);

        let pin = resolved(idx.lookup(&path, "did:keri:Enot_in_the_store").unwrap());
        assert!(pin.is_none(), "an unpinned DID must never resolve as found");
    }

    #[test]
    fn rebuilds_when_store_changes() {
        // Big enough to engage the index, so we can prove a rebuild on change.
        let mut dids = big_dids(4000);
        let refs: Vec<&str> = dids.iter().map(|s| s.as_str()).collect();
        let (dir, path) = store_with(&refs);
        let idx = PinIndex::for_store(&path);
        let present = dids[3999].clone();
        let absent = "did:keri:Ewill_be_added_later";
        assert!(resolved(idx.lookup(&path, &present).unwrap()).is_some());
        assert!(resolved(idx.lookup(&path, absent).unwrap()).is_none());

        // Rewrite the store with the new DID appended; distinct length + mtime.
        dids.push(absent.to_string());
        let refs2: Vec<&str> = dids.iter().map(|s| s.as_str()).collect();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let path2 = dir.path().join("known_identities.json");
        {
            let mut arr = String::from("[");
            for (i, did) in refs2.iter().enumerate() {
                if i > 0 {
                    arr.push(',');
                }
                arr.push_str(&format!(
                    r#"{{"did":"{did}","public_key_hex":"{:064x}","curve":"ed25519","first_seen":"2024-01-01T00:00:00Z","origin":"manual","trust_level":"manual"}}"#,
                    i + 1
                ));
            }
            arr.push(']');
            fs::write(&path2, arr).unwrap();
        }

        // Index must rebuild and reflect the new contents.
        assert!(resolved(idx.lookup(&path, absent).unwrap()).is_some());
        assert!(resolved(idx.lookup(&path, &present).unwrap()).is_some());
    }

    #[test]
    fn small_store_is_not_indexed() {
        let (_dir, path) = store_with(&["did:keri:Eaaa", "did:keri:Ebbb"]);
        let idx = PinIndex::for_store(&path);
        assert!(
            matches!(
                idx.lookup(&path, "did:keri:Eaaa").unwrap(),
                IndexLookup::NotApplicable
            ),
            "a tiny store must defer to the authoritative scan, no sidecar"
        );
        assert!(
            !path.with_extension("idx").exists(),
            "no sidecar for a small store"
        );
    }

    #[test]
    fn pretty_printed_store_is_indexable() {
        // serde_json::to_string_pretty layout (what write_all emits).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_identities.json");
        let pins: Vec<PinnedIdentity> = (0..600)
            .map(|i| PinnedIdentity {
                did: format!("did:keri:E{i:043}"),
                public_key_hex: PublicKeyHex::new_unchecked(format!("{:064x}", i + 1)),
                curve: auths_crypto::CurveType::Ed25519,
                kel_tip_said: None,
                kel_sequence: None,
                first_seen: chrono::Utc::now(),
                origin: "manual".to_string(),
                trust_level: super::super::pinned::TrustLevel::Manual,
            })
            .collect();
        fs::write(&path, serde_json::to_string_pretty(&pins).unwrap()).unwrap();

        let idx = PinIndex::for_store(&path);
        let pin = resolved(
            idx.lookup(
                &path,
                "did:keri:E0000000000000000000000000000000000000000599",
            )
            .unwrap(),
        );
        assert!(pin.is_some(), "pretty-printed store must index");
    }

    #[test]
    fn confirm_read_rejects_out_of_range_or_garbage_span() {
        // The confirm-read step only ever returns a pin that actually parses
        // from the store at the recorded span. A degenerate span (1 byte, or
        // past EOF) yields None — it can never fabricate a pin.
        let (_dir, path) = store_with(&["did:keri:Eaaa", "did:keri:Ebbb", "did:keri:Eccc"]);
        assert!(
            read_entry_at(&path, 0, 1).unwrap().is_none(),
            "a 1-byte span never parses to a pin"
        );
        assert!(
            read_entry_at(&path, u64::MAX - 1, 64).unwrap().is_none(),
            "a span past EOF never parses to a pin"
        );
    }
}
