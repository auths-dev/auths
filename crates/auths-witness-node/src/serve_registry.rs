//! Read-only git smart-HTTP over the witness's held KEL store.
//!
//! A witness holds the party KELs it receipts: the `kel` role's write bridge
//! ([`crate::kel_sink`]) persists every accepted event under a per-prefix ref
//! (`refs/auths/kel/<s1>/<prefix>`) in the `--registry` repo, alongside any
//! aggregated `refs/auths/registry` tree an operator synced. Exposing all of
//! `refs/auths/*` read-only over git smart-HTTP makes the node its own
//! resolution surface — a verifier fetches one member
//! (`git fetch <node> refs/auths/kel/<s1>/<prefix>`) or a peer witness
//! replicates the namespace (`git fetch +refs/auths/*:refs/auths/*`, exactly
//! what [`crate::sync`] does), with no separate registry server anywhere. This
//! is the "serve what you witness" leg of
//! `docs/plans/network/network-auths-dev.md`, made true by the write path in
//! `docs/plans/network/witness-receipting-write-path.md`.
//!
//! Only `git-upload-pack` (fetch) is ever invoked. There is no `receive-pack`
//! code path, so the surface is **read-only by construction** — not by config
//! that could be flipped. Writes are a separate, signed ingest (the KEL
//! receipting role), never an anonymous push.
//!
//! The heavy lifting — pkt-line framing, protocol negotiation, packfile
//! generation — is delegated to the `git` binary's own `upload-pack`, the
//! reference implementation, rather than reimplemented. The node passes the
//! client's `Git-Protocol` through so protocol v2 (which avoids advertising
//! every ref) works, and decompresses gzip request bodies, so any standard git
//! client interoperates.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The only git service this node speaks. `receive-pack` is deliberately absent.
const SERVICE: &str = "git-upload-pack";

/// Smart-HTTP media types for the upload-pack service (RFC-less, but stable git
/// protocol strings). Kept as `&'static str` so a response's header pair is one
/// concrete type.
const ADVERTISEMENT_CONTENT_TYPE: &str = "application/x-git-upload-pack-advertisement";
const RESULT_CONTENT_TYPE: &str = "application/x-git-upload-pack-result";

/// Each response is a per-fetch computation — never a cacheable fixed body.
const NO_CACHE: &str = "no-cache, max-age=0, must-revalidate";

/// Request-body cap for the fetch negotiation. A client's want/have list is
/// small (KB) even for large repos, but generous here so a deep fetch of a
/// many-ref registry is never truncated. Far above the anchor role's cap; the
/// registry routes carry their own envelope for exactly this reason.
pub const REGISTRY_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Concurrent `upload-pack` subprocesses to allow. Each fetch forks `git`, so
/// this bounds fork pressure independently of the anchor role's limit.
pub const REGISTRY_MAX_CONCURRENT_REQUESTS: usize = 32;

/// Per-request timeout for the registry routes. A pack transfer legitimately
/// takes longer than an anchor POST, so it gets its own, larger budget.
pub const REGISTRY_TIMEOUT: Duration = Duration::from_secs(120);

/// The read-only git-smart-HTTP router over `registry` — the repo whose
/// `refs/auths/*` this node serves. Mounted at the node root, so the git URL is
/// simply the node's base (`git fetch <base> +refs/auths/*:refs/auths/*`).
/// Also exposes the roster: which prefixes this witness holds.
///
/// Args:
/// * `registry`: path to the local registry repo (the `--registry` dir).
///
/// Usage:
/// ```ignore
/// let app = app.merge(serve_registry::registry_router(&args.registry));
/// ```
pub fn registry_router(registry: &Path) -> Router {
    let repo = Arc::new(registry.to_path_buf());
    Router::new()
        .route("/info/refs", get(info_refs))
        .route("/git-upload-pack", post(upload_pack))
        .route("/v1/registry/roster", get(roster))
        .with_state(repo)
}

/// One roster row: a prefix this witness holds and its KEL tip.
#[derive(serde::Serialize)]
struct RosterEntry {
    /// The member's KERI prefix.
    prefix: String,
    /// Latest stored sequence number.
    sequence: u128,
    /// SAID of the latest stored event.
    said: String,
}

/// `GET /v1/registry/roster` — the prefixes this witness holds, with tips.
///
/// Backed by ref enumeration + per-identity `tip.json` reads — an index
/// lookup, never a KEL walk — so listing stays flat as members grow (the
/// bulk-onboarding bench showed KEL-walking rosters go superlinear).
async fn roster(State(repo): State<Arc<PathBuf>>) -> Response {
    let store = auths_sdk::storage::PerPrefixKelStore::open(repo.as_path());
    let prefixes = match store.list_prefixes() {
        Ok(prefixes) => prefixes,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("roster enumeration failed: {e}\n"),
            )
                .into_response();
        }
    };
    let entries: Vec<RosterEntry> = prefixes
        .into_iter()
        .filter_map(|prefix| {
            let tip = store.get_tip(&prefix).ok()?;
            Some(RosterEntry {
                prefix: prefix.to_string(),
                sequence: tip.sequence,
                said: tip.said.to_string(),
            })
        })
        .collect();
    axum::Json(entries).into_response()
}

/// Whether the `git` binary is invocable — the registry role's hard dependency.
/// The node calls this at startup and refuses the role (I-DEPLOY-6, fail closed)
/// rather than 500-ing every fetch later.
pub async fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `GET /info/refs?service=git-upload-pack` — the smart-HTTP ref advertisement.
async fn info_refs(
    State(repo): State<Arc<PathBuf>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    // Read-only: advertise nothing but upload-pack. A client asking for
    // receive-pack (a push) is refused here — there is no write surface.
    if query.as_deref() != Some(&format!("service={SERVICE}")) {
        return (
            StatusCode::FORBIDDEN,
            format!("only service={SERVICE} is served (read-only registry)\n"),
        )
            .into_response();
    }

    let mut cmd = Command::new("git");
    cmd.args(["upload-pack", "--stateless-rpc", "--advertise-refs"])
        .arg(repo.as_path());
    apply_git_protocol(&mut cmd, &headers);

    let out = match cmd.output().await {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => return git_failed("upload-pack --advertise-refs", &out.stderr),
        Err(e) => return spawn_failed(e),
    };

    // Smart-HTTP wraps the advertisement in the service pkt-line + a flush.
    let mut body = pkt_line(format!("# service={SERVICE}\n").as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&out);

    (
        [
            (header::CONTENT_TYPE, ADVERTISEMENT_CONTENT_TYPE),
            (header::CACHE_CONTROL, NO_CACHE),
        ],
        body,
    )
        .into_response()
}

/// `POST /git-upload-pack` — the fetch negotiation + packfile response.
async fn upload_pack(
    State(repo): State<Arc<PathBuf>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // git clients may gzip the request body; upload-pack expects it raw.
    let input = if is_gzip(&headers) {
        match gunzip(&body) {
            Ok(decoded) => decoded,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("gzip decode: {e}\n")).into_response();
            }
        }
    } else {
        body.to_vec()
    };

    let mut cmd = Command::new("git");
    cmd.args(["upload-pack", "--stateless-rpc"])
        .arg(repo.as_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_git_protocol(&mut cmd, &headers);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return spawn_failed(e),
    };

    // Feed the negotiation to git on its own task while we drain stdout, so a
    // large request can never deadlock against a filling stdout pipe.
    if let Some(mut stdin) = child.stdin.take() {
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            // Dropping `stdin` closes it, signalling end-of-input to git.
        });
    }

    let out = match child.wait_with_output().await {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => return git_failed("upload-pack", &out.stderr),
        Err(e) => return spawn_failed(e),
    };

    (
        [
            (header::CONTENT_TYPE, RESULT_CONTENT_TYPE),
            (header::CACHE_CONTROL, NO_CACHE),
        ],
        out,
    )
        .into_response()
}

/// Frame `payload` as a single git pkt-line (4-hex length prefix + payload).
fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut line = format!("{:04x}", payload.len() + 4).into_bytes();
    line.extend_from_slice(payload);
    line
}

/// Pass the client's negotiated protocol version through to `git` so protocol
/// v2 (ref-filtered, essential at scale) is honoured; absent, git uses v0.
fn apply_git_protocol(cmd: &mut Command, headers: &HeaderMap) {
    if let Some(proto) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", proto);
    }
}

fn is_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("gzip"))
}

fn gunzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn git_failed(what: &str, stderr: &[u8]) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("git {what} failed: {}\n", String::from_utf8_lossy(stderr)),
    )
        .into_response()
}

fn spawn_failed(e: std::io::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("could not run git: {e}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_prefixes_hex_length() {
        // "# service=git-upload-pack\n" is 26 bytes → 26 + 4 = 30 = 0x1e.
        let line = pkt_line(b"# service=git-upload-pack\n");
        assert_eq!(&line[..4], b"001e");
        assert_eq!(&line[4..], b"# service=git-upload-pack\n");
    }

    #[test]
    fn gunzip_roundtrips() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"0011command=ls-refs\n0000").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(gunzip(&compressed).unwrap(), b"0011command=ls-refs\n0000");
    }

    #[test]
    fn only_upload_pack_service_is_accepted() {
        // A defensive check that the constant is the fetch service, never
        // receive-pack — the read-only guarantee depends on it.
        assert_eq!(SERVICE, "git-upload-pack");
    }
}
