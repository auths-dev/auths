//! The node's public status page (`GET /`) — epic W0.1.
//!
//! One embedded-HTML handler: no JS, no build step, no dependency the node
//! doesn't already link. It renders the facts a human — often a would-be witness
//! operator — wants when they point a browser at `https://<node>`: the node's
//! name, its member key, the roles it serves, how many members it holds, and the
//! one-liners to mirror its registry and add it to a principal's declared set.
//!
//! It is deliberately the WHOLE web surface the node has. Growth pressure never
//! goes into making the node bigger (network-auths-dev §6): everything richer —
//! browsing KELs, re-verifying receipts, inspecting anchors — lives in the
//! untrusted explorer at `explorer.auths.dev`, off the audited node binary. A
//! stranger's conformant witness gets this same page for free from the same
//! code.

use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Html;
use axum::routing::get;

/// The slice of node identity the status page renders. Cloneable so it can back
/// a dedicated `/` router independent of any role's typed state.
#[derive(Clone)]
pub struct StatusState {
    /// This node's public name, as carried in its cosignatures.
    pub witness_name: String,
    /// The node's member verifying key (`did:key:…`), or `None` when the seed
    /// couldn't be read (a registry-only node started without one).
    pub member_did: Option<String>,
    /// The roles this node serves (`anchor`, `kel`, `cosign`, `registry`).
    pub roles: Vec<String>,
    /// The party registry, read live to count members held.
    pub registry: PathBuf,
}

/// A `/`-only router serving the status page. Merge it into the node's app so
/// `GET /` answers regardless of role mix.
pub fn status_router(state: StatusState) -> Router {
    Router::new().route("/", get(status_page)).with_state(state)
}

async fn status_page(State(state): State<StatusState>, headers: HeaderMap) -> Html<String> {
    // Registry entries: a flat ref-enumeration index lookup, never a KEL walk.
    // This is the count of prefixes in the git registry — which a node may
    // *mirror* from a peer — not necessarily members it witnessed first-hand.
    let registry_count = auths_sdk::storage::PerPrefixKelStore::open(state.registry.as_path())
        .list_prefixes()
        .map(|p| p.len())
        .unwrap_or(0);
    let host = host(&headers);
    let base_url = base_url(&headers);
    Html(render(&state, registry_count, &host, &base_url))
}

/// The node's own public host (`auths-network.fly.dev`), from the request. Used
/// to build a browse link that addresses THIS node by host in the explorer — so
/// the link keeps working across a rename (the host is the stable address; the
/// directory catches the label up later). See url_intuition.md §5.
fn host(headers: &HeaderMap) -> String {
    headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("auths-network.fly.dev")
        .to_string()
}

/// Reconstruct the node's own public base URL from the request, so the shown
/// commands are copy-pasteable. Honors `x-forwarded-proto` (the node sits behind
/// TLS-terminating proxies in every shipped deploy); falls back to a scheme
/// inferred from the host.
fn base_url(headers: &HeaderMap) -> String {
    let host = host(headers);
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if host.starts_with("127.0.0.1") || host.starts_with("localhost") {
                "http".to_string()
            } else {
                "https".to_string()
            }
        });
    format!("{scheme}://{host}")
}

/// Minimal HTML entity escaping for the untrusted-ish dynamic fields (node name,
/// member key, roles all originate from local config, but escaping keeps the
/// page robust if that ever changes).
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render(state: &StatusState, registry_count: usize, host: &str, base_url: &str) -> String {
    let name = escape(&state.witness_name);
    let host_esc = escape(host);
    let member_key = state.member_did.as_deref().unwrap_or("—");
    let member_key_esc = escape(member_key);
    let roles = state
        .roles
        .iter()
        .map(|r| escape(r))
        .collect::<Vec<_>>()
        .join(" · ");
    let base = escape(base_url);
    let add_witness = format!("auths witness add --url {base}");
    let fetch = format!("git fetch '{base}' '+refs/auths/kel/*:refs/auths/kel/*'");

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} — Auths witness</title>
<style>
  :root {{ --paper:#faf8f4; --ink:#1c1814; --soft:#5b5348; --faint:#8a8074; --rule:#e5ddd0; --seal:#b5502a; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--paper); color:var(--ink); font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:44rem; margin:0 auto; padding:4rem 1.5rem 5rem; }}
  .kicker {{ font:600 12px/1 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.2em; text-transform:uppercase; color:var(--faint); }}
  h1 {{ font-size:2.4rem; font-weight:600; letter-spacing:-.02em; margin:.6rem 0 0; }}
  .meta {{ margin-top:.4rem; color:var(--soft); font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .card {{ border:1px solid var(--rule); border-radius:4px; background:#fff; padding:1rem 1.25rem; margin-top:1.5rem; }}
  .row {{ display:flex; gap:1rem; padding:.55rem 0; border-bottom:1px solid var(--rule); font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .row:last-child {{ border-bottom:0; }}
  .row .k {{ width:9rem; flex:0 0 auto; color:var(--faint); text-transform:uppercase; letter-spacing:.08em; font-size:11px; }}
  .row .v {{ min-width:0; word-break:break-all; }}
  h2 {{ font-size:1.1rem; margin:2.5rem 0 .5rem; }}
  pre {{ background:#15130f; color:#d6d0c8; border-radius:6px; padding:.9rem 1rem; overflow:auto; font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .comment {{ color:#9a948c; }}
  a {{ color:var(--seal); text-decoration:none; border-bottom:1px solid rgba(181,80,42,.35); }}
  a:hover {{ border-bottom-color:var(--seal); }}
  .links {{ margin-top:2rem; display:flex; flex-wrap:wrap; gap:1.25rem; font:13px/1 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .foot {{ margin-top:3rem; color:var(--faint); font-size:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <p class="kicker">Auths witness node</p>
  <h1>{name}</h1>
  <p class="meta">a small, dumb signer you check — not a service you trust</p>

  <div class="card">
    <div class="row"><span class="k">member key</span><span class="v">{member_key_esc}</span></div>
    <div class="row"><span class="k">roles</span><span class="v">{roles}</span></div>
    <div class="row"><span class="k">registry entries</span><span class="v">{registry_count} <span class="comment">— prefixes served (may be mirrored from a peer)</span></span></div>
    <div class="row"><span class="k">liveness</span><span class="v">up · see <a href="/health">/health</a></span></div>
  </div>

  <h2>Mirror this node’s key histories</h2>
  <pre><span class="comment"># pull every member’s KEL over plain git — no auth, no account</span>
{fetch}</pre>

  <h2>Witness a principal with this node</h2>
  <pre><span class="comment"># add this witness to your identity’s declared set</span>
{add_witness}
<span class="comment"># then the principal anchors the set (name + curve + member key) in their own key history</span></pre>

  <div class="links">
    <a href="https://explorer.auths.dev/node/{host_esc}">Browse it in the network ↗</a>
    <a href="https://explorer.auths.dev">The witness directory ↗</a>
    <a href="https://docs.auths.dev/witness-network/operators/run-a-node">Run your own ↗</a>
  </div>

  <p class="foot">Everything that proves here is open code: the node, the verifier, the conformance harness. This page is a convenience over evidence anyone can re-check.</p>
</div>
</body>
</html>
"##
    )
}
