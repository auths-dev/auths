//! In-process per-call signing — the fleet-throughput path.
//!
//! The subprocess ceremony (`git init` + `git commit` + `auths sign HEAD`, which
//! re-opens the Argon2id-protected keychain on every invocation) costs seconds per
//! brokered call. A fleet cannot meter at that latency. This module signs the SAME
//! commit object in-process: the agent seed is decrypted ONCE per session from the
//! headless file keychain, and every subsequent call builds the git commit bytes
//! directly (blob → tree → commit) and signs them with the identical SSHSIG the CLI
//! produces (`create_sshsig`, namespace `git`).
//!
//! Fidelity over cleverness: the FIRST call of each kind still runs the full
//! subprocess ceremony, and its raw commit is harvested into a template — the
//! session-static trailers (`Auths-Id`, `Auths-Device`, `Auths-Anchor-Seq`,
//! `Auths-Scope`) and the git identity line are reused VERBATIM; only the dynamic
//! trailer values (`Auths-Prev`, the `Auths-Settle-*` set) and the tree/timestamps
//! change per call. The offline `verify-spend` audit re-verifies every record
//! through the same verifier either way — a byte-level divergence fails closed as
//! `tampered-proof`, never silently.
//!
//! Availability: only when `AUTHS_PASSPHRASE` is set (the headless posture, where
//! the keychain can be opened without prompting). Anything else — no passphrase,
//! keychain errors, an unparsed first commit — quietly leaves the subprocess path
//! in charge.

use anyhow::{Context, bail};
use auths_crypto::SecureSeed;
use auths_mcp_core::treasury::encode_hex;
use auths_sdk::keychain::{KeyAlias, get_platform_keychain};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The dynamic trailer keys of a CALL commit.
const CALL_SLOTS: &[&str] = &["Auths-Prev"];
/// The dynamic trailer keys of a SETTLEMENT commit.
const SETTLE_SLOTS: &[&str] = &[
    "Auths-Settle-Call",
    "Auths-Settle-Rail",
    "Auths-Settle-Cents",
    "Auths-Settle-Ref",
    "Auths-Settle-Cumulative",
];

/// One message line: literal text, or a dynamic trailer slot to fill per call.
#[derive(Debug, Clone)]
enum Piece {
    Lit(String),
    Slot { prefix: String, key: &'static str },
}

/// A harvested commit shape: the git identity line plus the message with its
/// dynamic trailer values holed out.
#[derive(Debug, Clone)]
struct CommitTemplate {
    identity_line: String,
    pieces: Vec<Piece>,
}

impl CommitTemplate {
    /// Harvest a template from a subprocess-signed raw commit.
    fn harvest(raw: &[u8], slots: &[&'static str]) -> Option<CommitTemplate> {
        let text = std::str::from_utf8(raw).ok()?;
        let (head, message) = text.split_once("\n\n")?;
        let author = head
            .lines()
            .find_map(|l| l.strip_prefix("author "))?
            .to_string();
        // "NAME <EMAIL> TS TZ" → keep "NAME <EMAIL>".
        let identity_line = author.rsplitn(3, ' ').nth(2)?.to_string();
        let mut pieces = Vec::new();
        for line in message.lines() {
            let slot = slots.iter().find(|k| {
                line.strip_prefix(**k)
                    .is_some_and(|rest| rest.starts_with(':'))
            });
            match slot {
                Some(key) => {
                    let after = &line[key.len() + 1..];
                    let ws = after.len() - after.trim_start().len();
                    pieces.push(Piece::Slot {
                        prefix: line[..key.len() + 1 + ws].to_string(),
                        key,
                    });
                }
                None => pieces.push(Piece::Lit(line.to_string())),
            }
        }
        Some(CommitTemplate {
            identity_line,
            pieces,
        })
    }

    /// Render the message with this call's dynamic trailer values.
    fn render(&self, values: &HashMap<&str, String>) -> Option<String> {
        let mut out = String::new();
        for piece in &self.pieces {
            match piece {
                Piece::Lit(line) => out.push_str(line),
                Piece::Slot { prefix, key } => {
                    out.push_str(prefix);
                    out.push_str(values.get(key)?);
                }
            }
            out.push('\n');
        }
        Some(out)
    }
}

/// The session key: the agent seed decrypted once from the headless file keychain.
struct SessionKey {
    seed: SecureSeed,
    curve: auths_crypto::CurveType,
}

impl SessionKey {
    fn try_new(alias: &str) -> anyhow::Result<SessionKey> {
        let Ok(passphrase) = std::env::var("AUTHS_PASSPHRASE") else {
            bail!("AUTHS_PASSPHRASE unset — in-process signing needs the headless passphrase");
        };
        let keychain = get_platform_keychain()
            .map_err(|e| anyhow::anyhow!("open the keychain for session signing: {e}"))?;
        let (_did, _role, encrypted) = keychain
            .load_key(&KeyAlias::new_unchecked(alias))
            .map_err(|e| anyhow::anyhow!("load key `{alias}` for session signing: {e}"))?;
        let decrypted = auths_sdk::crypto::decrypt_keypair(&encrypted, &passphrase)
            .map_err(|e| anyhow::anyhow!("decrypt key `{alias}` for session signing: {e}"))?;
        let parsed = auths_crypto::parse_key_material(&decrypted)
            .map_err(|e| anyhow::anyhow!("parse key material for `{alias}`: {e}"))?;
        let curve = parsed.seed.curve();
        Ok(SessionKey {
            seed: parsed.seed.to_secure_seed(),
            curve,
        })
    }
}

/// Per-session in-process signing state, held by the chain.
pub struct InprocState {
    alias: String,
    key: OnceLock<Option<SessionKey>>,
    call_templates: Mutex<HashMap<String, CommitTemplate>>,
    settle_template: Mutex<Option<CommitTemplate>>,
}

impl InprocState {
    /// Fresh state for one wrapped session (no keychain touch until first use).
    pub fn new(alias: &str) -> InprocState {
        InprocState {
            alias: alias.to_string(),
            key: OnceLock::new(),
            call_templates: Mutex::new(HashMap::new()),
            settle_template: Mutex::new(None),
        }
    }

    fn session_key(&self) -> Option<&SessionKey> {
        self.key
            .get_or_init(|| match SessionKey::try_new(&self.alias) {
                Ok(key) => Some(key),
                Err(e) => {
                    eprintln!(
                        "auths-mcp-gateway: in-process signing unavailable ({e}) — \
                         staying on the per-call subprocess signer"
                    );
                    None
                }
            })
            .as_ref()
    }

    /// Learn the CALL commit shape for `capability` from a subprocess-signed commit.
    pub fn learn_call(&self, capability: &str, raw: &[u8]) {
        #[allow(clippy::expect_used)] // INVARIANT: poisoned mutex = another thread panicked
        let mut templates = self.call_templates.lock().expect("call templates lock");
        if !templates.contains_key(capability)
            && let Some(t) = CommitTemplate::harvest(raw, CALL_SLOTS)
        {
            templates.insert(capability.to_string(), t);
        }
    }

    /// Learn the SETTLEMENT commit shape from a subprocess-signed commit.
    pub fn learn_settlement(&self, raw: &[u8]) {
        #[allow(clippy::expect_used)] // INVARIANT: poisoned mutex = another thread panicked
        let mut template = self.settle_template.lock().expect("settle template lock");
        if template.is_none() {
            *template = CommitTemplate::harvest(raw, SETTLE_SLOTS);
        }
    }

    /// Sign a CALL commit in-process; `None` = not ready (caller uses the subprocess path).
    pub fn try_sign_call(
        &self,
        canonical: &[u8],
        capability: &str,
        prev_binding: &str,
    ) -> Option<(Vec<u8>, String)> {
        let template = {
            #[allow(clippy::expect_used)] // INVARIANT: poisoned mutex = another thread panicked
            let templates = self.call_templates.lock().expect("call templates lock");
            templates.get(capability).cloned()
        }?;
        let key = self.session_key()?;
        let values = HashMap::from([("Auths-Prev", prev_binding.to_string())]);
        let message = template.render(&values)?;
        sign_commit_object(
            key,
            &template.identity_line,
            "call.json",
            canonical,
            &message,
        )
        .map_err(|e| eprintln!("auths-mcp-gateway: in-process call sign failed ({e})"))
        .ok()
    }

    /// Sign a SETTLEMENT commit in-process; `None` = not ready.
    #[allow(clippy::too_many_arguments)]
    pub fn try_sign_settlement(
        &self,
        call_binding: &str,
        rail: &str,
        actual_cents: u64,
        rail_ref: &str,
        cumulative_cents: u64,
    ) -> Option<(Vec<u8>, String)> {
        let template = {
            #[allow(clippy::expect_used)] // INVARIANT: poisoned mutex = another thread panicked
            let template = self.settle_template.lock().expect("settle template lock");
            template.clone()
        }?;
        let key = self.session_key()?;
        let values = HashMap::from([
            ("Auths-Settle-Call", call_binding.to_string()),
            ("Auths-Settle-Rail", rail.to_string()),
            ("Auths-Settle-Cents", actual_cents.to_string()),
            ("Auths-Settle-Ref", rail_ref.to_string()),
            ("Auths-Settle-Cumulative", cumulative_cents.to_string()),
        ]);
        let message = template.render(&values)?;
        sign_commit_object(key, &template.identity_line, "settle.json", b"{}", &message)
            .map_err(|e| eprintln!("auths-mcp-gateway: in-process settle sign failed ({e})"))
            .ok()
    }
}

fn git_object_sha(kind: &str, content: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(format!("{kind} {}\0", content.len()).as_bytes());
    hasher.update(content);
    hasher.finalize().into()
}

fn tree_for_single_file(name: &str, content: &[u8]) -> [u8; 20] {
    let blob = git_object_sha("blob", content);
    let mut entry = Vec::with_capacity(name.len() + 28);
    entry.extend_from_slice(format!("100644 {name}\0").as_bytes());
    entry.extend_from_slice(&blob);
    git_object_sha("tree", &entry)
}

/// Build + SSHSIG-sign one git commit object exactly as `git commit` with
/// `gpg.format=ssh` does: the signature covers the object bytes WITHOUT the
/// `gpgsig` header; the header carries the PEM with space-continuation lines.
fn sign_commit_object(
    key: &SessionKey,
    identity_line: &str,
    filename: &str,
    file_content: &[u8],
    message: &str,
) -> anyhow::Result<(Vec<u8>, String)> {
    let tree_hex = encode_hex(&tree_for_single_file(filename, file_content));
    #[allow(clippy::disallowed_methods)] // CLI process boundary: wall-clock commit stamps
    let ts = chrono::Utc::now().timestamp();
    let unsigned_head = format!(
        "tree {tree_hex}\nauthor {identity_line} {ts} +0000\ncommitter {identity_line} {ts} +0000\n"
    );
    let payload = format!("{unsigned_head}\n{message}");
    let pem = auths_sdk::crypto::create_sshsig(&key.seed, payload.as_bytes(), "git", key.curve)
        .context("create the SSHSIG over the commit payload")?;
    let continuation = pem.trim_end().lines().collect::<Vec<_>>().join("\n ");
    let raw = format!("{unsigned_head}gpgsig {continuation}\n\n{message}");
    let sha = encode_hex(&git_object_sha("commit", raw.as_bytes()));
    Ok((raw.into_bytes(), sha))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_object_hashes_match_git() {
        // `echo -n 'hello' | git hash-object --stdin` → b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0
        assert_eq!(
            encode_hex(&git_object_sha("blob", b"hello")),
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
        );
    }

    #[test]
    fn harvest_and_render_swap_only_dynamic_values() {
        let raw = b"tree 0000000000000000000000000000000000000000\n\
author fleet <f@a> 1700000000 +0000\n\
committer fleet <f@a> 1700000000 +0000\n\
\n\
tools/call\n\
\n\
Auths-Prev: OLDPREV\n\
Auths-Id: did:keri:Eroot\n\
Auths-Scope: paid:call\n";
        let t = CommitTemplate::harvest(raw, CALL_SLOTS).unwrap();
        assert_eq!(t.identity_line, "fleet <f@a>");
        let rendered = t
            .render(&HashMap::from([("Auths-Prev", "NEWPREV".to_string())]))
            .unwrap();
        assert!(rendered.contains("Auths-Prev: NEWPREV"));
        assert!(rendered.contains("Auths-Id: did:keri:Eroot"));
        assert!(!rendered.contains("OLDPREV"));
    }
}
