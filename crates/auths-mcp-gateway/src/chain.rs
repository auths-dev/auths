//! Throwaway delegation-chain construction + per-call signing for the replay gate.
//!
//! Replay must drive the *real* enforcement path, which means a *real* signed
//! proof per call: the agent signs the canonical `tools/call` as an auths artifact
//! (a git commit over the canonical bytes, carrying the `Auths-Scope` trailer for
//! the capability it exercises) with its delegated device key. This module builds
//! that chain and produces those proofs by driving the proven `auths` CLI + `git`
//! toolchain — the same recipe the scripted suites use — in a sandbox HOME the
//! probe set up.
//!
//! Producing the proof is *glue*; the security boundary is the verify, which runs
//! natively in-process in `auths-mcp-core` (D2) over the raw commit bytes this
//! module returns. Signing reuses the audited signer rather than re-implementing
//! SSHSIG.

use std::path::{Path, PathBuf};
use std::process::Command;

use auths_mcp_core::{Cents, NonZeroCents};

/// A built delegation chain in a sandbox registry: the parent root and a delegated
/// scoped agent, both resolvable from the org registry the verifier replays.
pub struct Chain {
    /// The path to the `auths` CLI binary (proven signer/registry driver).
    auths_bin: PathBuf,
    /// The org/verify registry: org icp + scope seal + agent dip all resolvable.
    org_repo: PathBuf,
    /// The agent's delegate-machine registry (where the agent signs as its dip).
    agent_repo: PathBuf,
    /// A scratch dir for per-call work repos.
    work_root: PathBuf,
    /// The parent root `did:keri:`.
    pub root_did: String,
    /// The delegated agent `did:keri:`.
    pub agent_did: String,
    /// The agent's keychain alias (its delegate signing key).
    agent_alias: String,
    /// Whether the agent's delegation has been revoked this session.
    revoked: bool,
    /// In-process per-call signing: the first call of each kind runs the full
    /// subprocess ceremony and is harvested as a template; later calls sign the
    /// same commit shape in memory (the fleet-throughput path).
    inproc: crate::inproc_sign::InprocState,
}

/// The registry the verifier replays both KELs from (org icp + scope seal + agent
/// dip). The gateway's native gate resolves the agent + delegator KELs from here.
impl Chain {
    /// The org registry path (where both KELs + the scope seal resolve).
    pub fn org_repo(&self) -> &Path {
        &self.org_repo
    }
}

/// Translate a gateway capability (the MCP-facing dotted form, e.g. `fs.read`) to
/// the `auths` capability grammar (`:`-separated opaque tokens — `.` is not a legal
/// capability character). The verifier judges containment over these tokens, so the
/// scope minted at delegation and the scope claimed per call must use the same form.
fn to_auths_capability(cap: &str) -> String {
    cap.replace('.', ":")
}

/// The identity the gateway commits under when the machine has none: a clean HOME
/// (no gitconfig, no GIT_* env) must never abort a chain build on git's
/// auto-detect. Caller-provided env always wins — these apply only when absent.
pub(crate) fn default_git_identity() -> [(&'static str, &'static str); 4] {
    [
        ("GIT_AUTHOR_NAME", "auths-mcp-gateway"),
        ("GIT_AUTHOR_EMAIL", "gateway@auths.local"),
        ("GIT_COMMITTER_NAME", "auths-mcp-gateway"),
        ("GIT_COMMITTER_EMAIL", "gateway@auths.local"),
    ]
}

fn run(cmd: &mut Command) -> anyhow::Result<std::process::Output> {
    for (key, value) in default_git_identity() {
        if std::env::var_os(key).is_none()
            && !cmd.get_envs().any(|(k, _)| k == std::ffi::OsStr::new(key))
        {
            cmd.env(key, value);
        }
    }
    let out = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("spawn {:?}: {e}", cmd.get_program()))?;
    Ok(out)
}

fn must(cmd: &mut Command, what: &str) -> anyhow::Result<std::process::Output> {
    let out = run(cmd)?;
    if !out.status.success() {
        anyhow::bail!(
            "{what} failed (exit {:?}):\n{}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(out)
}

fn first_did(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes);
    // did:keri:E… (CESR base64url tail). Scan for the prefix and take the run of
    // base64url characters that follows.
    let needle = "did:keri:";
    let start = s.find(needle)?;
    let tail = &s[start + needle.len()..];
    let end = tail
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(tail.len());
    if end == 0 {
        return None;
    }
    Some(format!("{needle}{}", &tail[..end]))
}

impl Chain {
    /// Build the chain: locate `auths`, create the org root, delegate a scoped
    /// agent, and materialize the agent's delegate machine. `lab` is the sandbox
    /// root (a throwaway dir); `scope` is the capability set the parent anchors.
    ///
    /// The sandbox env (HOME, AUTHS_HOME/REPO, keychain, passphrase, git identity)
    /// must already be exported by the caller (the probe harness sets these);
    /// chain construction inherits them.
    pub fn build(lab: &Path, scope: &[String]) -> anyhow::Result<Self> {
        let auths_bin = locate_auths()?;
        // A fleet gateway names its own delegation label so N wraps can join ONE
        // shared root registry (one label per gateway); the default single-wrap
        // sandbox keeps the historical `agent` label and layout.
        let agent_alias =
            std::env::var("AUTHS_MCP_AGENT_LABEL").unwrap_or_else(|_| "agent".to_string());
        let org_repo = lab.join("registry");
        let agent_repo = if agent_alias == "agent" {
            lab.join("registry-agent")
        } else {
            lab.join(format!("registry-agent-{agent_alias}"))
        };
        // Per-delegation work namespace: N fleet gateways share one lab, and each
        // signs into its own subtree so per-call repos never collide across processes.
        let work_root = lab.join("work").join(&agent_alias);
        std::fs::create_dir_all(&org_repo)?;
        std::fs::create_dir_all(&work_root)?;

        // 1. The org root identity — reused when the registry already holds one, so
        //    a fleet of gateways delegates under a single shared root.
        let existing_root = Command::new(&auths_bin)
            .args([
                "--repo",
                &org_repo.to_string_lossy(),
                "--json",
                "id",
                "show",
            ])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| first_did(&out.stdout));
        let root_did = if let Some(did) = existing_root {
            did
        } else {
            let meta = lab.join("org-meta.json");
            std::fs::write(
                &meta,
                br#"{"name":"Parent Root","purpose":"bounded-agent MCP gateway"}"#,
            )?;
            must(
                Command::new(&auths_bin)
                    .args([
                        "--repo",
                        &org_repo.to_string_lossy(),
                        "--json",
                        "id",
                        "create",
                    ])
                    .args(["--metadata-file", &meta.to_string_lossy()])
                    .args(["--local-key-alias", "root"]),
                "id create (org root)",
            )?;
            let show = must(
                Command::new(&auths_bin).args([
                    "--repo",
                    &org_repo.to_string_lossy(),
                    "--json",
                    "id",
                    "show",
                ]),
                "id show (org root)",
            )?;
            first_did(&show.stdout).ok_or_else(|| {
                anyhow::anyhow!("could not read the org root did:keri from id show")
            })?
        };

        // 2. The delegated scoped agent.
        let mut add = Command::new(&auths_bin);
        add.args([
            "--repo",
            &org_repo.to_string_lossy(),
            "--json",
            "id",
            "agent",
            "add",
        ])
        .args(["--label", &agent_alias])
        .args(["--key", "root"])
        .args(["--curve", "ed25519"]);
        for cap in scope {
            add.args(["--scope", &to_auths_capability(cap)]);
        }
        let added = must(&mut add, "id agent add (scoped agent)")?;
        let agent_did = first_did(&added.stdout)
            .ok_or_else(|| anyhow::anyhow!("could not read the agent did:keri from agent add"))?;

        // 3. Materialize the agent's delegate machine: copy the org registry and
        //    drop the org icp root subtree, leaving only the agent dip so the local
        //    signer resolves to the agent (tree surgery only — no key moved).
        materialize_agent_machine(&org_repo, &agent_repo, &root_did)?;

        let inproc = crate::inproc_sign::InprocState::new(&agent_alias);
        Ok(Self {
            auths_bin,
            org_repo,
            agent_repo,
            work_root,
            root_did,
            agent_did,
            agent_alias,
            revoked: false,
            inproc,
        })
    }

    /// Revoke the agent's delegation (mid-session kill-switch). The next signed
    /// call re-derives liveness from the chain and is refused `Revoked`.
    pub fn revoke(&mut self) -> anyhow::Result<()> {
        must(
            Command::new(&self.auths_bin)
                .args([
                    "--repo",
                    &self.org_repo.to_string_lossy(),
                    "--json",
                    "id",
                    "agent",
                    "revoke",
                ])
                .args(["--key", "root"])
                .arg(&self.agent_did),
            "id agent revoke",
        )?;
        // Re-materialize so the agent machine sees the revocation in the registry it
        // signs from (the verify reads the org registry regardless).
        std::fs::remove_dir_all(&self.agent_repo).ok();
        materialize_agent_machine(&self.org_repo, &self.agent_repo, &self.root_did)?;
        self.revoked = true;
        Ok(())
    }

    /// Sign one canonical `tools/call` as the agent: write the canonical bytes into
    /// a fresh git commit, sign it with `auths sign HEAD --scope <cap>` (the agent's
    /// delegated device key), and return `(raw_commit_bytes, commit_sha)`. The raw
    /// commit is exactly what the native verifier authenticates.
    pub fn sign_call(
        &self,
        idx: usize,
        canonical: &[u8],
        capability: &str,
        prev_binding: &str,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        if let Some(signed) = self
            .inproc
            .try_sign_call(canonical, capability, prev_binding)
        {
            return Ok(signed);
        }
        let work = self.work_root.join(format!("call-{idx}"));
        std::fs::create_dir_all(&work)?;
        std::fs::write(work.join("call.json"), canonical)?;

        // Fresh repo so each call is its own signed commit.
        must(
            Command::new("git").arg("init").arg("-q").current_dir(&work),
            "git init (per-call work repo)",
        )?;
        // Configure git to sign as the agent through `auths-sign` (git's SSH signing
        // program). `auths sign HEAD` amends the commit, which triggers this signer.
        let sign_prog = locate_auths_sign(&self.auths_bin)?;
        for (k, v) in [
            ("gpg.format", "ssh".to_string()),
            ("gpg.ssh.program", sign_prog.to_string_lossy().to_string()),
            ("user.signingkey", format!("auths:{}", self.agent_alias)),
            ("commit.gpgsign", "true".to_string()),
            ("user.name", self.agent_alias.clone()),
            ("user.email", format!("{}@auths.local", self.agent_alias)),
        ] {
            must(
                Command::new("git")
                    .args(["config", k, &v])
                    .current_dir(&work),
                "git config (agent signer)",
            )?;
        }
        must(
            Command::new("git")
                .args(["add", "call.json"])
                .current_dir(&work),
            "git add",
        )?;
        // The signed `Auths-Prev` trailer links this call to the prior spend-log record (the hash of
        // its commit), or a fixed genesis sentinel for the first — so the offline audit can verify
        // the log is a continuous chain and catch a DROPPED or reordered record, not only an edited
        // one. The SSH signature applied below covers it.
        must(
            Command::new("git")
                .args(["commit", "-qm", "tools/call", "--no-gpg-sign"])
                .args(["--trailer", &format!("Auths-Prev:{prev_binding}")])
                .current_dir(&work),
            "git commit",
        )?;
        // Sign as the agent against its delegate-machine registry, claiming the
        // capability the call exercises (the verifier checks it ⊆ anchored scope).
        must(
            Command::new(&self.auths_bin)
                .args(["--repo", &self.agent_repo.to_string_lossy(), "sign", "HEAD"])
                .args(["--scope", &to_auths_capability(capability)])
                .current_dir(&work),
            "auths sign HEAD --scope",
        )?;
        let sha = must(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work),
            "git rev-parse HEAD",
        )?;
        let sha = String::from_utf8_lossy(&sha.stdout).trim().to_string();
        // The raw commit object text the verifier parses (gpgsig + trailers).
        let raw = must(
            Command::new("git")
                .args(["cat-file", "commit", &sha])
                .current_dir(&work),
            "git cat-file commit",
        )?;
        self.inproc.learn_call(capability, &raw.stdout);
        Ok((raw.stdout, sha))
    }

    /// Sign a SETTLEMENT commit: the agent attests its OWN settled cost under the dedicated
    /// `settle` capability. The cost lives in SIGNED git trailers (`Auths-Settle-*`), covered by
    /// the same SSH signature `verify_commit_against_kel_scoped` checks — so an offline auditor
    /// reads the agent-signed `actual_cents` straight from the commit bytes (no git, no tree
    /// hashing) once the signature + `settle ⊆ scope` are verified. `call_binding` is a hash of the
    /// call's own commit bytes, carried in the signed `Auths-Settle-Call` trailer so the audit can
    /// tie this settlement to exactly one call — a settlement cannot be reused on a different call.
    /// Operator can't lower the cost without breaking the signature; agent can't inflate a refused
    /// call (it carries no settlement and the audit cross-checks the rail response). `idx` keys a
    /// per-settlement work repo.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_settlement(
        &self,
        idx: usize,
        call_binding: &str,
        rail: &str,
        actual: NonZeroCents,
        rail_ref: &str,
        cumulative_cents: Cents,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        if let Some(signed) = self.inproc.try_sign_settlement(
            call_binding,
            rail,
            actual.get().get(),
            rail_ref,
            cumulative_cents.get(),
        ) {
            return Ok(signed);
        }
        let work = self.work_root.join(format!("settle-{idx}"));
        std::fs::create_dir_all(&work)?;
        // A minimal payload so the commit has a tree; the cost lives in the SIGNED trailers below.
        std::fs::write(work.join("settle.json"), b"{}")?;
        must(
            Command::new("git").arg("init").arg("-q").current_dir(&work),
            "git init (per-settlement work repo)",
        )?;
        let sign_prog = locate_auths_sign(&self.auths_bin)?;
        for (k, v) in [
            ("gpg.format", "ssh".to_string()),
            ("gpg.ssh.program", sign_prog.to_string_lossy().to_string()),
            ("user.signingkey", format!("auths:{}", self.agent_alias)),
            ("commit.gpgsign", "true".to_string()),
            ("user.name", self.agent_alias.clone()),
            ("user.email", format!("{}@auths.local", self.agent_alias)),
        ] {
            must(
                Command::new("git")
                    .args(["config", k, &v])
                    .current_dir(&work),
                "git config (agent signer)",
            )?;
        }
        must(
            Command::new("git")
                .args(["add", "settle.json"])
                .current_dir(&work),
            "git add",
        )?;
        // The settled cost as SIGNED trailers — the SSH signature covers the whole message.
        must(
            Command::new("git")
                .args(["commit", "-qm", "tools/settle", "--no-gpg-sign"])
                .args(["--trailer", &format!("Auths-Settle-Call:{call_binding}")])
                .args(["--trailer", &format!("Auths-Settle-Rail:{rail}")])
                // The settled cost/cumulative are stamped as raw cent integers (the audit parses
                // them back with `parse::<u64>()`) — unwrap Cents at this trailer-format boundary.
                .args([
                    "--trailer",
                    &format!("Auths-Settle-Cents:{}", actual.get().get()),
                ])
                .args(["--trailer", &format!("Auths-Settle-Ref:{rail_ref}")])
                .args([
                    "--trailer",
                    &format!("Auths-Settle-Cumulative:{}", cumulative_cents.get()),
                ])
                .current_dir(&work),
            "git commit (settlement, signed cost trailers)",
        )?;
        must(
            Command::new(&self.auths_bin)
                .args(["--repo", &self.agent_repo.to_string_lossy(), "sign", "HEAD"])
                .args(["--scope", &to_auths_capability("settle")])
                .current_dir(&work),
            "auths sign HEAD --scope settle",
        )?;
        let sha = must(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work),
            "git rev-parse HEAD",
        )?;
        let sha = String::from_utf8_lossy(&sha.stdout).trim().to_string();
        let raw = must(
            Command::new("git")
                .args(["cat-file", "commit", &sha])
                .current_dir(&work),
            "git cat-file commit",
        )?;
        self.inproc.learn_settlement(&raw.stdout);
        Ok((raw.stdout, sha))
    }
}

/// Materialize the agent's delegate machine: copy the org registry, then rewrite
/// `refs/auths/registry` to drop the org icp root's identity subtree so the local
/// signer resolves to the agent dip. Tree surgery only — no key material moved.
fn materialize_agent_machine(org: &Path, agent: &Path, root_did: &str) -> anyhow::Result<()> {
    let root_pfx = root_did.strip_prefix("did:keri:").unwrap_or(root_did);
    // Fresh copy.
    if agent.exists() {
        std::fs::remove_dir_all(agent)?;
    }
    must(
        Command::new("cp").arg("-R").arg(org).arg(agent),
        "cp -R org registry → agent machine",
    )?;
    let git_dir = agent.join(".git");
    let gd = git_dir.to_string_lossy().to_string();
    let idx = git_dir.join("tmp-index");
    let idx_s = idx.to_string_lossy().to_string();

    must(
        Command::new("git")
            .args(["--git-dir", &gd, "read-tree", "refs/auths/registry"])
            .env("GIT_INDEX_FILE", &idx_s),
        "read-tree refs/auths/registry",
    )?;
    let listed = must(
        Command::new("git")
            .args(["--git-dir", &gd, "ls-files"])
            .env("GIT_INDEX_FILE", &idx_s),
        "ls-files (agent index)",
    )?;
    let subtree = format!(
        "identities/{}/{}/{}/",
        &root_pfx[0..2.min(root_pfx.len())],
        &root_pfx[2..4.min(root_pfx.len())],
        root_pfx
    );
    for line in String::from_utf8_lossy(&listed.stdout).lines() {
        if line.contains(&subtree) {
            must(
                Command::new("git")
                    .args(["--git-dir", &gd, "rm", "--cached", "-q", "--", line])
                    .env("GIT_INDEX_FILE", &idx_s),
                "rm --cached (drop org icp subtree)",
            )?;
        }
    }
    let tree = must(
        Command::new("git")
            .args(["--git-dir", &gd, "write-tree"])
            .env("GIT_INDEX_FILE", &idx_s),
        "write-tree (agent-only)",
    )?;
    let tree = String::from_utf8_lossy(&tree.stdout).trim().to_string();
    let parent = must(
        Command::new("git").args(["--git-dir", &gd, "rev-parse", "refs/auths/registry"]),
        "rev-parse refs/auths/registry",
    )?;
    let parent = String::from_utf8_lossy(&parent.stdout).trim().to_string();
    let commit = must(
        Command::new("git").args([
            "--git-dir",
            &gd,
            "commit-tree",
            &tree,
            "-p",
            &parent,
            "-m",
            "agent-only",
        ]),
        "commit-tree (agent-only)",
    )?;
    let commit = String::from_utf8_lossy(&commit.stdout).trim().to_string();
    must(
        Command::new("git").args([
            "--git-dir",
            &gd,
            "update-ref",
            "refs/auths/registry",
            &commit,
        ]),
        "update-ref refs/auths/registry",
    )?;
    std::fs::remove_file(&idx).ok();
    Ok(())
}

/// Locate the `auths` CLI: honor `AUTHS_BIN`, else look beside this binary and in
/// the monorepo's release output. The probe harness exports `AUTHS_BIN`.
fn locate_auths() -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::env::var("AUTHS_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let cand = dir.join("auths");
        if cand.exists() {
            return Ok(cand);
        }
    }
    anyhow::bail!(
        "could not locate the `auths` CLI — set AUTHS_BIN to the release binary \
         (e.g. target/release/auths)"
    )
}

/// Locate `auths-sign` (git's SSH signing program): honor `AUTHS_SIGN`, else look
/// beside the `auths` binary.
fn locate_auths_sign(auths_bin: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::env::var("AUTHS_SIGN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
    }
    if let Some(dir) = auths_bin.parent() {
        let cand = dir.join("auths-sign");
        if cand.exists() {
            return Ok(cand);
        }
    }
    anyhow::bail!(
        "could not locate `auths-sign` — set AUTHS_SIGN to the release binary \
         (e.g. target/release/auths-sign)"
    )
}
