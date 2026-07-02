#!/usr/bin/env python3
"""
Auths CLI Golden-Path Smoke Test

Drives the locally built `auths` binary through the full first-run lifecycle a
real developer (and a CI job, and an agent operator) would hit, in isolated
HOME directories, fully headless — no Touch ID, no prompts, no network writes.

Usage:
    cargo build -p auths-cli                       # build first (debug)
    python3 docs/smoketests/end_to_end.py          # run everything
    python3 docs/smoketests/end_to_end.py --release  # test the release binary
    AUTHS_BIN=/path/to/auths python3 docs/smoketests/end_to_end.py

What it covers (the golden paths):
  1. Developer first-run    init → status → whoami → key/device list
  2. The 30-second aha      auths demo (must be headless and fast)
  3. Artifact signing       sign <file> → verify <file>
  4. Git commit signing     git commit (auto-sign via init's git config) → verify HEAD
  5. Stateless verification id export-bundle → verify HEAD --identity-bundle
  6. Trust pinning          trust pin / list / show / remove
  7. Agent delegation       id agent add → list → (the supported agent path)
  8. Key rotation           id rotate → sign + verify again (stale-key regression)
  9. CI profile             init --profile ci ×3 fresh HOMEs (flakiness probe, #246)
     then sign using the printed env block (the documented CI handoff)
 10. Retired path UX        init --profile agent must fail with actionable guidance
 11. Hygiene                doctor, config show, error lookup, completions, --json

Results (per-step exit code, duration, full output) are written to
docs/smoketests/last_run.json for analysis.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
RESULTS_PATH = SCRIPT_DIR / "last_run.json"

# ── Colors ───────────────────────────────────────────────────────────────────

RED, GREEN, YELLOW, BLUE, CYAN = "\033[0;31m", "\033[0;32m", "\033[1;33m", "\033[0;34m", "\033[0;36m"
BOLD, DIM, NC = "\033[1m", "\033[2m", "\033[0m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{NC}"


def section(title: str) -> None:
    print(f"\n{_c(BLUE, '=' * 78)}\n{_c(BOLD + BLUE, f'  {title}')}\n{_c(BLUE, '=' * 78)}")


def info(msg: str) -> None:
    print(f"  {msg}")


# ── Result tracking ──────────────────────────────────────────────────────────


@dataclass
class StepResult:
    name: str
    cmd: str
    returncode: int | None
    duration_s: float
    stdout: str
    stderr: str
    ok: bool
    note: str = ""
    skipped: bool = False


@dataclass
class Report:
    steps: list[StepResult] = field(default_factory=list)

    def add(self, r: StepResult) -> None:
        self.steps.append(r)
        flag = (
            _c(YELLOW, "⚠ SKIP")
            if r.skipped
            else _c(GREEN, "✓ PASS")
            if r.ok
            else _c(RED, "✗ FAIL")
        )
        note = f"  {_c(DIM, r.note)}" if r.note else ""
        print(f"  {flag}  {r.name}  {_c(DIM, f'({r.duration_s:.1f}s)')}{note}")
        if not r.ok and not r.skipped:
            tail = (r.stderr or r.stdout).strip().split("\n")
            for line in tail[-4:]:
                print(f"        {_c(DIM, line)}")

    @property
    def failed(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok and not s.skipped]


# ── Execution harness ────────────────────────────────────────────────────────


class Runner:
    """Runs `auths` against an isolated HOME with a headless file keychain."""

    def __init__(self, auths_bin: Path, home: Path, report: Report):
        self.auths_bin = auths_bin
        self.home = home
        self.report = report
        home.mkdir(parents=True, exist_ok=True)
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(home),
                "AUTHS_KEYCHAIN_BACKEND": "file",
                # Must satisfy the strength policy: >=12 chars, >=3 of 4 character
                # classes (crates/auths-core/src/crypto/encryption.rs).
                "AUTHS_PASSPHRASE": "Smoke-Test-Pass1!",
                "GIT_AUTHOR_NAME": "Smoke Tester",
                "GIT_AUTHOR_EMAIL": "smoke@auths.dev",
                "GIT_COMMITTER_NAME": "Smoke Tester",
                "GIT_COMMITTER_EMAIL": "smoke@auths.dev",
                # Keep the built binaries first on PATH for git's ssh-program lookup.
                "PATH": f"{self.auths_bin.parent}:{os.environ.get('PATH', '')}",
            }
        )

    def run(
        self,
        name: str,
        args: list[str],
        cwd: Path | None = None,
        timeout: int = 90,
        expect_failure: bool = False,
        ok_codes: tuple[int, ...] = (0,),
        note: str = "",
        raw_cmd: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> StepResult:
        cmd = raw_cmd if raw_cmd is not None else [str(self.auths_bin), *args]
        env = self.env.copy()
        if extra_env:
            env.update(extra_env)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                env=env,
                cwd=cwd or self.home,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            rc: int | None = proc.returncode
            out, err = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            rc, out, err = None, (e.stdout or ""), f"TIMEOUT after {timeout}s"
        except Exception as e:  # noqa: BLE001 — smoke harness records everything
            rc, out, err = None, "", f"EXCEPTION: {e}"
        duration = time.monotonic() - start

        if rc is None:
            ok = False
        elif expect_failure:
            ok = rc not in ok_codes
        else:
            ok = rc in ok_codes

        result = StepResult(
            name=name,
            cmd=" ".join(cmd),
            returncode=rc,
            duration_s=duration,
            stdout=out,
            stderr=err,
            ok=ok,
            note=note,
        )
        self.report.add(result)
        return result

    def skip(self, name: str, reason: str) -> StepResult:
        result = StepResult(
            name=name, cmd="", returncode=None, duration_s=0.0,
            stdout="", stderr="", ok=True, skipped=True, note=reason,
        )
        self.report.add(result)
        return result


# ── Helpers ──────────────────────────────────────────────────────────────────


def find_did(text: str) -> str | None:
    m = re.search(r"did:keri:[A-Za-z0-9_-]{20,}", text)
    return m.group(0) if m else None


def find_hex_key(text: str) -> str | None:
    m = re.search(r"\b[0-9a-f]{64,66}\b", text)
    return m.group(0) if m else None


def parse_env_block(text: str) -> dict[str, str]:
    """Extract `export KEY="VALUE"` lines from `init --profile ci` output."""
    env: dict[str, str] = {}
    for m in re.finditer(r'export ([A-Z_0-9]+)="([^"]*)"', text):
        env[m.group(1)] = m.group(2)
    return env


def git(runner: Runner, repo: Path, *args: str, name: str, **kw) -> StepResult:
    return runner.run(name, [], cwd=repo, raw_cmd=["git", *args], **kw)


# ── Scenarios ────────────────────────────────────────────────────────────────


def scenario_developer(auths: Path, work: Path, report: Report) -> Runner:
    section("1. DEVELOPER FIRST-RUN  (init → status → whoami → key/device list)")
    r = Runner(auths, work / "home-dev", report)

    r.run("git global identity (test fixture)", [], raw_cmd=[
        "git", "config", "--global", "user.name", "Smoke Tester"])
    r.run("git global email (test fixture)", [], raw_cmd=[
        "git", "config", "--global", "user.email", "smoke@auths.dev"])

    r.run("init --profile developer --non-interactive",
          ["init", "--profile", "developer", "--non-interactive"], timeout=180)
    status = r.run("status", ["status"])
    combined = status.stdout + status.stderr
    if status.ok and "this device" not in combined:
        status.ok = False
        status.note = "status must count the current machine, not report 'Devices: none'"
    r.run("whoami", ["whoami"])
    r.run("whoami --json", ["--json", "whoami"])
    r.run("key list", ["key", "list"])
    r.run("device list", ["device", "list"])
    return r


def scenario_demo(r: Runner) -> None:
    section("2. THE 30-SECOND AHA  (auths demo, headless)")
    res = r.run("demo", ["demo"], timeout=30)
    if res.ok and res.duration_s > 10:
        res.note += f" SLOW: {res.duration_s:.1f}s (target <5s)"


def scenario_artifact(r: Runner, work: Path) -> None:
    section("3. ARTIFACT SIGNING  (sign <file> → verify)")
    artifact = work / "artifact.txt"
    artifact.write_text("smoke test artifact\n")

    res = r.run("sign <file>", ["sign", str(artifact)], cwd=work)
    if not res.ok:
        r.run("sign <file> --key main --device-key main (fallback)",
              ["sign", str(artifact), "--key", "main", "--device-key", "main"],
              cwd=work, note="plain `sign <file>` failed; needed explicit aliases")

    sig = artifact.with_suffix(".txt.auths.json")
    if sig.exists():
        r.run("verify <file> (default sig discovery)", ["verify", str(artifact)], cwd=work)
        r.run("verify <file.auths.json> (direct)", ["verify", str(sig)], cwd=work)
    else:
        r.skip("verify artifact", f"no signature file produced at {sig.name}")


def scenario_git_signing(r: Runner, work: Path) -> Path:
    section("4. GIT COMMIT SIGNING  (README path: git commit → verify; then auths sign HEAD)")
    repo = work / "demo-repo"
    repo.mkdir(exist_ok=True)
    git(r, repo, "init", "-q", name="git init")
    (repo / "README.md").write_text("# smoke\n")
    git(r, repo, "add", ".", name="git add")
    commit = git(r, repo, "commit", "-q", "-m", "smoke: signed commit", name="git commit (auto-sign)")
    if commit.ok:
        r.run("verify HEAD (README path: plain git commit)", ["verify", "HEAD"], cwd=repo)

        # Amend must not duplicate trailers (hook uses --if-exists replace).
        amend = git(r, repo, "commit", "--amend", "-q", "-m", "smoke: amended commit",
                    name="git commit --amend")
        if amend.ok:
            count = git(r, repo, "log", "-1", "--format=%B", name="trailer dedup check (1 Auths-Id)")
            ids = count.stdout.count("Auths-Id:")
            if ids != 1:
                count.ok = False
                count.note = f"expected exactly 1 Auths-Id trailer after amend, found {ids}"
            r.run("verify HEAD (after amend)", ["verify", "HEAD"], cwd=repo)

        r.run("sign HEAD (repair/backfill path)", ["sign", "HEAD"], cwd=repo, timeout=120)
        r.run("verify HEAD (after auths sign HEAD)", ["verify", "HEAD"], cwd=repo)
    else:
        r.skip("verify HEAD", "commit failed — git signing config from init is broken")
    return repo


def scenario_bundle(r: Runner, work: Path, repo: Path) -> None:
    section("5. STATELESS VERIFICATION  (export-bundle → verify --identity-bundle)")
    bundle = work / "identity-bundle.json"
    exported = r.run(
        "id export-bundle",
        ["id", "export-bundle", "--alias", "main", "-o", str(bundle), "--max-age-secs", "3600"],
    )
    if exported.ok and bundle.exists() and repo.exists():
        r.run("verify HEAD --identity-bundle", ["verify", "HEAD", "--identity-bundle", str(bundle)], cwd=repo)
        artifact = repo.parent / "artifact.txt"
        if artifact.exists():
            r.run("verify <artifact> --identity-bundle",
                  ["verify", str(artifact), "--identity-bundle", str(bundle)], cwd=repo.parent)
    else:
        r.skip("verify HEAD --identity-bundle", "bundle export failed or no signed repo")


def scenario_trust(r: Runner) -> None:
    section("6. TRUST PINNING  (pin --did only → list → show → remove)")
    r.run("trust list (empty)", ["trust", "list"])

    ident = r.run("whoami --json (for pin inputs)", ["--json", "whoami"], note="parsing did")
    did = find_did(ident.stdout + ident.stderr)
    key = find_hex_key(ident.stdout + ident.stderr)
    if ident.ok and not key:
        ident.ok = False
        ident.note = "whoami --json must expose public_key_hex"
    if did:
        r.run("trust pin --did (key resolved from KEL)", ["trust", "pin", "--did", did])
        r.run("trust list (pinned)", ["trust", "list"])
        r.run("trust show", ["trust", "show", did])
        r.run("trust remove", ["trust", "remove", did])
    else:
        r.skip("trust pin", "could not parse did from whoami --json")


def scenario_agent_delegation(r: Runner) -> None:
    section("7. AGENT DELEGATION  (the supported agent path: id agent add)")
    r.run(
        "id agent add --label smoke-agent --scope sign_commit",
        ["id", "agent", "add", "--label", "smoke-agent", "--key", "main",
         "--scope", "sign_commit", "--expires-in", "3600"],
        timeout=120,
    )
    r.run("id agent list", ["id", "agent", "list"])


def scenario_rotation(r: Runner, work: Path) -> None:
    section("8. KEY ROTATION  (id rotate → sign + verify again, stable alias)")
    repo = work / "demo-repo"
    pre_sha = ""
    if repo.exists():
        pre_sha = git(r, repo, "rev-parse", "HEAD",
                      name="capture pre-rotation HEAD").stdout.strip()

    r.run("id rotate", ["id", "rotate"], timeout=120)
    status = r.run("status (after rotate)", ["status"])

    # Stable alias: the signing key name must NOT change across rotation.
    keys = r.run("key list (after rotate)", ["--json", "key", "list"])
    if keys.ok and '"main"' not in keys.stdout:
        keys.ok = False
        keys.note = "stable-alias regression: 'main' missing after rotation"

    artifact = work / "post-rotate.txt"
    artifact.write_text("signed after rotation\n")
    res = r.run("sign <file> (after rotate)", ["sign", str(artifact)], cwd=work)
    sig = artifact.with_suffix(".txt.auths.json")
    if res.ok and sig.exists():
        r.run("verify <file> (after rotate)", ["verify", str(artifact)], cwd=work)
    else:
        r.skip("verify after rotate", "post-rotation signing failed")

    if repo.exists():
        # Plain `git commit` must keep working after rotation — this is the
        # exact regression that shipped in <=0.1.2 (alias rename broke
        # user.signingKey silently).
        (repo / "post-rotate.md").write_text("post-rotation commit\n")
        git(r, repo, "add", "-A", name="git add (after rotate)")
        commit = git(r, repo, "commit", "-q", "-m", "smoke: post-rotation commit",
                     name="git commit (after rotate)")
        if commit.ok:
            r.run("verify HEAD (after rotate)", ["verify", "HEAD"], cwd=repo)
        else:
            r.skip("verify HEAD (after rotate)", "post-rotation commit failed")

        # Commits are signed by the delegated device #0, and `id rotate` rotates the ROOT
        # key — which does NOT rotate the device's key. The delegation persists across the
        # root rotation, so a device-#0-signed pre-rotation commit stays valid. (Superseding
        # a device's commits requires rotating/revoking THAT device, not the root — device
        # key rotation is tracked separately as #205.)
        if pre_sha:
            r.run("verify pre-rotation commit (survives root rotation)",
                  ["verify", pre_sha], cwd=repo)


def scenario_ci(auths: Path, work: Path, report: Report) -> None:
    section("9. CI PROFILE  (3 fresh HOMEs — flakiness probe for #246 — then env-block handoff)")
    last_runner: Runner | None = None
    last_init: StepResult | None = None
    for i in range(1, 4):
        ci = Runner(auths, work / f"home-ci-{i}", report)
        ci_repo = ci.home / "ci-workspace"
        ci_repo.mkdir(parents=True, exist_ok=True)
        last_init = ci.run(
            f"init --profile ci --non-interactive (run {i}/3)",
            ["init", "--profile", "ci", "--non-interactive"],
            cwd=ci_repo, timeout=180,
        )
        last_runner = ci

    if last_runner and last_init and last_init.ok:
        # The env block must be pipeable: parsing stdout ONLY is the regression
        # test for "data goes to stdout" (D8).
        env_block = parse_env_block(last_init.stdout)
        if env_block:
            artifact = last_runner.home / "ci-artifact.txt"
            artifact.write_text("ci artifact\n")
            last_runner.run(
                "sign <file> using printed CI env block",
                ["sign", str(artifact)],
                cwd=last_runner.home / "ci-workspace",
                extra_env=env_block,
                note=f"env block had {len(env_block)} vars",
            )
        else:
            last_runner.skip("CI env-block handoff", "init output contained no export lines to copy")
    elif last_runner:
        last_runner.skip("CI env-block handoff", "ci init failed")


def scenario_weak_passphrase(auths: Path, work: Path, report: Report) -> None:
    section("10. TRANSACTIONAL INIT  (weak passphrase → typed error, zero state left)")
    r = Runner(auths, work / "home-weak-pass", report)
    res = r.run(
        "init with weak AUTHS_PASSPHRASE (expected to fail)",
        ["init", "--profile", "developer", "--non-interactive"],
        expect_failure=True, timeout=120,
        extra_env={"AUTHS_PASSPHRASE": "weak-passphrase"},
    )
    combined = res.stdout + res.stderr
    if res.ok and "AUTHS_PASSPHRASE" not in combined:
        res.ok = False
        res.note = "error must name the AUTHS_PASSPHRASE env var as the input to fix"

    status = r.run("status (must show no identity)", ["status"],
                   extra_env={"AUTHS_PASSPHRASE": "weak-passphrase"})
    if status.ok and "not initialized" not in (status.stdout + status.stderr):
        status.ok = False
        status.note = "failed init left a half-created identity behind"
    keys = r.run("key list (must be empty)", ["--json", "key", "list"],
                 extra_env={"AUTHS_PASSPHRASE": "weak-passphrase"})
    if keys.ok and '"count": 0' not in keys.stdout and '"count":0' not in keys.stdout:
        keys.ok = False
        keys.note = "failed init left keys behind"


def scenario_exit_codes(r: Runner, work: Path) -> None:
    section("12. EXIT-CODE CONTRACT  (0 verified · 1 failed · 2 could-not-attempt)")
    artifact = work / "artifact.txt"
    sig = artifact.with_suffix(".txt.auths.json")
    if sig.exists():
        tampered_dir = work / "tampered"
        tampered_dir.mkdir(exist_ok=True)
        tampered = tampered_dir / "artifact.txt"
        tampered.write_text("tampered content\n")
        tampered_sig = tampered_dir / "artifact.txt.auths.json"
        tampered_sig.write_text(sig.read_text())
        res = r.run("verify tampered artifact (expect rc=1)",
                    ["verify", str(tampered)], cwd=tampered_dir, expect_failure=True)
        if res.ok and res.returncode != 1:
            res.ok = False
            res.note = f"verification failure must exit 1, got {res.returncode}"
    else:
        r.skip("verify tampered artifact", "no signed artifact available")

    res = r.run("verify malformed input (expect rc=2)",
                ["verify", "definitely-not-a-ref-or-file"], expect_failure=True)
    if res.ok and res.returncode != 2:
        res.ok = False
        res.note = f"could-not-attempt must exit 2, got {res.returncode}"


def scenario_retired_agent_profile(auths: Path, work: Path, report: Report) -> None:
    section("11. AGENT PROFILE, NON-INTERACTIVE  (must fail with delegation guidance)")
    r = Runner(auths, work / "home-agent-profile", report)
    res = r.run(
        "init --profile agent --non-interactive (expected to fail)",
        ["init", "--profile", "agent", "--non-interactive"],
        expect_failure=True, timeout=120,
    )
    combined = res.stdout + res.stderr
    if res.ok and "id agent add" not in combined:
        res.ok = False
        res.note = "failed as expected BUT the error does not point at `auths id agent add`"


def scenario_hygiene(r: Runner) -> None:
    section("13. HYGIENE  (doctor, config, error lookup, completions, json)")
    r.run("doctor (0 or 2 = functional)", ["doctor"], ok_codes=(0, 2), timeout=60)
    r.run("config show", ["config", "show"])
    r.run("error show AUTHS-E3020", ["error", "AUTHS-E3020"])
    r.run("error list", ["error", "list"])
    r.run("completions bash", ["completions", "bash"])
    r.run("--help", ["--help"])
    r.run("--help-all", ["--help-all"])
    r.run("--version", ["--version"])


# ── Main ─────────────────────────────────────────────────────────────────────


def resolve_binary(release: bool) -> Path:
    if env_bin := os.environ.get("AUTHS_BIN"):
        return Path(env_bin)
    profile = "release" if release else "debug"
    return REPO_ROOT / "target" / profile / "auths"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="test target/release/auths")
    parser.add_argument("--keep", action="store_true", help="keep the temp work dir")
    args = parser.parse_args()

    auths = resolve_binary(args.release)
    if not auths.exists():
        print(_c(RED, f"binary not found: {auths}\nbuild it first: cargo build -p auths-cli"))
        return 2

    version = subprocess.run([str(auths), "--version"], capture_output=True, text=True).stdout.strip()
    print(_c(BOLD + GREEN, "\nAuths CLI Golden-Path Smoke Test"))
    info(f"binary:  {auths}")
    info(f"version: {version}")

    report = Report()
    work = Path(tempfile.mkdtemp(prefix="auths-smoke-"))
    info(f"workdir: {work}")

    try:
        dev = scenario_developer(auths, work, report)
        scenario_demo(dev)
        scenario_artifact(dev, work)
        repo = scenario_git_signing(dev, work)
        scenario_bundle(dev, work, repo)
        scenario_trust(dev)
        scenario_agent_delegation(dev)
        scenario_rotation(dev, work)
        scenario_ci(auths, work, report)
        scenario_weak_passphrase(auths, work, report)
        scenario_retired_agent_profile(auths, work, report)
        scenario_exit_codes(dev, work)
        scenario_hygiene(dev)
    finally:
        RESULTS_PATH.write_text(json.dumps(
            {
                "binary": str(auths),
                "version": version,
                "steps": [vars(s) for s in report.steps],
            },
            indent=2,
        ))
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    section("SUMMARY")
    passed = sum(1 for s in report.steps if s.ok and not s.skipped)
    skipped = sum(1 for s in report.steps if s.skipped)
    failed = len(report.failed)
    print(f"  total {len(report.steps)} · {_c(GREEN, f'passed {passed}')} · "
          f"{_c(RED, f'failed {failed}')} · {_c(YELLOW, f'skipped {skipped}')}")
    if report.failed:
        print(_c(RED, "\n  Failures:"))
        for s in report.failed:
            print(f"    • {s.name}  {_c(DIM, f'rc={s.returncode}')}")
    info(f"\nfull results: {RESULTS_PATH}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
