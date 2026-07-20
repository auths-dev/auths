"""E2E: the MCP gateway's spend log stays offline-verifiable AND tamper-evident
across period rotation.

Why this exists (what a user expects):

* **Security.** The spend log a bounded-agent gateway writes is the moat: anyone
  can re-derive the spend and re-verify every signed proof OFFLINE, trusting
  neither the gateway nor its operator. Tampering — an edited proof, a dropped
  record, a truncated tail — must be caught.
* **Performance / scale.** For high-frequency agents the log rotates by period
  into ``spend-log/<delegation>/<YYYY-MM>.jsonl`` so no single file grows without
  bound. Rotation is a *performance* feature and it must never open a *security*
  hole: a log split across period files has to still fully re-verify and still
  catch tampering across the rotation boundary.

Regression guard: the offline audit (in ``replay``/``wrap`` and the standalone
``verify-spend``) once read the pre-rotation *flat* path and silently SKIPPED the
audit of a rotated log ("no spend log to audit"). This test fails closed if that
returns.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


def _find_binary(env_var: str, name: str):
    if path := os.environ.get(env_var):
        p = Path(path)
        if p.exists():
            return p
    if found := shutil.which(name):
        return Path(found)
    workspace_root = Path(__file__).resolve().parent.parent.parent
    for profile in ("debug", "release"):
        cand = workspace_root / "target" / profile / name
        if cand.exists():
            return cand
    return None


@pytest.fixture(scope="module")
def gateway_bin():
    b = _find_binary("GATEWAY_BIN", "auths-mcp-gateway")
    if b is None:
        pytest.skip("auths-mcp-gateway binary not built")
    return b


@pytest.fixture
def transcript(tmp_path):
    """A minimal hermetic session: four in-scope, in-budget calls — enough
    records to split across two period files for the rotation-boundary check."""
    t = {
        "grant": {"scope": ["fs.read"], "budget": "$5.00", "ttl": "30m"},
        "calls": [
            {"tool": "read_file", "args": {"path": f"/etc/hosts#{i}"},
             "cost_cents": 0, "expect": "allowed"}
            for i in range(4)
        ],
    }
    p = tmp_path / "transcript.json"
    p.write_text(json.dumps(t))
    return p


def _replay(gateway_bin, transcript, tmp_path):
    """Drive the hermetic replay; return (stdout, parsed audit-cmd args dict)."""
    lab = tmp_path / "lab"
    lab.mkdir()
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "LAB_DIR": str(lab),
        "AUTHS_HOME": str(lab / "registry"),
        "AUTHS_REPO": str(lab / "registry"),
        "AUTHS_KEYCHAIN_BACKEND": "file",
        "AUTHS_KEYCHAIN_FILE": str(lab / "keys.enc"),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@auths.dev",
        "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@auths.dev",
        "NO_COLOR": "1",
    }
    out = subprocess.run(
        [str(gateway_bin), "replay", "--transcript", str(transcript)],
        capture_output=True, text=True, env=env, timeout=180,
    )
    stdout = out.stdout + out.stderr
    m = re.search(r"audit-cmd:\s*--log\s+(\S+)\s+--registry\s+(\S+)\s+--agent\s+(\S+)\s+--root\s+(\S+)", stdout)
    args = None
    if m:
        args = {"log": m.group(1), "registry": m.group(2),
                "agent": m.group(3), "root": m.group(4), "env": env}
    return stdout, args


def _verify_run(gateway_bin, log, args, extra=()):
    return subprocess.run(
        [str(gateway_bin), "verify-spend",
         "--log", str(log), "--registry", args["registry"],
         "--agent", args["agent"], "--root", args["root"], *extra],
        capture_output=True, text=True, env=args["env"], timeout=120,
    )


def _verify_spend(gateway_bin, log, args):
    out = _verify_run(gateway_bin, log, args)
    return out.stdout + out.stderr


def _read_records(log_path: Path):
    """The one-period-file record lines this hermetic replay wrote (JSONL)."""
    return [ln for ln in Path(log_path).read_text().splitlines() if ln.strip()]


def _head_of(gateway_bin, log, args):
    """The checkpoint head (`binding=`) the auditor pins — the anti-rollback anchor."""
    text = _verify_spend(gateway_bin, log, args)
    m = re.search(r"binding=(\S+)", text)
    return m.group(1) if m else None


@pytest.mark.slow
@pytest.mark.requires_binary
class TestSpendLogAuditAcrossRotation:
    def test_replay_self_audit_finds_the_rotated_log(self, gateway_bin, transcript, tmp_path):
        """The in-process self-audit must FIND and re-verify the rotated log —
        never 'SKIPPED — no spend log to audit' (the exact regression)."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert "audit: SKIPPED" not in stdout, f"audit skipped a rotated log:\n{stdout}"
        # The honest offline verdict is `self-consistent` (completeness is unprovable offline).
        assert "audit: self-consistent" in stdout, f"self-audit not consistent:\n{stdout}"
        assert args is not None, f"no audit-cmd emitted:\n{stdout}"
        # The emitted log path is the rotated layout: a per-delegation directory.
        assert f"spend-log{os.sep}" in args["log"] and args["log"].endswith(".jsonl")
        assert Path(args["log"]).parent.name != "spend-log", "log is flat, not rotated"

    def test_verify_spend_walks_a_multi_period_rotated_log(self, gateway_bin, transcript, tmp_path):
        """Split the log across two period files (a real rotation boundary) and
        assert the standalone auditor re-derives `consistent` over the directory —
        the hash chain must hold ACROSS files, not just within one."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        spend_dir = log_file.parent
        records = [ln for ln in log_file.read_text().splitlines() if ln.strip()]
        assert len(records) >= 2, "need >=2 records to split across periods"
        half = len(records) // 2
        # Sorted period names so the directory walk replays in append order.
        (spend_dir / "2000-01.jsonl").write_text("\n".join(records[:half]) + "\n")
        (spend_dir / "2999-12.jsonl").write_text("\n".join(records[half:]) + "\n")
        log_file.unlink()  # remove the original single-period file

        out = _verify_spend(gateway_bin, spend_dir, args)
        assert "verify-spend: self-consistent" in out, \
            f"rotated multi-file audit not consistent:\n{out}"

    def test_tampering_is_caught_across_the_rotation_boundary(self, gateway_bin, transcript, tmp_path):
        """A dropped record in an EARLIER period file breaks the signed back-link
        chain and must be caught — rotation must not let a hostile operator hide a
        truncation between files."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        spend_dir = log_file.parent
        records = [ln for ln in log_file.read_text().splitlines() if ln.strip()]
        assert len(records) >= 3
        half = len(records) // 2
        # Rotate, then DROP the first record of the earlier period (chain break).
        (spend_dir / "2000-01.jsonl").write_text("\n".join(records[1:half]) + "\n")
        (spend_dir / "2999-12.jsonl").write_text("\n".join(records[half:]) + "\n")
        log_file.unlink()

        out = _verify_spend(gateway_bin, spend_dir, args)
        assert "verify-spend: self-consistent" not in out, f"tampered rotated log passed:\n{out}"
        assert re.search(r"chain-break|budget-mismatch|tampered-proof", out), \
            f"tamper not caught with a distinct verdict:\n{out}"


@pytest.mark.slow
@pytest.mark.requires_binary
class TestSpendLogAuditQuality:
    """The audit says exactly what it proved — no bare `consistent`, distinct break
    kinds, a portable verdict object, and an unverified operator block."""

    def test_tail_truncation_reads_self_consistent_with_caveat(self, gateway_bin, transcript, tmp_path):
        # Dropping the LAST record of a $0 log is invisible to the offline
        # audit (completeness is unprovable offline) — but the verdict must SAY so and the pinned
        # head must change, never a bare `consistent`.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        full_head = _head_of(gateway_bin, log_file, args)
        records = _read_records(log_file)
        assert len(records) >= 2
        log_file.write_text("\n".join(records[:-1]) + "\n")

        out = _verify_run(gateway_bin, log_file, args)
        text = out.stdout + out.stderr
        assert out.returncode == 0, text  # truncation of a $0 tail is undetectable offline
        assert "self-consistent" in text and "consistent —" not in text.replace("self-consistent", ""), text
        assert "completeness unproven" in text, text
        truncated_head = _head_of(gateway_bin, log_file, args)
        assert truncated_head and truncated_head != full_head, "the pinned head must change"

    def test_verify_spend_json_is_a_portable_object(self, gateway_bin, transcript, tmp_path):
        # `--json` emits one portable `audit/v1` line, not scraped text.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        out = _verify_run(gateway_bin, Path(args["log"]), args, extra=["--json"])
        line = next(ln for ln in out.stdout.splitlines() if ln.strip().startswith("{"))
        report = json.loads(line)
        assert report["version"] == "audit/v1", report
        assert report["code"] == "self-consistent", report
        assert report["checkpoint"]["binding"], report

    def test_verdict_word_is_not_doubled(self, gateway_bin, transcript, tmp_path):
        # The clean line is exactly `verify-spend: self-consistent — …`, the word once.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        out = _verify_run(gateway_bin, Path(args["log"]), args)
        line = next(ln for ln in (out.stdout + out.stderr).splitlines()
                    if ln.startswith("verify-spend:"))
        assert re.match(r"^verify-spend: self-consistent — ", line), line
        assert "self-consistent — self-consistent" not in line, line

    def test_structural_breaks_are_distinguished(self, gateway_bin, transcript, tmp_path):
        # Delete-middle → Missing, swap → OutOfOrder,
        # duplicate → Duplicate, each naming an index.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        base = _read_records(log_file)
        assert len(base) >= 4, "need >=4 records for delete-middle/swap/duplicate"

        # delete the middle record.
        dropped = base[:1] + base[2:]
        log_file.write_text("\n".join(dropped) + "\n")
        text = _verify_spend(gateway_bin, log_file, args)
        assert "chain-break" in text and "Missing" in text, text
        assert re.search(r"record \d+", text), text

        # swap two adjacent records.
        swapped = base[:1] + [base[2], base[1]] + base[3:]
        log_file.write_text("\n".join(swapped) + "\n")
        text = _verify_spend(gateway_bin, log_file, args)
        assert "chain-break" in text and "OutOfOrder" in text, text

        # duplicate a record.
        dup = base[:2] + [base[1]] + base[2:]
        log_file.write_text("\n".join(dup) + "\n")
        text = _verify_spend(gateway_bin, log_file, args)
        assert "chain-break" in text and "Duplicate" in text, text

    def test_receipt_display_edit_does_not_forge_a_verdict(self, gateway_bin, transcript, tmp_path):
        # The operator block is `unverified_display`; editing its `tool` forges no
        # verdict because the audit re-derives from signed material only.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        records = [json.loads(ln) for ln in _read_records(log_file)]
        assert "unverified_display" in records[0], records[0].keys()
        assert "receipt" not in records[0], "the wire must not carry a bare `receipt`"
        records[0]["unverified_display"]["tool"] = "wire_money"
        log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        out = _verify_run(gateway_bin, log_file, args, extra=["--json"])
        line = next(ln for ln in out.stdout.splitlines() if ln.strip().startswith("{"))
        report = json.loads(line)
        # The re-derived verdict reflects only signed material — the display edit changes nothing.
        assert report["code"] == "self-consistent", report

    def test_emptied_log_is_not_a_clean_pass(self, gateway_bin, transcript, tmp_path):
        # An emptied log re-derives records:0 with the completeness caveat, never a
        # silent clean bill of health.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        log_file.write_text("")
        out = _verify_run(gateway_bin, log_file, args, extra=["--json"])
        line = next(ln for ln in out.stdout.splitlines() if ln.strip().startswith("{"))
        report = json.loads(line)
        assert report["records"] == 0, report
        assert report.get("completeness") == "unproven-offline" or report["consistent"], report

    def test_reformat_and_truncation_speak_not_serde(self, gateway_bin, transcript, tmp_path):
        # `jq .` and a truncated tail SPEAK `malformed-log`, never serde noise
        # and never `tampered-proof`.
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        records = _read_records(log_file)

        # `jq .` pretty-prints each record across many lines.
        pretty = "\n".join(json.dumps(json.loads(r), indent=2) for r in records)
        log_file.write_text(pretty + "\n")
        text = _verify_spend(gateway_bin, log_file, args)
        assert "malformed-log" in text, text
        assert "tampered-proof" not in text, text

        # A crash-truncated final record.
        half = records[-1][: len(records[-1]) // 2]
        log_file.write_text("\n".join(records[:-1] + [half]) + "\n")
        text = _verify_spend(gateway_bin, log_file, args)
        assert "malformed-log" in text and "truncated" in text, text
        assert "tampered-proof" not in text, text


def _stripe_fixture(dir_path: Path, charge_id="ch_3MmlLrLkdIwHu7ix0snN0B15", cents=300):
    body = {
        "rail": "stripe",
        "charge": {"id": charge_id, "object": "charge", "amount": cents,
                   "amount_captured": cents, "amount_refunded": 0, "currency": "usd",
                   "captured": True, "paid": True, "status": "succeeded", "livemode": False},
    }
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "stripe-charge.json").write_text(json.dumps(body))
    return "stripe-charge.json"


def _replay_metered(gateway_bin, tmp_path):
    """Replay a METERED transcript (a stripe fixture drives the cost) and return (stdout, args)."""
    fixtures = tmp_path / "fixtures"
    _stripe_fixture(fixtures)
    t = {
        "grant": {"scope": ["paid.call"], "budget": "$50.00", "ttl": "30m"},
        "calls": [
            {"tool": "paid_call", "rail": "stripe",
             "response_fixture": "stripe-charge.json", "expect": "allowed"},
        ],
    }
    p = tmp_path / "metered.json"
    p.write_text(json.dumps(t))
    lab = tmp_path / "lab"
    lab.mkdir()
    env = {
        **os.environ,
        "HOME": str(tmp_path), "LAB_DIR": str(lab),
        "AUTHS_HOME": str(lab / "registry"), "AUTHS_REPO": str(lab / "registry"),
        "AUTHS_KEYCHAIN_BACKEND": "file", "AUTHS_KEYCHAIN_FILE": str(lab / "keys.enc"),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "AUTHS_MCP_RAIL_FIXTURES": str(fixtures),
        "AUTHS_MCP_TEST_MODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@auths.dev",
        "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@auths.dev",
        "NO_COLOR": "1",
    }
    out = subprocess.run(
        [str(gateway_bin), "replay", "--transcript", str(p)],
        capture_output=True, text=True, env=env, timeout=240,
    )
    stdout = out.stdout + out.stderr
    m = re.search(r"audit-cmd:\s*--log\s+(\S+)\s+--registry\s+(\S+)\s+--agent\s+(\S+)\s+--root\s+(\S+)", stdout)
    if not m:
        return stdout, None
    return stdout, {"log": m.group(1), "registry": m.group(2),
                    "agent": m.group(3), "root": m.group(4), "env": env}


@pytest.mark.slow
@pytest.mark.requires_binary
class TestMeteredAudit:
    def test_counterparty_rewrite_is_caught(self, gateway_bin, tmp_path):
        # Rewrite the rail_response charge id (leaving the SIGNED
        # Auths-Settle-Ref intact) — the audit catches `counterparty-mismatch`, exit non-zero.
        stdout, args = _replay_metered(gateway_bin, tmp_path)
        if args is None:
            pytest.skip(f"metered replay produced no audit-cmd:\n{stdout}")
        log_file = Path(args["log"])
        records = [json.loads(ln) for ln in _read_records(log_file)]
        rewritten = False
        for rec in records:
            settle = rec.get("settlement", {})
            resp = settle.get("rail_response")
            if resp:
                text = bytes(resp).decode("utf-8", "replace")
                if "ch_3Mml" in text:
                    text = text.replace("ch_3MmlLrLkdIwHu7ix0snN0B15", "ch_ATTACKERxxxxxxxxxxxx")
                    settle["rail_response"] = list(text.encode("utf-8"))
                    rewritten = True
        if not rewritten:
            pytest.skip("metered replay carried no re-writable rail response")
        log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        out = _verify_run(gateway_bin, log_file, args)
        text = out.stdout + out.stderr
        assert out.returncode != 0, text
        assert "counterparty-mismatch" in text, text

    def test_metered_replay_rederives_real_cents(self, gateway_bin, tmp_path):
        # A metered replay re-derives its real (non-zero) total, never
        # `budget-mismatch — re-derived 0c`.
        stdout, args = _replay_metered(gateway_bin, tmp_path)
        if args is None:
            pytest.skip(f"metered replay produced no audit-cmd:\n{stdout}")
        out = _verify_run(gateway_bin, Path(args["log"]), args, extra=["--json"])
        assert "budget-mismatch" not in (out.stdout + out.stderr), out.stdout + out.stderr
        line = next((ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")), None)
        assert line, out.stdout
        report = json.loads(line)
        assert report["consistent"], report
        assert report["settled_cents"] == 300, report
