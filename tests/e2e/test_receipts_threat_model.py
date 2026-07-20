"""E2E: the receipts threat-model gate — a frozen transcript
drives the REAL gateway to mint a signed spend log + registry, then the REAL
`auths-receipts-server` builds EvidenceBundles over it and every attack row is
asserted against `receipt_verify`'s offline re-derivation. No network, no chain.

Coverage map:
  1  clean deal → authorized/consistent, as-of head        (here)
  2  byte-flipped KEL event → tampered                     (here)
  3  truncated spend log, same anchor → head-mismatch      (here)
  4  stale treasury head → head-mismatch / anchor rejected  (Rust: cases/anchor.rs)
  4b concurrent-producer chain fork regression              (auths-site perf scenario
     `tests/performance/scenarios/chain.mjs`; the sequential linear-chain leg here)
  5  stated verdict ≠ recomputed → tampered                (here)
  6  over-budget call                                       (Rust: cases/judge.rs)
  7  revocation before head → unauthorized                 (here)
  8  revocation after head → authorized as-of; flagged      (here)
  8b TEL revocation, no KEL tip moved → unauthorized       (here, via telRevocation)
  9  registry substitution → unauthorized/refused          (here)
  10 forged treasury checkpoint                             (Rust: cases/anchor.rs)
  11–15, 18 escrow rows                                     (Rust: cases/escrow.rs)
  16 D1 gate-vs-rederivation mismatch → unverifiable        (Rust: cases/judge.rs)
  17 cross-rail budget                                      (Rust: cases/judge.rs)
  19 wrong-call binding                                     (here)
  20 AllowList injection redirect → out-of-counterparty     (here + Rust)
  21 policy downgrade → still out-of-counterparty           (Rust: cases/judge.rs)
"""

import json
import os
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


@pytest.fixture(scope="module")
def receipts_bin():
    b = _find_binary("RECEIPTS_BIN", "auths-receipts-server")
    if b is None:
        pytest.skip("auths-receipts-server binary not built")
    return b


def _lab_env(tmp_path: Path) -> dict:
    lab = tmp_path / "lab"
    lab.mkdir(exist_ok=True)
    return {
        **os.environ,
        "HOME": str(tmp_path),
        "LAB_DIR": str(lab),
        "AUTHS_HOME": str(lab / "registry"),
        "AUTHS_REPO": str(lab / "registry"),
        "AUTHS_KEYCHAIN_BACKEND": "file",
        "AUTHS_KEYCHAIN_FILE": str(lab / "keys.enc"),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "e2e",
        "GIT_AUTHOR_EMAIL": "e2e@auths.dev",
        "GIT_COMMITTER_NAME": "e2e",
        "GIT_COMMITTER_EMAIL": "e2e@auths.dev",
        "NO_COLOR": "1",
    }


def _mint_lab(gateway_bin, tmp_path: Path, calls: int = 4):
    """Replay a frozen transcript: a REAL delegation chain, signed calls, and a
    spend log the offline audit re-derives — the material every row attacks."""
    transcript = {
        "grant": {"scope": ["fs.read"], "budget": "$5.00", "ttl": "30m"},
        "calls": [
            {"tool": "read_file", "args": {"path": f"/etc/hosts#{i}"},
             "cost_cents": 0, "expect": "allowed"}
            for i in range(calls)
        ],
    }
    tpath = tmp_path / "transcript.json"
    tpath.write_text(json.dumps(transcript))
    env = _lab_env(tmp_path)
    out = subprocess.run(
        [str(gateway_bin), "replay", "--transcript", str(tpath)],
        capture_output=True, text=True, env=env, timeout=240,
    )
    stdout = out.stdout + out.stderr
    import re
    m = re.search(
        r"audit-cmd:\s*--log\s+(\S+)\s+--registry\s+(\S+)\s+--agent\s+(\S+)\s+--root\s+(\S+)",
        stdout,
    )
    assert m, f"replay emitted no audit-cmd:\n{stdout}"
    return {
        "log": m.group(1),
        "registry": m.group(2),
        "agent": m.group(3),
        "root": m.group(4),
        "env": env,
    }


class Mcp:
    """A minimal MCP stdio client — initialize + tools/call over JSONL."""

    def __init__(self, argv, env):
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
        )
        self._id = 0
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05",
                               "capabilities": {},
                               "clientInfo": {"name": "e2e", "version": "0"}}})
        self._recv()
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0",
                                          "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

    def _next(self):
        self._id += 1
        return self._id

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _recv(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                err = self.proc.stderr.read()
                raise AssertionError(f"server closed the stream:\n{err}")
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if "id" in msg:
                return msg

    def call(self, tool, args):
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
                    "params": {"name": tool, "arguments": args}})
        msg = self._recv()
        if "error" in msg:
            return {"_error": msg["error"]}
        content = msg["result"]["content"][0]["text"]
        return json.loads(content)

    def close(self):
        self.proc.kill()


def _receipts_server(receipts_bin, lab, extra_env=None) -> Mcp:
    env = {
        **lab["env"],
        "AUTHS_RECEIPTS_REGISTRY": lab["registry"],
        "AUTHS_RECEIPTS_AGENT": lab["agent"],
        "AUTHS_RECEIPTS_ROOT": lab["root"],
        "AUTHS_RECEIPTS_LOG": lab["log"],
        "AUTHS_RECEIPTS_COUNTERPARTY": "0xseller",
        **(extra_env or {}),
    }
    return Mcp([str(receipts_bin)], env)


@pytest.fixture(scope="module")
def lab(gateway_bin, tmp_path_factory):
    return _mint_lab(gateway_bin, tmp_path_factory.mktemp("receipts-lab"))


@pytest.fixture(scope="module")
def clean_bundle(receipts_bin, lab):
    server = _receipts_server(receipts_bin, lab)
    try:
        bundle = server.call("receipt_build", {"paymentRef": "#0"})
        assert "_error" not in bundle, bundle
        return bundle
    finally:
        server.close()


def _verify(receipts_bin, lab, bundle):
    server = _receipts_server(receipts_bin, lab)
    try:
        return server.call("receipt_verify", {"bundle": bundle})
    finally:
        server.close()


@pytest.mark.slow
@pytest.mark.requires_binary
class TestReceiptsThreatModel:
    def test_row1_clean_deal_authorized_as_of_head(self, receipts_bin, lab, clean_bundle):
        assert clean_bundle["version"] == "receipts/v1"
        assert clean_bundle["verdicts"]["call"] == "authorized"
        assert clean_bundle["verdicts"]["log"] == "consistent"
        assert clean_bundle["verdicts"]["asOf"]["head"], "no anchor head"
        v = _verify(receipts_bin, lab, clean_bundle)
        assert v["ok"], v
        # The verdict always restates the anchor — never a bare 'authorized'.
        assert v["verdicts"]["asOf"]["tier"]

    def test_row2_byte_flipped_kel_event_is_tampered(self, receipts_bin, lab, clean_bundle):
        import copy
        mutated = copy.deepcopy(clean_bundle)
        kel = mutated["proof"]["agentKel"]
        assert kel, "bundle embeds no agent KEL"
        text = json.dumps(kel[0])
        flipped = text.replace("a", "b", 1) if "a" in text else text.replace("1", "2", 1)
        mutated["proof"]["agentKel"][0] = json.loads(flipped)
        v = _verify(receipts_bin, lab, mutated)
        assert not v["ok"]
        assert v["reason"] in ("tampered", "head-mismatch", "invalid-proof"), v

    def test_row3_truncated_log_same_anchor_is_head_mismatch(self, receipts_bin, lab, clean_bundle):
        import copy
        mutated = copy.deepcopy(clean_bundle)
        assert len(mutated["proof"]["spendLog"]) >= 3
        mutated["proof"]["spendLog"] = mutated["proof"]["spendLog"][:-2]
        v = _verify(receipts_bin, lab, mutated)
        assert not v["ok"]
        assert v["reason"] == "head-mismatch", v

    def test_row4b_sequential_chain_rederives_linear(self, gateway_bin, lab):
        """The linear-chain leg: N calls re-derive as ONE chain, `consistent`.
        The pipelined-concurrency fork regression runs in the perf scenario
        (auths-site tests/performance/scenarios/chain.mjs) against the same
        critical section."""
        out = subprocess.run(
            [str(gateway_bin), "verify-spend",
             "--log", lab["log"], "--registry", lab["registry"],
             "--agent", lab["agent"], "--root", lab["root"]],
            capture_output=True, text=True, env=lab["env"], timeout=120,
        )
        assert "verify-spend: self-consistent" in out.stdout + out.stderr

    def test_row5_swapped_verdict_is_tampered(self, receipts_bin, lab, clean_bundle):
        import copy
        mutated = copy.deepcopy(clean_bundle)
        mutated["verdicts"]["call"] = "unauthorized"
        v = _verify(receipts_bin, lab, mutated)
        assert not v["ok"]
        # The bundle signature covers the verdicts, so either failure is sound;
        # both name the forgery.
        assert v["reason"] in ("invalid-signature", "tampered"), v

    def test_row19_wrong_call_binding_echo(self, receipts_bin, lab, clean_bundle):
        """A valid bundle for call X must not pass as evidence for call Y: the
        verifier echoes subject/tx/callIndex and the CALLER binds them."""
        v = _verify(receipts_bin, lab, clean_bundle)
        assert v["ok"]
        assert v["callIndex"] == clean_bundle["call"]["index"]
        assert v["subject"] == clean_bundle["subject"]
        # The caller's binding assertion — the disputed call here is #1, the
        # bundle is about #0: relevance check fails even though validity holds.
        disputed_index = 1
        assert v["callIndex"] != disputed_index, "the binding check must be able to fail"

    def test_row8b_tel_revocation_before_head_is_unauthorized(self, receipts_bin, lab):
        server = _receipts_server(receipts_bin, lab)
        try:
            bundle = server.call("dispute_evidence", {
                "paymentRef": "#0",
                "telRevocation": {"source": "tel", "ts": "2000-01-01T00:00:00Z"},
            })
            assert "_error" not in bundle, bundle
            assert bundle["verdicts"]["call"] == "unauthorized"
            v = server.call("receipt_verify", {"bundle": bundle})
            assert v["ok"], v  # internally consistent AND damning
        finally:
            server.close()

    def test_row9_registry_substitution_refused(self, gateway_bin, receipts_bin, lab,
                                                tmp_path_factory):
        other = _mint_lab(gateway_bin, tmp_path_factory.mktemp("other-root"), calls=1)
        env = {
            **lab["env"],
            "AUTHS_RECEIPTS_REGISTRY": other["registry"],  # wrong root's registry
            "AUTHS_RECEIPTS_AGENT": lab["agent"],
            "AUTHS_RECEIPTS_ROOT": other["root"],
            "AUTHS_RECEIPTS_LOG": lab["log"],
        }
        server = Mcp([str(receipts_bin)], env)
        try:
            result = server.call("receipt_build", {"paymentRef": "#0"})
            if "_error" not in result:
                assert result["verdicts"]["call"] in ("unauthorized", "unverifiable"), result
        finally:
            server.close()

    def test_row20_allow_list_redirect_refused_and_rederives(self, receipts_bin, lab):
        grant = {
            "scope": ["fs.read"],
            "cap": "$5",
            "currency": "USD",
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2036-01-01T00:00:00Z",
            "budgetBasis": "cross-rail",
            "counterpartyPolicy": {"kind": "allow-list", "allow": ["0xseller"]},
        }
        server = _receipts_server(
            receipts_bin, lab, {"AUTHS_RECEIPTS_GRANT": json.dumps(grant)},
        )
        try:
            # Steered to an attacker: in-scope, under cap, off-list.
            bundle = server.call("receipt_build",
                                 {"paymentRef": "#0", "counterparty": "0xattacker"})
            assert "_error" not in bundle, bundle
            assert bundle["verdicts"]["call"] == "out-of-counterparty"
            # …and it re-derives identically offline.
            v = server.call("receipt_verify", {"bundle": bundle})
            assert v["ok"], v
            assert v["verdicts"]["call"] == "out-of-counterparty"
            # The signed policy allows the legitimate seller.
            ok = server.call("receipt_build",
                             {"paymentRef": "#0", "counterparty": "0xseller"})
            assert ok["verdicts"]["call"] == "authorized"
        finally:
            server.close()

    def test_rows7_8_revocation_before_and_after_head(self, gateway_bin, receipts_bin,
                                                      lab, tmp_path_factory):
        # A dedicated lab so the revocation does not poison the shared fixture.
        rlab = _mint_lab(gateway_bin, tmp_path_factory.mktemp("revoke-lab"), calls=2)
        # Row 8: the bundle built BEFORE the revocation stays authorized as-of
        # its head forever (its embedded KEL predates the revocation).
        server = _receipts_server(receipts_bin, rlab)
        try:
            before = server.call("receipt_build", {"paymentRef": "#0"})
            assert before["verdicts"]["call"] == "authorized", before
        finally:
            server.close()

        auths_bin = _find_binary("AUTHS_BIN", "auths")
        assert auths_bin is not None, "auths CLI required for the revocation row"
        out = subprocess.run(
            [str(auths_bin), "--repo", rlab["registry"], "--json",
             "id", "agent", "revoke", rlab["agent"], "--key", "root"],
            capture_output=True, text=True, env=rlab["env"], timeout=120,
        )
        assert out.returncode == 0, out.stdout + out.stderr

        # Row 8 (offline leg): the pre-revocation bundle still verifies as-of H.
        v = _verify(receipts_bin, rlab, before)
        assert v["ok"], v
        assert v["verdicts"]["call"] == "authorized"

        # Row 7: a bundle built AFTER the revocation re-derives unauthorized.
        server = _receipts_server(receipts_bin, rlab)
        try:
            after = server.call("receipt_build", {"paymentRef": "#0"})
            if "_error" in after:
                # A resolve that fails closed on the revoked delegation is an
                # acceptable refusal shape too.
                return
            assert after["verdicts"]["call"] in ("unauthorized", "unverifiable"), after
            if after["verdicts"]["call"] == "unauthorized":
                v = _verify(receipts_bin, rlab, after)
                assert v["ok"], v
        finally:
            server.close()

    def test_dispute_bundle_carries_freshness_and_render(self, receipts_bin, lab):
        server = _receipts_server(receipts_bin, lab)
        try:
            bundle = server.call("dispute_evidence", {"paymentRef": "#0"})
            assert "_error" not in bundle, bundle
            # D4 — the build-time online re-check stamp.
            fresh = bundle["verdicts"].get("onlineFreshness")
            assert fresh and "checkedAt" in fresh and "contradicted" in fresh
            # The render exists and never re-expands hashed args.
            assert "args hash" in bundle["rendered"]
            args_hash = bundle["call"]["args_hash"]
            assert args_hash in bundle["rendered"]
            assert "/etc/hosts" not in json.dumps(bundle), "plaintext args leaked"
        finally:
            server.close()

    def test_reversal_within_remit_routes_subjective(self, receipts_bin, lab, clean_bundle):
        server = _receipts_server(receipts_bin, lab)
        try:
            out = server.call("reversal_determine", {"bundle": clean_bundle})
            assert out["determined"] is False
            assert out["route"] == "subjective"
        finally:
            server.close()

    def test_reversal_remit_violation_grounds_claim(self, receipts_bin, lab):
        grant = {
            "scope": ["fs.read"], "cap": "$5", "currency": "USD",
            "issuedAt": "2020-01-01T00:00:00Z", "expiresAt": "2036-01-01T00:00:00Z",
            "budgetBasis": "cross-rail",
            "counterpartyPolicy": {"kind": "allow-list", "allow": ["0xseller"]},
        }
        server = _receipts_server(
            receipts_bin, lab, {"AUTHS_RECEIPTS_GRANT": json.dumps(grant)},
        )
        try:
            bundle = server.call("receipt_build",
                                 {"paymentRef": "#0", "counterparty": "0xattacker"})
            assert bundle["verdicts"]["call"] == "out-of-counterparty"
            out = server.call("reversal_determine", {"bundle": bundle, "hold": "none"})
            assert out["determined"] is True, out
            det = out["determination"]
            assert det["version"] == "reversal/v1"
            assert det["parties"]["payerPrincipal"] == bundle["subject"]["root"]
            assert det["parties"]["payerPrincipal"] != bundle["subject"]["agent"]
            assert det["railHint"] == "claim-only"
            assert out["rail"]["result"]["outcome"] == "claim-recorded"
        finally:
            server.close()

    def test_export_produces_pdf_exhibit(self, receipts_bin, lab, clean_bundle):
        server = _receipts_server(receipts_bin, lab)
        try:
            out = server.call("evidence_export", {"bundle": clean_bundle, "format": "pdf"})
            assert out["format"] == "pdf"
            import base64
            pdf = base64.b64decode(out["base64"])
            assert pdf.startswith(b"%PDF-1.4")
            assert b"VERIFICATION APPENDIX" in pdf or b"AUTHS EVIDENCE" in pdf
        finally:
            server.close()


def _mint_metered_lab(gateway_bin, tmp_path: Path):
    """Replay a METERED transcript (a stripe fixture drives the cost, $3.00 = 300c) and return
    the audit-cmd args — the material the cost-downgrade row attacks."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    (fixtures / "stripe-charge.json").write_text(json.dumps({
        "rail": "stripe",
        "charge": {"id": "ch_3MmlLrLkdIwHu7ix0snN0B15", "object": "charge",
                   "amount": 300, "amount_captured": 300, "amount_refunded": 0,
                   "currency": "usd", "captured": True, "paid": True,
                   "status": "succeeded", "livemode": False},
    }))
    transcript = {
        "grant": {"scope": ["paid.call"], "budget": "$50.00", "ttl": "30m"},
        "calls": [{"tool": "paid_call", "rail": "stripe",
                   "response_fixture": "stripe-charge.json", "expect": "allowed"}],
    }
    tpath = tmp_path / "metered.json"
    tpath.write_text(json.dumps(transcript))
    env = {**_lab_env(tmp_path),
           "AUTHS_MCP_RAIL_FIXTURES": str(fixtures), "AUTHS_MCP_TEST_MODE": "1"}
    out = subprocess.run(
        [str(gateway_bin), "replay", "--transcript", str(tpath)],
        capture_output=True, text=True, env=env, timeout=240,
    )
    stdout = out.stdout + out.stderr
    import re
    m = re.search(
        r"audit-cmd:\s*--log\s+(\S+)\s+--registry\s+(\S+)\s+--agent\s+(\S+)\s+--root\s+(\S+)",
        stdout,
    )
    if not m:
        return None
    return {"log": m.group(1), "registry": m.group(2),
            "agent": m.group(3), "root": m.group(4), "env": env}


@pytest.mark.slow
@pytest.mark.requires_binary
class TestReceiptsCostMismatch:
    def test_row_amount_downgrade_is_cost_mismatch(self, gateway_bin, tmp_path_factory):
        # Downgrade the rail response 300c → 50c while the SIGNED
        # Auths-Settle-Cents stays 300 — the audit catches `cost-mismatch`, exit non-zero.
        tmp_path = tmp_path_factory.mktemp("cost-mismatch")
        args = _mint_metered_lab(gateway_bin, tmp_path)
        if args is None:
            pytest.skip("metered replay produced no audit-cmd")
        log_file = Path(args["log"])
        records = [json.loads(ln) for ln in log_file.read_text().splitlines() if ln.strip()]
        downgraded = False
        for rec in records:
            resp = rec.get("settlement", {}).get("rail_response")
            if resp:
                text = bytes(resp).decode("utf-8", "replace")
                if '"amount_captured": 300' in text or '"amount_captured":300' in text:
                    text = text.replace('"amount_captured": 300', '"amount_captured": 50')
                    text = text.replace('"amount_captured":300', '"amount_captured":50')
                    rec["settlement"]["rail_response"] = list(text.encode("utf-8"))
                    downgraded = True
        if not downgraded:
            pytest.skip("metered replay carried no re-writable rail response")
        log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        out = subprocess.run(
            [str(gateway_bin), "verify-spend", "--log", str(log_file),
             "--registry", args["registry"], "--agent", args["agent"], "--root", args["root"]],
            capture_output=True, text=True, env=args["env"], timeout=120,
        )
        text = out.stdout + out.stderr
        assert out.returncode != 0, text
        assert "cost-mismatch" in text, text
