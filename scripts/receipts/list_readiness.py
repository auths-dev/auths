#!/usr/bin/env python3
"""RC-E5.4 — marketplace listing readiness: stand up the publishing surface
`apps/market` actually requires, deterministically.

Produces, from a live (or hermetic replay) gateway lab:
  1. the signed `activity/v1` attestation (`activity.json`) — the ONLY published
     spend artifact; the raw per-call log never leaves this machine;
  2. the sibling `audit.json` = {registry_git_url, root, agent} — identity/key
     resolution only;
  3. a publishable identity registry directory (push it to any public git URL
     exposing refs/auths/*);
  4. a seeding check — the attestation carries > 0 settled cents (run the demo
     or real traffic first if it doesn't);
plus the checklist for (5) seller registration.

Usage:
    python3 scripts/receipts/list_readiness.py --live-dir <gateway live dir> \
        --agent <did:keri:…> --root <did:keri:…> \
        --registry-url https://github.com/you/registry.git --out ./publish
    python3 scripts/receipts/list_readiness.py --hermetic   # replay-minted lab
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "e2e"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-dir")
    ap.add_argument("--agent")
    ap.add_argument("--root")
    ap.add_argument("--registry-url", default="https://example.com/registry.git")
    ap.add_argument("--out", default="./publish")
    ap.add_argument("--hermetic", action="store_true")
    args = ap.parse_args()

    from test_receipts_threat_model import _find_binary, _mint_lab  # noqa: E402

    gateway = _find_binary("GATEWAY_BIN", "auths-mcp-gateway")
    if not gateway:
        print("build first: cargo build --release -p auths-mcp-gateway")
        return 1

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    if args.hermetic:
        tmp = Path(tempfile.mkdtemp(prefix="list-readiness-"))
        lab = _mint_lab(gateway, tmp, calls=4)
        live_dir = str(Path(lab["registry"]).parent)
        agent, root, env = lab["agent"], lab["root"], lab["env"]
    else:
        if not (args.live_dir and args.agent and args.root):
            print("--live-dir/--agent/--root required (or --hermetic)")
            return 2
        live_dir, agent, root = args.live_dir, args.agent, args.root
        env = dict(os.environ)

    print("» (1) exporting the signed activity/v1 attestation (no per-call data leaves)")
    r = subprocess.run(
        [str(gateway), "export-attestation",
         "--live-dir", live_dir, "--agent", agent, "--root", root,
         "--out", str(out / "activity.json"),
         "--registry-url", args.registry_url],
        capture_output=True, text=True, env=env, timeout=180,
    )
    print("  " + (r.stdout + r.stderr).strip())
    if r.returncode != 0:
        return 1

    doc = json.loads((out / "activity.json").read_text())
    print(f"» (2) audit.json written beside it (identity resolution only)")
    print(f"» (3) publish the registry: push {live_dir}/registry to {args.registry_url}")
    print(f"      (must expose refs/auths/* — the market fetches KELs, never spend data)")

    cents = int(doc.get("cumulative_cents", 0))
    if cents > 0:
        print(f"» (4) seeded: attestation carries {cents} settled cents — "
              "proven-live follows once the market witnesses growth across probes")
    else:
        print("» (4) NOT seeded: 0 settled cents — run scripts/receipts/demo.py or real "
              "traffic through your wrap, then re-export")

    print("""» (5) checklist — seller registration & listing:
      [ ] host activity.json + audit.json at a public https URL (the attestationUrl)
      [ ] push the registry to the audit.json registry_git_url
      [ ] list with endpointValue = the BARE server command (`auths-receipts-server`
          / `auths-escrow-server`) — never a wrap line (listing-input rejects it)
      [ ] register the seller (GitHub OAuth v0, or the auths-native presentation
          carrying `market:sell` for the auths-verified badge)
      [ ] re-export + republish activity.json on a cadence ≤ the market's probe
          cadence so witnessed growth accrues""")
    print(f"\npublish dir: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
