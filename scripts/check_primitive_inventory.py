#!/usr/bin/env python3
"""Drift guard for docs/security/primitive-inventory.md (PRD CR-7).

Parses the pin table in the inventory doc and asserts every `<crate> = <version>`
row matches a real pin in some Cargo.toml in the workspace. Fails (exit 1) if a
documented pin no longer matches the tree — so the inventory cannot silently
drift from what actually compiles.

Run: python3 scripts/check_primitive_inventory.py   (CI runs this)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "security" / "primitive-inventory.md"

# A pin-table row: | <primitive desc> | <crate> | <version> |
ROW = re.compile(r"^\|[^|]+\|\s*([a-z0-9][a-z0-9-]*)\s*\|\s*([0-9][0-9.]*)\s*\|\s*$")


def documented_pins():
    pins = {}  # crate -> version (last wins; same crate always same version)
    for line in DOC.read_text().splitlines():
        m = ROW.match(line)
        if m:
            pins[m.group(1)] = m.group(2)
    return pins


def declared_versions(crate):
    """Every version string the tree declares for `crate` (leading '=' stripped)."""
    pat = re.compile(rf'^{re.escape(crate)}\s*=\s*(?:"([^"]+)"|\{{[^}}]*\bversion\s*=\s*"([^"]+)")')
    found = set()
    for toml in [ROOT / "Cargo.toml", *ROOT.glob("crates/*/Cargo.toml")]:
        for line in toml.read_text().splitlines():
            m = pat.match(line.strip())
            if m:
                found.add((m.group(1) or m.group(2)).lstrip("="))
    return found


def main():
    if not DOC.exists():
        print(f"MISSING: {DOC} does not exist", file=sys.stderr)
        return 1
    pins = documented_pins()
    if not pins:
        print("no pin-table rows parsed — is the table format intact?", file=sys.stderr)
        return 1
    bad = []
    for crate, want in sorted(pins.items()):
        have = declared_versions(crate)
        if want not in have:
            bad.append((crate, want, sorted(have) or ["<not declared>"]))
    if bad:
        print("primitive-inventory.md drift — documented pin != Cargo.toml:", file=sys.stderr)
        for crate, want, have in bad:
            print(f"  {crate}: doc says {want}, tree has {', '.join(have)}", file=sys.stderr)
        return 1
    print(f"primitive-inventory.md: {len(pins)} pins all match the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
