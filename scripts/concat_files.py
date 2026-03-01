#!/usr/bin/env python3
"""Concatenate source files from specified paths into a single file.

Run:
    python scripts/concat_files.py                # current directory
    python scripts/concat_files.py src/           # single directory
    python scripts/concat_files.py src/ lib/      # multiple directories
    python scripts/concat_files.py -o out.txt .   # custom output file
"""

import argparse
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────

INCLUDE_EXTS = {
    ".rs",
    ".md",
    ".toml",
}

# Default directories to search when no paths provided
SEARCH_PREFIXES = [
    "packages",
    "crates",
    # "docs"
]

EXCLUDE = {
    ".git",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    ".egg-info",
    ".venv",
    "dist",
    "build",
    "out",
    "htmlcov",
    "coverage",
    "node_modules",
    ".next",
    ".cache",
    "target",
}

ENCODING = "utf-8"

BANNER_CHAR = "─"
BANNER_WIDTH = 160
JOIN_WITH = "\n\n" + BANNER_CHAR * BANNER_WIDTH + "\n"

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────


def is_excluded_path(path: Path) -> bool:
    return any(part in EXCLUDE for part in path.parts)


def should_include_file(path: Path) -> bool:
    return path.is_file() and path.suffix in INCLUDE_EXTS


def banner(title: str) -> str:
    pad = max(BANNER_WIDTH - len(title) - 2, 0)
    left = pad // 2
    right = pad - left
    return f"{BANNER_CHAR * left} {title} {BANNER_CHAR * right}\n"


def read_file(path: Path) -> str:
    try:
        return path.read_text(encoding=ENCODING)
    except Exception as e:
        return f"[ERROR READING FILE: {e}]"


# ─────────────────────────────────────────────────────────────
# TREE + FILE COLLECTION
# ─────────────────────────────────────────────────────────────


def print_tree(root: Path, prefix: str = "") -> None:
    try:
        entries = [
            p
            for p in root.iterdir()
            if not is_excluded_path(p) and (p.is_dir() or should_include_file(p))
        ]
    except PermissionError:
        return

    entries.sort(key=lambda p: (p.is_file(), p.name.lower()))

    for i, entry in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}{entry.name}")

        if entry.is_dir():
            extension = "    " if is_last else "│   "
            print_tree(entry, prefix + extension)


def collect_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if is_excluded_path(path):
            continue
        if should_include_file(path):
            files.append(path)
    return sorted(files)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Concatenate source files from specified paths into a single file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/concat_files.py                # current directory
    python scripts/concat_files.py src/           # single directory
    python scripts/concat_files.py src/ lib/      # multiple directories
    python scripts/concat_files.py -o out.txt .   # custom output file
""",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=None,
        help="Files or directories to include (default: packages/ and crates/)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("concat_output.txt"),
        help="Output file (default: concat_output.txt)",
    )
    parser.add_argument(
        "--no-tree",
        action="store_true",
        help="Skip printing the file tree",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Use default prefixes if no paths provided
    input_paths = args.paths if args.paths else [Path(p) for p in SEARCH_PREFIXES]

    # Resolve paths
    paths: list[Path] = []
    for p in input_paths:
        rp = p.resolve()
        if not rp.exists():
            print(f"Warning: {p} does not exist, skipping", file=sys.stderr)
            continue
        paths.append(rp)

    if not paths:
        print("Error: No valid paths provided", file=sys.stderr)
        sys.exit(1)

    # Find common root for display
    if len(paths) == 1:
        root = paths[0] if paths[0].is_dir() else paths[0].parent
    else:
        parts_list = [p.parts for p in paths]
        common_parts: list[str] = []
        for parts in zip(*parts_list):
            if len(set(parts)) == 1:
                common_parts.append(parts[0])
            else:
                break
        root = Path(*common_parts) if common_parts else Path("/")

    # Print tree (optional)
    if not args.no_tree:
        print(root)
        for i, p in enumerate(paths):
            is_last = i == len(paths) - 1
            connector = "└── " if is_last else "├── "
            try:
                rel = p.relative_to(root)
            except ValueError:
                rel = p
            if p.is_dir():
                print(f"{connector}{rel}")
                extension = "    " if is_last else "│   "
                print_tree(p, prefix=extension)
            else:
                print(f"{connector}{rel}")

    # Collect contents
    output: list[str] = []

    for p in paths:
        if p.is_file():
            try:
                rel = p.relative_to(root)
            except ValueError:
                rel = p
            output.append(banner(str(rel)))
            output.append(read_file(p))
        else:
            for file in collect_files(p):
                try:
                    rel = file.relative_to(root)
                except ValueError:
                    rel = file
                output.append(banner(str(rel)))
                output.append(read_file(file))

    if not output:
        print("No files found matching criteria", file=sys.stderr)
        sys.exit(1)

    out_path = args.output.resolve()
    out_path.write_text(JOIN_WITH.join(output), encoding=ENCODING)

    file_count = len(output) // 2
    print(f"\n✓ Wrote {file_count} file{'s' if file_count != 1 else ''} to {out_path}")


if __name__ == "__main__":
    main()
