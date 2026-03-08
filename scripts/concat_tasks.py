#!/usr/bin/env python3
"""Concatenate .flow task markdown files into a single text file in .scratch/.

Usage:
1. Edit the `tasks` list below with the task numbers you want.
2. Run:
python3 scripts/concat_tasks.py
3. Output: .scratch/tasks.txt
"""

import glob
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASKS_DIR = os.path.join(REPO_ROOT, ".flow", "tasks")
SCRATCH_DIR = os.path.join(REPO_ROOT, ".scratch")

# ── Edit this list ──
tasks = [44, 45, 46, 47, 48, 49, 50]


def natural_sort_key(path):
    parts = re.split(r"(\d+)", os.path.basename(path))
    return [int(p) if p.isdigit() else p for p in parts]


def main():
    os.makedirs(SCRATCH_DIR, exist_ok=True)

    all_files = []
    for task_id in tasks:
        pattern = os.path.join(TASKS_DIR, f"fn-{task_id}.*.md")
        matches = sorted(glob.glob(pattern), key=natural_sort_key)
        if not matches:
            print(f"warning: no files found for task {task_id}")
        all_files.extend(matches)

    if not all_files:
        print("No task files found.")
        return

    output_path = os.path.join(SCRATCH_DIR, "tasks.txt")
    with open(output_path, "w") as out:
        for path in all_files:
            out.write(f"{'=' * 80}\n")
            out.write(f"FILE: {os.path.basename(path)}\n")
            out.write(f"{'=' * 80}\n\n")
            with open(path) as f:
                out.write(f.read())
            out.write("\n\n")

    print(f"Wrote {len(all_files)} files to {output_path}")


if __name__ == "__main__":
    main()
